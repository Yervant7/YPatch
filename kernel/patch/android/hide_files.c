/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2025 Yervant7. All Rights Reserved.
 */

#include <ktypes.h>
#include <hook.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <asm-generic/compat.h>
#include <uapi/asm-generic/errno.h>
#include <syscall.h>
#include <symbol.h>
#include <linux/rculist.h>
#include <linux/list.h>
#include <kconfig.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <taskob.h>
#include <predata.h>
#include <accctl.h>
#include <asm/current.h>
#include <linux/printk.h>
#include <linux/rcupdate.h>
#include <linux/gfp.h>
#include <linux/vmalloc.h>
#include <kputils.h>
#include <linux/ptrace.h>
#include <predata.h>
#include <linux/kernel.h>
#include <linux/umh.h>
#include <linux/container_of.h>
#include <uapi/scdefs.h>
#include <sucompat.h>
#include <kallsyms.h>
#include <log.h>
#include <stddef.h>
#include <linux/spinlock.h>
#include <uapi/linux/limits.h>
#include <linux/hashtable.h>

#define HIDE_FILES_HASH_BITS 8
static DECLARE_HASHTABLE(hide_files_hash_table, HIDE_FILES_HASH_BITS);
static DEFINE_SPINLOCK(hide_files_hash_lock);

struct hide_file_entry {
    char *filename;
    struct hlist_node hnode;
    struct rcu_head rcu_head;
};

typedef unsigned int (*full_name_hash_t)(const void *salt, const char *, unsigned int);
static full_name_hash_t full_name_hash_fn = 0;

static void hide_file_entry_free(struct rcu_head *head)
{
    struct hide_file_entry *entry = container_of(head, struct hide_file_entry, rcu_head);
    if (entry->filename) {
        vfree(entry->filename);
    }
    vfree(entry);
}

int add_hide_file(const char *filename)
{
    if (!filename) return -EINVAL;

    struct hide_file_entry *entry = vmalloc(sizeof(struct hide_file_entry));
    if (!entry)
        return -ENOMEM;

    memset(entry, 0, sizeof(struct hide_file_entry));

    size_t len = strlen(filename);
    entry->filename = vmalloc(len + 1);
    if (!entry->filename) {
        vfree(entry);
        return -ENOMEM;
    }

    strcpy(entry->filename, filename);

    u32 key = full_name_hash_fn(NULL, filename, len);

    spin_lock(&hide_files_hash_lock);
    hash_add_rcu(hide_files_hash_table, &entry->hnode, key);
    spin_unlock(&hide_files_hash_lock);

    return 0;
}

int remove_hide_file(const char *filename)
{
    if (!filename) return -EINVAL;

    struct hide_file_entry *entry;
    int found = 0;

    u32 key = full_name_hash_fn(NULL, filename, strlen(filename));

    spin_lock(&hide_files_hash_lock);
    hash_for_each_possible_rcu(hide_files_hash_table, entry, hnode, key) {
        if (entry->filename && strcmp(entry->filename, filename) == 0) {
            hash_del_rcu(&entry->hnode);
            call_rcu(&entry->rcu_head, hide_file_entry_free);
            found = 1;
            break;
        }
    }
    spin_unlock(&hide_files_hash_lock);

    return found ? 0 : -ENOENT;
}

static int should_hide_file(const char *name, int namelen)
{
    if (!name || namelen <= 0) return 0;

    struct hide_file_entry *entry;
    int found = 0;

    u32 key = full_name_hash_fn(NULL, name, namelen);

    rcu_read_lock();
    hash_for_each_possible_rcu(hide_files_hash_table, entry, hnode, key) {
        if (entry->filename && strstr(name, entry->filename)) {
            found = 1;
            break;
        }
    }
    rcu_read_unlock();

    return found;
}

struct dir_context;

typedef bool (*filldir_t)(struct dir_context *, const char *, int, loff_t, u64, unsigned);

struct dir_context {
	filldir_t actor;
	loff_t pos;
};

static filldir_t customfilldir_ptr = NULL;

#define HIDDEN_DIR_MAGIC 0x1337C0DE
#define HIDDEN_DIR_MAGIC2 0xDEADBEEF

struct hidden_dir_context {
    unsigned long magic1;
    struct dir_context orig_ctx;
    filldir_t orig_actor;
    unsigned long magic2;
    struct dir_context *original_ctx_ptr;
};

static int (*orig_iterate_dir)(struct file *file, struct dir_context *ctx);

struct path;
struct filename;

static int (*orig_filename_lookup)(int dfd, struct filename *name, unsigned flags, struct path *path, struct path *root);

typedef char *(*d_path_t)(const struct path *, char *, int);
static d_path_t d_path = 0;

struct hook_passthrough_data {
    struct hidden_dir_context *hctx;
    struct dir_context *original_ctx;
};

static inline bool validate_hidden_context(struct hidden_dir_context *hctx)
{
    if (!hctx) return false;

    if (hctx->magic1 != HIDDEN_DIR_MAGIC || hctx->magic2 != HIDDEN_DIR_MAGIC2) {
        return false;
    }

    if (!hctx->orig_actor || hctx->orig_actor == customfilldir_ptr) {
        return false;
    }
    
    return true;
}

static bool custom_filldir(struct dir_context *ctx, const char *name, int namelen, 
                          loff_t offset, u64 ino, unsigned int d_type)
{
    if (should_hide_file(name, namelen)) {
        return true;
    }

    if (!ctx) {
        pr_err("custom_filldir: invalid context\n");
        return false;
    }

    struct hidden_dir_context *hctx = container_of(ctx, struct hidden_dir_context, orig_ctx);

    if (!validate_hidden_context(hctx)) {
        pr_err("custom_filldir: invalid hidden context - ctx=%p, hctx=%p\n", ctx, hctx);
        if (hctx) {
            pr_err("custom_filldir: magic1=0x%lx, magic2=0x%lx, orig_actor=%p\n", 
                   hctx->magic1, hctx->magic2, hctx->orig_actor);
        }
        return false;
    }

    return hctx->orig_actor(hctx->original_ctx_ptr, name, namelen, offset, ino, d_type);
}

static void before_iterate_dir(hook_fargs2_t *args, void *udata)
{
    args->local.data0 = NULL;
    struct dir_context *original_ctx = (struct dir_context *)args->arg1;

    uid_t uid = current_uid();

    if (!is_uid_excluded_fast(uid) || !original_ctx) {
        return;
    }
    
    if (!original_ctx->actor) {
        pr_err("before_iterate_dir: no actor in original context\n");
        return;
    }
    
    if (original_ctx->actor == custom_filldir) {
        pr_err("before_iterate_dir: already using custom_filldir\n");
        return;
    }

    struct hidden_dir_context *hctx = vmalloc(sizeof(struct hidden_dir_context));
    if (!hctx) {
        pr_err("before_iterate_dir: failed to allocate hidden context\n");
        return;
    }

    memset(hctx, 0, sizeof(struct hidden_dir_context));
    hctx->magic1 = HIDDEN_DIR_MAGIC;
    hctx->magic2 = HIDDEN_DIR_MAGIC2;
    hctx->orig_ctx = *original_ctx;
    hctx->orig_actor = original_ctx->actor;
    hctx->original_ctx_ptr = original_ctx;

    hctx->orig_ctx.actor = custom_filldir;

    struct hook_passthrough_data *passthrough = vmalloc(sizeof(*passthrough));
    if (!passthrough) {
        pr_err("before_iterate_dir: failed to allocate passthrough data\n");
        vfree(hctx);
        return;
    }

    memset(passthrough, 0, sizeof(*passthrough));
    
    passthrough->hctx = hctx;
    passthrough->original_ctx = original_ctx;
    args->local.data0 = (uint64_t)passthrough;

    args->arg1 = (uint64_t)&(hctx->orig_ctx);
    
    pr_info("before_iterate_dir: hook installed - uid=%d, original_actor=%p\n", 
             uid, hctx->orig_actor);
}

static void after_iterate_dir(hook_fargs2_t *args, void *udata)
{
    struct hook_passthrough_data *passthrough = (struct hook_passthrough_data *)args->local.data0;
    if (!passthrough) return;

    struct hidden_dir_context *hctx = passthrough->hctx;
    struct dir_context *original_ctx = passthrough->original_ctx;

    if (hctx && validate_hidden_context(hctx)) {
        if (original_ctx) {
            original_ctx->pos = hctx->orig_ctx.pos;
        }

        hctx->magic1 = 0;
        hctx->magic2 = 0;
    } else {
        pr_err("after_iterate_dir: invalid context during cleanup\n");
    }

    args->arg1 = (uint64_t)original_ctx;

    if (hctx) vfree(hctx);
    vfree(passthrough);
}

static int hooked_filename_lookup(int dfd, struct filename *name, unsigned flags, struct path *path, struct path *root)
{
    uid_t uid = current_uid();
    if (!is_uid_excluded_fast(uid)) {
        goto original;
    }
    char path_buf[PATH_MAX];
    int namelen;

    char *pathc = d_path(path, path_buf, sizeof(path_buf));
    if (IS_ERR(pathc))
        goto original;

    namelen = strlen(pathc);
    if (namelen <= 0)
        goto original;

    if (should_hide_file(pathc, namelen)) {
        return -ENOENT;
    }
    
original:
    return orig_filename_lookup(dfd, name, flags, path, root);
}

int hide_files_init()
{
    hook_err_t ret = 0;
    hook_err_t rc = HOOK_NO_ERR;

    hash_init(hide_files_hash_table);

    full_name_hash_fn = (full_name_hash_t)kallsyms_lookup_name("full_name_hash");
    if (!full_name_hash_fn) {
        log_boot("Failed to find full_name_hash symbol\n");
        return -1;
    }

    customfilldir_ptr = custom_filldir;

    void *iterate_dir_addr = (void *)kallsyms_lookup_name("iterate_dir");
    if (!iterate_dir_addr) {
        log_boot("Failed to find iterate_dir symbol\n");
        return -1;
    }
    
    log_boot("iterate_dir found at address: %p\n", iterate_dir_addr);

    rc = hook_wrap(iterate_dir_addr, 2, before_iterate_dir, after_iterate_dir, 0);
    log_boot("hook iterate_dir rc: %d\n", rc);
    ret |= rc;

    if (rc != HOOK_NO_ERR) {
        log_boot("Failed to hook iterate_dir, error: %d\n", rc);
        return -1;
    }

    d_path = (d_path_t)kallsyms_lookup_name("d_path");
    if (!d_path) {
        log_boot("Failed to find d_path symbol\n");
        return -1;
    }

    void *filename_lookup_addr = (void *)kallsyms_lookup_name("filename_lookup");
    if (!filename_lookup_addr) {
        log_boot("Failed to find filename_lookup symbol\n");
    } else {
        log_boot("filename_lookup found at address: %p\n", filename_lookup_addr);
        
        rc = hook(filename_lookup_addr, hooked_filename_lookup, (void **)orig_filename_lookup);
        log_boot("hook filename_lookup rc: %d\n", rc);
        ret |= rc;
        
        if (rc != HOOK_NO_ERR) {
            log_boot("Failed to hook filename_lookup, error: %d\n", rc);
        }
    }

    log_boot("hide_files_init completed successfully\n");
    return ret;
}