/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 * Copyright (C) 2025 Yervant7. All Rights Reserved.
 */

#include <linux/list.h>
#include <ktypes.h>
#include <compiler.h>
#include <stdbool.h>
#include <linux/syscall.h>
#include <ksyms.h>
#include <hook.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <stdbool.h>
#include <asm/current.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <uapi/scdefs.h>
#include <kputils.h>
#include <linux/ptrace.h>
#include <accctl.h>
#include <linux/string.h>
#include <linux/err.h>
#include <uapi/asm-generic/errno.h>
#include <taskob.h>
#include <linux/kernel.h>
#include <linux/rculist.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <syscall.h>
#include <predata.h>
#include <kconfig.h>
#include <linux/vmalloc.h>
#include <sucompat.h>
#include <symbol.h>
#include <uapi/linux/limits.h>
#include <linux/hashtable.h>

const char sh_path[] = SH_PATH;
const char default_su_path[] = SU_PATH;

#ifdef ANDROID
const char legacy_su_path[] = LEGACY_SU_PATH;
const char apd_path[] = APD_PATH;
#endif

static const char *current_su_path = 0;

#define SU_HASH_BITS 8
static DECLARE_HASHTABLE(su_hash_table, SU_HASH_BITS);
static DEFINE_SPINLOCK(su_hash_lock);

#define EXCLUDE_CACHE_START 10000
#define EXCLUDE_CACHE_END   11000
#define EXCLUDE_CACHE_SIZE  (EXCLUDE_CACHE_END - EXCLUDE_CACHE_START)

static uint8_t exclude_direct_cache[EXCLUDE_CACHE_SIZE] = {0};
static bool exclude_direct_enabled = false;

#define EXCLUDE_HASH_BITS 6
static DECLARE_HASHTABLE(exclude_hash_table, EXCLUDE_HASH_BITS);
static DEFINE_SPINLOCK(exclude_hash_lock);

struct su_entry {
    uid_t uid;
    struct su_profile profile;
    struct hlist_node hnode;
    struct rcu_head rcu_head;
};

struct exclude_entry {
    uid_t uid;
    int exclude;
    struct hlist_node hnode;
    struct rcu_head rcu_head;
};

static struct su_entry *find_su_entry(uid_t uid)
{
    struct su_entry *entry;
    hash_for_each_possible_rcu(su_hash_table, entry, hnode, uid) {
        if (entry->uid == uid)
            return entry;
    }
    return NULL;
}

static struct exclude_entry *find_exclude_entry(uid_t uid)
{
    struct exclude_entry *entry;
    hash_for_each_possible_rcu(exclude_hash_table, entry, hnode, uid) {
        if (entry->uid == uid)
            return entry;
    }
    return NULL;
}

static void exclude_entry_free(struct rcu_head *head)
{
    struct exclude_entry *entry = container_of(head, struct exclude_entry, rcu_head);
    vfree(entry);
}

static void su_entry_free(struct rcu_head *head)
{
    struct su_entry *entry = container_of(head, struct su_entry, rcu_head);
    vfree(entry);
}

int is_su_allow_uid(uid_t uid)
{
    struct su_entry *entry;
    int rc = 0;
    rcu_read_lock();
    entry = find_su_entry(uid);
    if (entry) {
        rc = entry->profile.uid == uid;
    }
    rcu_read_unlock();
    return rc;
}
KP_EXPORT_SYMBOL(is_su_allow_uid);

int su_add_allow_uid(uid_t uid, uid_t to_uid, const char *scontext)
{
    if (!scontext) scontext = "";

    struct su_entry *entry = (struct su_entry *)vmalloc(sizeof(struct su_entry));
    if (!entry)
        return -ENOMEM;

    memset(entry, 0, sizeof(struct su_entry));

    entry->uid = uid;
    entry->profile.uid = uid;
    entry->profile.to_uid = to_uid;
    memcpy(entry->profile.scontext, scontext, SUPERCALL_SCONTEXT_LEN);

    su_remove_allow_uid(uid);

    spin_lock(&su_hash_lock);
    hash_add_rcu(su_hash_table, &entry->hnode, uid);
    spin_unlock(&su_hash_lock);

    logkfd("uid: %d, to_uid: %d, sctx: %s\n", uid, to_uid, scontext);
    return 0;
}
KP_EXPORT_SYMBOL(su_add_allow_uid);

int su_remove_allow_uid(uid_t uid)
{
    struct su_entry *entry;

    spin_lock(&su_hash_lock);
    entry = find_su_entry(uid);
    if (entry) {
        hash_del_rcu(&entry->hnode);
        spin_unlock(&su_hash_lock);
        call_rcu(&entry->rcu_head, su_entry_free);
        return 0;
    }
    spin_unlock(&su_hash_lock);
    return -ENOENT;
}
KP_EXPORT_SYMBOL(su_remove_allow_uid);

int su_allow_uid_nums()
{
    int count = 0;
    int bkt;
    struct su_entry *entry;

    rcu_read_lock();
    hash_for_each_rcu(su_hash_table, bkt, entry, hnode) {
        count++;
    }
    rcu_read_unlock();

    return count;
}
KP_EXPORT_SYMBOL(su_allow_uid_nums);

static int allow_uids_cb(struct su_entry *entry, void *udata)
{
    struct {
        int is_user;
        uid_t *out_uids;
        int idx;
        int out_num;
    } *up = udata;

    if (up->idx >= up->out_num) {
        return -ENOBUFS;
    }

    if (up->is_user) {
        int cprc = compat_copy_to_user(up->out_uids + up->idx, &entry->profile.uid, sizeof(uid_t));
        if (cprc <= 0) {
            logkfd("compat_copy_to_user error: %d", cprc);
            return cprc;
        }
    } else {
        up->out_uids[up->idx] = entry->profile.uid;
    }

    up->idx++;
    return 0;
}

int su_allow_uids(int is_user, uid_t *out_uids, int out_num)
{
    struct {
        int is_user;
        uid_t *out_uids;
        int idx;
        int out_num;
    } udata = { is_user, out_uids, 0, out_num };

    struct su_entry *entry;
    int bkt;

    rcu_read_lock();
    hash_for_each_rcu(su_hash_table, bkt, entry, hnode) {
        int rc = allow_uids_cb(entry, &udata);
        if (rc) break;
    }
    rcu_read_unlock();

    return udata.idx;
}
KP_EXPORT_SYMBOL(su_allow_uids);

int su_allow_uid_profile(int is_user, uid_t uid, struct su_profile *out_profile)
{
    struct su_entry *entry;
    int rc = -ENOENT;

    rcu_read_lock();
    entry = find_su_entry(uid);
    if (entry) {
        if (is_user) {
            rc = compat_copy_to_user(out_profile, &entry->profile, sizeof(struct su_profile));
            if (rc <= 0) {
                logkfd("compat_copy_to_user error: %d", rc);
                rc = -EFAULT;
                goto out;
            }
            rc = 0;
        } else {
            memcpy(out_profile, &entry->profile, sizeof(struct su_profile));
            rc = 0;
        }
    }

out:
    rcu_read_unlock();
    return rc;
}
KP_EXPORT_SYMBOL(su_allow_uid_profile);

int su_reset_path(const char *path)
{
    if (!path) return -EINVAL;
    if (IS_ERR(path)) return PTR_ERR(path);
    current_su_path = path;
    logkfd("%s\n", current_su_path);
    dsb(ish);
    return 0;
}
KP_EXPORT_SYMBOL(su_reset_path);

const char *su_get_path()
{
    if (!current_su_path) current_su_path = default_su_path;
    return current_su_path;
}
KP_EXPORT_SYMBOL(su_get_path);

static void handle_before_execve(char **__user u_filename_p, char **__user uargv, void *udata)
{
    char __user *ufilename = *u_filename_p;
    char filename[SU_PATH_MAX_LEN];
    int flen = compat_strncpy_from_user(filename, ufilename, sizeof(filename));
    if (flen <= 0) return;

    if (!strcmp(current_su_path, filename)) {
        uid_t uid = current_uid();
        struct su_profile profile;
        if (su_allow_uid_profile(0, uid, &profile)) return;

        uid_t to_uid = profile.to_uid;
        const char *sctx = profile.scontext;
        commit_su(to_uid, sctx);

#ifdef ANDROID
        struct file *filp = filp_open(apd_path, O_RDONLY, 0);
        if (!filp || IS_ERR(filp)) {
#endif
            void *uptr = copy_to_user_stack(sh_path, sizeof(sh_path));
            if (uptr && !IS_ERR(uptr)) {
                *u_filename_p = (char *__user)uptr;
            }
            logkfi("call su uid: %d, to_uid: %d, sctx: %s, uptr: %llx\n", uid, to_uid, sctx, uptr);
#ifdef ANDROID
        } else {
            filp_close(filp, 0);

            uint64_t sp = current_user_stack_pointer();
            sp -= sizeof(apd_path);
            sp &= 0xFFFFFFFFFFFFFFF8;
            int cplen = compat_copy_to_user((void *)sp, apd_path, sizeof(apd_path));
            if (cplen > 0) {
                *u_filename_p = (char *)sp;
            }

            int argv_cplen = 0;
            if (strcmp(legacy_su_path, filename)) {
                sp = sp ?: current_user_stack_pointer();
                sp -= sizeof(legacy_su_path);
                sp &= 0xFFFFFFFFFFFFFFF8;
                argv_cplen = compat_copy_to_user((void *)sp, legacy_su_path, sizeof(legacy_su_path));
                if (argv_cplen > 0) {
                    int rc = set_user_arg_ptr(0, *uargv, 0, sp);
                    if (rc < 0) {
                        logkfi("call apd argv error, uid: %d, to_uid: %d, sctx: %s, rc: %d\n", uid, to_uid, sctx, rc);
                    }
                }
            }
            logkfi("call apd uid: %d, to_uid: %d, sctx: %s, cplen: %d, %d\n", uid, to_uid, sctx, cplen, argv_cplen);
        }
#endif // ANDROID
    } else if (!strcmp(SUPERCMD, filename)) {
        void handle_supercmd(char **__user u_filename_p, char **__user uargv);
        handle_supercmd(u_filename_p, uargv);
        return;
    }
}

bool is_uid_excluded_fast(uid_t uid)
{
    // Fast path: direct cache access with likely hint
    if (likely(exclude_direct_enabled && 
               uid >= EXCLUDE_CACHE_START && 
               uid < EXCLUDE_CACHE_END)) {
        return exclude_direct_cache[uid - EXCLUDE_CACHE_START];
    }

    // Fallback: Hash table with optimized lookup
    struct exclude_entry *entry;
    bool excluded = false;
    
    // Use RCU read lock for safe concurrent access
    rcu_read_lock();
    hash_for_each_possible_rcu(exclude_hash_table, entry, hnode, uid) {
        if (entry->uid == uid) {
            excluded = entry->exclude;
            break;
        }
    }
    rcu_read_unlock();
    
    return excluded;
}
KP_EXPORT_SYMBOL(is_uid_excluded_fast);

static void before_execve(hook_fargs3_t *args, void *udata)
{
    uid_t uid = current_uid();
    if (likely(is_uid_excluded_fast(uid))) {
        return;
    }
    void *arg0p = syscall_argn_p(args, 0);
    void *arg1p = syscall_argn_p(args, 1);
    handle_before_execve((char **)arg0p, (char **)arg1p, udata);
}

__maybe_unused static void before_execveat(hook_fargs5_t *args, void *udata)
{
    uid_t uid = current_uid();
    if (likely(is_uid_excluded_fast(uid))) {
        return;
    }
    void *arg1p = syscall_argn_p(args, 1);
    void *arg2p = syscall_argn_p(args, 2);
    handle_before_execve((char **)arg1p, (char **)arg2p, udata);
}

static void su_handler_arg1_ufilename_before(hook_fargs6_t *args, void *udata)
{
    uid_t uid = current_uid();
    if (likely(is_uid_excluded_fast(uid))) {
        return;
    }
    if (!is_su_allow_uid(uid)) return;

    char __user **u_filename_p = (char __user **)syscall_argn_p(args, 1);

    char filename[SU_PATH_MAX_LEN];
    int flen = compat_strncpy_from_user(filename, *u_filename_p, sizeof(filename));
    if (flen <= 0) return;

    if (!strcmp(current_su_path, filename)) {
        void *uptr = copy_to_user_stack(sh_path, sizeof(sh_path));
        if (uptr && !IS_ERR(uptr)) {
            *u_filename_p = uptr;
        } else {
            logkfi("su uid: %d, cp stack error: %d\n", uid, uptr);
        }
    }
}

int remove_ap_mod_exclude(uid_t uid)
{
    struct exclude_entry *entry;

    spin_lock(&exclude_hash_lock);
    entry = find_exclude_entry(uid);
    if (entry) {
        hash_del_rcu(&entry->hnode);
        spin_unlock(&exclude_hash_lock);
        call_rcu(&entry->rcu_head, exclude_entry_free);
        return 0;
    }
    spin_unlock(&exclude_hash_lock);
    return -ENOENT;
}

int set_ap_mod_exclude(uid_t uid, int exclude)
{
    exclude = !!exclude;
    
    // Fast path: direct cache
    if (uid >= EXCLUDE_CACHE_START && uid < EXCLUDE_CACHE_END) {
        exclude_direct_cache[uid - EXCLUDE_CACHE_START] = exclude;
        exclude_direct_enabled = true;
        
        if (!exclude) {
            remove_ap_mod_exclude(uid);
        }
        return 0;
    }
    
    // Fallback: hash table with optimized lookup
    if (exclude) {
        struct exclude_entry *entry = vmalloc(sizeof(*entry));
        if (!entry)
            return -ENOMEM;

        entry->uid = uid;
        entry->exclude = exclude;

        spin_lock(&exclude_hash_lock);
        struct exclude_entry *old_entry;
        // Optimized lookup and removal
        hash_for_each_possible_rcu(exclude_hash_table, old_entry, hnode, uid) {
            if (old_entry->uid == uid) {
                hash_del_rcu(&old_entry->hnode);
                call_rcu(&old_entry->rcu_head, exclude_entry_free);
                break;
            }
        }
        hash_add_rcu(exclude_hash_table, &entry->hnode, uid);
        spin_unlock(&exclude_hash_lock);
    } else {
        remove_ap_mod_exclude(uid);
    }

    return 0;
}
KP_EXPORT_SYMBOL(set_ap_mod_exclude);

int get_ap_mod_exclude(uid_t uid)
{
    return is_uid_excluded_fast(uid);
}
KP_EXPORT_SYMBOL(get_ap_mod_exclude);

int list_ap_mod_exclude(uid_t *uids, int len)
{
    struct exclude_entry *entry;
    int bkt;
    int cnt = 0;
    rcu_read_lock();
    hash_for_each_rcu(exclude_hash_table, bkt, entry, hnode) {
        if (cnt >= len) break;
        uids[cnt++] = entry->uid;
    }
    rcu_read_unlock();
    return cnt;
}
KP_EXPORT_SYMBOL(list_ap_mod_exclude);

int su_compat_init()
{
    current_su_path = default_su_path;

    hash_init(su_hash_table);
    hash_init(exclude_hash_table);

#ifdef ANDROID
    if (!all_allow_sctx[0]) {
        strcpy(all_allow_sctx, ALL_ALLOW_SCONTEXT_MAGISK);
    }
    su_add_allow_uid(2000, 0, all_allow_sctx);
    su_add_allow_uid(0, 0, all_allow_sctx);
#endif

    hook_err_t rc = HOOK_NO_ERR;

    uint8_t su_config = patch_config->patch_su_config;
    bool enable = !!(su_config & PATCH_CONFIG_SU_ENABLE);
    bool wrap = !!(su_config & PATCH_CONFIG_SU_HOOK_NO_WRAP);
    log_boot("su config: %x, enable: %d, wrap: %d\n", su_config, enable, wrap);

    // if (!enable) return;

    rc = hook_syscalln(__NR_execve, 3, before_execve, 0, (void *)0);
    log_boot("hook __NR_execve rc: %d\n", rc);

    rc = hook_syscalln(__NR3264_fstatat, 4, su_handler_arg1_ufilename_before, 0, (void *)0);
    log_boot("hook __NR3264_fstatat rc: %d\n", rc);

    rc = hook_syscalln(__NR_faccessat, 3, su_handler_arg1_ufilename_before, 0, (void *)0);
    log_boot("hook __NR_faccessat rc: %d\n", rc);

    // __NR_execve 11
    rc = hook_compat_syscalln(11, 3, before_execve, 0, (void *)1);
    log_boot("hook 32 __NR_execve rc: %d\n", rc);

    // __NR_fstatat64 327
    rc = hook_compat_syscalln(327, 4, su_handler_arg1_ufilename_before, 0, (void *)0);
    log_boot("hook 32 __NR_fstatat64 rc: %d\n", rc);

    //  __NR_faccessat 334
    rc = hook_compat_syscalln(334, 3, su_handler_arg1_ufilename_before, 0, (void *)0);
    log_boot("hook 32 __NR_faccessat rc: %d\n", rc);

    return 0;
}