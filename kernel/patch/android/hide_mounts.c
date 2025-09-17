/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2025 Yervant7. All Rights Reserved.
 */

#include <linux/fs.h>
#include <linux/err.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/printk.h>
#include <linux/rcupdate.h>
#include <linux/vmalloc.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <uapi/linux/limits.h>

#include <stddef.h>
#include <linux/string.h>

#include <ktypes.h>
#include <hook.h>
#include <sucompat.h>
#include <kputils.h>
#include <log.h>

struct vfsmount;
struct seq_file;
struct fs_struct;

 #define HASH_LEN_DECLARE u32 hash; u32 len

struct qstr {
	union {
		struct {
			HASH_LEN_DECLARE;
		};
		u64 hash_len;
	};
	const unsigned char *name;
};

static int g_fs_root_offset = -1;
static int g_path_mnt_offset = -1;
static int g_path_dentry_offset = -1;
static int g_mnt_root_offset = -1;
static int g_mnt_mountpoint_offset = -1;
static int g_dentry_d_name_offset = -1;

#define GET_FIELD(ptr, offset, type) (*(type *)((char *)(ptr) + (offset)))

static const char *hidden_mount_prefixes[] = {
    "/data/adb/modules",
    "/debug_ramdisk",
    "/system",
    "/system_ext",
    "/vendor",
    "/product",
    "/odm",
    NULL
};

static int should_hide_mount(const char *mountpoint, const char *rootname)
{
    int i;
    if (!mountpoint && !rootname)
        return 0;

    const char *target = mountpoint ? mountpoint : rootname;

    for (i = 0; hidden_mount_prefixes[i] != NULL; i++) {
        const char *prefix = hidden_mount_prefixes[i];
        size_t len = strlen(prefix);

        if (strncmp(target, prefix, len) == 0) {
            if (target[len] == '\0' || target[len] == '/') {
                return 1;
            }
        }
    }

    return 0;
}

static int is_valid_qstr(const struct qstr *qstr)
{
    if (!qstr)
        return 0;
    if (IS_ERR_OR_NULL(qstr->name))
        return 0;
    if (qstr->len >= PATH_MAX || qstr->len < 0)
        return 0;

    return 1;
}

static int (*orig_show_vfsmnt)(struct seq_file *m, struct vfsmount *mnt);
static int hooked_show_vfsmnt(struct seq_file *m, struct vfsmount *mnt)
{
    if (!mnt || g_mnt_root_offset < 0 || g_mnt_mountpoint_offset < 0 || g_dentry_d_name_offset < 0) {
        return orig_show_vfsmnt(m, mnt);
    }
    uid_t uid = current_uid();
    if (!get_ap_mod_exclude(uid)) {
        return orig_show_vfsmnt(m, mnt);
    }
    rcu_read_lock();

    struct dentry *mnt_root = GET_FIELD(mnt, g_mnt_root_offset, struct dentry *);
    struct dentry *mnt_mountpoint = GET_FIELD(mnt, g_mnt_mountpoint_offset, struct dentry *);

    if (!mnt_root || !mnt_mountpoint) {
        rcu_read_unlock();
        return orig_show_vfsmnt(m, mnt);
    }

    const struct qstr *root_qstr = (const struct qstr *)((char *)mnt_root + g_dentry_d_name_offset);
    const struct qstr *mountpoint_qstr = (const struct qstr *)((char *)mnt_mountpoint + g_dentry_d_name_offset);

    if (!is_valid_qstr(root_qstr) || !is_valid_qstr(mountpoint_qstr)) {
        rcu_read_unlock();
        return orig_show_vfsmnt(m, mnt);
    }
    
    const char *mountpoint = mountpoint_qstr ? (const char *)mountpoint_qstr->name : NULL;
    const char *rootname = root_qstr ? (const char *)root_qstr->name : NULL;

    if (should_hide_mount(mountpoint, rootname)) {
        rcu_read_unlock();
        return 0;
    }
    
    rcu_read_unlock();
    return orig_show_vfsmnt(m, mnt);
}

static int (*orig_show_mountinfo)(struct seq_file *m, struct vfsmount *mnt);
static int hooked_show_mountinfo(struct seq_file *m, struct vfsmount *mnt)
{
    if (!mnt || g_mnt_root_offset < 0 || g_mnt_mountpoint_offset < 0 || g_dentry_d_name_offset < 0) {
        return orig_show_mountinfo(m, mnt);
    }
    uid_t uid = current_uid();
    if (!get_ap_mod_exclude(uid)) {
        return orig_show_mountinfo(m, mnt);
    }
    rcu_read_lock();

    struct dentry *mnt_root = GET_FIELD(mnt, g_mnt_root_offset, struct dentry *);
    struct dentry *mnt_mountpoint = GET_FIELD(mnt, g_mnt_mountpoint_offset, struct dentry *);
    if (!mnt_root || !mnt_mountpoint) {
        rcu_read_unlock();
        return orig_show_mountinfo(m, mnt);
    }
    const struct qstr *root_qstr = (const struct qstr *)((char *)mnt_root + g_dentry_d_name_offset);
    const struct qstr *mountpoint_qstr = (const struct qstr *)((char *)mnt_mountpoint + g_dentry_d_name_offset);

    if (!is_valid_qstr(root_qstr) || !is_valid_qstr(mountpoint_qstr)) {
        rcu_read_unlock();
        return orig_show_mountinfo(m, mnt);
    }

    const char *mountpoint = mountpoint_qstr ? (const char *)mountpoint_qstr->name : NULL;
    const char *rootname = root_qstr ? (const char *)root_qstr->name : NULL;
    if (should_hide_mount(mountpoint, rootname)) {
        rcu_read_unlock();
        return 0;
    }
    rcu_read_unlock();
    return orig_show_mountinfo(m, mnt);
}

static int (*orig_show_vfsstat)(struct seq_file *m, struct vfsmount *mnt);
static int hooked_show_vfsstat(struct seq_file *m, struct vfsmount *mnt)
{
    if (!mnt || g_mnt_root_offset < 0 || g_mnt_mountpoint_offset < 0 || g_dentry_d_name_offset < 0) {
        return orig_show_vfsstat(m, mnt);
    }
    uid_t uid = current_uid();
    if (!get_ap_mod_exclude(uid)) {
        return orig_show_vfsstat(m, mnt);
    }
    rcu_read_lock();
    struct dentry *mnt_root = GET_FIELD(mnt, g_mnt_root_offset, struct dentry *);
    struct dentry *mnt_mountpoint = GET_FIELD(mnt, g_mnt_mountpoint_offset, struct dentry *);
    if (!mnt_root || !mnt_mountpoint) {
        rcu_read_unlock();
        return orig_show_vfsstat(m, mnt);
    }
    const struct qstr *root_qstr = (const struct qstr *)((char *)mnt_root + g_dentry_d_name_offset);
    const struct qstr *mountpoint_qstr = (const struct qstr *)((char *)mnt_mountpoint + g_dentry_d_name_offset);

    if (!is_valid_qstr(root_qstr) || !is_valid_qstr(mountpoint_qstr)) {
        rcu_read_unlock();
        return orig_show_vfsstat(m, mnt);
    }

    const char *mountpoint = mountpoint_qstr ? (const char *)mountpoint_qstr->name : NULL;
    const char *rootname = root_qstr ? (const char *)root_qstr->name : NULL;
    if (should_hide_mount(mountpoint, rootname)) {
        rcu_read_unlock();
        return 0;
    }
    rcu_read_unlock();
    return orig_show_vfsstat(m, mnt);
}

static int is_root_dentry_by_scan(struct dentry *dentry_candidate)
{
    int offset;
    if (IS_ERR_OR_NULL(dentry_candidate)) {
        return 0;
    }

    for (offset = 0; offset <= 256; offset += sizeof(void*)) {
        const struct qstr *qstr_candidate = (const struct qstr *)((char *)dentry_candidate + offset);
        if (qstr_candidate->len == 1 && qstr_candidate->name &&
            !IS_ERR_OR_NULL(qstr_candidate->name) &&
            strncmp((const char*)qstr_candidate->name, "/", 1) == 0) {
            return 1;
        }
    }
    return 0;
}

static int discover_dentry_d_name_offset(struct dentry *root_dentry)
{
    int offset;
    log_boot("[*] Scanning for dentry->d_name offset...\n");

    for (offset = 0; offset <= 256; offset += sizeof(void*)) {
        const struct qstr *candidate = (const struct qstr *)((char *)root_dentry + offset);
        if (candidate->len == 1 && candidate->name &&
            !IS_ERR_OR_NULL(candidate->name) &&
            strncmp((const char*)candidate->name, "/", 1) == 0) {
            g_dentry_d_name_offset = offset;
            log_boot("[+] dentry->d_name offset found at %d\n", offset);
            return 0;
        }
    }

    log_boot("[-] FAILED to find dentry->d_name offset\n");
    return -1;
}

static int discover_vfsmount_offsets(struct vfsmount *root_mnt, struct dentry *root_dentry)
{
    int offset;
    int found_root = 0, found_mp = 0;
    log_boot("[*] Scanning for vfsmount->mnt_root and vfsmount->mnt_mountpoint offsets...\n");

    for (offset = 0; offset <= 256; offset += sizeof(void*)) {
        void *candidate = GET_FIELD(root_mnt, offset, void *);
        if (candidate == (void *)root_dentry) {
            if (!found_root) {
                g_mnt_root_offset = offset;
                found_root = 1;
                log_boot("[+] vfsmount->mnt_root offset found at %d\n", offset);
            } else {
                g_mnt_mountpoint_offset = offset;
                found_mp = 1;
                log_boot("[+] vfsmount->mnt_mountpoint offset found at %d\n", offset);
                break;
            }
        }
    }

    if (!found_root) {
        log_boot("[-] FAILED to find vfsmount->mnt_root offset\n");
        return -1;
    }
    if (!found_mp) {
        g_mnt_mountpoint_offset = g_mnt_root_offset;
        log_boot("[+] vfsmount->mnt_mountpoint offset set to be same as mnt_root: %d\n", g_mnt_mountpoint_offset);
    }
    return 0;
}

static int discover_path_offsets(void *path_ptr, struct vfsmount **out_mnt, struct dentry **out_dentry)
{
    int off1, off2;
    log_boot("[*] Scanning for path->mnt and path->dentry offsets...\n");

    for (off1 = 0; off1 < 16; off1 += sizeof(void*)) {
        for (off2 = 0; off2 < 16; off2 += sizeof(void*)) {
            if (off1 == off2) continue;

            struct vfsmount *mnt_candidate = GET_FIELD(path_ptr, off1, struct vfsmount *);
            struct dentry *dentry_candidate = GET_FIELD(path_ptr, off2, struct dentry *);

            if (IS_ERR_OR_NULL(mnt_candidate) || IS_ERR_OR_NULL(dentry_candidate)) {
                continue;
            }

            if (is_root_dentry_by_scan(dentry_candidate)) {
                g_path_mnt_offset = off1;
                g_path_dentry_offset = off2;
                *out_mnt = mnt_candidate;
                *out_dentry = dentry_candidate;
                log_boot("[+] path->mnt offset found at %d\n", g_path_mnt_offset);
                log_boot("[+] path->dentry offset found at %d\n", g_path_dentry_offset);
                return 0;
            }
        }
    }

    log_boot("[-] FAILED to find path->mnt and path->dentry offsets\n");
    return -1;
}


static int discover_fs_struct_offsets(struct fs_struct *fs)
{
    int offset;
    log_boot("[*] Scanning for fs_struct->root offset...\n");

    for (offset = 0; offset <= 256; offset += sizeof(void*)) {
        void *path_candidate_ptr = (char *)fs + offset;
        struct vfsmount *dummy_mnt;
        struct dentry *dummy_dentry;

        if (discover_path_offsets(path_candidate_ptr, &dummy_mnt, &dummy_dentry) == 0) {
            g_fs_root_offset = offset;
            log_boot("[+] fs_struct->root offset found at %d\n", offset);

            g_path_mnt_offset = -1;
            g_path_dentry_offset = -1;
            return 0;
        }
    }

    log_boot("[-] FAILED to find fs_struct->root offset\n");
    return -1;
}

static int discover_all_offsets(void)
{
    struct task_struct *init_task;
    struct fs_struct *fs;
    void *root_path_ptr;
    struct vfsmount *root_mnt;
    struct dentry *root_dentry;
    unsigned long init_task_addr;

    init_task_addr = kallsyms_lookup_name("init_task");
    if (!init_task_addr) {
        log_boot("[-] init_task not found in kallsyms\n");
        return -EFAULT;
    }
    init_task = (struct task_struct *)init_task_addr;
    fs = (struct fs_struct *)((char *)init_task + task_struct_offset.fs_offset);

    if (discover_fs_struct_offsets(fs) != 0) {
        return -1;
    }

    root_path_ptr = (void *)((char *)fs + g_fs_root_offset);

    if (discover_path_offsets(root_path_ptr, &root_mnt, &root_dentry) != 0) {
        return -1;
    }

    log_boot("[+] Got root_mnt at %px and root_dentry at %px\n", root_mnt, root_dentry);

    if (discover_vfsmount_offsets(root_mnt, root_dentry) != 0) {
        return -1;
    }
    if (discover_dentry_d_name_offset(root_dentry) != 0) {
        return -1;
    }

    return 0;
}

int hide_mounts_init(void)
{
    hook_err_t ret = 0;

    log_boot("[+] Initializing hide_mounts module...\n");

    if (discover_all_offsets() != 0) {
        log_boot("[-] Failed to discover critical kernel offsets. Aborting hooks.\n");
        return -1;
    }

    void *show_vfsmnt_addr = (void *)kallsyms_lookup_name("show_vfsmnt");
    void *show_mountinfo_addr = (void *)kallsyms_lookup_name("show_mountinfo");
    void *show_vfsstat_addr = (void *)kallsyms_lookup_name("show_vfsstat");
    
    // Hook show_vfsmnt
    if (show_vfsmnt_addr) {
        hook_err_t rc = hook(show_vfsmnt_addr, hooked_show_vfsmnt, (void **)&orig_show_vfsmnt);
        log_boot("[+] Hooking show_vfsmnt: %d\n", rc);
        ret |= rc;
    } else {
        log_boot("[-] show_vfsmnt symbol not found\n");
    }

    // Hook show_mountinfo
    if (show_mountinfo_addr) {
        hook_err_t rc = hook(show_mountinfo_addr, hooked_show_mountinfo, (void **)&orig_show_mountinfo);
        log_boot("[+] Hooking show_mountinfo: %d\n", rc);
        ret |= rc;
    } else {
        log_boot("[-] show_mountinfo symbol not found\n");
    }

    // Hook show_vfsstat
    if (show_vfsstat_addr) {
        hook_err_t rc = hook(show_vfsstat_addr, hooked_show_vfsstat, (void **)&orig_show_vfsstat);
        log_boot("[+] Hooking show_vfsstat: %d\n", rc);
        ret |= rc;
    } else {
        log_boot("[-] show_vfsstat symbol not found\n");
    }

    log_boot("[+] hide_mounts_init completed with result: %d\n", ret);
    return ret;
}