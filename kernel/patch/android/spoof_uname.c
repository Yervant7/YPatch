/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2025 Yervant7. All Rights Reserved.
 */

#include <ktypes.h>
#include <hook.h>
#include <linux/fs.h>
#include <linux/utsname.h>
#include <linux/err.h>
#include <asm-generic/compat.h>
#include <uapi/asm-generic/unistd.h>
#include <uapi/asm-generic/errno.h>
#include <syscall.h>
#include <symbol.h>
#include <kconfig.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <taskob.h>
#include <predata.h>
#include <accctl.h>
#include <asm/current.h>
#include <linux/printk.h>
#include <linux/vmalloc.h>
#include <kputils.h>
#include <linux/ptrace.h>
#include <predata.h>
#include <linux/kernel.h>
#include <linux/umh.h>
#include <uapi/scdefs.h>
#include <linux/rcupdate.h>
#include <linux/rculist.h>
#include <sucompat.h>
#include <linux/spinlock.h>

#define ANDROID_UNAME_SYSNAME 0x1001
#define ANDROID_UNAME_NODENAME 0x1002
#define ANDROID_UNAME_RELEASE 0x1003
#define ANDROID_UNAME_VERSION 0x1004
#define ANDROID_UNAME_MACHINE 0x1005
#define ANDROID_UNAME_DOMAINNAME 0x1006

#define MAX_SPOOF_UNAME_FIELDS 6

struct spoof_uname_entry {
    int type; // (sysname, nodename...)
    char *value;
    struct rcu_head rcu_head;
};

static struct spoof_uname_entry *spoof_uname_entries[MAX_SPOOF_UNAME_FIELDS];
static DEFINE_SPINLOCK(spoof_uname_lock);

static void spoof_uname_entry_free(struct rcu_head *head)
{
    struct spoof_uname_entry *entry = container_of(head, struct spoof_uname_entry, rcu_head);
    if (entry->value) {
        vfree(entry->value);
    }
    vfree(entry);
}

static int find_spoof_uname_index(int type)
{
    switch (type) {
        case ANDROID_UNAME_SYSNAME:
            return 0;
        case ANDROID_UNAME_NODENAME:
            return 1;
        case ANDROID_UNAME_RELEASE:
            return 2;
        case ANDROID_UNAME_VERSION:
            return 3;
        case ANDROID_UNAME_MACHINE:
            return 4;
        case ANDROID_UNAME_DOMAINNAME:
            return 5;
        default:
            return -1;
    }
}

int add_spoof_uname(int type, const char *value)
{
    if (!value) return -EINVAL;

    int index = find_spoof_uname_index(type);
    if (index < 0 || index >= MAX_SPOOF_UNAME_FIELDS) {
        return -EINVAL;
    }

    struct spoof_uname_entry *entry = vmalloc(sizeof(struct spoof_uname_entry));
    if (!entry)
        return -ENOMEM;

    memset(entry, 0, sizeof(struct spoof_uname_entry));
    entry->type = type;

    size_t len = strlen(value);
    entry->value = vmalloc(len + 1);
    if (!entry->value) {
        vfree(entry);
        return -ENOMEM;
    }

    strcpy(entry->value, value);

    spin_lock(&spoof_uname_lock);
    if (spoof_uname_entries[index]) {
        struct spoof_uname_entry *old_entry = spoof_uname_entries[index];
        spoof_uname_entries[index] = entry;
        spin_unlock(&spoof_uname_lock);
        call_rcu(&old_entry->rcu_head, spoof_uname_entry_free);
    } else {
        spoof_uname_entries[index] = entry;
        spin_unlock(&spoof_uname_lock);
    }

    return 0;
}

int remove_spoof_uname(int type)
{
    int index = find_spoof_uname_index(type);
    if (index < 0 || index >= MAX_SPOOF_UNAME_FIELDS) {
        return -EINVAL;
    }

    spin_lock(&spoof_uname_lock);
    struct spoof_uname_entry *entry = spoof_uname_entries[index];
    if (entry) {
        spoof_uname_entries[index] = NULL;
        spin_unlock(&spoof_uname_lock);
        call_rcu(&entry->rcu_head, spoof_uname_entry_free);
        return 0;
    }
    spin_unlock(&spoof_uname_lock);

    return -ENOENT;
}

// Function to check if uname should be spoofed and get spoofed values
static int get_spoofed_uname(struct new_utsname *spoofed)
{
    int found = 0;
    
    rcu_read_lock();
    
    // Try to get spoofed sysname
    struct spoof_uname_entry *entry = rcu_dereference(spoof_uname_entries[0]);
    if (entry && entry->type == ANDROID_UNAME_SYSNAME && entry->value) {
        size_t len = strlen(entry->value);
        size_t copy_len = len > sizeof(spoofed->sysname) - 1 ? sizeof(spoofed->sysname) - 1 : len;
        memcpy(spoofed->sysname, entry->value, copy_len);
        spoofed->sysname[copy_len] = '\0';
        found = 1;
    }
    
    // Try to get spoofed nodename
    entry = rcu_dereference(spoof_uname_entries[1]);
    if (entry && entry->type == ANDROID_UNAME_NODENAME && entry->value) {
        size_t len = strlen(entry->value);
        size_t copy_len = len > sizeof(spoofed->nodename) - 1 ? sizeof(spoofed->nodename) - 1 : len;
        memcpy(spoofed->nodename, entry->value, copy_len);
        spoofed->nodename[copy_len] = '\0';
        found = 1;
    }
    
    // Try to get spoofed release
    entry = rcu_dereference(spoof_uname_entries[2]);
    if (entry && entry->type == ANDROID_UNAME_RELEASE && entry->value) {
        size_t len = strlen(entry->value);
        size_t copy_len = len > sizeof(spoofed->release) - 1 ? sizeof(spoofed->release) - 1 : len;
        memcpy(spoofed->release, entry->value, copy_len);
        spoofed->release[copy_len] = '\0';
        found = 1;
    }
    
    // Try to get spoofed version
    entry = rcu_dereference(spoof_uname_entries[3]);
    if (entry && entry->type == ANDROID_UNAME_VERSION && entry->value) {
        size_t len = strlen(entry->value);
        size_t copy_len = len > sizeof(spoofed->version) - 1 ? sizeof(spoofed->version) - 1 : len;
        memcpy(spoofed->version, entry->value, copy_len);
        spoofed->version[copy_len] = '\0';
        found = 1;
    }
    
    // Try to get spoofed machine
    entry = rcu_dereference(spoof_uname_entries[4]);
    if (entry && entry->type == ANDROID_UNAME_MACHINE && entry->value) {
        size_t len = strlen(entry->value);
        size_t copy_len = len > sizeof(spoofed->machine) - 1 ? sizeof(spoofed->machine) - 1 : len;
        memcpy(spoofed->machine, entry->value, copy_len);
        spoofed->machine[copy_len] = '\0';
        found = 1;
    }
    
    // Try to get spoofed domainname
    entry = rcu_dereference(spoof_uname_entries[5]);
    if (entry && entry->type == ANDROID_UNAME_DOMAINNAME && entry->value) {
        size_t len = strlen(entry->value);
        size_t copy_len = len > sizeof(spoofed->domainname) - 1 ? sizeof(spoofed->domainname) - 1 : len;
        memcpy(spoofed->domainname, entry->value, copy_len);
        spoofed->domainname[copy_len] = '\0';
        found = 1;
    }
    
    rcu_read_unlock();
    
    return found;
}

// Hook for sys_newuname syscall
static void before_sys_newuname(hook_fargs1_t *args, void *udata)
{
    // struct new_utsname is the first argument
    struct new_utsname __user *name = (struct new_utsname __user *)syscall_argn(args, 0);
    uid_t uid = current_uid();
    if (!is_uid_excluded_fast(uid)) {
        return;
    }

    if (!name)
        return;
    
    // Get spoofed values
    struct new_utsname spoofed;
    memset(&spoofed, 0, sizeof(spoofed));
    
    if (get_spoofed_uname(&spoofed)) {
        // Copy spoofed values to user space
        int rc = compat_copy_to_user(name, &spoofed, sizeof(spoofed));
        if (rc > 0) {
            // Successfully copied spoofed data, skip the original syscall
            args->skip_origin = 1;
            args->ret = 0; // Success
            pr_info("Spoofed uname information\n");
        }
    }
    // If no spoofed data found or copy failed, let the original syscall proceed
}

int spoof_uname_init()
{
    hook_err_t ret = 0;
    hook_err_t rc = HOOK_NO_ERR;

    rc = hook_syscalln(__NR_uname, 1, before_sys_newuname, 0, 0);
    log_boot("hook __NR_newuname rc: %d\n", rc);
    ret |= rc;

    return ret;
}