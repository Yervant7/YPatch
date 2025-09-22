/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2025 Yervant7. All Rights Reserved.
 */

#include <ktypes.h>
#include <compiler.h>
#include <kpmodule.h>
#include <uapi/scdefs.h>
#include <sucompat.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <linux/string.h>
#include <kputils.h>
#include <asm/current.h>

KPM_NAME("kpm-ypatch");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Yervant7");
KPM_DESCRIPTION("KernelPatch Module YPatch optional.");

void before(hook_fargs0_t *args, void *udata)
{
    uid_t uid = current_uid();
    if (likely(get_ap_mod_exclude(uid))) {
        return;
    }
    return;
}

static long ypatch_hook_init(const char *args, const char *event, void *__user reserved)
{
    pr_info("kpm-ypatch init");

    for (int i = 0; i <= 451; i++) {
        if (i == __NR_execve || i == __NR3264_fstatat || i == __NR_faccessat || i == __NR_supercall || i == __NR_uname)
            continue;
        hook_syscalln(i, 0, before, 0, (void *)0);
    }

    for (int i = 0; i <= 451; i++) {
        if (i == 11 || i == 327 || i == 334)
            continue;
        hook_compat_syscalln(i, 0, before, 0, (void *)0);
    }

    return 0;
}

static long ypatch_hook_control0(const char *args, char *__user out_msg, int outlen)
{
    return 0;
}

static long ypatch_hook_exit(void *__user reserved)
{
    pr_info("kpm-ypatch exit\n");

    for (int i = 0; i <= 451; i++) {
        if (i == __NR_execve || i == __NR3264_fstatat || i == __NR_faccessat || i == __NR_supercall || i == __NR_uname)
            continue;
        unhook_syscalln(i, before, 0);
    }

    for (int i = 0; i <= 451; i++) {
        if (i == 11 || i == 327 || i == 334)
             continue;
        unhook_compat_syscalln(i, before, 0);
    }

    return 0;
}

KPM_INIT(ypatch_hook_init);
KPM_CTL0(ypatch_hook_control0);
KPM_EXIT(ypatch_hook_exit);