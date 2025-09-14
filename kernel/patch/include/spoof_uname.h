/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2025 Yervant7. All Rights Reserved.
 */

#ifndef _SPOOF_UNAME_H_
#define _SPOOF_UNAME_H_

int add_spoof_uname(int type, const char *value);
int remove_spoof_uname(int type);

#endif // _SPOOF_UNAME_H_