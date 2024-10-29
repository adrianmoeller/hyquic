/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/* HyQUIC - A hybrid user-kernel QUIC implementation 
 * based on the QUIC kernel implementation by Xin Long.
 * Copyright (C) 2024  Adrian Moeller
 * 
 * Written or modified by:
 * 	   Adrian Moeller
 */

#ifndef __QUIC_DEBUG_H__
#define __QUIC_DEBUG_H__

#define _HQ_MSG(___sk, ___msg) "[HyQUIC] %s@%s: "___msg"\n",quic_is_serv(___sk)?"server":"client",__func__
#define HQ_MSG(__sk, __msg) _HQ_MSG(__sk, __msg)
#define HQ_PR_ERR(__sk, __msg, ...) printk(KERN_ERR pr_fmt("[HyQUIC] %s@%s: "__msg"\n"), quic_is_serv(__sk)?"server":"client", __func__, ##__VA_ARGS__)
#define HQ_PR_DEBUG(__sk, __msg, ...) pr_debug(_HQ_MSG(__sk, __msg), ##__VA_ARGS__)

#define _Q_MSG(___sk, ___msg) "[QUIC] %s@%s: "___msg"\n",quic_is_serv(___sk)?"server":"client",__func__
#define Q_MSG(__sk, __msg) _Q_MSG(__sk, __msg)
#define Q_PR_ERR(__sk, __msg, ...) printk(KERN_ERR pr_fmt("[QUIC] %s@%s: "__msg"\n"), quic_is_serv(__sk)?"server":"client", __func__, ##__VA_ARGS__)
#define Q_PR_DEBUG(__sk, __msg, ...) pr_debug(_Q_MSG(__sk, __msg), ##__VA_ARGS__)

#endif // __QUIC_DEBUG_H__