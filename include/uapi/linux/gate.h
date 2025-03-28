/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_GATE_H
#define _UAPI_LINUX_GATE_H

#include <linux/time_types.h>
#include <linux/types.h>

/**
 * define GATE_WAIT_ABSTIME - interpret timespec as an absolute timeout.
 */
#define GATE_WAIT_ABSTIME (1ULL << 0)
/**
 * define GATE_WAIT_RELTIME - interpret timespec as a relative timeout.
 */
#define GATE_WAIT_RELTIME (1ULL << 1)

struct gate_wait_options {
	__u64 flags;
	struct __kernel_timespec timeout;
	__s32 clockid;
	__u32 __reserved0;
} __attribute__((__aligned__(8)));

struct gate_wake_options {
	__u64 flags;
} __attribute__((__aligned__(8)));

#endif /* _UAPI_LINUX_GATE_H */
