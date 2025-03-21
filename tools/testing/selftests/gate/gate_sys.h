// SPDX-License-Identifier: GPL-2.0

#ifndef __GATE_SYS__
#define __GATE_SYS__

#include <linux/time_types.h>
#include <linux/unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

static inline long sys_gate_wait(void *uaddr, __kernel_ulong_t mask,
				 __kernel_ulong_t expected, unsigned int flags,
				 const struct __kernel_timespec *ts,
				 clockid_t clockid)
{
	return syscall(__NR_gate_wait, uaddr, mask, expected, flags, ts,
		       clockid);
}

static inline long sys_gate_wake(pid_t pid, void *uaddr, unsigned int flags)
{
	return syscall(__NR_gate_wake, pid, uaddr, flags);
}

#endif
