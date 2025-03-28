// SPDX-License-Identifier: GPL-2.0

#ifndef __GATE_SYS__
#define __GATE_SYS__

#include <linux/gate.h>
#include <linux/time_types.h>
#include <linux/unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

static inline long sys_gate_wait(void *uaddr, __kernel_ulong_t mask,
				 __kernel_ulong_t expected, size_t usize,
				 const struct gate_wait_options *options,
				 size_t options_size)
{
	return syscall(__NR_gate_wait, uaddr, mask, expected, usize, options,
		       options_size);
}

static inline long sys_gate_wake(pid_t pid, void *uaddr,
				 const struct gate_wake_options *options,
				 size_t options_size)
{
	return syscall(__NR_gate_wake, pid, uaddr, options, options_size);
}

#endif
