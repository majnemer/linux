/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_GATE_H
#define _UAPI_LINUX_GATE_H

/*
 * Size flags.
 */
#define GATE_WAIT_SIZE_U8 0x000
#define GATE_WAIT_SIZE_U16 0x001
#define GATE_WAIT_SIZE_U32 0x002
#define GATE_WAIT_SIZE_U64 0x003
/**
 * define GATE_WAIT_TIMER_ABSTIME - interpret timespec as an absolute timeout.
 */
#define GATE_WAIT_TIMER_ABSTIME 0x200

#endif /* _UAPI_LINUX_GATE_H */
