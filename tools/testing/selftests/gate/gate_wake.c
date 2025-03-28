// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE
#include <assert.h>
#include <linux/gate.h>
#include <linux/unistd.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include "gate_sys.h"
#include "../kselftest_harness.h"

static void *start_routine_EAGAIN(void *arg)
{
	_Atomic uint8_t gate1 = 1;
	_Atomic pid_t *child_tidp = arg;

	*child_tidp = gettid();
	sys_gate_wait(&gate1, (__kernel_ulong_t)-1, gate1, sizeof(gate1), NULL,
		      (size_t)0);
	assert(0);
	return NULL;
}

/*
 * Expect EAGAIN because uaddr does not match.
 */
TEST(gate_wake_EAGAIN)
{
	long s;
	pthread_t thread;
	uint8_t gate0 = 0;
	_Atomic pid_t child_tid = 0;

	s = pthread_create(&thread, NULL, &start_routine_EAGAIN, &child_tid);
	ASSERT_EQ(s, 0);

	while (child_tid == 0)
		;

	do {
		s = sys_gate_wake(child_tid, &gate0, NULL, (size_t)0);
	} while (s == 0);
	ASSERT_EQ(s, -1);
	EXPECT_EQ(errno, EAGAIN);
}

TEST(gate_wake_EINVAL)
{
	struct gate_wake_options options;
	uint8_t gate;
	long s;

	/*
	 * flags are invalid.
	 */
	memset(&options, 0, sizeof(options));
	options.flags = (uint64_t)-1;
	s = sys_gate_wake(getpid(), &gate, &options, sizeof(options));
	ASSERT_EQ(s, -1);
	EXPECT_EQ(errno, EINVAL);
}

TEST(gate_wake_EPERM)
{
	uint8_t gate;
	long s;

	/*
	 * pid is outside our process.
	 */
	s = sys_gate_wake((pid_t)1, &gate, NULL, (size_t)0);
	ASSERT_EQ(s, -1);
	EXPECT_EQ(errno, EPERM);
}

TEST(gate_wake_ESRCH)
{
	uint8_t gate;
	long s;

	/*
	 * pid does not identify a running process.
	 */
	s = sys_gate_wake((pid_t)-1, &gate, NULL, (size_t)0);
	ASSERT_EQ(s, -1);
	EXPECT_EQ(errno, ESRCH);
}

TEST_HARNESS_MAIN
