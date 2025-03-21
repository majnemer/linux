// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE
#include <assert.h>
#include <linux/gate.h>
#include <linux/time_types.h>
#include <linux/unistd.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include "gate_sys.h"
#include "../kselftest_harness.h"

static const clockid_t clocks[] = {
	CLOCK_REALTIME,
	CLOCK_MONOTONIC,
};

static const struct __kernel_timespec one_ns = {
	.tv_sec = 0,
	.tv_nsec = 1,
};

/*
 * Expect EAGAIN because 1 != 42.
 */
TEST(gate_wait_EAGAIN)
{
	_Atomic uint8_t gate = 1;
	uint8_t expected = 42;
	long s;

	s = sys_gate_wait(&gate, (__kernel_ulong_t)-1, expected,
			  GATE_WAIT_SIZE_U8, NULL, CLOCK_REALTIME);
	ASSERT_EQ(s, -1);
	EXPECT_EQ(errno, EAGAIN);
}

TEST(gate_wait_EFAULT)
{
	_Atomic uint8_t gate = 1;
	uint8_t expected = 1;
	long s;

	/*
	 * uaddr points to NULL, get_user() should give EFAULT.
	 */
	s = sys_gate_wait(NULL, (__kernel_ulong_t)-1, expected,
			  GATE_WAIT_SIZE_U8, NULL, CLOCK_REALTIME);
	ASSERT_EQ(s, -1);
	EXPECT_EQ(errno, EFAULT);

	/*
	 * ts points to invalid memory, get_user() should give EFAULT.
	 */
	s = sys_gate_wait(&gate, (__kernel_ulong_t)-1, expected,
			  GATE_WAIT_SIZE_U8, (void *)-1, CLOCK_REALTIME);
	ASSERT_EQ(s, -1);
	EXPECT_EQ(errno, EFAULT);
}

void alarm_handler(int sig)
{
	assert(sig == SIGALRM);
}

TEST(gate_wait_EINTR)
{
	long s;
	struct sigaction sa;
	_Atomic uint8_t gate = 1;

	sa.sa_handler = alarm_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESETHAND;

	s = sigaction(SIGALRM, &sa, NULL);
	ASSERT_EQ(s, 0);

	alarm(1);

	s = sys_gate_wait(&gate, (__kernel_ulong_t)-1, gate, GATE_WAIT_SIZE_U8,
			  NULL, CLOCK_REALTIME);
	ASSERT_EQ(s, -1);
	EXPECT_EQ(errno, EINTR);
}

TEST(gate_wait_EINVAL)
{
	_Atomic uint16_t gate = 1;
	uint16_t expected = 1;
	struct __kernel_timespec bad_timeout;
	long s;

	/*
	 * uaddr is misaligned.
	 */
	s = syscall(__NR_gate_wait, (uint16_t *)(((uintptr_t)&gate) + 1),
		    (__kernel_ulong_t)-1, expected, GATE_WAIT_SIZE_U16, NULL,
		    CLOCK_REALTIME);
	ASSERT_EQ(s, -1);
	EXPECT_EQ(errno, EINVAL);

	/*
	 * flags are invalid.
	 */
	s = sys_gate_wait(&gate, (__kernel_ulong_t)-1, expected,
			  (unsigned int)-1, NULL, CLOCK_REALTIME);
	ASSERT_EQ(s, -1);
	EXPECT_EQ(errno, EINVAL);

	/*
	 * timeout is invalid.
	 */
	bad_timeout.tv_sec = -1;
	bad_timeout.tv_nsec = 0;
	s = sys_gate_wait(&gate, (__kernel_ulong_t)-1, expected,
			  GATE_WAIT_SIZE_U16, &bad_timeout, CLOCK_REALTIME);
	ASSERT_EQ(s, -1);
	EXPECT_EQ(errno, EINVAL);

	bad_timeout.tv_sec = 0;
	bad_timeout.tv_nsec = -1;
	s = sys_gate_wait(&gate, (__kernel_ulong_t)-1, expected,
			  GATE_WAIT_SIZE_U16, &bad_timeout, CLOCK_REALTIME);
	ASSERT_EQ(s, -1);
	EXPECT_EQ(errno, EINVAL);

	/*
	 * clockid is invalid.
	 */
	s = sys_gate_wait(&gate, (__kernel_ulong_t)-1, expected,
			  GATE_WAIT_SIZE_U16, &one_ns, -1);
	ASSERT_EQ(s, -1);
	EXPECT_EQ(errno, EINVAL);
}

/*
 * Expect ETIMEDOUT because 1 == 1 but a gate_wake() did not occur.
 */
TEST(gate_wait_ETIMEDOUT)
{
	_Atomic uint8_t gate = 1;
	uint8_t expected = 1;
	long s;

	for (int i = 0; i < ARRAY_SIZE(clocks); ++i) {
		clockid_t clock = clocks[i];
		s = sys_gate_wait(&gate, (__kernel_ulong_t)-1, expected,
				  GATE_WAIT_SIZE_U8, &one_ns, clock);
		ASSERT_EQ(s, -1);
		EXPECT_EQ(errno, ETIMEDOUT);
	}
}

TEST_HARNESS_MAIN
