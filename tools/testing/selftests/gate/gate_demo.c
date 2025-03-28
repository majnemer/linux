/*
 * gate_demo.c
 *
 * Usage: gate_demo [nloops=5]
 *
 * Demonstrate the use of gates in a program where parent thread and
 * child thread use a pair of gates to synchronize access to a shared
 * resource: the terminal.
 * The two threads each write 'nloops' messages to the terminal and
 * employ a synchronization protocol that ensures that they alternate in
 * writing messages.
 */
#define _GNU_SOURCE
#include <err.h> /* for err() */
#include <errno.h> /* for E* , errno */
#include <linux/gate.h> /* for GATE_* */
#include <sched.h> /* for CLONE_* */
#include <stdatomic.h> /* for atomic_*() */
#include <stdint.h> /* for uint8_t */
#include <stdio.h> /* for printf() */
#include <stdlib.h> /* for strtol(), exit(), EXIT_* */
#include <sys/mman.h> /* for mmap(), MAP_* */
#include <time.h> /* for CLOCK_* */
#include <unistd.h> /* for gettid() */
#include "gate_sys.h"

#define STACK_SIZE (1024 * 1024)

static _Atomic uint8_t child_gate = 0; /* State: unavailable */
static _Atomic uint8_t parent_gate = 1; /* State: available */

static long nloops = 5;

static pid_t parent_tid;

/*
 * Acquire the gate pointed to by 'gatep': wait for its value to
 * become 1, and then set the value to 0.
 */

static void gate_wait(_Atomic uint8_t *gatep)
{
	long s;
	uint8_t desired = 0;
	uint8_t expected;

	/*
	 * atomic_compare_exchange_strong(ptr, expected, desired)
	 * atomically performs the equivalent of:
	 *
	 *   *val = *ptr;
	 *   if (val == *expected) {
	 *       *ptr = desired;
	 *       return true;
	 *   } else {
	 *       *expected = val;
	 *       return false;
	 *   }
	 *
	 * It returns true if the test yielded true and *ptr was updated.
	 */

	while (1) {
		/* Is the gate available? */
		expected = 1;
		if (atomic_compare_exchange_strong(gatep, &expected, desired))
			break; /* Yes */

		/* gate is not available; wait. */

		s = sys_gate_wait(gatep, (__kernel_ulong_t)-1, expected,
				  sizeof(*gatep), NULL, (size_t)0);
		if (s == -1 && errno != EAGAIN)
			err(EXIT_FAILURE, "gate_wait");
	}
}

/*
 * Release the gate pointed to by 'gatep': if the gate currently
 * has the value 0, set its value to 1 and then wake any gate waiters,
 * so that if the peer is blocked in gate_wait(), it can proceed.
 */

static void gate_post(pid_t pid, _Atomic uint8_t *gatep)
{
	long s;
	uint8_t desired = 1;
	uint8_t expected = 0;

	/*
	 * atomic_compare_exchange_strong() was described
	 * in comments above.
	 */

	if (atomic_compare_exchange_strong(gatep, &expected, desired)) {
		s = sys_gate_wake(pid, gatep, NULL, (size_t)0);
		if (s == -1 && errno != EAGAIN)
			err(EXIT_FAILURE, "gate_wake");
	}
}

static int child_thread_fn(void *unused)
{
	pid_t child_tid;

	child_tid = gettid();
	for (long j = 0; j < nloops; j++) {
		gate_wait(&child_gate);
		printf("Child  (%jd) %ld\n", (intmax_t)child_tid, j);
		gate_post(parent_tid, &parent_gate);
	}

	return 0;
}

int main(int argc, char *argv[])
{
	void *stack;
	pid_t child_tid;

	if (argc > 1) {
		nloops = strtol(argv[1], NULL, 10);
		if (errno)
			err(EXIT_FAILURE, "nloops");
	}

	parent_tid = gettid();

	/* Allocate stack for the child thread */

	stack = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
	if (stack == MAP_FAILED)
		err(EXIT_FAILURE, "mmap stack");

	/* Create a child thread */

	child_tid = clone(child_thread_fn, (char *)stack + STACK_SIZE,
			  CLONE_VM | CLONE_SIGHAND | CLONE_THREAD, NULL);
	if (child_tid == -1)
		err(EXIT_FAILURE, "clone");

	/* Parent continues through to here. */

	for (long j = 0; j < nloops; j++) {
		gate_wait(&parent_gate);
		printf("Parent (%jd) %ld\n", (intmax_t)parent_tid, j);
		gate_post(child_tid, &child_gate);
	}

	gate_wait(&parent_gate);

	exit(EXIT_SUCCESS);
}
