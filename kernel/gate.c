#include <linux/compat.h>
#include <linux/sched.h>
#include <linux/sched/debug.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <linux/time_namespace.h>
#include <linux/restart_block.h>
#include <uapi/linux/gate.h>

/**
 * DOC: Gate System Calls
 *
 * The gate mechanism implements an atomic compare-and-wait protocol that
 * ensures wake-up signals are never lost--even in the presence of race
 * conditions between the waiting thread (waiter) and the waking thread (waker).
 * It does so by coordinating two independent state indicators:
 *
 *   1. The waiter's published intent, stored in &task_struct->gate_uaddr.
 *   2. The monitored user-space memory at address uaddr.
 *
 * The protocol uses carefully placed memory barriers to guarantee that at least
 * one of the following independent checks will observe the wake-up:
 *
 * Waiter Path:
 * ------------
 * - Immediately publishes its intent to sleep by writing uaddr into
 *   &task_struct->gate_uaddr using smp_store_mb(). This operation enforces a
 *   memory barrier so that any previous wake-up-related writes (to uaddr)
 *   become visible.
 * - Reads the value at uaddr via get_user() and compares it against an expected
 *   value.
 * - If the value does not match, the waiter aborts the sleep.
 * - If the value matches, the waiter enters a sleep loop and checks
 *   &task_struct->gate_uaddr to see if it has been cleared.
 *
 * Waker Path:
 * -----------
 * - Updates the value at the user-space address uaddr.
 * - Calls gate_wake() with the target PID and uaddr.
 * - Inside gate_wake(), a memory barrier (smp_mb__before_atomic()) is executed
 *   to ensure that the update to uaddr is visible before proceeding.
 * - The function then calls gate_wait_finish(), which uses cmpxchg() to verify
 *   that the target's &task_struct->gate_uaddr still equals uaddr and, if so,
 *   clears it.
 * - A successful clear indicates that the wake-up has been delivered, and the
 *   target is awakened.
 *
 * Guarantee of No Lost Wake-Ups:
 * -------------------------------
 * This design prevents lost wake-ups during two key scenarios:
 *
 * 1. Racing between &task_struct->gate_uaddr and uaddr:
 *
 * Waiter (W)                            | Waker (K)
 * ------------------------------------- | -------------------------------------
 * W1. WRITE_ONCE(gate_uaddr, uaddr);    | K1. *uaddr = newval;
 * W2. smp_mb();                         | K2. smp_mb__before_atomic();
 * W3. uval = *uaddr;                    | K3. cmpxchg(gate_uaddr, uaddr, NULL);
 * W4. cmpxchg(gate_uaddr, uaddr, NULL); |
 *
 * It is not possible for both:
 * - W to miss the update to uaddr from K and
 * - K to miss the update to gate_uaddr from W
 *
 * 2. Racing between &task_struct->gate_uaddr and &task_struct->__state:
 *
 * Waiter (W)                            | Waker (K)
 * ------------------------------------- | -------------------------------------
 * W1. WRITE_ONCE(gate_uaddr, uaddr);    | K1. smp_mb__before_atomic();
 * W2. smp_mb();                         | K2. cmpxchg(gate_uaddr, uaddr, NULL);
 * W3. set_current_state(INTERRUPTIBLE); | K3. wake_up_process();
 * W4. READ_ONCE(gate_uaddr) == NULL     |
 * W5. schedule();                       |
 * W6. cmpxchg(gate_uaddr, uaddr, NULL); |
 *
 * It is not possible for both:
 * - W to get woken by wake_up_process.
 * - W not observing the update to gate_uaddr.
 *
 * If K3 occurs before W5, schedule() will not deschedule the waiter and it will
 *  re-enter the top of the loop and will thus observe the update to
 *  &task_struct->gate_uaddr.
 *
 *  If K3 occurs before W3, then the barriers in wake_up_process() and
 *  set_current_state() will make W observe the update to
 *  &task_struct->gate_uaddr.
 */

/**
 * define GATE_WAIT_SIZE_MASK - bitmask to extract various GATE_WAIT_SIZE_U*
 * values.
 */
#define GATE_WAIT_SIZE_MASK 0x003
/**
 * define GATE_WAIT_ALL_VALID_FLAGS - bitmask of all flags which gate_wait()
 * recognizes.
 */
#define GATE_WAIT_ALL_VALID_FLAGS \
	(GATE_WAIT_SIZE_MASK | GATE_WAIT_TIMER_ABSTIME)

static long __sched gate_wait_restart(struct restart_block *restart);

/*
 * gate_wait_prepare() - Publish our potential wait by writing the wait key into
 * @p->gate_uaddr.
 * @p:     The task in question.
 * @uaddr: The address the task associates with its wait.
 *
 * The barrier here pairs with the smp_mb__before_atomic() in do_gate_wake().
 */
static __always_inline void gate_wait_prepare(struct task_struct *p,
					      void __user *uaddr)
{
	ASSERT_EXCLUSIVE_WRITER(p->gate_uaddr);
	smp_store_mb(p->gate_uaddr, uaddr);
}

/**
 * gate_wait_finish() - Attempts to revoke a previously published intent to
 * potentially wait by clearing @p->gate_uaddr.
 * @p:     The task in question.
 * @uaddr: The address we expect the task to be associated with.
 *
 * @p->gate_uaddr may be in one of three states:
 * 1. @uaddr.
 * 2. %NULL.
 * 3. Neither NULL nor @uaddr.
 *
 * do_gate_wake() avoids spurious wake-ups by only waking for #1.
 *
 * Return:
 * * %1       - @p was waiting on @uaddr.
 * * %0       - @p was not waiting on any gate address.
 * * %-EAGAIN - @p was waiting on a gate address but not @uaddr.
 */
static __always_inline long gate_wait_finish(struct task_struct *p,
					     void __user *uaddr)
{
	void __user *old_uaddr = uaddr;

	if (try_cmpxchg_relaxed(&p->gate_uaddr, &old_uaddr, NULL))
		return 1;
	if (old_uaddr == NULL)
		return 0;
	return -EAGAIN;
}

/**
 * enum gate_wait_restart_mode - controls the restart behavior following signal
 *                               interruption.
 * @GATE_WAIT_RESTARTBLOCK: Return %-ERESTART_RESTARTBLOCK.
 * @GATE_WAIT_RESTARTSYS:   Return %-ERESTARTSYS.
 *
 * @GATE_WAIT_RESTARTBLOCK is used to support relative timeouts interrupted by
 * signals. @GATE_WAIT_RESTARTSYS is used for indefinite waits or absolute
 * deadlines.
 */
enum gate_wait_restart_mode {
	GATE_WAIT_RESTARTBLOCK,
	GATE_WAIT_RESTARTSYS,
};

/**
 * get_user_value() - Safely read a value of specified size from user memory.
 * @uaddr:  User space address to read from
 * @size:   Size of value to read (1, 2, 4, or 8 bytes)
 * @result: Pointer to store the result
 *
 * Return:
 * * %0       - Success
 * * %-EFAULT - Failed to access user memory
 */
static inline long get_user_value(void __user *uaddr, size_t size,
				  unsigned long *result)
{
	switch (size) {
	case 1:
		return get_user(*result, (u8 __user *)uaddr);
	case 2:
		return get_user(*result, (u16 __user *)uaddr);
	case 4:
		return get_user(*result, (u32 __user *)uaddr);
#ifdef CONFIG_64BIT
	case 8:
		return get_user(*result, (u64 __user *)uaddr);
#endif
	default:
		return -EINVAL;
	}
}

/**
 * do_gate_wait() - Core wait-loop for gate_wait.
 * @uaddr:        User-space address on which the thread waits.
 * @mask:         Mask to extract only the bits that are of interest.
 * @size:         Number of bytes to deference.
 * @expected:     Expected value at *@uaddr.
 * @sl:           Pointer to a %struct hrtimer_sleeper if a timeout was given.
 * @abs_deadline: Absolute deadline to use for canceling the wait.
 * @clockid:      Clock identifier (%CLOCK_REALTIME or %CLOCK_MONOTONIC).
 * @restart_mode: Used to handle signals for relative timeouts.
 *
 * Return:
 * * %-EAGAIN                - Comparison failed; wait not entered.
 * * %0                      - Blocked and then woken.
 * * %-ETIMEDOUT             - Timed out before being woken.
 * * %-EFAULT                - Faulted when accessing @uaddr.
 * * %-ERESTARTSYS           - Interrupted by a signal.
 * * %-ERESTART_RESTARTBLOCK - Interrupted by a signal (with relative timeout).
 */
static long do_gate_wait(void __user *uaddr, size_t size, unsigned long mask,
			 unsigned long expected, struct hrtimer_sleeper *sl,
			 ktime_t abs_deadline, clockid_t clockid,
			 enum gate_wait_restart_mode restart_mode)
{
	long ret;
	unsigned long uval;
	struct restart_block *restart;

	/*
	 * Start by immediately registering our intent to wait.
	 * It is critical that this is ordered before the read from user-space
	 * for two reasons:
	 *
	 * 1. gate_wait_prepare() has a memory barrier which ensures that
	 *    get_user will read a write from an earlier wake attempt.
	 *
	 * 2. It allows us to inform the waker that we will or are already
	 *    descheduled and that they need to wake us.
	 */
	gate_wait_prepare(current, uaddr);

	ret = get_user_value(uaddr, size, &uval);
	if (unlikely(ret))
		goto out;

	if ((uval & mask) != expected) {
		ret = -EAGAIN;
		goto out;
	}

	if (sl)
		hrtimer_sleeper_start_expires(sl, HRTIMER_MODE_ABS);

	for (;;) {
		/*
		 * set_current_state() implies a full barrier after it updates
		 * current's state.
		 *
		 * This pairs with the smp_mb__before_atomic() barrier in
		 * do_gate_wake() and calls to wake_up_process().
		 */
		set_current_state(TASK_INTERRUPTIBLE | TASK_FREEZABLE);
		/*
		 * Check to see if anyone has woken us before we deschedule
		 * ourselves.
		 */
		if (READ_ONCE(current->gate_uaddr) == NULL) {
			ret = 0;
			goto out;
		}

		if (sl && !sl->task) {
			ret = -ETIMEDOUT;
			goto out;
		}

		if (signal_pending(current)) {
			ret = -ERESTARTSYS;
			goto out;
		}

		schedule();
	}

out:
	__set_current_state(TASK_RUNNING);
	if (ret != 0) {
		/*
		 * We gave up on waiting without being woken, clean up the wait
		 * intent.
		 *
		 * Note that the waiter might race against a waker at the last
		 * minute. If the waiter lost, we will return that we were woken
		 * to be consistent with the result of sys_gate_wait().
		 */
		if (unlikely(!gate_wait_finish(current, uaddr) &&
			     (ret == -ETIMEDOUT || ret == -ERESTARTSYS)))
			ret = 0;
	}
	if (unlikely(sl && ret == -ERESTARTSYS &&
		     restart_mode == GATE_WAIT_RESTARTBLOCK)) {
		/*
		 * A signal interrupted our timed wait, we need a restart block
		 * to properly restart relative time wait system calls.
		 */
		restart = &current->restart_block;
		restart->gate.uaddr = uaddr;
		restart->gate.mask = mask;
		restart->gate.expected = expected;
		restart->gate.abs_deadline = abs_deadline;
		restart->gate.monotonic = clockid == CLOCK_MONOTONIC;
		restart->gate.size = size;
		return set_restart_fn(restart, gate_wait_restart);
	}
	return ret;
}

static __always_inline void gate_setup_timeout(struct hrtimer_sleeper *slp,
					       ktime_t abs_deadline,
					       clockid_t clockid)
{
	if (!slp)
		return;
	hrtimer_setup_sleeper_on_stack(slp, clockid, HRTIMER_MODE_ABS);
	hrtimer_set_expires_range_ns(&slp->timer, abs_deadline,
				     current->timer_slack_ns);
}

static __always_inline void gate_destroy_timeout(struct hrtimer_sleeper *slp)
{

	if (!slp)
		return;
	hrtimer_cancel(&slp->timer);
	destroy_hrtimer_on_stack(&slp->timer);
}

static long __sched gate_wait_restart(struct restart_block *restart)
{
	long ret;
	struct hrtimer_sleeper sl;
	clockid_t clockid;

	/*
	 * Tentatively disarm the restart block in case we end up returning without
	 * observing a signal. do_gate_wait() will re-arm the restart block for us
	 * should the need arise.
	 */
	restart->fn = do_no_restart_syscall;

	clockid = restart->gate.monotonic ? CLOCK_MONOTONIC : CLOCK_REALTIME;
	gate_setup_timeout(&sl, restart->gate.abs_deadline, clockid);

	ret = do_gate_wait(restart->gate.uaddr, restart->gate.size,
			   restart->gate.mask, restart->gate.expected, &sl,
			   restart->gate.abs_deadline, clockid,
			   GATE_WAIT_RESTARTBLOCK);

	gate_destroy_timeout(&sl);

	return ret;
}

/**
 * sys_gate_wait() - Atomically compare-and-block the current thread; unblock if
 * a wake, timeout, or signal occurs.
 * @uaddr:    User-space address on which the thread waits.
 * @mask:     Mask to extract only the bits that are of interest.
 * @expected: Expected value at *@uaddr.
 * @flags:    Flags controlling the interpretation of @ts.
 * @ts:       Pointer to a user-space &struct __kernel_timespec specifying the
 *            wait duration.
 * @clockid:  Clock identifier (%CLOCK_REALTIME or %CLOCK_MONOTONIC).
 *
 * Return:
 * * %-EINVAL                - @clockid was not %CLOCK_REALTIME or
 *                             %CLOCK_MONOTONIC.
 * * %-EINVAL                - At least one of @flags or @ts is improper.
 * * %-EAGAIN                - Comparison failed; wait not entered.
 * * %0                      - Blocked and then woken.
 * * %-ETIMEDOUT             - Timed out before being woken.
 * * %-EFAULT                - Fault accessing @uaddr or @ts.
 * * %-ERESTARTSYS           - Interrupted by a signal.
 * * %-ERESTART_RESTARTBLOCK - Interrupted by a signal (with relative timeout).
 */
SYSCALL_DEFINE6(gate_wait, void __user *, uaddr, unsigned long, mask,
		unsigned long, expected, unsigned int, flags,
		struct __kernel_timespec __user *, ts, clockid_t, clockid)
{
	long ret;
	ktime_t abs_deadline;
	struct timespec64 kts;
	size_t size, max_size;
	enum gate_wait_restart_mode restart_mode;
	struct hrtimer_sleeper sl, *slp = NULL;

	if (unlikely(flags & ~GATE_WAIT_ALL_VALID_FLAGS)) {
		ret = -EINVAL;
		goto out;
	}

	size = 1 << (flags & GATE_WAIT_SIZE_MASK);

	if (in_32bit_reg_syscall())
		max_size = sizeof(u32);
	else
		max_size = sizeof(u64);

	if (unlikely(size > max_size)) {
		ret = -EINVAL;
		goto out;
	}

	if (unlikely(!IS_ALIGNED((unsigned long)uaddr, size))) {
		ret = -EINVAL;
		goto out;
	}

	/* Copy ts from user-space */
	if (ts) {
		if (unlikely(clockid != CLOCK_MONOTONIC &&
			     clockid != CLOCK_REALTIME)) {
			ret = -EINVAL;
			goto out;
		}
		ret = get_timespec64(&kts, ts);
		if (unlikely(ret))
			goto out;

		if (unlikely(!timespec64_valid(&kts))) {
			ret = -EINVAL;
			goto out;
		}

		abs_deadline = timespec64_to_ktime(kts);

		if (flags & GATE_WAIT_TIMER_ABSTIME) {
			abs_deadline =
				timens_ktime_to_host(clockid, abs_deadline);
			restart_mode = GATE_WAIT_RESTARTSYS;
		} else {
			abs_deadline =
				ktime_add_safe(ktime_get(), abs_deadline);
			/*
			 * Naively restarting the gate_wait when it has a
			 * relative timeout would cause it to wait too much.
			 *
			 * We use the restart block functionality to turn the
			 * relative timeout to an absolute deadline and source
			 * our deadline from that block.
			 */
			restart_mode = GATE_WAIT_RESTARTBLOCK;
		}

		slp = &sl;
	} else {
		abs_deadline = KTIME_MAX;
		restart_mode = GATE_WAIT_RESTARTSYS;
	}
	gate_setup_timeout(slp, abs_deadline, clockid);

	ret = do_gate_wait(uaddr, size, mask, expected, slp, abs_deadline,
			   clockid, restart_mode);
out:
	gate_destroy_timeout(slp);
	return ret;
}

/**
 * do_gate_wake() - Wake a thread blocked in sys_gate_wait().
 * @p:     The task in question.
 * @uaddr: The address we expect the task to be associated with.
 *
 * Return:
 * * %1       - @p was waiting on @uaddr.
 * * %0       - @p was not waiting on any gate address.
 * * %-EAGAIN - @p was waiting on a gate address but not @uaddr.
 */
static long do_gate_wake(struct task_struct *p, void __user *uaddr)
{
	long ret;

	/*
	 * gate_wait_finish() starts off with a cmpxchg_relaxed() which is
	 * combined here with this smp_mb__before_atomic() to make sure that a
	 * prior write to @uaddr before this call to do_gate_wake() is visible
	 * to the load in gate_wait.
	 *
	 * This barrier pairs with the smp_store_mb() in gate_wait_prepare().
	 */
	smp_mb__before_atomic();
	ret = gate_wait_finish(p, uaddr);

	/*
	 * The waker cleared @p->gate_uaddr so it needs to wake up @p.
	 * wake_up_process()'s return value depends on @p->state which may not
	 * yet have transitioned to %TASK_INTERRUPTIBLE.
	 */
	if (ret > 0)
		ret = wake_up_process(p);

	return ret;
}

/**
 * sys_gate_wake() - Wake a process blocked in sys_gate_wait().
 * @pid:   The process identifier in question.
 * @uaddr: The address we expect the process to be associated with.
 * @flags: Must be 0.
 *
 * Return:
 * * %1       - @pid was waiting on @uaddr.
 * * %0       - @pid was not waiting on any gate address.
 * * %-EAGAIN - @pid was waiting on a gate address but not @uaddr.
 * * %-EPERM  - @pid is a kernel thread (cannot be woken).
 * * %-EINVAL - @flags was not zero.
 * * %-ESRCH  - @pid was not found.
 */
SYSCALL_DEFINE3(gate_wake, pid_t, pid, void __user *, uaddr,
		unsigned int, flags)
{
	long ret;
	struct task_struct *p = NULL;

	if (unlikely(flags != 0)) {
		ret = -EINVAL;
		goto out;
	}

	p = find_get_task_by_vpid(pid);
	if (unlikely(!p)) {
		ret = -ESRCH;
		goto out;
	}

	if (unlikely(!same_thread_group(current, p))) {
		ret = -EPERM;
		goto out;
	}

	ret = do_gate_wake(p, uaddr);

out:
	if (p)
		put_task_struct(p);
	return ret;
}
