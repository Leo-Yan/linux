// SPDX-License-Identifier: GPL-2.0
#include <stdbool.h>
#include <errno.h>

#include <linux/stddef.h>
#include <linux/perf_event.h>

#include <linux/types.h>
#include <asm/barrier.h>
#include "../../../util/debug.h"
#include "../../../util/event.h"
#include "../../../util/synthetic-events.h"
#include "../../../util/arm_arch_timer.h"

int perf_read_arch_timer_conversion(const struct perf_event_mmap_page *pc,
				    struct perf_arch_timer_conversion *tc)
{
	bool cap_user_time_zero, cap_user_time_short;
	u32 seq;
	int i = 0;

	while (1) {
		seq = pc->lock;
		/* Add barrier between the sequence lock and data accessing */
		rmb();

		tc->time_mult = pc->time_mult;
		tc->time_shift = pc->time_shift;
		tc->time_zero = pc->time_zero;
		tc->time_cycles = pc->time_cycles;
		tc->time_mask = pc->time_mask;
		cap_user_time_zero = pc->cap_user_time_zero;
		cap_user_time_short = pc->cap_user_time_short;

		/* Add barrier between the data accessing and sequence lock */
		rmb();
		if (pc->lock == seq && !(seq & 1))
			break;
		if (++i > 10000) {
			pr_debug("%s: failed to get perf_event_mmap_page lock\n",
				 __func__);
			return -EINVAL;
		}
	}

	if (!cap_user_time_zero || !cap_user_time_short)
		return -EOPNOTSUPP;

	return 0;
}
