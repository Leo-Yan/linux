/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PERF_ARM_ARCH_TIMER_H
#define __PERF_ARM_ARCH_TIMER_H

#include <linux/types.h>

struct perf_arch_timer_conversion {
	u16 time_shift;
	u32 time_mult;
	u64 time_zero;
	u64 time_cycles;
	u64 time_mask;
};

struct perf_event_mmap_page;

int perf_read_arch_timer_conversion(const struct perf_event_mmap_page *pc,
				    struct perf_arch_timer_conversion *tc);

#endif // __PERF_ARM_ARCH_TIMER_H
