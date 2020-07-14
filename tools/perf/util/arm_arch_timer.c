// SPDX-License-Identifier: GPL-2.0
#include <linux/compiler.h>
#include <linux/types.h>

#include "arm_arch_timer.h"

u64 perf_time_to_arch_timer_cyc(u64 ns, struct perf_arch_timer_conversion *tc)
{
	u64 t, quot, rem;

	t = ns - tc->time_zero;
	quot = t / tc->time_mult;
	rem  = t % tc->time_mult;
	return (quot << tc->time_shift) +
	       (rem << tc->time_shift) / tc->time_mult;
}

u64 arch_timer_cyc_to_perf_time(u64 cyc, struct perf_arch_timer_conversion *tc)
{
	u64 quot, rem;

	cyc = tc->time_cycles + ((cyc - tc->time_cycles) & tc->time_mask);

	quot = cyc >> tc->time_shift;
	rem  = cyc & (((u64)1 << tc->time_shift) - 1);
	return tc->time_zero + quot * tc->time_mult +
	       ((rem * tc->time_mult) >> tc->time_shift);
}
