// SPDX-License-Identifier: GPL-2.0
#include <string.h>
#include "util/map_symbol.h"
#include "util/mem-events.h"
#include "util/pmu.h"
#include "mem-events.h"

#define E(t, n, s, l, a) { .tag = t, .name = n, .event_name = s, .ldlat = l, .aux_event = a }

struct perf_mem_event perf_mem_events_power[PERF_MEM_EVENTS__MAX] = {
	E("ldlat-loads",	"%s/mem-loads/",	"mem-loads",	false,	0),
	E("ldlat-stores",	"%s/mem-stores/",	"mem-stores",	false,	0),
	E(NULL,			NULL,			NULL,		false,	0),
};

static const char *mem_events__power_get_dev_name(void)
{
	return "cpu";
}

static bool mem_events__power_is_pmu_supported(struct perf_pmu *pmu)
{
	if (pmu && pmu->is_core)
		return true;

	return false;
}

static struct perf_arch_mem_event mem_events__power = {
	.get_dev_name = mem_events__power_get_dev_name,
	.is_pmu_supported = mem_events__power_is_pmu_supported,
};

struct perf_arch_mem_event *perf_pmu__mem_events_arch_init(void)
{
	return &mem_events__power;
}
