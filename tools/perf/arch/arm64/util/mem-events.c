// SPDX-License-Identifier: GPL-2.0
#include <string.h>
#include "util/map_symbol.h"
#include "util/mem-events.h"
#include "util/pmu.h"
#include "mem-events.h"

#define E(t, n, s, l, a) { .tag = t, .name = n, .event_name = s, .ldlat = l, .aux_event = a }

struct perf_mem_event perf_mem_events_arm[PERF_MEM_EVENTS__MAX] = {
	E("spe-load",	"%s/ts_enable=1,pa_enable=1,load_filter=1,store_filter=0,min_latency=%u/",	NULL,	true,	0),
	E("spe-store",	"%s/ts_enable=1,pa_enable=1,load_filter=0,store_filter=1/",			NULL,	false,	0),
	E("spe-ldst",	"%s/ts_enable=1,pa_enable=1,load_filter=1,store_filter=1,min_latency=%u/",	NULL,	true,	0),
};

static const char *mem_events__arm_get_dev_name(void)
{
	return "arm_spe_0";
}

static bool mem_events__arm_is_pmu_supported(struct perf_pmu *pmu)
{
	if (!pmu)
		return false;

	if (strstr(pmu->name, mem_events__arm_get_dev_name()))
		return true;

	return false;
}

static bool mem_events__arm_is_ev_supported(struct perf_pmu *pmu,
					    unsigned int event)
{
	if (!mem_events__arm_is_pmu_supported(pmu))
		return false;

	if (event >= PERF_MEM_EVENTS__MAX)
		return false;

	return true;
}

static const char *mem_events__arm_get_ev_name(struct perf_pmu *pmu,
					       unsigned int event)
{
	if (!mem_events__arm_is_ev_supported(pmu, event))
		return NULL;

	return perf_mem_events_arm[event].tag;
}

static struct perf_arch_mem_event mem_events__arm = {
	.get_dev_name = mem_events__arm_get_dev_name,
	.is_pmu_supported = mem_events__arm_is_pmu_supported,
	.is_ev_supported = mem_events__arm_is_ev_supported,
	.get_ev_name = mem_events__arm_get_ev_name,
};

struct perf_arch_mem_event *perf_pmu__mem_events_arch_init(void)
{
	return &mem_events__arm;
}
