// SPDX-License-Identifier: GPL-2.0
#include "map_symbol.h"
#include "mem-events.h"

#define E(t, n, s) { .tag = t, .name = n, .sysfs_name = s }

static struct perf_mem_event perf_mem_events[PERF_MEM_EVENTS__MAX] = {
	E("spe-load",	"arm_spe_0/ts_enable=1,load_filter=1,store_filter=0,min_latency=%u/",	"arm_spe_0"),
	E("spe-store",	"arm_spe_0/ts_enable=1,load_filter=0,store_filter=1/",			"arm_spe_0"),
	E("spe-ldst",	"arm_spe_0/ts_enable=1,load_filter=1,store_filter=1,min_latency=%u/",	"arm_spe_0"),
};

static char mem_ld_name[100];
static char mem_st_name[100];
static char mem_ldst_name[100];

struct perf_mem_event *perf_mem_events__ptr(int i)
{
	if (i >= PERF_MEM_EVENTS__MAX)
		return NULL;

	return &perf_mem_events[i];
}

char *perf_mem_events__name(int i)
{
	struct perf_mem_event *e = perf_mem_events__ptr(i);

	if (i >= PERF_MEM_EVENTS__MAX)
		return NULL;

	if (i == PERF_MEM_EVENTS__LOAD) {
		scnprintf(mem_ld_name, sizeof(mem_ld_name),
			  e->name, perf_mem_events__loads_ldlat);
		return mem_ld_name;
	}

	if (i == PERF_MEM_EVENTS__STORE) {
		scnprintf(mem_st_name, sizeof(mem_st_name), e->name);
		return mem_st_name;
	}

	scnprintf(mem_ldst_name, sizeof(mem_ldst_name),
		  e->name, perf_mem_events__loads_ldlat);
	return mem_ldst_name;
}
