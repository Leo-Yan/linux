// SPDX-License-Identifier: GPL-2.0
#include "linux/string.h"
#include "util/map_symbol.h"
#include "util/mem-events.h"
#include "mem-events.h"


#define MEM_LOADS_AUX		0x8203

#define E(t, n, s, l, a) { .tag = t, .name = n, .event_name = s, .ldlat = l, .aux_event = a }

struct perf_mem_event perf_mem_events_intel[PERF_MEM_EVENTS__MAX] = {
	E("ldlat-loads",	"%s/mem-loads,ldlat=%u/P",	"mem-loads",	true,	0),
	E("ldlat-stores",	"%s/mem-stores/P",		"mem-stores",	false,	0),
	E(NULL,			NULL,				NULL,		false,	0),
};

struct perf_mem_event perf_mem_events_intel_aux[PERF_MEM_EVENTS__MAX] = {
	E("ldlat-loads",	"{%s/mem-loads-aux/,%s/mem-loads,ldlat=%u/}:P",	"mem-loads",	true,	MEM_LOADS_AUX),
	E("ldlat-stores",	"%s/mem-stores/P",		"mem-stores",	false,	0),
	E(NULL,			NULL,				NULL,		false,	0),
};

struct perf_mem_event perf_mem_events_amd[PERF_MEM_EVENTS__MAX] = {
	E(NULL,		NULL,		NULL,	false,	0),
	E(NULL,		NULL,		NULL,	false,	0),
	E("mem-ldst",	"%s//",		NULL,	false,	0),
};

static const char *mem_events__intel_get_dev_name(void)
{
	return "cpu";
}

static struct perf_arch_mem_event mem_events__intel = {
	.get_dev_name = mem_events__intel_get_dev_name,
};

static const char *mem_events__amd_get_dev_name(void)
{
	return "ibs_op";
}

static struct perf_arch_mem_event mem_events__amd = {
	.get_dev_name = mem_events__amd_get_dev_name,
};

struct perf_arch_mem_event *perf_pmu__mem_events_arch_init(void)
{
	if (x86__is_amd_cpu())
		return &mem_events__amd;
	else
		return &mem_events__intel;
}
