// SPDX-License-Identifier: GPL-2.0
#include "linux/string.h"
#include "util/map_symbol.h"
#include "util/mem-events.h"
#include "util/pmu.h"
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

static bool mem_events__intel_is_pmu_supported(struct perf_pmu *pmu)
{
	if (pmu && pmu->is_core)
		return true;

	return false;
}

static bool mem_events__intel_is_ev_supported(struct perf_pmu *pmu,
					      unsigned int event)
{
	struct perf_mem_event *mem_event;

	if (perf_pmu__have_event(pmu, "mem-loads-aux"))
		mem_events = perf_mem_events_intel_aux;
	else
		mem_events = perf_mem_events_intel;

	if (event >= PERF_MEM_EVENTS__MAX)
		return false;

	if (perf_pmu__have_event(pmu, mem_events[event].event_name))
		return true;
	else
		return false;
}

static struct perf_arch_mem_event mem_events__intel = {
	.get_dev_name = mem_events__intel_get_dev_name,
	.is_pmu_supported = mem_events__intel_is_pmu_supported,
	.is_ev_supported = mem_events__intel_is_ev_supported,
};

static const char *mem_events__amd_get_dev_name(void)
{
	return "ibs_op";
}

static bool mem_events__amd_is_pmu_supported(struct perf_pmu *pmu)
{
	if (!pmu)
		return false;

	if (strstr(pmu->name, mem_events__amd_get_dev_name()))
		return true;

	return false;
}

static bool mem_events__amd_is_ev_supported(struct perf_pmu *pmu,
					    unsigned int event)
{
	if (!mem_events__amd_is_pmu_supported(pmu))
		return false;

	if (event == PERF_MEM_EVENTS__LOAD_STORE)
		return true;
	else
		return false;
}

static struct perf_arch_mem_event mem_events__amd = {
	.get_dev_name = mem_events__amd_get_dev_name,
	.is_pmu_supported = mem_events__amd_is_pmu_supported,
	.is_ev_supported = mem_events__amd_is_ev_supported,
};

struct perf_arch_mem_event *perf_pmu__mem_events_arch_init(void)
{
	if (x86__is_amd_cpu())
		return &mem_events__amd;
	else
		return &mem_events__intel;
}
