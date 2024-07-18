// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright(C) 2015 Linaro Limited. All rights reserved.
 * Author: Mathieu Poirier <mathieu.poirier@linaro.org>
 */

#include <dirent.h>
#include <stdbool.h>
#include <linux/coresight-pmu.h>
#include <linux/string.h>
#include <linux/zalloc.h>
#include <api/fs/fs.h>

#include "../../../util/auxtrace.h"
#include "../../../util/debug.h"
#include "../../../util/evlist.h"
#include "../../../util/pmu.h"
#include "../../../util/pmus.h"
#include "cs-etm.h"
#include "arm-spe.h"
#include "hisi-ptt.h"

static struct perf_pmu **
find_auxtrace_pmus_by_name(struct evlist *evlist, const char *name, int *nr_pmu)
{
	struct perf_pmu **pmus = NULL;
	struct evsel *evsel;
	int i = 0, nr = 0;

	assert(name);
	assert(nr_pmu);

	*nr_pmu = 0;

	evlist__for_each_entry(evlist, evsel) {
		if (strstarts(evsel->pmu_name, name))
			nr++;
	}

	if (!nr)
		return NULL;

	pmus = zalloc(sizeof(struct perf_pmu *) * nr);
	if (!pmus) {
		pr_err("Failed to allocate PMU pointer arrary.\n");
		return NULL;
	}

	evlist__for_each_entry(evlist, evsel) {
		if (strstarts(evsel->pmu_name, name)) {
			pmus[i] = evsel->pmu;
			i++;
		}
	}

	*nr_pmu = nr;
	return pmus;
}

struct auxtrace_record
*auxtrace_record__init(struct evlist *evlist, int *err)
{
	struct perf_pmu	**cs_etm_pmu = NULL;
	struct perf_pmu **arm_spe_pmus = NULL;
	struct perf_pmu **hisi_ptt_pmus = NULL;
	struct auxtrace_record *itr = NULL;
	int auxtrace_event_cnt = 0;
	int nr_etm = 0;
	int nr_spe = 0;
	int nr_ptt = 0;

	if (!evlist)
		return NULL;

	cs_etm_pmu =
		find_auxtrace_pmus_by_name(evlist, CORESIGHT_ETM_PMU_NAME, &nr_etm);
	arm_spe_pmus =
		find_auxtrace_pmus_by_name(evlist, ARM_SPE_PMU_NAME, &nr_spe);
	hisi_ptt_pmus =
		find_auxtrace_pmus_by_name(evlist, HISI_PTT_PMU_NAME, &nr_ptt);

	auxtrace_event_cnt = !!nr_etm + !!nr_spe + !!nr_ptt;
	if (!auxtrace_event_cnt) {
		/*
		 * Clear 'err' even if we haven't found an event - that way perf
		 * record can still be used even if tracers aren't present.
		 * The NULL return value will take care of telling the
		 * infrastructure HW tracing isn't available.
		 */
		*err = 0;
		goto out;
	} else if (auxtrace_event_cnt > 1) {
		pr_err("Concurrent AUX trace operation not currently supported\n");
		*err = -EOPNOTSUPP;
		goto out;
	}

	if (cs_etm_pmu)
		itr = cs_etm_record_init(err);

#if defined(__aarch64__)
	if (arm_spe_pmus)
		itr = arm_spe_recording_init(err, arm_spe_pmus[0]);

	if (hisi_ptt_pmus)
		itr = hisi_ptt_recording_init(err, hisi_ptt_pmus[0]);
#endif

out:
	free(cs_etm_pmu);
	free(arm_spe_pmus);
	free(hisi_ptt_pmus);
	return itr;
}

#if defined(__arm__)
u64 compat_auxtrace_mmap__read_head(struct auxtrace_mmap *mm)
{
	struct perf_event_mmap_page *pc = mm->userpg;
	u64 result;

	__asm__ __volatile__(
"	ldrd    %0, %H0, [%1]"
	: "=&r" (result)
	: "r" (&pc->aux_head), "Qo" (pc->aux_head)
	);

	return result;
}

int compat_auxtrace_mmap__write_tail(struct auxtrace_mmap *mm, u64 tail)
{
	struct perf_event_mmap_page *pc = mm->userpg;

	/* Ensure all reads are done before we write the tail out */
	smp_mb();

	__asm__ __volatile__(
"	strd    %2, %H2, [%1]"
	: "=Qo" (pc->aux_tail)
	: "r" (&pc->aux_tail), "r" (tail)
	);

	return 0;
}
#endif
