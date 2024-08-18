/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Arm Statistical Profiling Extensions (SPE) support
 * Copyright (c) 2017-2018, Arm Ltd.
 */

#ifndef INCLUDE__PERF_ARM_SPE_H__
#define INCLUDE__PERF_ARM_SPE_H__

#define ARM_SPE_PMU_NAME "arm_spe_"

enum {
	ARM_SPE_PMU_TYPE,
	ARM_SPE_PER_CPU_MMAPS,
	/*
	 * The initial version doesn't have version number, so version 1 is
	 * reserved and the header version starts from 2.
	 */
	ARM_SPE_HEADER_VERSION,
	ARM_SPE_CPU_NUM,
	ARM_SPE_AUXTRACE_PRIV_MAX,
};

enum {
	ARM_SPE_CPU,
	ARM_SPE_CPU_MIDR,
	ARM_SPE_CPU_PMU_TYPE,
	ARM_SPE_CAP_MIN_IVAL,
	ARM_SPE_CAP_LDS,
	ARM_SPE_PER_CPU_PRIV_MAX,
};

#define ARM_SPE_HEADER_CURRENT_VERSION	2

#define ARM_SPE_METADATA_SIZE(cnt)	((cnt) * sizeof(u64))

#define ARM_SPE_AUXTRACE_V1_PRIV_MAX		\
	(ARM_SPE_PER_CPU_MMAPS + 1)
#define ARM_SPE_AUXTRACE_V1_PRIV_SIZE		\
	ARM_SPE_METADATA_SIZE(ARM_SPE_AUXTRACE_V1_PRIV_MAX)

#define ARM_SPE_AUXTRACE_V2_PRIV_MAX		\
	(ARM_SPE_CPU_NUM + 1)
#define ARM_SPE_AUXTRACE_V2_PRIV_SIZE		\
	ARM_SPE_METADATA_SIZE(ARM_SPE_AUXTRACE_V2_PRIV_MAX)

#define ARM_SPE_AUXTRACE_V2_PRIV_PER_CPU_MAX	\
	(ARM_SPE_CAP_LDS + 1)
#define ARM_SPE_AUXTRACE_V2_PER_CPU_SIZE	\
	ARM_SPE_METADATA_SIZE(ARM_SPE_AUXTRACE_V2_PRIV_PER_CPU_MAX)

union perf_event;
struct perf_session;
struct perf_pmu;

struct auxtrace_record *arm_spe_recording_init(int *err,
					       struct perf_pmu **arm_spe_pmu,
					       int nr_pmu);

int arm_spe_process_auxtrace_info(union perf_event *event,
				  struct perf_session *session);

void arm_spe_pmu_default_config(const struct perf_pmu *arm_spe_pmu,
				struct perf_event_attr *attr);

#endif
