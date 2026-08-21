// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright(C) 2020 Linaro Limited. All rights reserved.
 * Author: Mike Leach <mike.leach@linaro.org>
 */

#include "coresight-config.h"

/* ETMv4 includes and features */
#if IS_ENABLED(CONFIG_CORESIGHT_SOURCE_ETM4X)
#include "coresight-etm4x-cfg.h"
#include "coresight-cfg-preload.h"

/* preload configurations and features */

/* preload in features for ETMv4 */

/* strobe feature */

/*
 * Arm ARM (ARM DDI 0487 M.c), section D24.4.23: TRCCNTRLDVR<n>.VALUE is a
 * 16-bit reload value.
 */
#define STROBE_PARAM_MASK	GENMASK_ULL(15, 0)

static struct cscfg_parameter_desc strobe_params[] = {
	{
		.name = "window",
		.value = 5000,
		.value_mask = STROBE_PARAM_MASK,
	},
	{
		.name = "period",
		.value = 10000,
		.value_mask = STROBE_PARAM_MASK,
	},
};

static struct cscfg_regval_desc strobe_regs[] = {
	/* Parameter carriers; ETM register values are generated at enable time. */
	{
		.type = CS_CFG_REG_TYPE_RESOURCE | CS_CFG_REG_TYPE_VAL_PARAM,
		.param_idx = 0,
	},
	{
		.type = CS_CFG_REG_TYPE_RESOURCE | CS_CFG_REG_TYPE_VAL_PARAM,
		.param_idx = 1,
	},
};

struct cscfg_feature_desc strobe_etm4x = {
	.name = "strobing",
	.description = "Generate periodic trace capture windows.\n"
		       "parameter \'window\': CPU cycles (W), maximum 65535\n"
		       "parameter \'period\': trace enabled for W cycles every period x W cycles, maximum 65535\n",
	.match_flags = CS_CFG_MATCH_CLASS_SRC_ETM4,
	.nr_params = ARRAY_SIZE(strobe_params),
	.params_desc = strobe_params,
	.nr_regs = ARRAY_SIZE(strobe_regs),
	.regs_desc = strobe_regs,
};

/* create an autofdo configuration */

/* we will provide 9 sets of preset parameter values */
#define AFDO_NR_PRESETS	9
/* the total number of parameters in used features */
#define AFDO_NR_PARAMS	ARRAY_SIZE(strobe_params)

static const char *afdo_ref_names[] = {
	"strobing",
};

/*
 * set of presets leaves strobing window constant while varying period to allow
 * experimentation with mark / space ratios for various workloads
 */
static u64 afdo_presets[AFDO_NR_PRESETS][AFDO_NR_PARAMS] = {
	{ 5000, 2 },
	{ 5000, 4 },
	{ 5000, 8 },
	{ 5000, 16 },
	{ 5000, 64 },
	{ 5000, 128 },
	{ 5000, 512 },
	{ 5000, 1024 },
	{ 5000, 4096 },
};

struct cscfg_config_desc afdo_etm4x = {
	.name = "autofdo",
	.description = "Setup ETMs with strobing for autofdo\n"
	"Supplied presets allow experimentation with mark-space ratio for various loads\n",
	.nr_feat_refs = ARRAY_SIZE(afdo_ref_names),
	.feat_ref_names = afdo_ref_names,
	.nr_presets = AFDO_NR_PRESETS,
	.nr_total_params = AFDO_NR_PARAMS,
	.presets = &afdo_presets[0][0],
};

/* end of ETM4x configurations */
#endif	/* IS_ENABLED(CONFIG_CORESIGHT_SOURCE_ETM4X) */
