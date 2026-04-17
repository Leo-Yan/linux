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

static struct cscfg_parameter_desc strobe_params[] = {
	{
		.name = "window",
		.value = 5000,
	},
	{
		.name = "period",
		.value = 10000,
	},
};

static struct cscfg_reg_desc strobe_regs[] = {
	CS_CFG_REG_RO("TRCRSCTLRn(2)", TRCRSCTLRn(2), 0x20001),
	CS_CFG_REG_RO("TRCRSCTLRn(3)", TRCRSCTLRn(3), 0x20002),
	CS_CFG_REG_RW("TRCCNTRLDVRn(0)", TRCCNTRLDVRn(0), 5000),
	CS_CFG_REG_RO("TRCCNTCTLRn(0)", TRCCNTCTLRn(0), 0x10001),
	CS_CFG_REG_RW("TRCCNTRLDVRn(1)", TRCCNTRLDVRn(1), 10000),
	CS_CFG_REG_RO("TRCCNTCTLRn(1)", TRCCNTCTLRn(1), 0x8102),
	CS_CFG_REG_RO("TRCSEQEVRn(0)", TRCSEQEVRn(0), 0x0081),
	CS_CFG_REG_RO("TRCSEQEVRn(1)", TRCSEQEVRn(1), 0x0),
	CS_CFG_REG_RO_MASK("TRCVICTLR", TRCVICTLR, 0x3, 0x3),
};

CS_STRINGS_RO(strobing, trcrsctlr2, TRCRSCTLRn(2));
CS_STRINGS_RO(strobing, trcrsctlr3, TRCRSCTLRn(3));
CS_STRINGS_RW(strobing, trccntrldvr0, TRCCNTRLDVRn(0));
CS_STRINGS_RO(strobing, trccntctlr0, TRCCNTCTLRn(0));
CS_STRINGS_RW(strobing, trccntrldvr1, TRCCNTRLDVRn(1));
CS_STRINGS_RO(strobing, trccntctlr1, TRCCNTCTLRn(1));
CS_STRINGS_RO(strobing, trcseqevr0, TRCSEQEVRn(0));
CS_STRINGS_RO(strobing, trcseqevr1, TRCSEQEVRn(1));
CS_STRINGS_RO(strobing, trcvictlr, TRCVICTLR);

static struct configfs_attribute *strobing_attrs[] = {
	&strobing_attr_trcrsctlr2,
	&strobing_attr_trcrsctlr3,
	&strobing_attr_trccntrldvr0,
	&strobing_attr_trccntctlr0,
	&strobing_attr_trccntrldvr1,
	&strobing_attr_trccntctlr1,
	&strobing_attr_trcseqevr0,
	&strobing_attr_trcseqevr1,
	&strobing_attr_trcvictlr,
	NULL,
};

struct cscfg_feat_desc strobe_etm4x = {
	.name = "strobing",
	.description = "Generate periodic trace capture windows.\n"
		       "parameter \'window\': a number of CPU cycles (W)\n"
		       "parameter \'period\': trace enabled for W cycles every period x W cycles\n",
	.flags = CS_CFG_CLASS_SRC_ETM4,
	.params_desc = strobe_params,
	.nr_regs = ARRAY_SIZE(strobe_regs),
	.regs_desc = strobe_regs,
	.nr_params = 2,
	.attrs = strobing_attrs,
	.nr_attrs = ARRAY_SIZE(strobing_attrs),
};

/*
 * set of presets leaves strobing window constant while varying period to allow
 * experimentation with mark / space ratios for various workloads
 */
static u64 afdo_presets[][2] = {
	{ 5000, 10000 },
	{ 5000,     2 },
	{ 5000,     4 },
	{ 5000,     8 },
	{ 5000,    16 },
	{ 5000,    64 },
	{ 5000,   128 },
	{ 5000,   512 },
	{ 5000,  1024 },
	{ 5000,  4096 },
};

const char *afdo_param_name[] = { "window", "period" };

struct cscfg_config_desc afdo_etm4x = {
	.name = "autofdo",
	.description = "Setup ETMs with strobing for autofdo\n"
		       "Supplied presets allow experimentation with mark-space "
		       "ratio for various loads\n",
	.feat_name = "strobing",
	.nr_presets = ARRAY_SIZE(afdo_presets),
	.nr_total_params = 2,
	.param_names = afdo_param_name,
	.presets = &afdo_presets[0][0],
};

/* end of ETM4x configurations */
#endif	/* IS_ENABLED(CONFIG_CORESIGHT_SOURCE_ETM4X) */
