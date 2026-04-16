// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright(C) 2023  Marvell.
 * Based on coresight-cfg-afdo.c
 */

#include "coresight-config.h"

/* ETMv4 includes and features */
#if IS_ENABLED(CONFIG_CORESIGHT_SOURCE_ETM4X)
#include "coresight-etm4x-cfg.h"

/* panic_stop feature */
static struct cscfg_parameter_desc gen_etrig_params[] = {
	{
		.name = "address",
		.value = (u64)panic,
	},
};

static struct cscfg_reg_desc gen_etrig_regs[] = {
	CS_CFG_REG_RO("TRCRSCTLRn(2)", TRCRSCTLRn(2), 0x40001),
	CS_CFG_REG64_RW("TRCACVRn(0)", TRCACVRn(0), (u64)panic),
	CS_CFG_REG_RO("TRCACATRn(0)", TRCACATRn(0), 0xf00),
	CS_CFG_REG_RO("TRCEVENTCTL0R", TRCEVENTCTL0R, 0x2),
};

CS_STRINGS_RO(gen_etrig, trcrsctlr2, TRCRSCTLRn(2));
CS_STRINGS_RW(gen_etrig, trcacvr0, TRCACVRn(0));
CS_STRINGS_RO(gen_etrig, trcacatr0, TRCACATRn(0));
CS_STRINGS_RO(gen_etrig, trceventctl0r, TRCEVENTCTL0R);

static struct configfs_attribute *gen_etrig_attrs[] = {
	&gen_etrig_attr_trcrsctlr2,
	&gen_etrig_attr_trcacvr0,
	&gen_etrig_attr_trcacatr0,
	&gen_etrig_attr_trceventctl0r,
	NULL,
};

struct cscfg_feature_desc gen_etrig_etm4x = {
	.name = "gen_etrig",
	.description = "Generate external trigger on address match\n"
		       "parameter \'address\': address of kernel address\n",
	.flags = CS_CFG_CLASS_SRC_ETM4,
	.params_desc = gen_etrig_params,
	.nr_regs = ARRAY_SIZE(gen_etrig_regs),
	.regs_desc = gen_etrig_regs,
	.nr_params = 1,
	.attrs = gen_etrig_attrs,
	.nr_attrs = ARRAY_SIZE(gen_etrig_attrs),
};

struct cscfg_config_desc pstop_etm4x = {
	.name = "panicstop",
	.description = "Stop ETM on kernel panic\n",
	.feat_name = "gen_etrig",
	.nr_total_params = 1,
};

/* end of ETM4x configurations */
#endif	/* IS_ENABLED(CONFIG_CORESIGHT_SOURCE_ETM4X) */
