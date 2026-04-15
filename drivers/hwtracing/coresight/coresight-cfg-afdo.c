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

#include <linux/configfs.h>

static inline struct cscfg_dynamic_cfg *to_dynamic_cfg(struct config_item *item)
{
	return container_of(to_config_group(item), struct cscfg_dynamic_cfg,
			    group);
}

#define CS_STRINGS_W(__struct, __id, __val) 				\
static ssize_t __struct##_##__id##_store(struct config_item *item, 	\
                const char *page, size_t len) 				\
{ 									\
	struct cscfg_dynamic_cfg *cfg = to_dynamic_cfg(item);		\
	struct cscfg_regval_desc *reg_desc = NULL;			\
	uint32_t val;							\
	int ret, i;							\
									\
	ret = kstrtou32(page, 0, &val);					\
    	if (ret)							\
        	return ret;						\
									\
	for (i = 0; i < cfg->reg.nr_regs; i++) {			\
		if (cfg->reg.regs[i].offset == __val) {			\
			reg_desc = &cfg->reg.regs[i];			\
			break;						\
		}							\
	}								\
									\
	if (!reg_desc)							\
		return -ENOENT;						\
									\
	reg_desc->val32 = val;						\
									\
        return len; 							\
}

#define CS_STRINGS_R(__struct, __id, __val) 				\
static ssize_t __struct##_##__id##_show(struct config_item *item,	\
					char *page) 			\
{									\
	struct cscfg_dynamic_cfg *cfg = to_dynamic_cfg(item);		\
	struct cscfg_regval_desc *reg_desc = NULL;			\
	int i;								\
									\
	for (i = 0; i < cfg->reg.nr_regs; i++) {			\
		if (cfg->reg.regs[i].offset == __val) {			\
			reg_desc = &cfg->reg.regs[i];			\
			break;						\
		}							\
	}								\
									\
	if (!reg_desc)							\
		return -ENOENT;						\
									\
        return sprintf(page, "%x\n", reg_desc->val32); 			\
}

#define CS_STRINGS_RW(struct_name, _id, _val) \
        CS_STRINGS_R(struct_name, _id, _val) \
        CS_STRINGS_W(struct_name, _id, _val) \
        CONFIGFS_ATTR(struct_name##_, _id)

#define CS_STRINGS_RO(struct_name, _id, _val) \
        CS_STRINGS_R(struct_name, _id, _val) \
        CONFIGFS_ATTR_RO(struct_name##_, _id)

CS_STRINGS_RO(strobing, trcrsctlr2, TRCRSCTLRn(2));
CS_STRINGS_RO(strobing, trcrsctlr3, TRCRSCTLRn(3));
CS_STRINGS_RW(strobing, trccntvr0, TRCCNTVRn(0));
CS_STRINGS_RO(strobing, trccntrldvr0, TRCCNTRLDVRn(0));
CS_STRINGS_RO(strobing, trccntctlr0, TRCCNTCTLRn(0));
CS_STRINGS_RW(strobing, trccntvr1, TRCCNTVRn(1));
CS_STRINGS_RO(strobing, trccntrldvr1, TRCCNTRLDVRn(1));
CS_STRINGS_RO(strobing, trccntctlr1, TRCCNTCTLRn(1));
CS_STRINGS_RO(strobing, trcseqevr0, TRCSEQEVRn(0));
CS_STRINGS_RO(strobing, trcseqevr1, TRCSEQEVRn(1));
CS_STRINGS_RO(strobing, trcvictlr, TRCVICTLR);

static struct configfs_attribute *strobing_attrs[] = {
	&strobing_attr_trcrsctlr2,
	&strobing_attr_trcrsctlr3,
	&strobing_attr_trccntvr0,
	&strobing_attr_trccntrldvr0,
	&strobing_attr_trccntctlr0,
	&strobing_attr_trccntvr1,
	&strobing_attr_trccntrldvr1,
	&strobing_attr_trccntctlr1,
	&strobing_attr_trcseqevr0,
	&strobing_attr_trcseqevr1,
	&strobing_attr_trcvictlr,
	NULL,
};

struct cscfg_feature_desc strobe_etm4x = {
	.name = "strobing",
	.description = "Generate periodic trace capture windows.\n"
		       "parameter \'window\': a number of CPU cycles (W)\n"
		       "parameter \'period\': trace enabled for W cycles every period x W cycles\n",
	.flags = CS_CFG_CLASS_SRC_ETM4,
	.nr_regs = ARRAY_SIZE(strobe_regs),
	.regs_desc = strobe_regs,
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

struct cscfg_config_desc afdo_etm4x = {
	.name = "autofdo",
	.description = "Setup ETMs with strobing for autofdo\n"
		       "Supplied presets allow experimentation with mark-space "
		       "ratio for various loads\n",
	.feat_name = "strobing",
	.nr_presets = ARRAY_SIZE(afdo_presets),
	.nr_total_params = 2,
	.presets = &afdo_presets[0][0],
};

/* end of ETM4x configurations */
#endif	/* IS_ENABLED(CONFIG_CORESIGHT_SOURCE_ETM4X) */
