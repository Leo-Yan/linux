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

static struct cscfg_regval_desc strobe_regs[] = {
	/* resource selectors */
	{
		.name = "TRCRSCTLRn(2)",
		.type = CS_CFG_REG_TYPE_RESOURCE,
		.offset = TRCRSCTLRn(2),
		.hw_info = ETM4_CFG_RES_SEL,
		.val32 = 0x20001,
	},
	{
		.name = "TRCRSCTLRn(3)",
		.type = CS_CFG_REG_TYPE_RESOURCE,
		.offset = TRCRSCTLRn(3),
		.hw_info = ETM4_CFG_RES_SEQ,
		.val32 = 0x20002,
	},
	/* strobe window counter 0 - reload from param 0 */
	{
		.name = "TRCCNTVRn(0)",
		.type = CS_CFG_REG_TYPE_RESOURCE | CS_CFG_REG_TYPE_VAL_SAVE,
		.offset = TRCCNTVRn(0),
		.hw_info = ETM4_CFG_RES_CTR,
	},
	{
		.name = "TRCCNTRLDVRn(0)",
		.type = CS_CFG_REG_TYPE_RESOURCE | CS_CFG_REG_TYPE_VAL_PARAM,
		.offset = TRCCNTRLDVRn(0),
		.hw_info = ETM4_CFG_RES_CTR,
		.val32 = 0,
	},
	{
		.name = "TRCCNTCTLRn(0)",
		.type = CS_CFG_REG_TYPE_RESOURCE,
		.offset = TRCCNTCTLRn(0),
		.hw_info = ETM4_CFG_RES_CTR,
		.val32 = 0x10001,
	},
	/* strobe period counter 1 - reload from param 1 */
	{
		.name = "TRCCNTVRn(1)",
		.type = CS_CFG_REG_TYPE_RESOURCE | CS_CFG_REG_TYPE_VAL_SAVE,
		.offset = TRCCNTVRn(1),
		.hw_info = ETM4_CFG_RES_CTR,
	},
	{
		.name = "TRCCNTRLDVRn(1)",
		.type = CS_CFG_REG_TYPE_RESOURCE | CS_CFG_REG_TYPE_VAL_PARAM,
		.offset = TRCCNTRLDVRn(1),
		.hw_info = ETM4_CFG_RES_CTR,
		.val32 = 1,
	},
	{
		.name = "TRCCNTCTLRn(1)",
		.type = CS_CFG_REG_TYPE_RESOURCE,
		.offset = TRCCNTCTLRn(1),
		.hw_info = ETM4_CFG_RES_CTR,
		.val32 = 0x8102,
	},
	/* sequencer */
	{
		.name = "TRCSEQEVRn(0)",
		.type = CS_CFG_REG_TYPE_RESOURCE,
		.offset = TRCSEQEVRn(0),
		.hw_info = ETM4_CFG_RES_SEQ,
		.val32 = 0x0081,
	},
	{
		.name = "TRCSEQEVRn(1)",
		.type = CS_CFG_REG_TYPE_RESOURCE,
		.offset = TRCSEQEVRn(1),
		.hw_info = ETM4_CFG_RES_SEQ,
		.val32 = 0x0000,
	},
	/* view-inst */
	{
		.name = "TRCVICTLR",
		.type = CS_CFG_REG_TYPE_STD | CS_CFG_REG_TYPE_VAL_MASK,
		.offset = TRCVICTLR,
		.val32 = 0x0003,
		.mask32 = 0x0003,
	},
	/* end of regs */
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
	struct cscfg_feature_desc *feat_desc = cfg->desc;		\
	struct cscfg_regval_desc *reg_desc = NULL;			\
	uint32_t val;							\
	int ret, i;							\
									\
	ret = kstrtou32(page, 0, &val);					\
    	if (ret)							\
        	return ret;						\
									\
	for (i = 0; i < feat_desc->nr_regs; i++) {			\
		if (feat_desc->regs_desc[i].offset == __val) {		\
			reg_desc = &feat_desc->regs_desc[i];		\
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
	struct cscfg_feature_desc *feat_desc = cfg->desc;		\
	struct cscfg_regval_desc *reg_desc = NULL;			\
	int i;								\
									\
	for (i = 0; i < feat_desc->nr_regs; i++) {			\
		if (feat_desc->regs_desc[i].offset == __val) {		\
			reg_desc = &feat_desc->regs_desc[i];		\
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

CS_STRINGS_RO(strobing, TRCRSCTLR2, TRCRSCTLRn(2));
CS_STRINGS_RO(strobing, TRCRSCTLR3, TRCRSCTLRn(3));
CS_STRINGS_RW(strobing, TRCCNTVR0, TRCCNTVRn(0));
CS_STRINGS_RO(strobing, TRCCNTRLDVR0, TRCCNTRLDVRn(0));
CS_STRINGS_RO(strobing, TRCCNTCTLR0, TRCCNTCTLRn(0));
CS_STRINGS_RW(strobing, TRCCNTVR1, TRCCNTVRn(1));
CS_STRINGS_RO(strobing, TRCCNTRLDVR1, TRCCNTRLDVRn(1));
CS_STRINGS_RO(strobing, TRCCNTCTLR1, TRCCNTCTLRn(1));
CS_STRINGS_RO(strobing, TRCSEQEVR0, TRCSEQEVRn(0));
CS_STRINGS_RO(strobing, TRCSEQEVR1, TRCSEQEVRn(1));

CS_STRINGS_R(strobing, TRCVICTLR, TRCVICTLR)

static struct configfs_attribute strobing_attr_TRCVICTLR = {
	.ca_name	= "TRCVICTLR",
	.ca_mode	= S_IRUGO,
	.ca_owner	= THIS_MODULE,
	.show		= strobing_TRCVICTLR_show,
};

static struct configfs_attribute *strobing_attrs[] = {
	&strobing_attr_TRCRSCTLR2,
	&strobing_attr_TRCRSCTLR3,
	&strobing_attr_TRCCNTVR0,
	&strobing_attr_TRCCNTRLDVR0,
	&strobing_attr_TRCCNTCTLR0,
	&strobing_attr_TRCCNTVR1,
	&strobing_attr_TRCCNTRLDVR1,
	&strobing_attr_TRCCNTCTLR1,
	&strobing_attr_TRCSEQEVR0,
	&strobing_attr_TRCSEQEVR1,
	&strobing_attr_TRCVICTLR,
	NULL,
};

struct cscfg_feature_desc strobe_etm4x = {
	.name = "strobing",
	.description = "Generate periodic trace capture windows.\n"
		       "parameter \'window\': a number of CPU cycles (W)\n"
		       "parameter \'period\': trace enabled for W cycles every period x W cycles\n",
	.match_flags = CS_CFG_MATCH_CLASS_SRC_ETM4,
	.nr_params = ARRAY_SIZE(strobe_params),
	.params_desc = strobe_params,
	.nr_regs = ARRAY_SIZE(strobe_regs),
	.regs_desc = strobe_regs,
	.attrs = strobing_attrs,
	.nr_attrs = ARRAY_SIZE(strobing_attrs),
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
