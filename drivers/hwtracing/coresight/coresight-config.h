/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2020 Linaro Limited, All rights reserved.
 * Author: Mike Leach <mike.leach@linaro.org>
 */

#ifndef _CORESIGHT_CORESIGHT_CONFIG_H
#define _CORESIGHT_CORESIGHT_CONFIG_H

#include <linux/configfs.h>
#include <linux/coresight.h>
#include <linux/types.h>

#define CS_CFG_REG_TYPE_MASK		0x0001	/* reg value bit masked */
#define CS_CFG_REG_TYPE_64BIT		0x0002	/* reg value 64 bit */
#define CS_CFG_REG_TYPE_RO		0x0004	/* reg is read only */
#define CS_CFG_REG_TYPE_RW		0x0008	/* reg is read-write */

#define CS_CFG_REG(_name, _offset, _type, _v32, _mask)		\
	{							\
		.name	= (_name),				\
		.offset	= (_offset),				\
		.type	= (_type),				\
		.val32	= (_v32),				\
		.mask	= (_mask),				\
	}

#define CS_CFG_REG64(_name, _offset, _type, _v64)		\
	{							\
		.name	= (_name),				\
		.offset	= (_offset),				\
		.type	= (_type),				\
		.val	= (_v64),				\
	}

#define CS_CFG_REG_RO(_name, _offset, _v32)			\
	CS_CFG_REG(_name, _offset, CS_CFG_REG_TYPE_RO, _v32, 0)

#define CS_CFG_REG_RW(_name, _offset, _v32)			\
	CS_CFG_REG(_name, _offset, CS_CFG_REG_TYPE_RW, _v32, 0)

#define CS_CFG_REG64_RW(_name, _offset, _v64)			\
	CS_CFG_REG64(_name, _offset,				\
		     (CS_CFG_REG_TYPE_RW | CS_CFG_REG_TYPE_64BIT), _v64)

#define CS_CFG_REG_RO_MASK(_name, _offset, _v32, _mask) 	\
	CS_CFG_REG(_name, _offset,				\
		   (CS_CFG_REG_TYPE_RO | CS_CFG_REG_TYPE_MASK), _v32, _mask)

#define CS_CFG_CLASS_SRC_ETM4		0x0001	/* match any ETMv4 device */

/**
 * Parameter descriptor for a device feature.
 *
 * @name:  Name of parameter.
 * @value: Initial or default value.
 */
struct cscfg_parameter_desc {
	const char *name;
	u64 value;
};

/**
 * Representation of register value and a descriptor of register usage.
 *
 * Used as a descriptor in the feature descriptors.
 * Used as a value in when in a feature loading into a csdev.
 *
 * Supports full 64 bit register value, or 32 bit value with optional mask
 * value.
 *
 * @type:	define register usage and interpretation.
 * @offset:	the address offset for register in the hardware device (per device specification).
 * @hw_info:	optional hardware device type specific information. (ETM / CTI specific etc)
 * @val64:	64 bit value.
 * @val32:	32 bit value.
 * @mask32:	32 bit mask when using 32 bit value to access device register - if mask type.
 * @param_idx:	parameter index value into parameter array if param type.
 */
struct cscfg_reg_desc {
	u32 type;
	u32 offset;
	union {
		u64 val;
		struct {
			u32 val32;
			u32 mask;
		};
	};
	const char *name;
};

/**
 * Device feature descriptor - combination of registers and parameters to
 * program a device to implement a specific complex function.
 *
 * @name:	 feature name.
 * @description: brief description of the feature.
 * @item:	 List entry.
 * @match_flags: matching information if loading into a device
 * @nr_params:   number of parameters used.
 * @params_desc: array of parameters used.
 * @nr_regs:	 number of registers used.
 * @regs_desc:	 array of registers used.
 * @load_owner:	 handle to load owner for dynamic load and unload of features.
 * @fs_group:	 reference to configfs group for dynamic unload.
 */
struct cscfg_feat_desc {
	const char *name;
	const char *description;
	struct list_head item;
	struct cscfg_parameter_desc *params_desc;
	u32 flags;
	int nr_params;
	int nr_regs;
	struct cscfg_reg_desc *regs_desc;
	void *load_owner;
	struct config_group *fs_group;
	struct configfs_attribute **attrs;
	int nr_attrs;
};

/**
 * Configuration descriptor - describes selectable system configuration.
 *
 * A configuration describes device features in use, and may provide preset
 * values for the parameters in those features.
 *
 * A single set of presets is the sum of the parameters declared by
 * all the features in use - this value is @nr_total_params.
 *
 * @name:		name of the configuration - used for selection.
 * @description:	description of the purpose of the configuration.
 * @item:		list entry.
 * @feat_name:		references to features used in this configuration.
 * @nr_presets:		Number of sets of presets supplied by this configuration.
 * @nr_total_params:	Sum of all parameters declared by used features
 * @presets:		Array of preset values.
 * @event_ea:		Extended attribute for perf event value
 * @active_cnt:		ref count for activate on this configuration.
 * @load_owner:		handle to load owner for dynamic load and unload of configs.
 * @fs_group:		reference to configfs group for dynamic unload.
 * @available:		config can be activated - multi-stage load sets true on completion.
 */
struct cscfg_config_desc {
	const char *name;
	const char *description;
	struct list_head item;
	const char *feat_name;
	int nr_presets;
	int nr_total_params;
	const char **param_names;
	const u64 *presets; /* nr_presets * nr_total_params */
	struct dev_ext_attribute *event_ea;
	atomic_t active_cnt;
	void *load_owner;
	struct config_group *fs_group;
	bool available;
};

/**
 * config register instance - part of a loaded feature.
 *                            maps register values to csdev driver structures
 *
 * @reg_desc:		value to use when setting feature on device / store for
 *			readback of volatile values.
 * @driver_regval:	pointer to internal driver element used to set the value
 *			in hardware.
 */
struct cscfg_regval_csdev {
	struct cscfg_reg_desc reg_desc;
	void *driver_regval;
};

/**
 * config parameter instance - part of a loaded feature.
 *
 * @feat_csdev:		parent feature
 * @reg_csdev:		register value updated by this parameter.
 * @current_value:	current value of parameter - may be set by user via
 *			sysfs, or modified during device operation.
 * @val64:		true if 64 bit value
 */
struct cscfg_parameter_csdev {
	struct cscfg_feature_csdev *feat_csdev;
	struct cscfg_regval_csdev *reg_csdev;
	u64 current_value;
	bool val64;
};

/**
 * Feature instance loaded into a CoreSight device.
 *
 * When a feature is loaded into a specific device, then this structure holds
 * the connections between the register / parameter values used and the
 * internal data structures that are written when the feature is enabled.
 *
 * Since applying a feature modifies internal data structures in the device,
 * then we have a reference to the device spinlock to protect access to these
 * structures (@drv_spinlock).
 *
 * @feat_desc:		pointer to the static descriptor for this feature.
 * @csdev:		parent CoreSight device instance.
 * @node:		list entry into feature list for this device.
 * @drv_spinlock:	device spinlock for access to driver register data.
 * @nr_params:		number of parameters.
 * @params_csdev:	current parameter values on this device
 * @nr_regs:		number of registers to be programmed.
 * @regs_csdev:		Programming details for the registers
 */
struct cscfg_feature_csdev {
	const struct cscfg_feat_desc *feat_desc;
	struct coresight_device *csdev;
	struct list_head node;
	raw_spinlock_t *drv_spinlock;
	int nr_params;
	struct cscfg_parameter_csdev *params_csdev;
	int nr_regs;
	struct cscfg_regval_csdev *regs_csdev;
};

/**
 * Configuration instance when loaded into a CoreSight device.
 *
 * The instance contains references to loaded features on this device that are
 * used by the configuration.
 *
 * @config_desc:reference to the descriptor for this configuration
 * @csdev:	parent coresight device for this configuration instance.
 * @enabled:	true if configuration is enabled on this device.
 * @node:	list entry within the coresight device
 * @nr_feat:	Number of features on this device that are used in the
 *		configuration.
 * @feats_csdev:references to the device features to enable.
 */
struct cscfg_config_csdev {
	struct cscfg_config_desc *config_desc;
	struct coresight_device *csdev;
	bool enabled;
	struct list_head node;
	int nr_feat;
	struct cscfg_feature_csdev *feats_csdev[];
};

/**
 * Coresight device operations.
 *
 * Registered coresight devices provide these operations to manage feature
 * instances compatible with the device hardware and drivers
 *
 * @load_feat:	Pass a feature descriptor into the device and create the
 *		loaded feature instance (struct cscfg_feature_csdev).
 */
struct cscfg_csdev_feat_ops {
	int (*load_feat)(struct coresight_device *csdev,
			 struct cscfg_feature_csdev *feat_csdev);
};

struct cscfg_reg {
	struct cscfg_reg_desc *regs;
	int nr_regs;
};

struct cscfg_dynamic_cfg {
	struct cscfg_feat_desc *desc;
	struct cscfg_reg reg;
	struct config_group group;
	int refcnt;
	u32 type;

	/* For legacy reason */
	struct cscfg_config_desc *config_desc;
	int preset;
};

/* coresight config helper functions*/

/* enable / disable config on a device - called with appropriate locks set.*/
int cscfg_csdev_enable_config(struct cscfg_config_csdev *config_csdev, int preset);
void cscfg_csdev_disable_config(struct cscfg_config_csdev *config_csdev);

/* reset a feature to default values */
void cscfg_reset_feat(struct cscfg_feature_csdev *feat_csdev);

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
	struct cscfg_reg_desc *reg_desc = NULL;			\
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
	struct cscfg_reg_desc *reg_desc = NULL;			\
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

#endif /* _CORESIGHT_CORESIGHT_CONFIG_H */
