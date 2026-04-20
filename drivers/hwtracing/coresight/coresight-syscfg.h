/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Coresight system configuration driver.
 */

#ifndef CORESIGHT_SYSCFG_H
#define CORESIGHT_SYSCFG_H

#include <linux/configfs.h>
#include <linux/coresight.h>
#include <linux/device.h>

#include "coresight-config.h"

/**
 * System configuration manager device.
 *
 * Contains lists of the loaded configurations and features, plus a list of CoreSight devices
 * registered with the system as supporting configuration management.
 *
 * Need a device to 'own' some coresight system wide sysfs entries in
 * perf events, configfs etc.
 *
 * @dev:		The device.
 * @config_desc_list:	List of system configuration descriptors to load into registered devices.
 * @load_order_list:    Ordered list of owners for dynamically loaded configurations.
 * @sys_active_cnt:	Total number of active config descriptor references.
 * @cfgfs_subsys:	configfs subsystem used to manage configurations.
 * @sysfs_active_config:Active config hash used if CoreSight controlled from sysfs.
 * @sysfs_active_preset:Active preset index used if CoreSight controlled from sysfs.
 * @load_state:		A multi-stage load/unload operation is in progress.
 */
/* get reference to dev in cscfg_manager */
struct device *cscfg_device(void);

/* internal core operations for cscfg */
int __init cscfg_init(void);
void cscfg_exit(void);
int cscfg_preload(void *owner_handle);
const struct cscfg_feat_desc *cscfg_get_named_feat_desc(const char *name);
int cscfg_update_feat_param_val(struct cscfg_feat_desc *feat_desc,
				int param_idx, u64 value);
void cscfg_config_sysfs_set_preset(int preset);

int cscfg_load_config_sets(struct cscfg_config_desc **config_descs,
			   struct cscfg_feat_desc **feat_descs);

struct cscfg_info *cscfg_get_config(unsigned long cfg_hash);
void cscfg_put_config(struct cscfg_info *cfg_info);

#endif /* CORESIGHT_SYSCFG_H */
