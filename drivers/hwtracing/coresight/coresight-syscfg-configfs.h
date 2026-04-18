/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Coresight system configuration driver - support for configfs.
 */

#ifndef CORESIGHT_SYSCFG_CONFIGFS_H
#define CORESIGHT_SYSCFG_CONFIGFS_H

#include <linux/configfs.h>
#include "coresight-syscfg.h"

#define CSCFG_FS_SUBSYS_NAME "cs-syscfg"

int cscfg_configfs_init(struct cscfg_manager *cscfg_mgr);
void cscfg_configfs_release(struct cscfg_manager *cscfg_mgr);

int cscfg_feat_create_group(struct cscfg_feat_desc *feat_desc);
void cscfg_feat_delete_group(struct cscfg_feat_desc *feat_desc);

int cscfg_preload_cfg_create_group(struct cscfg_config_desc *config_desc);
void cscfg_preload_cfg_delete_group(struct cscfg_config_desc *config_desc);

struct cscfg_info *cscfg_search_config(struct cscfg_manager *cscfg_mgr,
				       unsigned long hash);
struct cscfg_reg *cscfg_get_reg_list(struct cscfg_info *cfg_info, int type);

#endif /* CORESIGHT_SYSCFG_CONFIGFS_H */
