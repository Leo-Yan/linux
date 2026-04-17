/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Coresight system configuration driver - support for configfs.
 */

#ifndef CORESIGHT_SYSCFG_CONFIGFS_H
#define CORESIGHT_SYSCFG_CONFIGFS_H

#include <linux/configfs.h>
#include "coresight-syscfg.h"

#define CSCFG_FS_SUBSYS_NAME "cs-syscfg"

struct cscfg_feat {
	struct cscfg_feat_desc *feat_desc;
	struct config_group group;
	struct config_group params_group;
};

struct cscfg_feat_param {
	int idx;
	struct config_group group;
};

struct cscfg_fs_config {
	struct cscfg_config_desc *config_desc;
	struct config_group group;
	bool active;
	int preset;
};

struct cscfg_fs_preset {
	int preset_num;
	struct cscfg_config_desc *config_desc;
	struct config_group group;
};

struct cscfg_info {
	int hash;
	struct config_group group;
};

int cscfg_configfs_init(struct cscfg_manager *cscfg_mgr);
void cscfg_configfs_release(struct cscfg_manager *cscfg_mgr);
int cscfg_configfs_add_config(struct cscfg_config_desc *config_desc);
int cscfg_configfs_add_feature(struct cscfg_feat_desc *feat_desc);
void cscfg_configfs_del_config(struct cscfg_config_desc *config_desc);
void cscfg_configfs_del_feature(struct cscfg_feat_desc *feat_desc);
struct cscfg_info *cscfg_search_config(struct cscfg_manager *cscfg_mgr,
				       unsigned long hash);
struct cscfg_reg *cscfg_get_reg_list(struct cscfg_info *cfg_info, int type);

#endif /* CORESIGHT_SYSCFG_CONFIGFS_H */
