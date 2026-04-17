// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2020 Linaro Limited, All rights reserved.
 * Author: Mike Leach <mike.leach@linaro.org>
 */

#include <linux/configfs.h>

#include "coresight-config.h"
#include "coresight-syscfg-configfs.h"

#define attr_item_to_feat(item)	\
	container_of(to_config_group(item), struct cscfg_feat, group)

#define attr_item_to_feat_param(item)	\
	container_of(to_config_group(item), struct cscfg_feat_param, group)

static const struct config_item_type cscfg_feats_type = {
	.ct_owner = THIS_MODULE,
};

static struct config_group cscfg_feats_grp = {
	.cg_item = {
		.ci_namebuf = "features",
		.ci_type = &cscfg_feats_type,
	},
};

static ssize_t cscfg_feat_description_show(struct config_item *item, char *page)
{
	struct cscfg_feat *feat = attr_item_to_feat(item);
	struct cscfg_feat_desc *desc = feat->feat_desc;

	return scnprintf(page, PAGE_SIZE, "%s", desc->description);
}
CONFIGFS_ATTR_RO(cscfg_feat_, description);

static ssize_t cscfg_feat_matches_show(struct config_item *item, char *page)
{
	struct cscfg_feat *feat = attr_item_to_feat(item);
	struct cscfg_feat_desc *desc = feat->feat_desc;

	if (!(desc->flags & CS_CFG_CLASS_SRC_ETM4))
		return 0;

	return scnprintf(page, PAGE_SIZE, "SRC_ETMV4\n");
}
CONFIGFS_ATTR_RO(cscfg_feat_, matches);

static ssize_t cscfg_feat_nr_params_show(struct config_item *item, char *page)
{
	struct cscfg_feat *feat = attr_item_to_feat(item);
	struct cscfg_feat_desc *desc = feat->feat_desc;

	return scnprintf(page, PAGE_SIZE, "%d\n", desc->nr_params);
}
CONFIGFS_ATTR_RO(cscfg_feat_, nr_params);

static struct configfs_attribute *cscfg_feat_attrs[] = {
	&cscfg_feat_attr_description,
	&cscfg_feat_attr_matches,
	&cscfg_feat_attr_nr_params,
	NULL,
};

static const struct config_item_type cscfg_feat_type = {
	.ct_owner = THIS_MODULE,
	.ct_attrs = cscfg_feat_attrs,
};

static ssize_t cscfg_feat_param_value_show(struct config_item *item, char *page)
{
	struct cscfg_feat_param *param = attr_item_to_feat_param(item);
	struct cscfg_feat *feat = attr_item_to_feat(item->ci_parent->ci_parent);
	struct cscfg_feat_desc *desc = feat->feat_desc;

	return scnprintf(page, PAGE_SIZE, "0x%llx\n",
			 desc->params_desc[param->idx].value);
}
CONFIGFS_ATTR_RO(cscfg_feat_param_, value);

static struct configfs_attribute *cscfg_feat_param_attrs[] = {
	&cscfg_feat_param_attr_value,
	NULL,
};

static const struct config_item_type cscfg_feat_param_type = {
	.ct_owner = THIS_MODULE,
	.ct_attrs = cscfg_feat_param_attrs,
};

static void cscfg_release_feat_param_group(struct config_group *params_group)
{
	struct cscfg_feat_param *param;
	struct config_item *ci, *n;

	list_for_each_entry_safe(ci, n, &cscfg_feats_grp.cg_children, ci_entry) {
		param = attr_item_to_feat_param(ci);
		list_del(&ci->ci_entry);
		kfree(param);
	}
}

static int cscfg_create_param_group_items(struct config_group *params_group,
					  struct cscfg_feat_desc *feat_desc)
{
	struct cscfg_feat_param *param;
	int i;

	for (i = 0; i < feat_desc->nr_params; i++) {
		param = kzalloc(sizeof(*param), GFP_KERNEL);
		if (!param)
			goto failed;

		param->idx = i;
		config_group_init_type_name(&param->group,
					    feat_desc->params_desc[i].name,
					    &cscfg_feat_param_type);
		configfs_add_default_group(&param->group, params_group);
	}
	return 0;

failed:
	cscfg_release_feat_param_group(params_group);
	return -ENOMEM;
}

static const struct config_item_type cscfg_params_group_type = {
	.ct_owner = THIS_MODULE,
};

static struct config_group *
cscfg_create_feature_group(struct cscfg_feat_desc *feat_desc)
{
	struct cscfg_feat *feat;
	int ret;

	feat = kzalloc(sizeof(*feat), GFP_KERNEL);
	if (!feat)
		return ERR_PTR(-ENOMEM);

	feat->feat_desc = feat_desc;
	config_group_init_type_name(&feat->group, feat_desc->name,
				    &cscfg_feat_type);

	config_group_init_type_name(&feat->params_group, "params",
				    &cscfg_params_group_type);
	configfs_add_default_group(&feat->params_group, &feat->group);
	ret = cscfg_create_param_group_items(&feat->params_group, feat_desc);
	if (ret) {
		kfree(feat);
		return ERR_PTR(ret);
	}

	return &feat->group;
}

/* attributes for the config view group */
static ssize_t cscfg_cfg_description_show(struct config_item *item, char *page)
{
	struct cscfg_dynamic_cfg *cfg = container_of(to_config_group(item),
						     struct cscfg_dynamic_cfg, group);

	return scnprintf(page, PAGE_SIZE, "%s", cfg->config_desc->description);
}
CONFIGFS_ATTR_RO(cscfg_cfg_, description);

static ssize_t cscfg_cfg_feature_refs_show(struct config_item *item, char *page)
{
	struct cscfg_dynamic_cfg *cfg = container_of(to_config_group(item),
						     struct cscfg_dynamic_cfg, group);

	return scnprintf(page, PAGE_SIZE, "%s\n", cfg->desc->name);
}
CONFIGFS_ATTR_RO(cscfg_cfg_, feature_refs);

/* list preset values in order of features and params */
static ssize_t cscfg_cfg_values_show(struct config_item *item, char *page)
{
	const struct cscfg_config_desc *config_desc;
	struct cscfg_fs_preset *fs_preset;
	int i, val_idx, preset_idx;
	ssize_t used = 0;

	fs_preset = container_of(to_config_group(item), struct cscfg_fs_preset, group);
	config_desc = fs_preset->config_desc;

	if (!config_desc->nr_presets)
		return 0;

	preset_idx = fs_preset->preset_num;

	/* start index on the correct array line */
	val_idx = config_desc->nr_total_params * preset_idx;

	for (i = 0; i < config_desc->nr_total_params; i++) {
		used += scnprintf(page + used, PAGE_SIZE - used,
				  "%s.%s = 0x%llx ",
				  config_desc->feat_name,
				  config_desc->param_names[i],
				  config_desc->presets[val_idx++]);
	}

	used += scnprintf(page + used, PAGE_SIZE - used, "\n");
	return used;
}
CONFIGFS_ATTR_RO(cscfg_cfg_, values);

static ssize_t cscfg_cfg_enable_show(struct config_item *item, char *page)
{
	struct cscfg_dynamic_cfg *cfg = container_of(to_config_group(item),
						     struct cscfg_dynamic_cfg, group);

	return scnprintf(page, PAGE_SIZE, "%d\n", !!cfg->refcnt);
}

static ssize_t cscfg_cfg_enable_store(struct config_item *item,
					const char *page, size_t count)
{
	struct cscfg_dynamic_cfg *cfg = container_of(to_config_group(item),
						     struct cscfg_dynamic_cfg, group);
	bool val;
	int ret;

	ret = kstrtobool(page, &val);
	if (ret < 0)
		return ret;

	/* TODO: add locking */
	if (val)
		cfg->refcnt++;
	else
		cfg->refcnt--;

	return 0;
}
CONFIGFS_ATTR(cscfg_cfg_, enable);

static ssize_t cscfg_cfg_preset_show(struct config_item *item, char *page)
{
	struct cscfg_dynamic_cfg *cfg = container_of(to_config_group(item),
						     struct cscfg_dynamic_cfg, group);

	return scnprintf(page, PAGE_SIZE, "%d\n", cfg->preset);
}

static ssize_t cscfg_cfg_preset_store(struct config_item *item,
					     const char *page, size_t count)
{
	struct cscfg_dynamic_cfg *cfg = container_of(to_config_group(item),
						     struct cscfg_dynamic_cfg, group);
	const struct cscfg_config_desc *config_desc = cfg->config_desc;
	int preset, ret;

	ret = kstrtoint(page, 0, &preset);
	if (ret < 0)
		return ret;

	/*
	 * presets start at 1, and go up to max (15),
	 * but the config may provide fewer.
	 */
	if ((preset < 1) || (preset > config_desc->nr_presets))
		return -EINVAL;

	/* set new value */
	cfg->preset = preset;

	/* TODO: apply preset to cfg's reg list */
	return 0;
}
CONFIGFS_ATTR(cscfg_cfg_, preset);

static struct configfs_attribute *cscfg_config_view_attrs[] = {
	&cscfg_cfg_attr_description,
	&cscfg_cfg_attr_feature_refs,
	&cscfg_cfg_attr_enable,
	&cscfg_cfg_attr_preset,
	NULL,
};

static const struct config_item_type cscfg_config_view_type = {
	.ct_owner = THIS_MODULE,
	.ct_attrs = cscfg_config_view_attrs,
};

static struct configfs_attribute *cscfg_config_preset_attrs[] = {
	&cscfg_cfg_attr_values,
	NULL,
};

static const struct config_item_type cscfg_config_preset_type = {
	.ct_owner = THIS_MODULE,
	.ct_attrs = cscfg_config_preset_attrs,
};

static int cscfg_add_preset_groups(struct cscfg_dynamic_cfg *cfg,
				   struct cscfg_config_desc *config_desc)
{
	int preset_num;
	struct cscfg_fs_preset *cfg_fs_preset;
	char name[CONFIGFS_ITEM_NAME_LEN];

	if (!config_desc->nr_presets)
		return 0;

	for (preset_num = 1; preset_num < config_desc->nr_presets; preset_num++) {
		cfg_fs_preset = devm_kzalloc(cscfg_device(),
					     sizeof(struct cscfg_fs_preset), GFP_KERNEL);

		if (!cfg_fs_preset)
			return -ENOMEM;

		snprintf(name, CONFIGFS_ITEM_NAME_LEN, "preset%d", preset_num);
		cfg_fs_preset->preset_num = preset_num;
		cfg_fs_preset->config_desc = config_desc;
		config_group_init_type_name(&cfg_fs_preset->group, name,
					    &cscfg_config_preset_type);
		configfs_add_default_group(&cfg_fs_preset->group, &cfg->group);
	}
	return 0;
}

static struct config_group *cscfg_create_config_group(struct cscfg_config_desc *config_desc)
{
	struct cscfg_feat *feat;
	struct cscfg_feat_desc *desc = NULL;
	struct cscfg_dynamic_cfg *cfg;
	struct config_item *ci;
	int err;

	list_for_each_entry(ci, &cscfg_feats_grp.cg_children, ci_entry) {
		feat = attr_item_to_feat(ci);

		printk("%s: feat=%s config=%s\n", __func__,
			feat->feat_desc->name, config_desc->feat_name);
		if (!strcmp(config_desc->feat_name, feat->feat_desc->name)) {
		        printk("%s: found feat\n", __func__);
			desc = feat->feat_desc;
			break;
		}
	}

	if (!desc)
		return ERR_PTR(-ENOENT);

	cfg = kzalloc(sizeof(*cfg), GFP_KERNEL);
	if (!cfg)
		return ERR_PTR(-ENOMEM);

	cfg->desc = desc;

	cfg->reg.nr_regs = desc->nr_regs;
	cfg->reg.regs = kzalloc(sizeof(*desc->regs_desc) * desc->nr_regs, GFP_KERNEL);
	memcpy(cfg->reg.regs, desc->regs_desc, sizeof(*desc->regs_desc) * desc->nr_regs);

	config_group_init_type_name(&cfg->group, config_desc->name, &cscfg_config_view_type);

	/* add in a preset<n> dir for each preset */
	err = cscfg_add_preset_groups(cfg, config_desc);
	if (err)
		return ERR_PTR(err);

	return &cfg->group;
}


static const struct config_item_type cscfg_configs_type = {
	.ct_owner = THIS_MODULE,
};

static struct config_group cscfg_configs_grp = {
	.cg_item = {
		.ci_namebuf = "configurations",
		.ci_type = &cscfg_configs_type,
	},
};

/* add configuration to configurations group */
int cscfg_configfs_add_config(struct cscfg_config_desc *config_desc)
{
	struct config_group *new_group;
	int err;

	new_group = cscfg_create_config_group(config_desc);
	if (IS_ERR(new_group))
		return PTR_ERR(new_group);

	err =  configfs_register_group(&cscfg_configs_grp, new_group);
	if (!err)
		config_desc->fs_group = new_group;
	return err;
}

void cscfg_configfs_del_config(struct cscfg_config_desc *config_desc)
{
	if (config_desc->fs_group) {
		configfs_unregister_group(config_desc->fs_group);
		config_desc->fs_group = NULL;
	}
}

/* add feature to features group */
int cscfg_configfs_add_feature(struct cscfg_feat_desc *feat_desc)
{
	struct config_group *new_group;
	int err;

	new_group = cscfg_create_feature_group(feat_desc);
	if (IS_ERR(new_group))
		return PTR_ERR(new_group);
	err =  configfs_register_group(&cscfg_feats_grp, new_group);
	if (!err)
		feat_desc->fs_group = new_group;
	return err;
}

void cscfg_configfs_del_feature(struct cscfg_feat_desc *feat_desc)
{
	if (feat_desc->fs_group) {
		configfs_unregister_group(feat_desc->fs_group);
		feat_desc->fs_group = NULL;
	}
}

static inline struct cscfg_info *to_cscfg_info(struct config_item *item)
{
	return container_of(to_config_group(item), struct cscfg_info, group);
}

static struct config_item_type dyn_cfg_type = {
	.ct_owner = THIS_MODULE,
};

//static int features_desc_link(struct config_item *feat_desc_ci,
//			      struct config_item *feat_ci)
//{
//	struct cscfg_info *cfg_info = container_of(to_config_group(feat_desc_ci),
//						   struct cscfg_info, features_group);
//	struct cscfg_dynamic_cfg *dyn_cfg;
//	int ret;
//
//	printk("%s: src_feat_ci=%px feat_ci=%px cscfg_info=%px\n",
//		__func__, feat_desc_ci, feat_ci, cfg_info);
//
//	dyn_cfg = kzalloc(sizeof(*dyn_cfg), GFP_KERNEL);
//	if (!dyn_cfg)
//		return -ENOMEM;
//
//	config_group_init_type_name(&dyn_cfg->group, "test", &dyn_cfg_type);
//	ret = configfs_register_group(&cfg_info->configs_group, &dyn_cfg->group);
//	if (ret) {
//		kfree(dyn_cfg);
//		return ret;
//	}
//
//	return 0;
//}
//
//static void features_desc_unlink(struct config_item *src_feat_ci,
//				 struct config_item *feat_ci)
//{
//	struct cscfg_info *cfg_info = container_of(to_config_group(feat_ci),
//						   struct cscfg_info, features_group);
//
//	printk("%s: cscfg_info=%px\n", __func__, cfg_info);
//
//	return;
//}

//static struct configfs_item_operations features_desc_ops = {
//	.allow_link	= features_desc_link,
//	.drop_link	= features_desc_unlink,
//};
//
//static const struct config_item_type features_desc = {
//	.ct_item_ops	= &features_desc_ops,
//	.ct_owner       = THIS_MODULE,
//};

//static const struct config_item_type configs_type = {
//	.ct_owner       = THIS_MODULE,
//};

static void cscfg_config_attr_release(struct config_item *item)
{
	struct cscfg_info *cfg_info = to_cscfg_info(item);

	kfree(cfg_info);
}

static struct configfs_item_operations cscfg_root_item_ops = {
	.release	= cscfg_config_attr_release,
};

static ssize_t cscfg_root_hash_show(struct config_item *item, char *page)
{
	struct cscfg_info *cfg_info = container_of(to_config_group(item),
						   struct cscfg_info, group);

	return sysfs_emit(page, "%x\n", cfg_info->hash);
}

static ssize_t cscfg_root_bind_show(struct config_item *item, char *page)
{
	struct config_item *ci;

	list_for_each_entry(ci, &cscfg_feats_grp.cg_children, ci_entry) {
		struct cscfg_feat *feat = attr_item_to_feat(ci);

		printk("%s: feat=%s\n", __func__, feat->feat_desc->name);
	}

	return sysfs_emit(page, "success\n");
}

static ssize_t cscfg_root_bind_store(struct config_item *item, const char *page,
				     size_t len)
{
	struct cscfg_feat *feat;
	struct cscfg_feat_desc *desc = NULL;
	struct cscfg_dynamic_cfg *cfg;
	struct config_item *ci;

	if (strlen(page) < 0)
		return -EINVAL;

	printk("%s: page=%s\n", __func__, page);

	list_for_each_entry(ci, &cscfg_feats_grp.cg_children, ci_entry) {
		feat = attr_item_to_feat(ci);

		printk("%s: feat=%s\n", __func__, feat->feat_desc->name);
		if (sysfs_streq(page, feat->feat_desc->name)) {
		        printk("%s: found feat\n", __func__);
			desc = feat->feat_desc;
			break;
		}
	}

	if (!desc)
		return -ENOENT;

	cfg = kzalloc(sizeof(*cfg), GFP_KERNEL);
	if (!cfg)
		return -ENOMEM;

	cfg->desc = desc;

	cfg->reg.nr_regs = desc->nr_regs;
	cfg->reg.regs = kzalloc(sizeof(*desc->regs_desc) * desc->nr_regs, GFP_KERNEL);
	memcpy(cfg->reg.regs, desc->regs_desc, sizeof(*desc->regs_desc) * desc->nr_regs);
	cfg->type = 0x12345678;

	dyn_cfg_type.ct_attrs = desc->attrs;

	config_group_init_type_name(&cfg->group, desc->name, &dyn_cfg_type);
	configfs_register_group(to_config_group(item), &cfg->group);
	return len;
}

static ssize_t cscfg_root_unbind_show(struct config_item *item, char *page)
{
	return 0;
}

static ssize_t cscfg_root_unbind_store(struct config_item *item, const char *page,
				     size_t len)
{
	return 0;
}

CONFIGFS_ATTR(cscfg_root_, bind);
CONFIGFS_ATTR(cscfg_root_, unbind);
CONFIGFS_ATTR_RO(cscfg_root_, hash);

static struct configfs_attribute *cscfg_root_attrs[] = {
	&cscfg_root_attr_bind,
	&cscfg_root_attr_unbind,
	&cscfg_root_attr_hash,
	NULL,
};

static const struct config_item_type cscfg_root_type = {
	.ct_item_ops	= &cscfg_root_item_ops,
	.ct_attrs	= cscfg_root_attrs,
	.ct_owner	= THIS_MODULE,
};

static struct config_group *cscfg_make(struct config_group *group,
				       const char *name)
{
	struct cscfg_info *cfg_info;

	cfg_info = kzalloc(sizeof(*cfg_info), GFP_KERNEL);
	if (!cfg_info)
		return ERR_PTR(-ENOMEM);

	cfg_info->hash = hashlen_hash(hashlen_string(NULL, name));
	printk("%s: cscfg_info=%px hash=%x\n", __func__, cfg_info, cfg_info->hash);

	config_group_init_type_name(&cfg_info->group, name, &cscfg_root_type);

	//config_group_init_type_name(&cfg_info->features_group, "features",
	//			    &features_desc);
	//configfs_add_default_group(&cfg_info->features_group,
	//			   &cfg_info->group);

	//config_group_init_type_name(&cfg_info->configs_group, "configs",
	//			      &configs_type);
	//configfs_add_default_group(&cfg_info->configs_group,
	//			   &cfg_info->group);

	return &cfg_info->group;
}

static void cscfg_drop(struct config_group *group, struct config_item *item)
{
	config_item_put(item);
}

static struct configfs_group_operations cscfg_ops = {
	.make_group     = &cscfg_make,
	.drop_item      = &cscfg_drop,
};

static const struct config_item_type cscfg_type = {
	.ct_group_ops   = &cscfg_ops,
	.ct_owner       = THIS_MODULE,
};

int cscfg_configfs_init(struct cscfg_manager *cscfg_mgr)
{
	struct configfs_subsystem *subsys;

	if (!cscfg_mgr)
		return -EINVAL;

	subsys = &cscfg_mgr->cfgfs_subsys;
	config_item_set_name(&subsys->su_group.cg_item, CSCFG_FS_SUBSYS_NAME);
	subsys->su_group.cg_item.ci_type = &cscfg_type;

	config_group_init(&subsys->su_group);
	mutex_init(&subsys->su_mutex);

	/* Add default groups to subsystem */
	config_group_init(&cscfg_configs_grp);
	configfs_add_default_group(&cscfg_configs_grp, &subsys->su_group);

	config_group_init(&cscfg_feats_grp);
	configfs_add_default_group(&cscfg_feats_grp, &subsys->su_group);

	return configfs_register_subsystem(subsys);
}

void cscfg_configfs_release(struct cscfg_manager *cscfg_mgr)
{
	configfs_unregister_subsystem(&cscfg_mgr->cfgfs_subsys);
}

static struct cscfg_info *cscfg_search_group(struct config_group *grp,
					     unsigned long hash)
{
	struct config_item *item;

	pr_info("%s: hash=%lx\n", __func__, hash);

	list_for_each_entry(item, &grp->cg_children, ci_entry) {
		pr_info("%s: group %s\n", __func__, config_item_name(item));

		/*
		 * If this item is actually a group, recurse into it.
		 *
		 * In configfs, groups are also config_items. A common way
		 * to identify "group-ness" is by the type used for that item.
		 * If you know which items in your subsystem are groups,
		 * you can check that and cast.
		 */
		if (item->ci_type && item->ci_type->ct_item_ops) {
			struct cscfg_info *cfg_info = container_of(to_config_group(item),
						   struct cscfg_info, group);

			pr_info("%s: cfg_info->hash=%x\n", __func__, cfg_info->hash);

			if (cfg_info->hash == hash) {
				pr_info("%s: found cfg_info for %s\n", __func__, config_item_name(item));
				return cfg_info;
			}
		}
	}

	return NULL;
}

struct cscfg_info *cscfg_search_config(struct cscfg_manager *cscfg_mgr,
				       unsigned long hash)
{
	struct configfs_subsystem *subsys = &cscfg_mgr->cfgfs_subsys;
	struct cscfg_info *cfg_info;

	mutex_lock(&subsys->su_mutex);
	printk("%s\n", config_item_name(&subsys->su_group.cg_item));
	cfg_info = cscfg_search_group(&subsys->su_group, hash);
	mutex_unlock(&subsys->su_mutex);

	return cfg_info;
}

struct cscfg_reg *cscfg_get_reg_list(struct cscfg_info *cfg_info, int type)
{
	struct config_group *grp = &cfg_info->group;
	struct config_item *item;
	struct cscfg_dynamic_cfg *cfg;

	list_for_each_entry(item, &grp->cg_children, ci_entry) {
		pr_info("%s: group %s\n", __func__, config_item_name(item));

		cfg = container_of(to_config_group(item),
				   struct cscfg_dynamic_cfg, group);

		if (cfg->type == type) {
			pr_info("%s: found cfg for type %x\n", __func__, type);
			return &cfg->reg;
		}
	}

	return NULL;
}
EXPORT_SYMBOL_GPL(cscfg_get_reg_list);

