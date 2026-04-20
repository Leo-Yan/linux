// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2020 Linaro Limited, All rights reserved.
 * Author: Mike Leach <mike.leach@linaro.org>
 */

#include <linux/configfs.h>

#include "coresight-config.h"
#include "coresight-syscfg-configfs.h"

#define attr_item_to_feat(item) \
	container_of(to_config_group(item), struct cscfg_feat, group)

#define attr_item_to_feat_param(item) \
	container_of(to_config_group(item), struct cscfg_feat_param, group)

#define attr_item_to_cfg(item) \
	container_of(to_config_group(item), struct cscfg_cfg, group)

#define attr_item_to_cfg_preset(item) \
	container_of(to_config_group(item), struct cscfg_cfg_preset, group);

static ssize_t cscfg_root_hash_show(struct config_item *item, char *page)
{
	struct cscfg_info *cfg_info = container_of(to_config_group(item),
						   struct cscfg_info, group);

	return sysfs_emit(page, "%lx\n", cfg_info->hash);
}
CONFIGFS_ATTR_RO(cscfg_root_, hash);

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

static const struct config_item_type cscfg_params_group_type = {
	.ct_owner = THIS_MODULE,
};

static struct configfs_attribute *cscfg_feat_param_attrs[] = {
	&cscfg_feat_param_attr_value,
	NULL,
};

static const struct config_item_type cscfg_feat_param_type = {
	.ct_owner = THIS_MODULE,
	.ct_attrs = cscfg_feat_param_attrs,
};

static int cscfg_feat_create_param_group(struct cscfg_feat *feat,
					 struct cscfg_feat_desc *feat_desc)
{
	struct cscfg_feat_param *param;
	int i;

	config_group_init_type_name(&feat->params_group, "params",
				    &cscfg_params_group_type);
	configfs_add_default_group(&feat->params_group, &feat->group);

	param = kcalloc(feat_desc->nr_params, sizeof(*param), GFP_KERNEL);
	if (!param)
		return -ENOMEM;

	for (i = 0; i < feat_desc->nr_params; i++) {
		param[i].idx = i;
		config_group_init_type_name(&param[i].group,
					    feat_desc->params_desc[i].name,
					    &cscfg_feat_param_type);
		configfs_add_default_group(&param[i].group, &feat->params_group);
	}

	return 0;
}

static struct config_group *
cscfg_feat_alloc_group(struct cscfg_feat_desc *feat_desc)
{
	struct cscfg_feat *feat;
	int ret;

	feat = kzalloc(sizeof(*feat), GFP_KERNEL);
	if (!feat)
		return ERR_PTR(-ENOMEM);

	feat->feat_desc = feat_desc;
	config_group_init_type_name(&feat->group, feat_desc->name,
				    &cscfg_feat_type);

	ret = cscfg_feat_create_param_group(feat, feat_desc);
	if (ret) {
		kfree(feat);
		return ERR_PTR(ret);
	}

	return &feat->group;
}

int cscfg_feat_create_group(struct cscfg_feat_desc *feat_desc)
{
	struct config_group *new_group;
	int err;

	new_group = cscfg_feat_alloc_group(feat_desc);
	if (IS_ERR(new_group))
		return PTR_ERR(new_group);
	err =  configfs_register_group(&cscfg_feats_grp, new_group);
	if (!err)
		feat_desc->fs_group = new_group;
	return err;
}

void cscfg_feat_delete_group(struct cscfg_feat_desc *feat_desc)
{
	/* TODO */
}

static ssize_t cscfg_preload_cfg_description_show(struct config_item *item, char *page)
{
	struct cscfg_cfg *cfg = attr_item_to_cfg(item);

	return scnprintf(page, PAGE_SIZE, "%s", cfg->config_desc->description);
}
CONFIGFS_ATTR_RO(cscfg_preload_cfg_, description);

static ssize_t cscfg_preload_cfg_feature_refs_show(struct config_item *item, char *page)
{
	struct cscfg_cfg *cfg = attr_item_to_cfg(item);

	return scnprintf(page, PAGE_SIZE, "%s\n", cfg->desc->name);
}
CONFIGFS_ATTR_RO(cscfg_preload_cfg_, feature_refs);

static ssize_t cscfg_preload_cfg_enable_show(struct config_item *item, char *page)
{
	struct cscfg_cfg *cfg = container_of(to_config_group(item),
						     struct cscfg_cfg, group);

	return scnprintf(page, PAGE_SIZE, "%d\n", !!cfg->refcnt);
}

static ssize_t cscfg_preload_cfg_enable_store(struct config_item *item,
					const char *page, size_t count)
{
	struct cscfg_cfg *cfg = container_of(to_config_group(item),
						     struct cscfg_cfg, group);
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

	return count;
}
CONFIGFS_ATTR(cscfg_preload_cfg_, enable);

static ssize_t cscfg_preload_cfg_preset_show(struct config_item *item, char *page)
{
	struct cscfg_cfg *cfg = attr_item_to_cfg(item);

	return scnprintf(page, PAGE_SIZE, "%d\n", cfg->current_preset);
}

static ssize_t cscfg_preload_cfg_preset_store(struct config_item *item,
					     const char *page, size_t count)
{
	struct cscfg_cfg *cfg = attr_item_to_cfg(item);
	int preset, ret;

	ret = kstrtoint(page, 0, &preset);
	if (ret < 0)
		return ret;

	if ((preset < 1) || (preset > cfg->nr_presets))
		return -EINVAL;

	/* set new value */
	cfg->current_preset = preset;

	/* TODO: apply preset to cfg's reg list */

	return count;
}
CONFIGFS_ATTR(cscfg_preload_cfg_, preset);

static struct configfs_attribute *cscfg_preload_cfg_attrs[] = {
	&cscfg_preload_cfg_attr_description,
	&cscfg_preload_cfg_attr_feature_refs,
	&cscfg_preload_cfg_attr_enable,
	&cscfg_preload_cfg_attr_preset,
	NULL,
};

static const struct config_item_type cscfg_preload_cfg_type = {
	.ct_owner = THIS_MODULE,
	.ct_attrs = cscfg_preload_cfg_attrs,
};

static ssize_t cscfg_preload_cfg_preset_values_show(struct config_item *item, char *page)
{
	struct cscfg_cfg *cfg = attr_item_to_cfg(item->ci_parent);
	const struct cscfg_config_desc *config_desc = cfg->config_desc;
	struct cscfg_cfg_preset *preset = attr_item_to_cfg_preset(item);
	int i, val_idx, preset_idx;
	ssize_t used = 0;

	if (!config_desc->nr_presets)
		return 0;

	preset_idx = preset->idx;

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
CONFIGFS_ATTR_RO(cscfg_preload_cfg_preset_, values);

static struct configfs_attribute *cscfg_preload_cfg_preset_attrs[] = {
	&cscfg_preload_cfg_preset_attr_values,
	NULL,
};

static const struct config_item_type cscfg_preload_cfg_preset_type = {
	.ct_owner = THIS_MODULE,
	.ct_attrs = cscfg_preload_cfg_preset_attrs,
};

static int cscfg_preload_cfg_add_preset_groups(struct cscfg_cfg *cfg,
					       struct cscfg_config_desc *config_desc)
{
	struct cscfg_cfg_preset *presets;
	char name[CONFIGFS_ITEM_NAME_LEN];
	int i;

	if (!config_desc->nr_presets)
		return 0;

	presets = kcalloc(config_desc->nr_presets, sizeof(*presets), GFP_KERNEL);
	if (!presets)
		return -ENOMEM;

	for (i = 0; i < config_desc->nr_presets; i++) {
		snprintf(name, CONFIGFS_ITEM_NAME_LEN, "preset%d", i + 1);
		presets[i].idx = i;
		config_group_init_type_name(&presets[i].group, name,
					    &cscfg_preload_cfg_preset_type);
		configfs_add_default_group(&presets[i].group, &cfg->legacy_group);
	}

	cfg->nr_presets = config_desc->nr_presets;
	cfg->presets = presets;
	return 0;
}

static struct cscfg_cfg *
cscfg_preload_cfg_alloc_group(struct cscfg_config_desc *config_desc)
{
	struct cscfg_feat *feat;
	struct cscfg_feat_desc *desc = NULL;
	struct cscfg_cfg *cfg;
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
	cfg->config_desc = config_desc;

	cfg->reg.nr_regs = desc->nr_regs;
	cfg->reg.regs = kzalloc(sizeof(*desc->regs_desc) * desc->nr_regs, GFP_KERNEL);
	memcpy(cfg->reg.regs, desc->regs_desc, sizeof(*desc->regs_desc) * desc->nr_regs);

	config_group_init_type_name(&cfg->legacy_group, config_desc->name, &cscfg_preload_cfg_type);

	/* add in a preset<n> dir for each preset */
	err = cscfg_preload_cfg_add_preset_groups(cfg, config_desc);
	if (err) {
		kfree(cfg->reg.regs);
		kfree(cfg);
		return ERR_PTR(err);
	}

	return cfg;
}

static const struct config_item_type cscfg_preload_cfg_grp_type = {
	.ct_owner = THIS_MODULE,
};

static struct config_group cscfg_preload_cfg_grp = {
	.cg_item = {
		.ci_namebuf = "configurations",
		.ci_type = &cscfg_preload_cfg_grp_type,
	},
};

static struct configfs_attribute *cscfg_preload_cfg_xxx_attrs[] = {
	&cscfg_root_attr_hash,
	NULL,
};

static const struct config_item_type cscfg_preload_xxx_type = {
	.ct_attrs	= cscfg_preload_cfg_xxx_attrs,
	.ct_owner	= THIS_MODULE,
};

static struct config_item_type dyn_cfg_xxx_type = {
	.ct_owner = THIS_MODULE,
};

int cscfg_preload_cfg_create_group(struct cscfg_manager *cscfg_mgr,
				   struct cscfg_config_desc *config_desc)
{
	struct configfs_subsystem *subsys = &cscfg_mgr->cfgfs_subsys;
	struct config_group *new_group;
	struct cscfg_info *cfg_info;
	struct cscfg_cfg *cfg;
	char name[CONFIGFS_ITEM_NAME_LEN];
	int err;

	cfg_info = kzalloc(sizeof(*cfg_info), GFP_KERNEL);
	cfg_info->hash = hashlen_hash(hashlen_string(NULL, config_desc->name));
	//printk("%s: cscfg_info=%px hash=%x\n", __func__, cfg_info, cfg_info->hash);

	snprintf(name, CONFIGFS_ITEM_NAME_LEN, "preload-%s", config_desc->name);
	config_group_init_type_name(&cfg_info->group, name, &cscfg_preload_xxx_type);
	configfs_register_group(&subsys->su_group, &cfg_info->group);

	cfg = cscfg_preload_cfg_alloc_group(config_desc);
	if (IS_ERR(cfg))
		return PTR_ERR(new_group);

	config_group_init_type_name(&cfg->group, config_desc->name, &dyn_cfg_xxx_type);
	configfs_register_group(&cfg_info->group, &cfg->group);

	err = configfs_register_group(&cscfg_preload_cfg_grp, &cfg->legacy_group);
	if (!err)
		config_desc->fs_group = new_group;

	return err;
}

void cscfg_preload_cfg_delete_group(struct cscfg_config_desc *config_desc)
{
	if (config_desc->fs_group) {
		configfs_unregister_group(config_desc->fs_group);
		config_desc->fs_group = NULL;
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
//	struct cscfg_cfg *dyn_cfg;
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
	struct cscfg_cfg *cfg;
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
	printk("%s: cscfg_info=%px hash=%lx\n", __func__, cfg_info, cfg_info->hash);

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
	config_group_init(&cscfg_preload_cfg_grp);
	configfs_add_default_group(&cscfg_preload_cfg_grp, &subsys->su_group);

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
		if (strstr(config_item_name(item), "preload-") ||
		    (item->ci_type && item->ci_type->ct_item_ops)) {
			struct cscfg_info *cfg_info = container_of(to_config_group(item),
						   struct cscfg_info, group);

			pr_info("%s: cfg_info->hash=%lx hash=%lx\n", __func__, cfg_info->hash, hash);

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
	struct cscfg_cfg *cfg;

	list_for_each_entry(item, &grp->cg_children, ci_entry) {
		pr_info("%s: group %s\n", __func__, config_item_name(item));

		cfg = container_of(to_config_group(item),
				   struct cscfg_cfg, group);

		if (cfg->type == type) {
			pr_info("%s: found cfg for type %x\n", __func__, type);
			return &cfg->reg;
		}
	}

	return NULL;
}
EXPORT_SYMBOL_GPL(cscfg_get_reg_list);

