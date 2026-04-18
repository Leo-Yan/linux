// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2020 Linaro Limited, All rights reserved.
 * Author: Mike Leach <mike.leach@linaro.org>
 */

#include <linux/platform_device.h>
#include <linux/slab.h>

#include "coresight-config.h"
#include "coresight-etm-perf.h"
#include "coresight-syscfg.h"
#include "coresight-syscfg-configfs.h"

static DEFINE_MUTEX(cscfg_mutex);

static struct cscfg_manager *cscfg_mgr;

struct cscfg_info *cscfg_get_config(unsigned long cfg_hash)
{
	struct cscfg_info *cfg_info;

	mutex_lock(&cscfg_mutex);
	cfg_info = cscfg_search_config(cscfg_mgr, cfg_hash);
	mutex_unlock(&cscfg_mutex);

	return cfg_info;
}
EXPORT_SYMBOL_GPL(cscfg_get_config);

#if 0
/*
 * load config into the system - validate used features exist then add to
 * config list.
 */
static int cscfg_load_config(struct cscfg_config_desc *config_desc)
{
	int err;

	/* add config to perf fs to allow selection */
	err = etm_perf_add_symlink_cscfg(cscfg_device(), config_desc);
	if (err)
		return err;

	return 0;
}
#endif

static int cscfg_register_feats(struct cscfg_feat_desc **feat_descs)
{
	struct cscfg_feat_desc *desc;
	int i, j, err;

	if (!feat_descs)
		return -EINVAL;

	for (i = 0; (desc = feat_descs[i]) != NULL; i++) {
		err = cscfg_feat_create_group(desc);
		if (err)
			goto failed;
	}

	return 0;

failed:
	for (j = 0; j < i; j++)
		cscfg_feat_delete_group(feat_descs[j]);

	return err;
}

static void cscfg_unregister_feats(struct cscfg_feat_desc **feat_descs)
{
	struct cscfg_feat_desc *desc;
	int i;

	for (i = 0; (desc = feat_descs[i]) != NULL; i++)
		cscfg_feat_delete_group(desc);
}

static int cscfg_register_configs(struct cscfg_config_desc **config_descs)
{
	struct cscfg_config_desc *desc;
	int i, err;

	if (!config_descs)
		return -EINVAL;

	for (i = 0; (desc = config_descs[i]) != NULL; i++) {
		err = cscfg_preload_cfg_create_group(desc);
		if (err)
			goto failed;
	}

	return 0;

failed:
	/* TODO: cleanup configs */
	//for (j = 0; j < i; j++)
	//	cscfg_configfs_del_config(config_descs[j]);

	return err;
}

#if 0
static int cscfg_unregister_configs(struct cscfg_config_desc **config_descs)
{
	struct cscfg_config_desc *desc;
	int i;

	for (i = 0; (desc = config_descs[i]) != NULL; i++)
		cscfg_configfs_del_config(desc);
}
#endif

static int cscfg_fs_register_cfgs_feats(struct cscfg_config_desc **config_descs,
					struct cscfg_feat_desc **feat_descs)
{
	int err;

	err = cscfg_register_feats(feat_descs);
	if (err)
		return err;

	err = cscfg_register_configs(config_descs);
	if (err) {
		cscfg_unregister_feats(feat_descs);
		return err;
	}

	return 0;
}

/**
 * cscfg_load_config_sets - API function to load feature and config sets.
 *
 * Take a 0 terminated array of feature descriptors and/or configuration
 * descriptors and load into the system.
 * Features are loaded first to ensure configuration dependencies can be met.
 *
 * To facilitate dynamic loading and unloading, features and configurations
 * have a "load_owner", to allow later unload by the same owner. An owner may
 * be a loadable module or configuration dynamically created via configfs.
 * As later loaded configurations can use earlier loaded features, creating load
 * dependencies, a load order list is maintained. Unload is strictly in the
 * reverse order to load.
 *
 * @config_descs: 0 terminated array of configuration descriptors.
 * @feat_descs:   0 terminated array of feature descriptors.
 */
int cscfg_load_config_sets(struct cscfg_config_desc **config_descs,
			   struct cscfg_feat_desc **feat_descs)
{
	int err = 0;

	guard(mutex)(&cscfg_mutex);

	/* create the configfs elements */
	err = cscfg_fs_register_cfgs_feats(config_descs, feat_descs);

	return err;
}
EXPORT_SYMBOL_GPL(cscfg_load_config_sets);

struct device *cscfg_device(void)
{
	return cscfg_mgr ? &cscfg_mgr->dev : NULL;
}

/* Must have a release function or the kernel will complain on module unload */
static void cscfg_dev_release(struct device *dev)
{
	guard(mutex)(&cscfg_mutex);

	kfree(cscfg_mgr);
	cscfg_mgr = NULL;
}

/* a device is needed to "own" some kernel elements such as sysfs entries.  */
static int cscfg_create_device(void)
{
	struct device *dev;
	int ret;

	cscfg_mgr = kzalloc_obj(struct cscfg_manager);
	if (!cscfg_mgr)
		return -ENOMEM;

	guard(mutex)(&cscfg_mutex);

	/* setup the device */
	dev = cscfg_device();
	dev->release = cscfg_dev_release;
	dev->init_name = "cs_system_cfg";

	ret = device_register(dev);
	if (ret)
		put_device(dev);

	return ret;
}

/*
 * Loading and unloading is generally on user discretion.
 * If exiting due to coresight module unload, we need to unload any configurations that remain,
 * before we unregister the configfs intrastructure.
 *
 * Do this by walking the load_owner list and taking appropriate action, depending on the load
 * owner type.
 */
static void cscfg_clear_device(void)
{
	/* TODO */
	return;
}

/* Initialise system config management API device  */
int __init cscfg_init(void)
{
	int err = 0;

	/* create the device and init cscfg_mgr */
	err = cscfg_create_device();
	if (err)
		return err;

	/* initialise configfs subsystem */
	err = cscfg_configfs_init(cscfg_mgr);
	if (err)
		goto exit_err;

	/* preload built-in configurations */
	err = cscfg_preload(THIS_MODULE);
	if (err)
		goto exit_err;

	dev_info(cscfg_device(), "CoreSight Configuration manager initialised");
	return 0;

exit_err:
	cscfg_clear_device();
	return err;
}

void cscfg_exit(void)
{
	cscfg_clear_device();
}
