// SPDX-License-Identifier: GPL-2.0

#include <linux/acpi.h>
#include <linux/acpi_iort.h>
#include <linux/bitfield.h>
#include <linux/bitops.h>
#include <linux/cpuhotplug.h>
#include <linux/cpumask.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/msi.h>
#include <linux/perf_event.h>
#include <linux/platform_device.h>
#include <linux/smp.h>
#include <linux/sysfs.h>
#include <linux/types.h>

#define SMMU_PMEVCNTR(n)		(0 + (n) * 4)
#define SMMU_PMEVTYPER(n)		(0x400 + (n) * 4)
#define SMMU_PMCGCR(n)			(0x800 + (n) * 4)
#define SMMU_PMCGCR_CGNC		GENMASK(27, 24)
#define SMMU_PMCGCR_SIDG		GENMASK(22, 16)
#define SMMU_PMCGCR_EN			BIT(11)
#define SMMU_PMCGCR_TCEFCFG_MATCH	BIT(8)
#define SMMU_PMCGSMR(n)			(0xA00 + (n) * 4)
#define SMMU_PMCNTENSET(n)		(0xC00 + (n) * 4)
#define SMMU_PMCNTENCLR(n)		(0xC20 + (n) * 4)
#define SMMU_PMINTENSET(n)		(0xC40 + (n) * 4)
#define SMMU_PMINTENCLR(n)		(0xC60 + (n) * 4)
#define SMMU_PMOVSCLR(n)		(0xC80 + (n) * 4)
#define SMMU_PMOVSSET(n)		(0xCC0 + (n) * 4)
#define SMMU_PMCFGR			0xE00
#define SMMU_PMCFGR_NCG			GENMASK(31, 24)
#define SMMU_PMCFGR_SIZE		GENMASK(13, 8)
#define SMMU_PMCFGR_NCTR		GENMASK(7, 0)
#define SMMU_PMCR			0xE04
#define SMMU_PMCR_EV_CNT_RST		BIT(1)
#define SMMU_PMCR_ENABLE		BIT(0)
#define SMMU_PMCEID0			0xE20
#define SMMU_PMCEID1			0xE24

#define SMMU_PMU_MAX_COUNTERS		256
#define SMMU_PMU_MAX_GROUPS		256
#define SMMU_PMU_ARCH_MAX_EVENTS	64

static int cpuhp_state_num;

struct smmu_pmu_group {
	unsigned int idx;
	unsigned int counter_start;
	unsigned int num_counters;
	unsigned int sidg;
	unsigned int stream;

	atomic_t ref;
};

struct smmu_pmu {
	struct hlist_node node;
	struct perf_event *events[SMMU_PMU_MAX_COUNTERS];
	DECLARE_BITMAP(supported_events, SMMU_PMU_ARCH_MAX_EVENTS);
	DECLARE_BITMAP(used_counters, SMMU_PMU_MAX_COUNTERS);
	unsigned int num_counters;
	unsigned int num_groups;
	struct smmu_pmu_group groups[SMMU_PMU_MAX_GROUPS];

	unsigned int irq;
	unsigned int on_cpu;
	struct pmu pmu;
	struct device *dev;
	void __iomem *reg_base;
	u32 options;
};

#define to_smmu_pmu(p) (container_of(p, struct smmu_pmu, pmu))

#define SMMU_PMU_EVENT_ATTR_EXTRACTOR(_name, _config, _start, _end)        \
	static inline u32 get_##_name(struct perf_event *event)            \
	{                                                                  \
		return FIELD_GET(GENMASK_ULL(_end, _start),                \
				 event->attr._config);                     \
	}                                                                  \

SMMU_PMU_EVENT_ATTR_EXTRACTOR(event, config, 0, 15);
SMMU_PMU_EVENT_ATTR_EXTRACTOR(filter_sid_group, config1, 0, 6);
SMMU_PMU_EVENT_ATTR_EXTRACTOR(filter_stream, config1, 32, 63);

static inline void smmu_pmu_enable(struct pmu *pmu)
{
	struct smmu_pmu *smmu_pmu = to_smmu_pmu(pmu);

	//writel(SMMU_PMCR_EV_CNT_RST | SMMU_PMCR_ENABLE,
	writel(SMMU_PMCR_ENABLE, smmu_pmu->reg_base + SMMU_PMCR);

	dev_dbg(smmu_pmu->dev, "%s: PMCR=0x%x\n", __func__,
		readl(smmu_pmu->reg_base + SMMU_PMCR));
}

static inline void smmu_pmu_disable(struct pmu *pmu)
{
	struct smmu_pmu *smmu_pmu = to_smmu_pmu(pmu);

	writel(0, smmu_pmu->reg_base + SMMU_PMCR);

	dev_dbg(smmu_pmu->dev, "%s: PMCR=0x%x\n", __func__,
		readl(smmu_pmu->reg_base + SMMU_PMCR));
}

static inline void smmu_pmu_counter_set_value(struct smmu_pmu *smmu_pmu,
					      u32 n, u32 value)
{
	dev_dbg(smmu_pmu->dev, "%s: SMMU_PMEVCNTR(%d)=0x%x\n",
		__func__, n, value);
	writel(value, smmu_pmu->reg_base + SMMU_PMEVCNTR(n));
}

static inline u32 smmu_pmu_counter_get_value(struct smmu_pmu *smmu_pmu, u32 n)
{
	u32 value;

	value = readl(smmu_pmu->reg_base + SMMU_PMEVCNTR(n));
	dev_dbg(smmu_pmu->dev, "%s: SMMU_PMEVCNTR(%d)=0x%x\n",
		__func__, n, value);
	return value;
}

static inline void smmu_pmu_counter_enable(struct smmu_pmu *smmu_pmu, u32 idx)
{
	int n, j;

	n = idx / 32;
	j = idx % 32;
	dev_dbg(smmu_pmu->dev, "%s: SMMU_PMCNTENSET(%d)=0x%lx\n",
		__func__, n, BIT(j));
	writel(BIT(j), smmu_pmu->reg_base + SMMU_PMCNTENSET(n));
}

static inline void smmu_pmu_counter_disable(struct smmu_pmu *smmu_pmu, u32 idx)
{
	int n, j;

	n = idx / 32;
	j = idx % 32;
	dev_dbg(smmu_pmu->dev, "%s: SMMU_PMCNTENCLR(%d)=0x%lx\n",
		__func__, n, BIT(j));
	writel(BIT(j), smmu_pmu->reg_base + SMMU_PMCNTENCLR(n));
}

static inline void smmu_pmu_interrupt_enable(struct smmu_pmu *smmu_pmu, u32 idx)
{
	int n, j;

	n = idx / 32;
	j = idx % 32;
	dev_dbg(smmu_pmu->dev, "%s: SMMU_PMINTENSET(%d)=0x%lx\n",
		__func__, n, BIT(j));
	writel(BIT(j), smmu_pmu->reg_base + SMMU_PMINTENSET(n));
}

static inline void smmu_pmu_interrupt_disable(struct smmu_pmu *smmu_pmu,
					      u32 idx)
{
	int n, j;

	n = idx / 32;
	j = idx % 32;
	dev_dbg(smmu_pmu->dev, "%s: SMMU_PMINTENCLR(%d)=0x%lx\n",
		__func__, n, BIT(j));
	writel(BIT(j), smmu_pmu->reg_base + SMMU_PMINTENCLR(n));
}

static inline void smmu_pmu_set_evtyper(struct smmu_pmu *smmu_pmu, u32 idx,
					u32 val)
{
	dev_dbg(smmu_pmu->dev, "%s: SMMU_PMEVTYPER(%d)=0x%x\n",
		__func__, idx, val);
	writel(val, smmu_pmu->reg_base + SMMU_PMEVTYPER(idx));
}

static inline void smmu_pmu_set_group(struct smmu_pmu *smmu_pmu, u32 grp,
				      u32 val)
{
	dev_dbg(smmu_pmu->dev, "%s: SMMU_PMCGCR(%d)=0x%x\n",
		__func__, grp, val);
	writel(val, smmu_pmu->reg_base + SMMU_PMCGCR(grp));
}

static inline void smmu_pmu_set_smr(struct smmu_pmu *smmu_pmu, u32 grp, u32 val)
{
	dev_dbg(smmu_pmu->dev, "%s: SMMU_PMCGSMR(%d)=0x%x\n",
		__func__, grp, val);
	writel(val, smmu_pmu->reg_base + SMMU_PMCGSMR(grp));
}

static void smmu_pmu_event_update(struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;
	struct smmu_pmu *smmu_pmu = to_smmu_pmu(event->pmu);
	u32 delta, prev, now;
	u32 idx = hwc->idx;

	do {
		prev = local64_read(&hwc->prev_count);
		now = smmu_pmu_counter_get_value(smmu_pmu, idx);
	} while (local64_cmpxchg(&hwc->prev_count, prev, now) != prev);

	/* handle overflow. */
	delta = now - prev;
	delta &= 0xFFFFFFFF;

	dev_dbg(smmu_pmu->dev, "%s: prev=0x%x now=0x%x delta=0x%x\n",
		__func__, prev, now, delta);

	local64_add(delta, &event->count);

	dev_dbg(smmu_pmu->dev, "%s: event count=0x%lx\n",
		__func__, local64_read(&event->count));
}

static void smmu_pmu_set_period(struct smmu_pmu *smmu_pmu,
				struct hw_perf_event *hwc)
{
	u32 idx = hwc->idx;
	u64 new;

	/*
	 * We limit the max period to half the max counter value
	 * of the counter size, so that even in the case of extreme
	 * interrupt latency the counter will (hopefully) not wrap
	 * past its initial value.
	 */
	new = 0xFFFFFFFF >> 1;
	smmu_pmu_counter_set_value(smmu_pmu, idx, new);

	local64_set(&hwc->prev_count, new);

	dev_dbg(smmu_pmu->dev, "%s: hwc->prev_count=0x%lx event counter=%xlx\n",
		__func__, local64_read(&hwc->prev_count),
		smmu_pmu_counter_get_value(smmu_pmu, idx));
}

static struct smmu_pmu_group *
smmu_pmu_get_counter_group(struct smmu_pmu *smmu_pmu,
			   struct perf_event *event)
{
	unsigned int sidg;
	struct smmu_pmu_group *group;
	int i;

	sidg = get_filter_sid_group(event);
	for (i = 0; i < smmu_pmu->num_groups; i++) {
		group = &smmu_pmu->groups[i];
		if (sidg == group->sidg)
			return group;
	}

	dev_err(smmu_pmu->dev, "Fail to find group for sidg %d\n", sidg);
	return NULL;
}

static int smmu_pmu_get_event_idx(struct smmu_pmu *smmu_pmu,
				  struct perf_event *event)
{
	int idx;
	struct smmu_pmu_group *group;

	group = smmu_pmu_get_counter_group(smmu_pmu, event);
	if (!group)
		return -EINVAL;

	idx = find_next_zero_bit(smmu_pmu->used_counters,
				 group->counter_start + group->num_counters,
				 group->counter_start);
	if (idx == group->counter_start + group->num_counters)
		/* The counters are all in use. */
		return -EAGAIN;

	set_bit(idx, smmu_pmu->used_counters);

	group->stream = get_filter_stream(event);
	return idx;
}

static bool smmu_pmu_events_compatible(struct perf_event *curr,
				       struct perf_event *new)
{
	if (new->pmu != curr->pmu)
		return false;

	return true;
}

/*
 * Implementation of abstract pmu functionality required by
 * the core perf events code.
 */

static int smmu_pmu_event_init(struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;
	struct smmu_pmu *smmu_pmu = to_smmu_pmu(event->pmu);
	struct device *dev = smmu_pmu->dev;
	struct perf_event *sibling;
	int group_num_events = 1;
	u16 event_id;

	if (event->attr.type != event->pmu->type)
		return -ENOENT;

	if (hwc->sample_period) {
		dev_dbg(dev, "Sampling not supported\n");
		return -EOPNOTSUPP;
	}

	if (event->cpu < 0) {
		dev_dbg(dev, "Per-task mode not supported\n");
		return -EOPNOTSUPP;
	}

	/* Verify specified event is supported on this PMU */
	event_id = get_event(event);
	if (event_id < SMMU_PMU_ARCH_MAX_EVENTS &&
	    (!test_bit(event_id, smmu_pmu->supported_events))) {
		dev_dbg(dev, "Invalid event %d for this PMU\n", event_id);
		return -EINVAL;
	}

	dev_dbg(smmu_pmu->dev, "%s: event_id=0x%x\n", __func__, event_id);

	/* Don't allow groups with mixed PMUs, except for s/w events */
	if (!is_software_event(event->group_leader)) {
		if (!smmu_pmu_events_compatible(event->group_leader, event))
			return -EINVAL;

		if (++group_num_events > smmu_pmu->num_counters)
			return -EINVAL;
	}

	for_each_sibling_event(sibling, event->group_leader) {
		if (is_software_event(sibling))
			continue;

		if (!smmu_pmu_events_compatible(sibling, event))
			return -EINVAL;

		if (++group_num_events > smmu_pmu->num_counters)
			return -EINVAL;
	}

	hwc->idx = -1;

	/*
	 * Ensure all events are on the same cpu so all events are in the
	 * same cpu context, to avoid races on pmu_enable etc.
	 */
	event->cpu = smmu_pmu->on_cpu;
	return 0;
}

static void smmu_pmu_event_start(struct perf_event *event, int flags)
{
	struct smmu_pmu *smmu_pmu = to_smmu_pmu(event->pmu);
	struct hw_perf_event *hwc = &event->hw;
	int idx = hwc->idx;
	struct smmu_pmu_group *group;
	u32 val;

	hwc->state = 0;

	dev_dbg(smmu_pmu->dev, "%s: event idx=%d\n", __func__, idx);
	group = smmu_pmu_get_counter_group(smmu_pmu, event);
	if (atomic_inc_return(&group->ref) == 1) {
		val = SMMU_PMCGCR_EN;
		if (group->stream)
			val |= SMMU_PMCGCR_TCEFCFG_MATCH;

		dev_dbg(smmu_pmu->dev, "%s: counter idx=%d group=%d pmcgcr=0x%x stream=0x%x\n",
			__func__, idx, group->idx, val, group->stream);
		smmu_pmu_set_group(smmu_pmu, group->idx, val);
		smmu_pmu_set_smr(smmu_pmu, group->idx, group->stream);
	}

	smmu_pmu_set_period(smmu_pmu, hwc);
	smmu_pmu_counter_enable(smmu_pmu, idx);
}

static void smmu_pmu_event_stop(struct perf_event *event, int flags)
{
	struct smmu_pmu *smmu_pmu = to_smmu_pmu(event->pmu);
	struct hw_perf_event *hwc = &event->hw;
	int idx = hwc->idx;
	struct smmu_pmu_group *group;

	if (hwc->state & PERF_HES_STOPPED)
		return;

	smmu_pmu_counter_disable(smmu_pmu, idx);
	/* As the counter gets updated on _start, ignore PERF_EF_UPDATE */
	smmu_pmu_event_update(event);

	group = smmu_pmu_get_counter_group(smmu_pmu, event);
	if (!atomic_dec_return(&group->ref)) {
		smmu_pmu_set_group(smmu_pmu, group->idx, 0);
		smmu_pmu_set_smr(smmu_pmu, group->idx, 0);
	}

	hwc->state |= PERF_HES_STOPPED | PERF_HES_UPTODATE;
}

static int smmu_pmu_event_add(struct perf_event *event, int flags)
{
	struct hw_perf_event *hwc = &event->hw;
	int idx;
	struct smmu_pmu *smmu_pmu = to_smmu_pmu(event->pmu);

	idx = smmu_pmu_get_event_idx(smmu_pmu, event);
	if (idx < 0)
		return idx;

	hwc->idx = idx;
	hwc->state = PERF_HES_STOPPED | PERF_HES_UPTODATE;
	smmu_pmu->events[idx] = event;
	local64_set(&hwc->prev_count, 0);

	dev_dbg(smmu_pmu->dev, "%s: event idx=%d\n", __func__, hwc->idx);

	smmu_pmu_set_evtyper(smmu_pmu, idx, get_event(event));
	smmu_pmu_interrupt_enable(smmu_pmu, idx);

	if (flags & PERF_EF_START)
		smmu_pmu_event_start(event, flags);

	/* Propagate changes to the userspace mapping. */
	perf_event_update_userpage(event);
	return 0;
}

static void smmu_pmu_event_del(struct perf_event *event, int flags)
{
	struct hw_perf_event *hwc = &event->hw;
	struct smmu_pmu *smmu_pmu = to_smmu_pmu(event->pmu);
	int idx = hwc->idx;

	smmu_pmu_event_stop(event, flags | PERF_EF_UPDATE);
	smmu_pmu_interrupt_disable(smmu_pmu, idx);
	smmu_pmu->events[idx] = NULL;
	clear_bit(idx, smmu_pmu->used_counters);

	perf_event_update_userpage(event);
}

static void smmu_pmu_event_read(struct perf_event *event)
{
	smmu_pmu_event_update(event);
}

/* cpumask */
static ssize_t smmu_pmu_cpumask_show(struct device *dev,
				     struct device_attribute *attr,
				     char *buf)
{
	struct smmu_pmu *smmu_pmu = to_smmu_pmu(dev_get_drvdata(dev));

	return cpumap_print_to_pagebuf(true, buf, cpumask_of(smmu_pmu->on_cpu));
}

static struct device_attribute smmu_pmu_cpumask_attr =
		__ATTR(cpumask, 0444, smmu_pmu_cpumask_show, NULL);

static struct attribute *smmu_pmu_cpumask_attrs[] = {
	&smmu_pmu_cpumask_attr.attr,
	NULL
};

static const struct attribute_group smmu_pmu_cpumask_group = {
	.attrs = smmu_pmu_cpumask_attrs,
};

/* Events */
static ssize_t smmu_pmu_event_show(struct device *dev,
				   struct device_attribute *attr, char *page)
{
	struct perf_pmu_events_attr *pmu_attr;

	pmu_attr = container_of(attr, struct perf_pmu_events_attr, attr);

	return sysfs_emit(page, "event=0x%02llx\n", pmu_attr->id);
}

#define SMMU_EVENT_ATTR(name, config)			\
	PMU_EVENT_ATTR_ID(name, smmu_pmu_event_show, config)

static struct attribute *smmu_pmu_events[] = {
	SMMU_EVENT_ATTR(cycles, 0),
	SMMU_EVENT_ATTR(cycles_div64, 1),
	SMMU_EVENT_ATTR(tlb_alloc, 8),
	SMMU_EVENT_ATTR(tlb_alloc_rd, 9),
	SMMU_EVENT_ATTR(tlb_alloc_wt, 10),
	SMMU_EVENT_ATTR(access, 16),
	SMMU_EVENT_ATTR(access_rd, 17),
	SMMU_EVENT_ATTR(access_wt, 18),
	NULL
};

static umode_t smmu_pmu_event_is_visible(struct kobject *kobj,
					 struct attribute *attr, int unused)
{
	struct device *dev = kobj_to_dev(kobj);
	struct smmu_pmu *smmu_pmu = to_smmu_pmu(dev_get_drvdata(dev));
	struct perf_pmu_events_attr *pmu_attr;

	pmu_attr = container_of(attr, struct perf_pmu_events_attr, attr.attr);

	if (test_bit(pmu_attr->id, smmu_pmu->supported_events))
		return attr->mode;

	return 0;
}

static const struct attribute_group smmu_pmu_events_group = {
	.name = "events",
	.attrs = smmu_pmu_events,
	.is_visible = smmu_pmu_event_is_visible,
};

/* Formats */
PMU_FORMAT_ATTR(event,		   "config:0-18");
PMU_FORMAT_ATTR(filter_sid_group,  "config1:0-6");
PMU_FORMAT_ATTR(filter_stream,	   "config1:32-63");

static struct attribute *smmu_pmu_formats[] = {
	&format_attr_event.attr,
	&format_attr_filter_sid_group.attr,
	&format_attr_filter_stream.attr,
	NULL
};

static const struct attribute_group smmu_pmu_format_group = {
	.name = "format",
	.attrs = smmu_pmu_formats,
};

static const struct attribute_group *smmu_pmu_attr_grps[] = {
	&smmu_pmu_cpumask_group,
	&smmu_pmu_events_group,
	&smmu_pmu_format_group,
	NULL
};

/*
 * Generic device handlers
 */

static int smmu_pmu_offline_cpu(unsigned int cpu, struct hlist_node *node)
{
	struct smmu_pmu *smmu_pmu;
	unsigned int target;

	smmu_pmu = hlist_entry_safe(node, struct smmu_pmu, node);
	if (cpu != smmu_pmu->on_cpu)
		return 0;

	target = cpumask_any_but(cpu_online_mask, cpu);
	if (target >= nr_cpu_ids)
		return 0;

	perf_pmu_migrate_context(&smmu_pmu->pmu, cpu, target);
	smmu_pmu->on_cpu = target;
	WARN_ON(irq_set_affinity(smmu_pmu->irq, cpumask_of(target)));

	return 0;
}

static irqreturn_t smmu_pmu_handle_irq(int irq_num, void *data)
{
	struct smmu_pmu *smmu_pmu = data;
	u32 ovsr;
	unsigned int idx;
	int n, i;
	int handled = 0;

	dev_err(smmu_pmu->dev, "%s: enter\n", __func__);

	n = DIV_ROUND_UP(smmu_pmu->num_counters, 32);
	for (i = 0; i < n; i++) {
		ovsr = readl(smmu_pmu->reg_base + SMMU_PMOVSSET(i));
		if (!ovsr)
			continue;

		dev_err(smmu_pmu->dev, "%s: ovsr=0x%x\n", __func__, ovsr);

		writel(ovsr, smmu_pmu->reg_base + SMMU_PMOVSCLR(i));

		for_each_set_bit(idx, (unsigned long *)&ovsr, 32) {
			struct perf_event *event = smmu_pmu->events[i * 32 + idx];
			struct hw_perf_event *hwc;


			if (WARN_ON_ONCE(!event))
				continue;

			smmu_pmu_event_update(event);
			hwc = &event->hw;

			dev_err(smmu_pmu->dev, "%s: event idx=%d hwc->idx=%d\n",
				__func__, idx, hwc->idx);

			smmu_pmu_set_period(smmu_pmu, hwc);
		}

		handled = 1;
	}

	if (!handled)
		return IRQ_NONE;

	return IRQ_HANDLED;
}

static void smmu_pmu_reset(struct smmu_pmu *smmu_pmu)
{
	int n, j, i;

	smmu_pmu_disable(&smmu_pmu->pmu);

	/* Disable counter and interrupt for all event counters */
	n = DIV_ROUND_UP(smmu_pmu->num_counters, 32);
	j = smmu_pmu->num_counters % 32;

	for (i = 0; i < n; i++) {
		u32 counter_mask;

		if (i == n - 1)
			counter_mask = GENMASK_ULL(j - 1, 0);
		else
			counter_mask = GENMASK_ULL(31, 0);

		writel_relaxed(counter_mask,
			       smmu_pmu->reg_base + SMMU_PMCNTENCLR(i));
		writel_relaxed(counter_mask,
			       smmu_pmu->reg_base + SMMU_PMINTENCLR(i));
		writel_relaxed(counter_mask,
			       smmu_pmu->reg_base + SMMU_PMOVSCLR(i));
	}
}

static int smmu_pmu_init_counter_groups(struct smmu_pmu *smmu_pmu)
{
	int i;
	int start_idx = 0;
	struct smmu_pmu_group *group;
	u32 cfgr, cgcr;

	cfgr = readl_relaxed(smmu_pmu->reg_base + SMMU_PMCFGR);
	smmu_pmu->num_groups = FIELD_GET(SMMU_PMCFGR_NCG, cfgr) + 1;

	for (i = 0; i < smmu_pmu->num_groups; i++) {
		cgcr = readl_relaxed(smmu_pmu->reg_base + SMMU_PMCGCR(i));
		group = &smmu_pmu->groups[i];
		group->idx = i;
		group->counter_start = start_idx;
		group->num_counters = FIELD_GET(SMMU_PMCGCR_CGNC, cgcr);
		group->sidg = FIELD_GET(SMMU_PMCGCR_SIDG, cgcr);
		start_idx += group->num_counters;
		atomic_set(&group->ref, 0);
		dev_info(smmu_pmu->dev, "SMMUv2 group%d sidg:%d counter:%d-%d\n",
			 i, group->sidg, group->counter_start,
			 group->counter_start + group->num_counters - 1);
	}

	if (start_idx > SMMU_PMU_MAX_COUNTERS) {
		dev_err(smmu_pmu->dev, "SMMUv2 counters are overflow %d\n",
			start_idx);
		return -EINVAL;
	}

	return 0;
}

static void __iomem *arm_smmu_ioremap(struct device *dev, resource_size_t start,
				      resource_size_t size)
{
	struct resource res = DEFINE_RES_MEM(start, size);

	return devm_ioremap_resource(dev, &res);
}

static int smmu_pmu_probe(struct platform_device *pdev)
{
	struct smmu_pmu *smmu_pmu;
	struct resource *res;
	u32 cfgr, reg_size, ceid[2];
	int err;
	char *name;
	struct device *dev = &pdev->dev;
	struct platform_device *ppdev = to_platform_device(dev->parent);
	u32 pg_shift;
	resource_size_t ioaddr;

	err = device_property_read_u32(dev, "pgshift", &pg_shift);
	if (err) {
		dev_err(dev, "Fail to read out page shift: %d\n", err);
		return err;
	}

	smmu_pmu = devm_kzalloc(dev, sizeof(*smmu_pmu), GFP_KERNEL);
	if (!smmu_pmu)
		return -ENOMEM;

	smmu_pmu->dev = dev;
	platform_set_drvdata(pdev, smmu_pmu);

	smmu_pmu->pmu = (struct pmu) {
		.module		= THIS_MODULE,
		.task_ctx_nr    = perf_invalid_context,
		.pmu_enable	= smmu_pmu_enable,
		.pmu_disable	= smmu_pmu_disable,
		.event_init	= smmu_pmu_event_init,
		.add		= smmu_pmu_event_add,
		.del		= smmu_pmu_event_del,
		.start		= smmu_pmu_event_start,
		.stop		= smmu_pmu_event_stop,
		.read		= smmu_pmu_event_read,
		.attr_groups	= smmu_pmu_attr_grps,
		.capabilities	= PERF_PMU_CAP_NO_EXCLUDE,
	};

	res = platform_get_resource(ppdev, IORESOURCE_MEM, 0);
	ioaddr = res->start + 3 * (1 << pg_shift);
	smmu_pmu->reg_base = arm_smmu_ioremap(dev, ioaddr, (1 << pg_shift));
	if (IS_ERR(smmu_pmu->reg_base))
		return PTR_ERR(smmu_pmu->reg_base);

	ceid[0] = readl_relaxed(smmu_pmu->reg_base + SMMU_PMCEID0);
	ceid[1] = readl_relaxed(smmu_pmu->reg_base + SMMU_PMCEID1);
	bitmap_from_arr32(smmu_pmu->supported_events, ceid,
			  SMMU_PMU_ARCH_MAX_EVENTS);

	cfgr = readl_relaxed(smmu_pmu->reg_base + SMMU_PMCFGR);
	smmu_pmu->num_counters = FIELD_GET(SMMU_PMCFGR_NCTR, cfgr) + 1;

	reg_size = FIELD_GET(SMMU_PMCFGR_SIZE, cfgr);
	/* Always 32-bit event counter */
	if (reg_size != 0x1F) {
		dev_err(dev, "Unexpected counter size 0x%x\n", reg_size);
		return err;
	}

	err = smmu_pmu_init_counter_groups(smmu_pmu);
	if (err) {
		dev_err(dev, "Init counter groups failed, PMU @%pa\n", &res->start);
		return err;
	}

	smmu_pmu_reset(smmu_pmu);

	smmu_pmu->irq = platform_get_irq(ppdev, 0);
	if (smmu_pmu->irq < 0)
		return smmu_pmu->irq;

	err = devm_request_irq(smmu_pmu->dev, smmu_pmu->irq, smmu_pmu_handle_irq,
			       IRQF_NOBALANCING | IRQF_SHARED | IRQF_NO_THREAD,
			       "smmuv2-pmu", smmu_pmu);
	if (err) {
		dev_err(dev, "Setup irq failed, PMU @%pa\n", &res->start);
		return err;
	}

	name = devm_kasprintf(&pdev->dev, GFP_KERNEL, "smmuv2_pmu_%llx",
			      (res->start) >> PAGE_SHIFT);
	if (!name) {
		dev_err(dev, "Create name failed, PMU @%pa\n", &res->start);
		return -EINVAL;
	}

	/* Pick one CPU to be the preferred one to use */
	smmu_pmu->on_cpu = raw_smp_processor_id();
	WARN_ON(irq_set_affinity(smmu_pmu->irq, cpumask_of(smmu_pmu->on_cpu)));

	err = cpuhp_state_add_instance_nocalls(cpuhp_state_num,
					       &smmu_pmu->node);
	if (err) {
		dev_err(dev, "Error %d registering hotplug, PMU @%pa\n",
			err, &res->start);
		return err;
	}

	err = perf_pmu_register(&smmu_pmu->pmu, name, -1);
	if (err) {
		dev_err(dev, "Error %d registering PMU @%pa\n",
			err, &res->start);
		goto out_unregister;
	}

	dev_info(dev, "Registered PMU @ %pa using %d counters %d groups\n",
		 &res->start, smmu_pmu->num_counters, smmu_pmu->num_groups);

	return 0;

out_unregister:
	cpuhp_state_remove_instance_nocalls(cpuhp_state_num, &smmu_pmu->node);
	return err;
}

static int smmu_pmu_remove(struct platform_device *pdev)
{
	struct smmu_pmu *smmu_pmu = platform_get_drvdata(pdev);

	perf_pmu_unregister(&smmu_pmu->pmu);
	cpuhp_state_remove_instance_nocalls(cpuhp_state_num, &smmu_pmu->node);
	return 0;
}

static void smmu_pmu_shutdown(struct platform_device *pdev)
{
	struct smmu_pmu *smmu_pmu = platform_get_drvdata(pdev);

	smmu_pmu_disable(&smmu_pmu->pmu);
}

static struct platform_driver smmu_pmu_driver = {
	.driver = {
		.name = "arm-smmu-pmu",
		.suppress_bind_attrs = true,
	},
	.probe = smmu_pmu_probe,
	.remove = smmu_pmu_remove,
	.shutdown = smmu_pmu_shutdown,
};

static int __init smmu_pmu_init(void)
{
	cpuhp_state_num = cpuhp_setup_state_multi(CPUHP_AP_ONLINE_DYN,
						  "perf/arm/pmcg:online",
						  NULL,
						  smmu_pmu_offline_cpu);
	if (cpuhp_state_num < 0)
		return cpuhp_state_num;

	return platform_driver_register(&smmu_pmu_driver);
}
module_init(smmu_pmu_init);

static void __exit smmu_pmu_exit(void)
{
	platform_driver_unregister(&smmu_pmu_driver);
	cpuhp_remove_multi_state(cpuhp_state_num);
}
module_exit(smmu_pmu_exit);

MODULE_DESCRIPTION("PMU driver for ARM SMMUv2 Performance Monitors Extension");
MODULE_LICENSE("GPL v2");
