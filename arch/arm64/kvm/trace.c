/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bug.h>
#include <linux/cpu_pm.h>
#include <linux/entry-kvm.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/kvm_host.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/mman.h>
#include <linux/sched.h>
#include <linux/kmemleak.h>
#include <linux/kvm.h>
#include <linux/kvm_irqfd.h>
#include <linux/irqbypass.h>
#include <linux/sched/stat.h>
#include <linux/psci.h>
#include <trace/events/kvm.h>
#include <linux/module.h>

//#define CREATE_TRACE_POINTS

#include <linux/version.h>
#include <linux/tracepoint.h>
#include <linux/version.h>

#include "trace_arm.h"

static void kvm_entry_tp(void *data, struct kvm_vcpu *vcpu)
{
	if (trace_kvm_entry_enabled())
		trace_kvm_entry(*vcpu_pc(vcpu));

	if (trace_kvm_entry_v2_enabled())
                trace_kvm_entry_v2(vcpu);
}

static void kvm_exit_tp(void *data, int ret, struct kvm_vcpu *vcpu)
{
	if (trace_kvm_exit_enabled())
		trace_kvm_exit(ret, kvm_vcpu_trap_get_class(vcpu),
			       *vcpu_pc(vcpu));

	if (trace_kvm_exit_v2_enabled())
                trace_kvm_exit_v2(ret, vcpu);
}

static int kvm_tp_init(void)
{
        register_trace_kvm_entry_tp(kvm_entry_tp, NULL);
        register_trace_kvm_exit_tp(kvm_exit_tp, NULL);

        return 0;
}

module_init(kvm_tp_init)
