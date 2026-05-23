// SPDX-License-Identifier: GPL-2.0
#include <linux/compiler.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "../tests.h"

static void do_syscall(void)
{
	syscall(SYS_getpid);
}

static void foo(void)
{
	do_syscall();
}

static int callchain(int argc __maybe_unused, const char **argv __maybe_unused)
{
	foo();

	return 0;
}

DEFINE_WORKLOAD(callchain);
