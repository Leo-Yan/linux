// SPDX-License-Identifier: GPL-2.0
/*
 * dlfilter-nonempty-brstack.c: Filter out samples with no branch stack
 * Copyright (c) 2026, Meta Platforms, Inc.
 */
#include <stddef.h>

#include <perf/perf_dlfilter.h>

int filter_event(void *data, const struct perf_dlfilter_sample *sample, void *ctx)
{
	/* Return 1 to filter out the sample, 0 to keep it */
	return !sample->brstack_nr;
}

const char *filter_description(const char **long_description)
{
	static char *long_desc =
		"Instruction trace decoders can add branch history to existing "
		"samples, but samples that were recorded while no trace was "
		"being collected get an empty branch stack. Filter those out so "
		"that only samples carrying branch history remain.";

	*long_description = long_desc;
	return "Keep only samples with a non-empty branch stack";
}
