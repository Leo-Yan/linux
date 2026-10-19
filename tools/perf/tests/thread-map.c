// SPDX-License-Identifier: GPL-2.0
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <linux/kernel.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/prctl.h>
#include "tests.h"
#include "thread_map.h"
#include "debug.h"
#include "event.h"
#include "tool.h"
#include "util/synthetic-events.h"
#include <perf/event.h>
#include <internal/threadmap.h>

struct perf_sample;
struct perf_tool;
struct machine;

#define NAME	(const char *) "perf"
#define NAMEUL	(unsigned long) NAME

static int test__thread_map(struct test_suite *test __maybe_unused, int subtest __maybe_unused)
{
	struct perf_thread_map *map;

	TEST_ASSERT_VAL("failed to set process name",
			!prctl(PR_SET_NAME, NAMEUL, 0, 0, 0));

	/* test map on current pid */
	map = thread_map__new_by_pid(getpid());
	TEST_ASSERT_VAL("failed to alloc map", map);

	thread_map__read_comms(map);

	TEST_ASSERT_VAL("wrong nr", map->nr == 1);
	TEST_ASSERT_VAL("wrong pid",
			perf_thread_map__pid(map, 0) == getpid());
	TEST_ASSERT_VAL("wrong comm",
			perf_thread_map__comm(map, 0) &&
			!strcmp(perf_thread_map__comm(map, 0), NAME));
	TEST_ASSERT_VAL("wrong refcnt",
			refcount_read(&map->refcnt) == 1);
	perf_thread_map__put(map);

	/* test dummy pid */
	map = perf_thread_map__new_dummy();
	TEST_ASSERT_VAL("failed to alloc map", map);

	thread_map__read_comms(map);

	TEST_ASSERT_VAL("wrong nr", map->nr == 1);
	TEST_ASSERT_VAL("wrong pid", perf_thread_map__pid(map, 0) == -1);
	TEST_ASSERT_VAL("wrong comm",
			perf_thread_map__comm(map, 0) &&
			!strcmp(perf_thread_map__comm(map, 0), "dummy"));
	TEST_ASSERT_VAL("wrong refcnt",
			refcount_read(&map->refcnt) == 1);
	perf_thread_map__put(map);
	return 0;
}

static int process_event(const struct perf_tool *tool __maybe_unused,
			 union perf_event *event,
			 struct perf_sample *sample __maybe_unused,
			 struct machine *machine __maybe_unused)
{
	struct perf_record_thread_map *map = &event->thread_map;
	struct perf_thread_map *threads;

	TEST_ASSERT_VAL("wrong nr",   map->nr == 1);
	TEST_ASSERT_VAL("wrong pid",  map->entries[0].pid == (u64) getpid());
	TEST_ASSERT_VAL("wrong comm", !strcmp(map->entries[0].comm, NAME));

	threads = thread_map__new_event(&event->thread_map);
	TEST_ASSERT_VAL("failed to alloc map", threads);

	TEST_ASSERT_VAL("wrong nr", threads->nr == 1);
	TEST_ASSERT_VAL("wrong pid",
			perf_thread_map__pid(threads, 0) == getpid());
	TEST_ASSERT_VAL("wrong comm",
			perf_thread_map__comm(threads, 0) &&
			!strcmp(perf_thread_map__comm(threads, 0), NAME));
	TEST_ASSERT_VAL("wrong refcnt",
			refcount_read(&threads->refcnt) == 1);
	perf_thread_map__put(threads);
	return 0;
}

struct thread_map_synthesize {
	struct perf_tool tool;
	struct perf_thread_map *source;
	struct perf_thread_map *threads;
	int offset;
	int calls;
	int fail_at;
};

static int process_thread_map_chunk(const struct perf_tool *tool,
				    union perf_event *event,
				    struct perf_sample *sample __maybe_unused,
				    struct machine *machine __maybe_unused)
{
	struct thread_map_synthesize *data = container_of(tool, struct thread_map_synthesize, tool);
	struct perf_record_thread_map *map = &event->thread_map;
	const int max_nr = (UINT16_MAX - sizeof(*map)) / sizeof(map->entries[0]);
	int nr = min(data->source->nr - data->offset, max_nr);
	bool more = data->offset + nr < data->source->nr;
	int ret;

	data->calls++;
	TEST_ASSERT_VAL("wrong chunk type", event->header.type == PERF_RECORD_THREAD_MAP);
	TEST_ASSERT_VAL("wrong chunk nr", map->nr == (u64)nr);
	TEST_ASSERT_VAL("wrong chunk size",
			event->header.size == sizeof(*map) + nr * sizeof(map->entries[0]));
	TEST_ASSERT_VAL("wrong continuation marker",
			event->header.misc == (more ? PERF_RECORD_MISC_THREAD_MAP_MORE : 0));

	if (data->calls == data->fail_at)
		return -EIO;

	ret = thread_map__append_event(&data->threads, map);
	if (ret)
		return ret;
	data->offset += nr;
	return 0;
}

static int check_thread_map_chunks(struct thread_map_synthesize *data)
{
	const int max_nr = (UINT16_MAX - sizeof(struct perf_record_thread_map)) /
			   sizeof(struct perf_record_thread_map_entry);
	int ret;

	ret = perf_event__synthesize_thread_map2(&data->tool, data->source,
					       process_thread_map_chunk, NULL);
	if (data->fail_at) {
		TEST_ASSERT_VAL("callback error not propagated", ret == -EIO);
		TEST_ASSERT_VAL("callbacks continued after error", data->calls == data->fail_at);
		return 0;
	}

	TEST_ASSERT_VAL("failed to synthesize chunks", !ret);
	TEST_ASSERT_VAL("wrong chunk count",
			data->calls == max(1, (data->source->nr + max_nr - 1) / max_nr));
	TEST_ASSERT_VAL("incomplete thread map", data->offset == data->source->nr);
	TEST_ASSERT_VAL("failed to assemble thread map", data->threads);
	TEST_ASSERT_VAL("wrong assembled nr", data->threads->nr == data->source->nr);
	TEST_ASSERT_VAL("wrong assembled refcnt", refcount_read(&data->threads->refcnt) == 1);

	for (int i = 0; i < data->source->nr; i++) {
		const char *expected = perf_thread_map__comm(data->source, i);
		const char *comm = perf_thread_map__comm(data->threads, i);

		if (!expected)
			expected = "";
		TEST_ASSERT_VAL("wrong assembled pid",
				perf_thread_map__pid(data->threads, i) ==
				perf_thread_map__pid(data->source, i));
		TEST_ASSERT_VAL("wrong assembled comm", comm && !strncmp(comm, expected, 16));
		TEST_ASSERT_VAL("assembled comm not terminated", strlen(comm) == strnlen(expected, 16));
	}
	return 0;
}

static int test_thread_map_chunks(int nr, int fail_at)
{
	struct thread_map_synthesize data = { .fail_at = fail_at };
	int ret = -ENOMEM;

	data.source = perf_thread_map__new_array(nr, NULL);
	if (!data.source)
		return ret;

	for (int i = 0; i < nr; i++) {
		char comm[32];

		/* Include missing comms and full-width, non-NUL-terminated wire comms. */
		perf_thread_map__set_pid(data.source, i, nr - i);
		if (i % 3 == 0)
			continue;
		if (i % 3 == 1)
			snprintf(comm, sizeof(comm), "thread-%d", i);
		else
			strcpy(comm, "1234567890123456");
		data.source->map[i].comm = strdup(comm);
		if (!data.source->map[i].comm)
			goto out;
	}

	ret = check_thread_map_chunks(&data);
out:
	perf_thread_map__put(data.threads);
	perf_thread_map__put(data.source);
	return ret;
}

static int test__thread_map_synthesize(struct test_suite *test __maybe_unused, int subtest __maybe_unused)
{
	struct perf_thread_map *threads;
	static const int sizes[] = { 0, 1, 2729, 2730, 3000, 5458, 5459 };
	int ret;

	TEST_ASSERT_VAL("failed to set process name",
			!prctl(PR_SET_NAME, NAMEUL, 0, 0, 0));

	/* test map on current pid */
	threads = thread_map__new_by_pid(getpid());
	TEST_ASSERT_VAL("failed to alloc map", threads);

	thread_map__read_comms(threads);

	TEST_ASSERT_VAL("failed to synthesize map",
		!perf_event__synthesize_thread_map2(NULL, threads, process_event, NULL));

	perf_thread_map__put(threads);
	for (unsigned int i = 0; i < ARRAY_SIZE(sizes); i++) {
		ret = test_thread_map_chunks(sizes[i], 0);
		if (ret)
			return ret;
	}
	for (int fail_at = 1; fail_at <= 2; fail_at++) {
		ret = test_thread_map_chunks(5459, fail_at);
		if (ret)
			return ret;
	}

	return 0;
}

static int test__thread_map_remove(struct test_suite *test __maybe_unused, int subtest __maybe_unused)
{
	struct perf_thread_map *threads;
	char *str;

	TEST_ASSERT_VAL("failed to allocate map string",
			asprintf(&str, "%d,%d", getpid(), getppid()) >= 0);

	threads = thread_map__new_str(str, /*tid=*/NULL, /*all_threads=*/false);
	free(str);

	TEST_ASSERT_VAL("failed to allocate thread_map",
			threads);

	if (verbose > 0)
		thread_map__fprintf(threads, stderr);

	TEST_ASSERT_VAL("failed to remove thread",
			!thread_map__remove(threads, 0));

	TEST_ASSERT_VAL("thread_map count != 1", threads->nr == 1);

	if (verbose > 0)
		thread_map__fprintf(threads, stderr);

	TEST_ASSERT_VAL("failed to remove thread",
			!thread_map__remove(threads, 0));

	TEST_ASSERT_VAL("thread_map count != 0", threads->nr == 0);

	if (verbose > 0)
		thread_map__fprintf(threads, stderr);

	TEST_ASSERT_VAL("failed to not remove thread",
			thread_map__remove(threads, 0));

	perf_thread_map__put(threads);
	return 0;
}

DEFINE_SUITE("Thread map", thread_map);
DEFINE_SUITE("Synthesize thread map", thread_map_synthesize);
DEFINE_SUITE("Remove thread map", thread_map_remove);
