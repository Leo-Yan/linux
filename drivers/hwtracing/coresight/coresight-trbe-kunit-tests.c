// SPDX-License-Identifier: GPL-2.0

#include <kunit/test.h>
#include <linux/limits.h>

static void trbe_test_init(struct perf_output_handle *handle,
			   struct trbe_buf *buf,
			   struct trbe_cpudata *cpudata,
			   int nr_pages, u64 trbe_align,
			   u64 trbe_hw_align,
			   bool trig_is_supported)
{
	*handle = (struct perf_output_handle) { };
	*buf = (struct trbe_buf) { };
	*cpudata = (struct trbe_cpudata) {
		.trbe_align = trbe_align,
		.trbe_hw_align = trbe_hw_align,
		.trig_is_supported = trig_is_supported,
	};

	buf->nr_pages = nr_pages;
	buf->cpudata = cpudata;
	handle->rb = (void *)buf;
}

static void __trbe_test_assert_normal_offset(struct kunit *test,
					     struct perf_output_handle *handle,
					     struct trbe_buf *buf,
					     int expected_ret,
					     unsigned long expected_limit,
					     unsigned long expected_count,
					     unsigned int line)
{
	unsigned long limit;
	unsigned long count;
	int ret;

	buf->trbe_limit = 0;
	buf->trbe_count = 0;

	ret = trbe_normal_offset(handle);

	limit = buf->trbe_limit;
	count = buf->trbe_count;

	KUNIT_ASSERT_EQ_MSG(test, ret, expected_ret,
			    "line %u: ret=%d expected=%d",
			    line, ret, expected_ret);
	KUNIT_ASSERT_EQ_MSG(test, limit, expected_limit,
			    "line %u: limit=%#lx expected=%#lx",
			    line, limit, expected_limit);
	KUNIT_ASSERT_EQ_MSG(test, count, expected_count,
			    "line %u: count=%#lx expected=%#lx",
			    line, count, expected_count);
}

#define trbe_test_assert_normal_offset(...) \
	__trbe_test_assert_normal_offset(__VA_ARGS__, __LINE__)

static void test_normal_offset_limit(struct kunit *test)
{
	struct perf_output_handle handle;
	struct trbe_buf buf;
	struct trbe_cpudata cpudata;

	trbe_test_init(&handle, &buf, &cpudata, SZ_1M / PAGE_SIZE,
		       PAGE_SIZE, 1, false);

	/*
	 * ### : Free space, $$$ : Filled space
	 *
	 * |################|################|
	 * `head            `wakeup
	 * `tail            `limit
	 */
	handle.head = 0;
	handle.size = SZ_1M;
	handle.wakeup = SZ_1M / 2;

	trbe_test_assert_normal_offset(test, &handle, &buf, 0, SZ_1M / 2, 0);

	/*
	 * |################|################|
	 * `head            `wakeup         `tail
	 *                  `limit
	 */
	handle.head = 0;
	handle.size = SZ_1M - 1;
	handle.wakeup = SZ_1M / 2;

	trbe_test_assert_normal_offset(test, &handle, &buf, 0, SZ_1M / 2, 0);

	/*
	 * |#################################|
	 * `head                            `tail
	 * `wakeup                         `limit
	 */
	handle.head = 0;
	handle.size = SZ_1M - 1;
	handle.wakeup = 0;

	trbe_test_assert_normal_offset(test, &handle, &buf, -ENOSPC, 0, 0);

	/*
	 * |#################################|
	 * `head                            `tail
	 *                                   `wakeup
	 *                                 `limit
	 */
	handle.head = 0;
	handle.size = SZ_1M - 1;
	handle.wakeup = SZ_1M;

	trbe_test_assert_normal_offset(test, &handle, &buf, 0,
				       SZ_1M - PAGE_SIZE, 0);

	/*
	 * |$$$$$$$$$$$$$$$$|########|#######|
	 *                  `head           `tail
	 *                           `wakeup
	 *                                 `limit
	 */
	handle.head = SZ_1M / 2;
	handle.size = SZ_1M / 2 - 1;
	handle.wakeup = SZ_1M * 3 / 4;

	trbe_test_assert_normal_offset(test, &handle, &buf, 0,
				       SZ_1M * 3 / 4, 0);

	/*
	 * |$$$$$$$$|$$$$$$$|################|
	 *                  `head           `tail
	 *          `wakeup
	 *                                 `limit
	 */
	handle.head = SZ_1M / 2;
	handle.size = SZ_1M / 2 - 1;
	handle.wakeup = SZ_1M * 1 / 4;

	trbe_test_assert_normal_offset(test, &handle, &buf, 0,
				       SZ_1M - PAGE_SIZE, 0);

	/*
	 * |$$$$$$$$$$$$$$$$|################|
	 *                  `head           `tail
	 *                                  `wakeup
	 *                                 `limit
	 */
	handle.head = SZ_1M / 2;
	handle.size = SZ_1M / 2 - 1;
	handle.wakeup = SZ_1M - 1;

	trbe_test_assert_normal_offset(test, &handle, &buf, 0,
				       SZ_1M - PAGE_SIZE, 0);

	/*
	 * |#########|$$$$$$$$$$|########|###|
	 *           `tail      `head    `wakeup
	 *                                   `limit
	 */
	handle.head = SZ_1M * 3 / 4;
	handle.size = SZ_1M / 2;
	handle.wakeup = handle.head + SZ_1M / 8;

	trbe_test_assert_normal_offset(test, &handle, &buf, 0,
				       SZ_1M * 7 / 8, 0);

	/*
	 * |####|####|$$$$$$$$$$|############|
	 *           `tail      `head
	 *      `wakeup
	 *                                   `limit
	 */
	handle.head = SZ_1M * 3 / 4;
	handle.size = SZ_1M / 2;
	handle.wakeup = SZ_1M + SZ_1M / 8;

	trbe_test_assert_normal_offset(test, &handle, &buf, 0, SZ_1M, 0);

	/*
	 * |#######|########|$$$$$$$$$$$$$$$$|
	 * `head   `wakeup  `>tail
	 *         `limit
	 */
	handle.head = SZ_1M;
	handle.wakeup = SZ_1M + SZ_1M / 8;
	handle.size = SZ_1M / 2;

	trbe_test_assert_normal_offset(test, &handle, &buf, 0, SZ_1M / 8, 0);

	/*
	 * |#######|$$$$$$$$$$$$$$$$$|#######|
	 *         `tail             `head
	 *         `wakeup
	 *                                   `limit
	 */
	handle.head = SZ_1M * 3 / 4;
	handle.size = SZ_1M / 2;
	handle.wakeup = SZ_1M + SZ_1M / 4;

	trbe_test_assert_normal_offset(test, &handle, &buf, 0, SZ_1M, 0);

	/*
	 * |#######|$$$$$$$$|$$$$$$$$|#######|
	 *         `tail    `wakeup  `head
	 *                                   `limit
	 */
	handle.head = SZ_1M * 3 / 4;
	handle.size = SZ_1M / 2;
	handle.wakeup = SZ_1M + SZ_1M / 2;

	trbe_test_assert_normal_offset(test, &handle, &buf, 0, SZ_1M, 0);

	/*
	 * |$$$$$$$|########|########|$$$$$$$|
	 *         `head    `wakeup  `tail
	 *                           `limit
	 */
	handle.head = SZ_1M / 4;
	handle.size = SZ_1M / 2;
	handle.wakeup = SZ_1M / 2;

	trbe_test_assert_normal_offset(test, &handle, &buf, 0, SZ_1M / 2, 0);

	/*
	 * |$$$$$$$|#################|$$$$$$$|
	 *         `head             `tail
	 *                           `wakeup
	 *                           `limit
	 */
	handle.head = SZ_1M / 4;
	handle.size = SZ_1M / 2;
	handle.wakeup = SZ_1M * 3 / 4;

	trbe_test_assert_normal_offset(test, &handle, &buf, 0,
				       SZ_1M * 3 / 4, 0);

	/*
	 * |$$$$$$$|#################|$$$$$$$|
	 * `wakeup `head             `tail
	 *                           `limit
	 */
	handle.head = SZ_1M / 4;
	handle.size = SZ_1M / 2;
	handle.wakeup = 0;

	trbe_test_assert_normal_offset(test, &handle, &buf, 0,
				       SZ_1M * 3 / 4, 0);

	/*
	 * |$$$$$$|$$$$$$$$$$$$$$$$$$$$$$$$$$|
	 *        `head
	 *        `tail
	 */
	handle.head = SZ_1M / 4;
	handle.size = 0;

	trbe_test_assert_normal_offset(test, &handle, &buf, -ENOSPC, 0, 0);

	/*
	 * |$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$|#$|
	 *                                `head
	 *                                  `tail
	 */
	handle.head = SZ_1M - SZ_1K * 2;
	handle.size = SZ_1K;
	handle.wakeup = 0;

	trbe_test_assert_normal_offset(test, &handle, &buf, -ENOSPC, 0, 0);
}

static void test_normal_offset_limit_and_counter(struct kunit *test)
{
	struct perf_output_handle handle;
	struct trbe_buf buf;
	struct trbe_cpudata cpudata;

	trbe_test_init(&handle, &buf, &cpudata, SZ_1M / PAGE_SIZE,
		       PAGE_SIZE, 1, true);

	/*
	 * ### : Free space, $$$ : Filled space
	 *
	 * |################|################|
	 * `head            `wakeup          `limit
	 * `tail
	 * `----- count ----'
	 */
	handle.head = 0;
	handle.size = SZ_1M;
	handle.wakeup = SZ_1M / 2;

	trbe_test_assert_normal_offset(test, &handle, &buf, 0,
				       SZ_1M, SZ_1M / 2);

	/*
	 * |################|################|
	 * `head            `wakeup         `tail
	 *                                 `limit
	 * `----- count ----'
	 */
	handle.head = 0;
	handle.size = SZ_1M - 1;
	handle.wakeup = SZ_1M / 2;

	trbe_test_assert_normal_offset(test, &handle, &buf, 0,
				       SZ_1M - PAGE_SIZE, SZ_1M / 2);

	/*
	 * |#################################|
	 * `head                            `tail
	 * `wakeup                         `limit
	 */
	handle.head = 0;
	handle.size = SZ_1M - 1;
	handle.wakeup = 0;

	trbe_test_assert_normal_offset(test, &handle, &buf, -ENOSPC, 0, 0);

	/*
	 * |#################################|
	 * `head                            `tail
	 *                                   `wakeup
	 *                                 `limit
	 */
	handle.head = 0;
	handle.size = SZ_1M - 1;
	handle.wakeup = SZ_1M;

	trbe_test_assert_normal_offset(test, &handle, &buf, 0,
				       SZ_1M - PAGE_SIZE, 0);

	/*
	 * |$$$$$$$$$$$$$$$$|########|#######|
	 *                  `head           `tail
	 *                           `wakeup
	 *                                 `limit
	 *                  [  count ]
	 */
	handle.head = SZ_1M / 2;
	handle.size = SZ_1M / 2 - 1;
	handle.wakeup = SZ_1M * 3 / 4;

	trbe_test_assert_normal_offset(test, &handle, &buf, 0,
				       SZ_1M - PAGE_SIZE, SZ_1M / 4);

	/*
	 * |$$$$$$$$|$$$$$$$|################|
	 *                  `head           `tail
	 *          `wakeup
	 *                                 `limit
	 */
	handle.head = SZ_1M / 2;
	handle.size = SZ_1M / 2 - 1;
	handle.wakeup = SZ_1M * 1 / 4;

	trbe_test_assert_normal_offset(test, &handle, &buf, 0,
				       SZ_1M - PAGE_SIZE, 0);

	/*
	 * |$$$$$$$$$$$$$$$$|################|
	 *                  `head           `tail
	 *                                  `wakeup
	 *                                 `limit
	 */
	handle.head = SZ_1M / 2;
	handle.size = SZ_1M / 2 - 1;
	handle.wakeup = SZ_1M - 1;

	trbe_test_assert_normal_offset(test, &handle, &buf, 0,
				       SZ_1M - PAGE_SIZE, 0);

	/*
	 * |#########|$$$$$$$$$$|########|###|
	 *           `tail      `head    `wakeup
	 *                                   `limit
	 *                      [  count ]
	 */
	handle.head = SZ_1M * 3 / 4;
	handle.size = SZ_1M / 2;
	handle.wakeup = handle.head + SZ_1M / 8;

	trbe_test_assert_normal_offset(test, &handle, &buf, 0,
				       SZ_1M, SZ_1M / 8);

	/*
	 * |####|####|$$$$$$$$$$|############|
	 *           `tail      `head
	 *      `wakeup
	 *                                   `limit
	 *                      [   count  >>>
	 * >>>       ]
	 */
	handle.head = SZ_1M * 3 / 4;
	handle.size = SZ_1M / 2;
	handle.wakeup = SZ_1M + SZ_1M / 8;

	trbe_test_assert_normal_offset(test, &handle, &buf, 0, SZ_1M,
				       SZ_1M / 2 - TRBE_TRIGGER_STOP_HEADROOM);

	/*
	 * |#######|########|$$$$$$$$$$$$$$$$|
	 * `head   `wakeup  `>tail
	 *                  `limit
	 * [ count ]
	 */
	handle.head = SZ_1M;
	handle.wakeup = SZ_1M + SZ_1M / 8;
	handle.size = SZ_1M / 2;

	trbe_test_assert_normal_offset(test, &handle, &buf, 0,
				       SZ_1M / 2, SZ_1M / 8);

	/*
	 * |#######|$$$$$$$$$$$$$$$$$|#######|
	 *         `tail             `head
	 *         `wakeup
	 *                                   `limit
	 *                           [ count >
	 * >>>     ]
	 */
	handle.head = SZ_1M * 3 / 4;
	handle.size = SZ_1M / 2;
	handle.wakeup = SZ_1M + SZ_1M / 4;

	trbe_test_assert_normal_offset(test, &handle, &buf, 0, SZ_1M,
				       SZ_1M / 2 - TRBE_TRIGGER_STOP_HEADROOM);

	/*
	 * |#######|$$$$$$$$|$$$$$$$$|#######|
	 *         `tail    `wakeup  `head
	 *                                   `limit
	 *                           [ count >
	 * >>>     ]
	 */
	handle.head = SZ_1M * 3 / 4;
	handle.size = SZ_1M / 2;
	handle.wakeup = SZ_1M + SZ_1M / 2;

	trbe_test_assert_normal_offset(test, &handle, &buf, 0, SZ_1M,
				       SZ_1M / 2 - TRBE_TRIGGER_STOP_HEADROOM);

	/*
	 * |$$$$$$$|########|########|$$$$$$$|
	 *         `head    `wakeup  `tail
	 *                           `limit
	 *         [ count  ]
	 */
	handle.head = SZ_1M / 4;
	handle.size = SZ_1M / 2;
	handle.wakeup = SZ_1M / 2;

	trbe_test_assert_normal_offset(test, &handle, &buf, 0,
				       SZ_1M * 3 / 4, SZ_1M / 4);

	/*
	 * |$$$$$$$|#################|$$$$$$$|
	 *         `head             `tail
	 *                           `wakeup
	 *                           `limit
	 */
	handle.head = SZ_1M / 4;
	handle.size = SZ_1M / 2;
	handle.wakeup = SZ_1M * 3 / 4;

	trbe_test_assert_normal_offset(test, &handle, &buf, 0,
				       SZ_1M * 3 / 4, 0);

	/*
	 * |$$$$$$$|#################|$$$$$$$|
	 * `wakeup `head             `tail
	 *                           `limit
	 */
	handle.head = SZ_1M / 4;
	handle.size = SZ_1M / 2;
	handle.wakeup = 0;

	trbe_test_assert_normal_offset(test, &handle, &buf, 0,
				       SZ_1M * 3 / 4, 0);
}

static void test_normal_offset_alignment_padding(struct kunit *test)
{
	struct perf_output_handle handle;
	struct trbe_buf buf;
	struct trbe_cpudata cpudata;

	trbe_test_init(&handle, &buf, &cpudata, SZ_1M / PAGE_SIZE,
		       PAGE_SIZE, 1, false);

	handle.head = 128;
	handle.size = 2 * PAGE_SIZE;
	handle.wakeup = 0;

	trbe_test_assert_normal_offset(test, &handle, &buf, 0,
				       2 * PAGE_SIZE, 0);

	handle.head = SZ_1M - PAGE_SIZE / 2;
	handle.size = PAGE_SIZE / 4;
	handle.wakeup = 0;

	trbe_test_assert_normal_offset(test, &handle, &buf, -ENOSPC, 0, 0);
}

static void test_normal_offset_small_range_padding(struct kunit *test)
{
	struct perf_output_handle handle;
	struct trbe_buf buf;
	struct trbe_cpudata cpudata;

	trbe_test_init(&handle, &buf, &cpudata, SZ_1M / PAGE_SIZE,
		       PAGE_SIZE, 1, false);

	handle.head = 2 * PAGE_SIZE;
	handle.size = PAGE_SIZE / 4;
	handle.wakeup = 0;

	trbe_test_assert_normal_offset(test, &handle, &buf, -ENOSPC, 0, 0);
}

static void test_normal_offset_trigger_count_alignment(struct kunit *test)
{
	struct perf_output_handle handle;
	struct trbe_buf buf;
	struct trbe_cpudata cpudata;

	trbe_test_init(&handle, &buf, &cpudata, SZ_1M / PAGE_SIZE,
		       PAGE_SIZE, 256, true);

	handle.head = 0;
	handle.size = SZ_1M;
	handle.wakeup = PAGE_SIZE + 1;

	trbe_test_assert_normal_offset(test, &handle, &buf, 0, SZ_1M,
				       PAGE_SIZE + 256);

	handle.head = 0;
	handle.size = 2 * PAGE_SIZE;
	handle.wakeup = 2 * PAGE_SIZE - 1;

	trbe_test_assert_normal_offset(test, &handle, &buf, 0,
				       2 * PAGE_SIZE, 0);
}

static void test_normal_offset_trigger_count_over_u32(struct kunit *test)
{
	struct perf_output_handle handle;
	struct trbe_buf buf;
	struct trbe_cpudata cpudata;
	unsigned long wakeup = (unsigned long)U32_MAX + 1;
	int nr_pages = (wakeup + PAGE_SIZE) / PAGE_SIZE;

	trbe_test_init(&handle, &buf, &cpudata, nr_pages, PAGE_SIZE, 1, true);

	handle.head = 0;
	handle.size = (unsigned long)nr_pages * PAGE_SIZE;
	handle.wakeup = wakeup;

	trbe_test_assert_normal_offset(test, &handle, &buf, 0, wakeup, 0);
}

static void test_normal_offset_trigger_count_handle_wrap(struct kunit *test)
{
	struct perf_output_handle handle;
	struct trbe_buf buf;
	struct trbe_cpudata cpudata;

	trbe_test_init(&handle, &buf, &cpudata, SZ_1M / PAGE_SIZE,
		       PAGE_SIZE, 1, true);

	handle.head = ULONG_MAX - PAGE_SIZE + 1;
	handle.size = 2 * PAGE_SIZE;
	handle.wakeup = handle.head + PAGE_SIZE / 2;

	trbe_test_assert_normal_offset(test, &handle, &buf, 0,
				       SZ_1M, PAGE_SIZE / 2);
}

static void test_normal_offset_min_trace_size(struct kunit *test)
{
	struct perf_output_handle handle;
	struct trbe_buf buf;
	struct trbe_cpudata cpudata;
	unsigned long head = 2 * PAGE_SIZE - 32;

	trbe_test_init(&handle, &buf, &cpudata, SZ_1M / PAGE_SIZE, 1, 1, false);

	handle.head = head;
	handle.size = PAGE_SIZE + 96;
	handle.wakeup = 0;

	trbe_test_assert_normal_offset(test, &handle, &buf, 0,
				       3 * PAGE_SIZE, 0);

	trbe_test_init(&handle, &buf, &cpudata, SZ_1M / PAGE_SIZE, 1, 1, false);
	set_bit(TRBE_WORKAROUND_WRITE_OUT_OF_RANGE, cpudata.errata);

	handle.head = head;
	handle.size = PAGE_SIZE + 96;
	handle.wakeup = 0;

	trbe_test_assert_normal_offset(test, &handle, &buf, -ENOSPC, 0, 0);
}

static struct kunit_case coresight_trbe_testcases[] = {
	KUNIT_CASE(test_normal_offset_limit),
	KUNIT_CASE(test_normal_offset_limit_and_counter),
	KUNIT_CASE(test_normal_offset_alignment_padding),
	KUNIT_CASE(test_normal_offset_small_range_padding),
	KUNIT_CASE(test_normal_offset_trigger_count_alignment),
	KUNIT_CASE(test_normal_offset_trigger_count_over_u32),
	KUNIT_CASE(test_normal_offset_trigger_count_handle_wrap),
	KUNIT_CASE(test_normal_offset_min_trace_size),
	{}
};

static struct kunit_suite coresight_trbe_test_suite = {
	.name = "coresight_trbe_test_suite",
	.test_cases = coresight_trbe_testcases,
};

kunit_test_suites(&coresight_trbe_test_suite);
