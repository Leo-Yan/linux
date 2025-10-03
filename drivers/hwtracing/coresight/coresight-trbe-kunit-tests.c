// SPDX-License-Identifier: GPL-2.0

#include <kunit/test.h>
#include <kunit/device.h>
#include <linux/coresight.h>

#include "coresight-priv.h"
#include "coresight-trbe.h"

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");

static void test_compute_next(struct kunit *test)
{
	struct perf_output_handle handle = { 0 };
	struct trbe_buf buf = { 0 };
	struct trbe_cpudata cpudata = { 0 };
	u64 limit, count;

	cpudata.trbe_hw_align = 1;

	buf.nr_pages = SZ_1M / SZ_4K;
	buf.cpudata = &cpudata;

	handle.size = SZ_1M;
	handle.wakeup = SZ_1M / 2;
	handle.head = 0;
	handle.rb = (void *)&buf;

	/*
	 * |#############|#############|
	 * `> head       `> wakeup
	 * `> tail
	 *                             `> limit
	 * `--- count ---'
	 */
	limit = __trbe_next_limit(&handle);
	buf.trbe_limit = limit;
	count = __trbe_next_count(&handle);

	KUNIT_ASSERT_EQ(test, limit, SZ_1M);
	KUNIT_ASSERT_EQ(test, count, SZ_1M / 2);

	/*
	 * |#############|#############|
	 * `> head       `> wakeup     `> tail
	 *                            `> limit
	 * `--- count ---'
	 */
	handle.size = SZ_1M - 1;

	limit = __trbe_next_limit(&handle);
	buf.trbe_limit = limit;
	count = __trbe_next_count(&handle);

	KUNIT_ASSERT_EQ(test, limit, SZ_1M - SZ_4K);
	KUNIT_ASSERT_EQ(test, count, SZ_1M / 2);

	/*
	 * |###########################|
	 * `> head                     `> tail
	 * `> wakeup
	 *                            `> limit
	 */
	handle.wakeup = 0;

	limit = __trbe_next_limit(&handle);
	buf.trbe_limit = limit;
	count = __trbe_next_count(&handle);

	KUNIT_ASSERT_EQ(test, limit, SZ_1M - SZ_4K);
	KUNIT_ASSERT_EQ(test, count, 0);

	/*
	 * |###########################|
	 * `> head                     `> tail
	 *                             `> wakeup
	 *                            `> limit
	 * `------------ count -------'
	 */
	handle.wakeup = SZ_1M;

	limit = __trbe_next_limit(&handle);
	buf.trbe_limit = limit;
	count = __trbe_next_count(&handle);

	KUNIT_ASSERT_EQ(test, limit, SZ_1M - SZ_4K);
	KUNIT_ASSERT_EQ(test, count, SZ_1M - SZ_4K);

	/*
	 *                        ,> wakeup
	 * |$$$$$$$$$$$$$|########|####|
	 *               `> head       `> tail
	 *                            `> limit
	 *               `- count-'
	 */
	handle.size = SZ_1M;
	handle.wakeup = SZ_1M * 3 / 4;
	handle.head = SZ_1M / 2;
	handle.size = SZ_1M / 2 - 1;

	limit = __trbe_next_limit(&handle);
	buf.trbe_limit = limit;
	count = __trbe_next_count(&handle);

	KUNIT_ASSERT_EQ(test, limit, SZ_1M - SZ_4K);
	KUNIT_ASSERT_EQ(test, count, SZ_1M / 4);

	/*
	 *        ,> wakeup
	 * |$$$$$$|$$$$$$|#############|
	 *               `> head       `> tail
	 *                            ` limit
	 *               `--- count --'
	 */
	handle.wakeup = SZ_1M * 1 / 4;

	limit = __trbe_next_limit(&handle);
	buf.trbe_limit = limit;
	count = __trbe_next_count(&handle);

	KUNIT_ASSERT_EQ(test, limit, SZ_1M - SZ_4K);
	KUNIT_ASSERT_EQ(test, count, SZ_1M / 2 - SZ_4K);

	/*
	 *                             ,> wakeup
	 * |$$$$$$$$$$$$$|#############|
	 *               `> head       `> tail
	 *                            ` limit
	 *               `--- count --'
	 */
	handle.wakeup = SZ_1M - 1;

	limit = __trbe_next_limit(&handle);
	buf.trbe_limit = limit;
	count = __trbe_next_count(&handle);

	KUNIT_ASSERT_EQ(test, limit, SZ_1M - SZ_4K);
	KUNIT_ASSERT_EQ(test, count, SZ_1M / 2 - SZ_4K);

	/*
	 *                         ,> wakeup
	 * |######|$$$$$$$$$$$$|#######|
	 *        ` tail       `> head
	 *                             `> limit
	 *                     `---'
	 *                      count
	 */
	handle.head = SZ_1M * 3 / 4;
	handle.wakeup = handle.head + SZ_1M / 8;
	handle.size = SZ_1M / 2;

	limit = __trbe_next_limit(&handle);
	buf.trbe_limit = limit;
	count = __trbe_next_count(&handle);

	KUNIT_ASSERT_EQ(test, limit, SZ_1M);
	KUNIT_ASSERT_EQ(test, count, SZ_1M / 8);

	/*
	 *     ,> wakeup
	 * |######|$$$$$$$$$$$$|#######|
	 *        ` tail       `> head
	 *                     `-------,
	 * ----'
	 *  count
	 */
	handle.head = SZ_1M * 3 / 4;
	handle.wakeup = SZ_1M + SZ_1M / 8;
	handle.size = SZ_1M / 2;

	limit = __trbe_next_limit(&handle);
	buf.trbe_limit = limit;
	count = __trbe_next_count(&handle);

	KUNIT_ASSERT_EQ(test, limit, SZ_1M);
	KUNIT_ASSERT_EQ(test, count, SZ_1M / 2);

	/*
	 *     ,> wakeup
	 * |######|$$$$$$$$$$$$$$$$$$$$|
	 * `>head `>tail
	 */
	handle.head = SZ_1M;
	handle.wakeup = SZ_1M + SZ_1M / 8;
	handle.size = SZ_1M / 2;

	limit = __trbe_next_limit(&handle);
	buf.trbe_limit = limit;
	count = __trbe_next_count(&handle);

	KUNIT_ASSERT_EQ(test, limit, SZ_1M / 2);
	KUNIT_ASSERT_EQ(test, count, SZ_1M / 8);

	/*
	 *        ,> wakeup
	 * |######|$$$$$$$$$$$$|#######|
	 *        ` tail       `> head
	 *                     `-------,
	 * -------'
	 *  count
	 */
	handle.head = SZ_1M * 3 / 4;
	handle.wakeup = SZ_1M + SZ_1M / 4;
	handle.size = SZ_1M / 2;

	limit = __trbe_next_limit(&handle);
	buf.trbe_limit = limit;
	count = __trbe_next_count(&handle);

	KUNIT_ASSERT_EQ(test, limit, SZ_1M);
	KUNIT_ASSERT_EQ(test, count, SZ_1M / 2);

	/*
	 *              ,> wakeup
	 * |######|$$$$$$$$$$$$|#######|
	 *        ` tail       `> head
	 *                     `-------,
	 * -------'
	 *  count
	 */
	handle.head = SZ_1M * 3 / 4;
	handle.wakeup = SZ_1M + SZ_1M / 2;
	handle.size = SZ_1M / 2;

	limit = __trbe_next_limit(&handle);
	buf.trbe_limit = limit;
	count = __trbe_next_count(&handle);

	KUNIT_ASSERT_EQ(test, limit, SZ_1M);
	KUNIT_ASSERT_EQ(test, count, SZ_1M / 2);

	/*
	 *              ,> wakeup
	 * |$$$$$$|#####|######|$$$$$$$|
	 *        ` head       `> tail
	 *                     `> limit
	 *        `count'
	 */
	handle.head = SZ_1M / 4;
	handle.wakeup = SZ_1M / 2;
	handle.size = SZ_1M / 2;

	limit = __trbe_next_limit(&handle);
	buf.trbe_limit = limit;
	count = __trbe_next_count(&handle);

	KUNIT_ASSERT_EQ(test, limit, SZ_1M * 3 / 4);
	KUNIT_ASSERT_EQ(test, count, SZ_1M / 4);

	/*
	 *                     ,> wakeup
	 * |$$$$$$|############|$$$$$$$|
	 *        ` head       `> tail
	 *                     `> limit
	 *        `--- count --'
	 */
	handle.head = SZ_1M / 4;
	handle.wakeup = SZ_1M * 3 / 4;
	handle.size = SZ_1M / 2;

	limit = __trbe_next_limit(&handle);
	buf.trbe_limit = limit;
	count = __trbe_next_count(&handle);

	KUNIT_ASSERT_EQ(test, limit, SZ_1M * 3 / 4);
	KUNIT_ASSERT_EQ(test, count, SZ_1M / 2);

	/*
	 * ,> wakeup
	 * |$$$$$$|############|$$$$$$$|
	 *        `> head      `> tail
	 *                     `> limit
	 *        `--- count --'
	 */
	handle.head = SZ_1M / 4;
	handle.wakeup = 0;
	handle.size = SZ_1M / 2;

	limit = __trbe_next_limit(&handle);
	buf.trbe_limit = limit;
	count = __trbe_next_count(&handle);

	KUNIT_ASSERT_EQ(test, limit, SZ_1M * 3 / 4);
	KUNIT_ASSERT_EQ(test, count, SZ_1M / 2);

	/*
	 * ,> wakeup
	 * |$$$$$$|############|$$$$$$$|
	 *        `> head      `> tail
	 *                     `> limit
	 *        `--- count --'
	 */
	handle.head = SZ_1M / 4;
	handle.wakeup = 0;
	handle.size = SZ_1M / 2;

	limit = __trbe_next_limit(&handle);
	buf.trbe_limit = limit;
	count = __trbe_next_count(&handle);

	KUNIT_ASSERT_EQ(test, limit, SZ_1M * 3 / 4);
	KUNIT_ASSERT_EQ(test, count, SZ_1M / 2);

	/*
	 * |$$$$$$$$$$$$$$$$$$$$$$$$$$$|
	 *        `> head
	 *        `> tail
	 */
	handle.size = 0;

	limit = __trbe_next_limit(&handle);
	KUNIT_ASSERT_EQ(test, limit, 0);

	/*
	 * |$$$$$$$$$$|$$$$$|======|$$$|
	 *             limit head   tail
	 */
	handle.head = SZ_1M - SZ_1K * 2;
	handle.size = SZ_1K;

	limit = __trbe_next_limit(&handle);
	KUNIT_ASSERT_EQ(test, limit, 0);
}

static struct kunit_case coresight_trbe_testcases[] = {
	KUNIT_CASE(test_compute_next),
	{}
};

static struct kunit_suite coresight_trbe_test_suite= {
	.name = "coresight_trbe_test_suite",
	.test_cases = coresight_trbe_testcases,
};

kunit_test_suites(&coresight_trbe_test_suite);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Leo Yan <leo.yan@arm.com>");
MODULE_DESCRIPTION("Arm CoreSight TRBE KUnit tests");
