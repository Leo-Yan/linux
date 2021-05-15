// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <inttypes.h>
#include "builtin.h"
#include "perf.h"

#include "util/evlist.h" // for struct evsel_str_handler
#include "util/evsel.h"
#include "util/symbol.h"
#include "util/thread.h"
#include "util/header.h"

#include <subcmd/pager.h>
#include <subcmd/parse-options.h>
#include "util/trace-event.h"

#include "util/debug.h"
#include "util/session.h"
#include "util/tool.h"
#include "util/data.h"

#include <sys/types.h>
#include <sys/prctl.h>
#include <semaphore.h>
#include <pthread.h>
#include <math.h>
#include <limits.h>

#include <linux/list.h>
#include <linux/hash.h>
#include <linux/kernel.h>
#include <linux/zalloc.h>
#include <linux/err.h>

static struct perf_session *session;

/*
 * Aspired by the kernel lockdep which uses hash-table for fast lookup,
 * create a hash-table for quick searching lock stats.  Currently the
 * hash-table size is 4096.
 */
#define LOCKHASH_BITS		12
#define LOCKHASH_SIZE		(1UL << LOCKHASH_BITS)

static struct hlist_head lockhash_table[LOCKHASH_SIZE];

struct lock_stat {
	struct hlist_node	hash_entry;
	struct rb_node		rb;		/* used for sorting */

	/*
	 * FIXME: evsel__intval() returns u64,
	 * so address of lockdep_map should be treated as 64bit.
	 * Is there more better solution?
	 */
	void			*addr;		/* address of lockdep_map, used as ID */
	char			*name;		/* for strcpy(), we cannot use const */

	unsigned int		nr_acquire;
	unsigned int		nr_acquired;
	unsigned int		nr_contended;
	unsigned int		nr_release;

	unsigned int		nr_readlock;
	unsigned int		nr_trylock;

	/* these times are in nano sec. */
	u64                     avg_wait_time;
	u64			wait_time_total;
	u64			wait_time_min;
	u64			wait_time_max;

	int			discard; /* flag of blacklist */
};

/*
 * States for thread lock sequence
 *
 * The state UNINITIALIZED is required for detecting the first 'acquire' event;
 * since the tracepoints can be enabled in the middle of locking sequence, it's
 * no guarantee that the first event must be 'acquire' for a lock, it can be
 * any event of 'acquired', 'contended' or 'release'.
 */
#define SEQ_STATE_UNINITIALIZED		0
#define SEQ_STATE_RELEASED		1
#define SEQ_STATE_ACQUIRING		2
#define SEQ_STATE_ACQUIRED		3
#define SEQ_STATE_READ_ACQUIRED		4
#define SEQ_STATE_CONTENDED		5

/*
 * Structure for thread lock sequence
 *
 * A lock can be used for not only one thread, e.g. for the read lock
 * which can be acquired concurrently by multiple threads at the same
 * time.  So define the lock sequence structure which is to maintain
 * the states for a lock which is associated to a thread.
 *
 * Place to put on state of one lock sequence
 * 1) acquire -> acquired -> release
 * 2) acquire -> contended -> acquired -> release
 * 3) acquire (with read or try) -> release
 * 4) Are there other patterns?
 */
struct thread_lock_seq {
	struct list_head        list;
	int			state;
	u64			state_start_time;
	void                    *addr;

	int                     read_count;
};

struct thread_stat {
	struct rb_node		rb_node;

	u32                     tid;
	struct list_head        lock_list;
};

static struct rb_root thread_stats;

static const char *sort_key = "acquired";
static struct rb_root sort_result;

static struct lock_stat *lock_stat_add(void *addr, const char *name)
{
	struct lock_stat *stat;
	unsigned int hval = hash_long((unsigned long)addr, LOCKHASH_BITS);

	hlist_for_each_entry(stat, &lockhash_table[hval], hash_entry) {
		if (stat->addr == addr)
			return stat;
	}

	stat = zalloc(sizeof(*stat));
	if (!stat) {
		pr_err("Failed to allocate lock stat\n");
		return NULL;
	}

	stat->name = strdup(name);
	if (!stat->name) {
		pr_err("Failed to duplicate name for lock stat\n");
		free(stat);
		return NULL;
	}

	stat->addr = addr;
	stat->wait_time_min = ULLONG_MAX;

	hlist_add_head(&stat->hash_entry, &lockhash_table[hval]);
	return stat;
}

static void lock_stat_del_all(void)
{
	unsigned int i;
	struct lock_stat *stat;
	struct hlist_node *tmp;

	for (i = 0; i < LOCKHASH_SIZE; i++) {
		hlist_for_each_entry_safe(stat, tmp, &lockhash_table[i], hash_entry) {
			hlist_del(&stat->hash_entry);
			free(stat->name);
			free(stat);
		}
	}
}

static struct thread_stat *thread_stat_findnew(u32 tid)
{
	struct rb_node **p = &thread_stats.rb_node;
	struct rb_node *parent = NULL;
	struct thread_stat *stat, *new;

	while (*p != NULL) {
		parent = *p;
		stat = rb_entry(parent, struct thread_stat, rb_node);

		if (tid < stat->tid)
			p = &(*p)->rb_left;
		else if (tid > stat->tid)
			p = &(*p)->rb_right;
		else
			return stat;
	}

	new = zalloc(sizeof(struct thread_stat));
	if (!new) {
		pr_err("Failed to allocate thread stat\n");
		return NULL;
	}

	new->tid = tid;
	INIT_LIST_HEAD(&new->lock_list);

	rb_link_node(&new->rb_node, parent, p);
	rb_insert_color(&new->rb_node, &thread_stats);

	return new;
}

static struct thread_lock_seq *_get_lock_seq(struct thread_stat *thd_stat,
					     void *addr)
{
	struct thread_lock_seq *seq;

	list_for_each_entry(seq, &thd_stat->lock_list, list) {
		if (seq->addr == addr)
			return seq;
	}

	seq = zalloc(sizeof(struct thread_lock_seq));
	if (!seq) {
		pr_err("memory allocation failed\n");
		return NULL;
	}
	seq->state = SEQ_STATE_UNINITIALIZED;
	seq->addr = addr;

	list_add(&seq->list, &thd_stat->lock_list);
	return seq;
}

static struct thread_lock_seq *thread_find_lock_seq(u32 tid, void *addr)
{
	struct thread_stat *thd_stat;

	thd_stat = thread_stat_findnew(tid);
	if (!thd_stat)
		return NULL;

	return _get_lock_seq(thd_stat, addr);
}

static void thread_stat_purge(void)
{
	struct rb_root *root;
	struct rb_node *next;

	root = &thread_stats;
	next = rb_first(root);

	while (next) {
		struct thread_stat *stat;
		struct thread_lock_seq *seq, *tmp;

		stat = rb_entry(next, struct thread_stat, rb_node);
		next = rb_next(&stat->rb_node);
		rb_erase(&stat->rb_node, root);

		list_for_each_entry_safe(seq, tmp, &stat->lock_list, list) {
			list_del(&seq->list);
			free(seq);
		}
	        free(stat);
	}
}

static int lock_stat_compare(struct lock_stat *ls_a, struct lock_stat *ls_b)
{
	if (!strcmp(sort_key, "acquired"))
		return ls_a->nr_acquired > ls_b->nr_acquired;

	if (!strcmp(sort_key, "contended"))
		return ls_a->nr_contended > ls_b->nr_contended;

	if (!strcmp(sort_key, "wait_time"))
		return ls_a->avg_wait_time > ls_b->avg_wait_time;

	if (!strcmp(sort_key, "wait_time_total"))
		return ls_a->wait_time_total > ls_b->wait_time_total;

	if (!strcmp(sort_key, "wait_time_max"))
		return ls_a->wait_time_max > ls_b->wait_time_max;

	/* Unknown sort key */
	BUG_ON(1);
}

static void insert_to_result(struct lock_stat *st)
{
	struct rb_node **rb = &sort_result.rb_node;
	struct rb_node *parent = NULL;
	struct lock_stat *p;

	while (*rb) {
		p = container_of(*rb, struct lock_stat, rb);
		parent = *rb;

		if (lock_stat_compare(st, p))
			rb = &(*rb)->rb_left;
		else
			rb = &(*rb)->rb_right;
	}

	rb_link_node(&st->rb, parent, rb);
	rb_insert_color(&st->rb, &sort_result);
}

/* returns left most element of result, and erase it */
static struct lock_stat *pop_from_result(void)
{
	struct rb_node *node = sort_result.rb_node;

	if (!node)
		return NULL;

	while (node->rb_left)
		node = node->rb_left;

	rb_erase(node, &sort_result);
	return container_of(node, struct lock_stat, rb);
}

struct trace_lock_handler {
	int (*acquire_event)(struct evsel *evsel,
			     struct perf_sample *sample);

	int (*acquired_event)(struct evsel *evsel,
			      struct perf_sample *sample);

	int (*contended_event)(struct evsel *evsel,
			       struct perf_sample *sample);

	int (*release_event)(struct evsel *evsel,
			     struct perf_sample *sample);
};

enum broken_state {
	BROKEN_ACQUIRE,
	BROKEN_ACQUIRED,
	BROKEN_CONTENDED,
	BROKEN_RELEASE,
	BROKEN_MAX,
};

static int bad_hist[BROKEN_MAX];

enum acquire_flags {
	TRY_LOCK = 1,
	READ_LOCK = 2,
};

static int report_lock_acquire_event(struct evsel *evsel,
				     struct perf_sample *sample)
{
	void *addr;
	struct lock_stat *ls;
	struct thread_lock_seq *seq;
	const char *name = evsel__strval(evsel, sample, "name");
	u64 tmp	 = evsel__intval(evsel, sample, "lockdep_addr");
	int flag = evsel__intval(evsel, sample, "flags");

	memcpy(&addr, &tmp, sizeof(void *));

	ls = lock_stat_add(addr, name);
	if (!ls)
		return -ENOMEM;
	if (ls->discard)
		return 0;

	seq = thread_find_lock_seq(sample->tid, addr);
	if (!seq)
		return -ENOMEM;

	switch (seq->state) {
	case SEQ_STATE_UNINITIALIZED:
	case SEQ_STATE_RELEASED:
		if (!flag) {
			seq->state = SEQ_STATE_ACQUIRING;
		} else {
			if (flag & TRY_LOCK)
				ls->nr_trylock++;
			if (flag & READ_LOCK)
				ls->nr_readlock++;
			seq->state = SEQ_STATE_READ_ACQUIRED;
			seq->read_count = 1;
			ls->nr_acquired++;
		}
		break;
	case SEQ_STATE_READ_ACQUIRED:
		if (flag & READ_LOCK) {
			seq->read_count++;
			ls->nr_acquired++;
			goto end;
		} else {
			goto broken;
		}
		break;
	case SEQ_STATE_ACQUIRED:
	case SEQ_STATE_ACQUIRING:
	case SEQ_STATE_CONTENDED:
broken:
		/* broken lock sequence, discard it */
		ls->discard = 1;
		bad_hist[BROKEN_ACQUIRE]++;
		list_del_init(&seq->list);
		free(seq);
		goto end;
	default:
		BUG_ON("Unknown state of lock sequence found!\n");
		break;
	}

	ls->nr_acquire++;
	seq->state_start_time = sample->time;
end:
	return 0;
}

static int report_lock_acquired_event(struct evsel *evsel,
				      struct perf_sample *sample)
{
	void *addr;
	struct lock_stat *ls;
	struct thread_lock_seq *seq;
	u64 contended_term;
	const char *name = evsel__strval(evsel, sample, "name");
	u64 tmp = evsel__intval(evsel, sample, "lockdep_addr");

	memcpy(&addr, &tmp, sizeof(void *));

	ls = lock_stat_add(addr, name);
	if (!ls)
		return -ENOMEM;
	if (ls->discard)
		return 0;

	seq = thread_find_lock_seq(sample->tid, addr);
	if (!seq)
		return -ENOMEM;

	switch (seq->state) {
	case SEQ_STATE_UNINITIALIZED:
		/* orphan event, do nothing */
		return 0;
	case SEQ_STATE_ACQUIRING:
		break;
	case SEQ_STATE_CONTENDED:
		contended_term = sample->time - seq->state_start_time;
		ls->wait_time_total += contended_term;
		if (contended_term < ls->wait_time_min)
			ls->wait_time_min = contended_term;
		if (ls->wait_time_max < contended_term)
			ls->wait_time_max = contended_term;
		break;
	case SEQ_STATE_RELEASED:
	case SEQ_STATE_ACQUIRED:
	case SEQ_STATE_READ_ACQUIRED:
		/* broken lock sequence, discard it */
		ls->discard = 1;
		bad_hist[BROKEN_ACQUIRED]++;
		list_del_init(&seq->list);
		free(seq);
		goto end;
	default:
		BUG_ON("Unknown state of lock sequence found!\n");
		break;
	}

	seq->state = SEQ_STATE_ACQUIRED;
	ls->nr_acquired++;
	ls->avg_wait_time = ls->nr_contended ? ls->wait_time_total/ls->nr_contended : 0;
	seq->state_start_time = sample->time;
end:
	return 0;
}

static int report_lock_contended_event(struct evsel *evsel,
				       struct perf_sample *sample)
{
	void *addr;
	struct lock_stat *ls;
	struct thread_lock_seq *seq;
	const char *name = evsel__strval(evsel, sample, "name");
	u64 tmp = evsel__intval(evsel, sample, "lockdep_addr");

	memcpy(&addr, &tmp, sizeof(void *));

	ls = lock_stat_add(addr, name);
	if (!ls)
		return -ENOMEM;
	if (ls->discard)
		return 0;

	seq = thread_find_lock_seq(sample->tid, addr);
	if (!seq)
		return -ENOMEM;

	switch (seq->state) {
	case SEQ_STATE_UNINITIALIZED:
		/* orphan event, do nothing */
		return 0;
	case SEQ_STATE_ACQUIRING:
		break;
	case SEQ_STATE_RELEASED:
	case SEQ_STATE_ACQUIRED:
	case SEQ_STATE_READ_ACQUIRED:
	case SEQ_STATE_CONTENDED:
		/* broken lock sequence, discard it */
		ls->discard = 1;
		bad_hist[BROKEN_CONTENDED]++;
		list_del_init(&seq->list);
		free(seq);
		goto end;
	default:
		BUG_ON("Unknown state of lock sequence found!\n");
		break;
	}

	seq->state = SEQ_STATE_CONTENDED;
	ls->nr_contended++;
	ls->avg_wait_time = ls->wait_time_total/ls->nr_contended;
	seq->state_start_time = sample->time;
end:
	return 0;
}

static int report_lock_release_event(struct evsel *evsel,
				     struct perf_sample *sample)
{
	void *addr;
	struct lock_stat *ls;
	struct thread_lock_seq *seq;
	const char *name = evsel__strval(evsel, sample, "name");
	u64 tmp = evsel__intval(evsel, sample, "lockdep_addr");

	memcpy(&addr, &tmp, sizeof(void *));

	ls = lock_stat_add(addr, name);
	if (!ls)
		return -ENOMEM;
	if (ls->discard)
		return 0;

	seq = thread_find_lock_seq(sample->tid, addr);
	if (!seq)
		return -ENOMEM;

	switch (seq->state) {
	case SEQ_STATE_UNINITIALIZED:
		goto end;
	case SEQ_STATE_ACQUIRED:
		break;
	case SEQ_STATE_READ_ACQUIRED:
		seq->read_count--;
		BUG_ON(seq->read_count < 0);
		if (seq->read_count) {
			ls->nr_release++;
			goto end;
		}
		break;
	case SEQ_STATE_ACQUIRING:
	case SEQ_STATE_CONTENDED:
	case SEQ_STATE_RELEASED:
		/* broken lock sequence, discard it */
		ls->discard = 1;
		bad_hist[BROKEN_RELEASE]++;
		goto free_seq;
	default:
		BUG_ON("Unknown state of lock sequence found!\n");
		break;
	}

	ls->nr_release++;
free_seq:
	list_del_init(&seq->list);
	free(seq);
end:
	return 0;
}

/* lock oriented handlers */
/* TODO: handlers for CPU oriented, thread oriented */
static struct trace_lock_handler report_lock_ops  = {
	.acquire_event		= report_lock_acquire_event,
	.acquired_event		= report_lock_acquired_event,
	.contended_event	= report_lock_contended_event,
	.release_event		= report_lock_release_event,
};

static struct trace_lock_handler *trace_handler;

static int evsel__process_lock_acquire(struct evsel *evsel, struct perf_sample *sample)
{
	if (trace_handler->acquire_event)
		return trace_handler->acquire_event(evsel, sample);
	return 0;
}

static int evsel__process_lock_acquired(struct evsel *evsel, struct perf_sample *sample)
{
	if (trace_handler->acquired_event)
		return trace_handler->acquired_event(evsel, sample);
	return 0;
}

static int evsel__process_lock_contended(struct evsel *evsel, struct perf_sample *sample)
{
	if (trace_handler->contended_event)
		return trace_handler->contended_event(evsel, sample);
	return 0;
}

static int evsel__process_lock_release(struct evsel *evsel, struct perf_sample *sample)
{
	if (trace_handler->release_event)
		return trace_handler->release_event(evsel, sample);
	return 0;
}

static void print_bad_events(int bad, int total)
{
	/* Output for debug, this have to be removed */
	int i;
	const char *name[4] =
		{ "acquire", "acquired", "contended", "release" };

	pr_info("\n=== output for debug===\n\n");
	pr_info("bad: %d, total: %d\n", bad, total);
	pr_info("bad rate: %.2f %%\n", (double)bad / (double)total * 100);
	pr_info("histogram of events caused bad sequence\n");
	for (i = 0; i < BROKEN_MAX; i++)
		pr_info(" %10s: %d\n", name[i], bad_hist[i]);
}

/* TODO: various way to print, coloring, nano or milli sec */
static void print_result(void)
{
	struct lock_stat *st;
	char cut_name[20];
	int bad, total;

	pr_info("%20s ", "Name");
	pr_info("%10s ", "acquired");
	pr_info("%10s ", "contended");

	pr_info("%15s ", "avg wait (ns)");
	pr_info("%15s ", "total wait (ns)");
	pr_info("%15s ", "max wait (ns)");
	pr_info("%15s ", "min wait (ns)");

	pr_info("\n\n");

	bad = total = 0;
	while ((st = pop_from_result())) {
		total++;
		if (st->discard) {
			bad++;
			continue;
		}
		bzero(cut_name, 20);

		if (strlen(st->name) < 16) {
			/* output raw name */
			pr_info("%20s ", st->name);
		} else {
			strncpy(cut_name, st->name, 16);
			cut_name[16] = '.';
			cut_name[17] = '.';
			cut_name[18] = '.';
			cut_name[19] = '\0';
			/* cut off name for saving output style */
			pr_info("%20s ", cut_name);
		}

		pr_info("%10u ", st->nr_acquired);
		pr_info("%10u ", st->nr_contended);

		pr_info("%15" PRIu64 " ", st->avg_wait_time);
		pr_info("%15" PRIu64 " ", st->wait_time_total);
		pr_info("%15" PRIu64 " ", st->wait_time_max);
		pr_info("%15" PRIu64 " ", st->wait_time_min == ULLONG_MAX ?
		       0 : st->wait_time_min);
		pr_info("\n");
	}

	print_bad_events(bad, total);
}

static bool info_threads, info_map;

static void dump_threads(void)
{
	struct thread_stat *st;
	struct rb_node *node;
	struct thread *t;

	pr_info("%10s: comm\n", "Thread ID");

	node = rb_first(&thread_stats);
	while (node) {
		st = rb_entry(node, struct thread_stat, rb_node);
		t = perf_session__findnew(session, st->tid);
		pr_info("%10d: %s\n", st->tid, thread__comm_str(t));
		node = rb_next(node);
		thread__put(t);
	}
}

static void dump_map(void)
{
	unsigned int i;
	struct lock_stat *st;

	pr_info("Address of instance: name of class\n");
	for (i = 0; i < LOCKHASH_SIZE; i++) {
		hlist_for_each_entry(st, &lockhash_table[i], hash_entry) {
			pr_info(" %p: %s\n", st->addr, st->name);
		}
	}
}

static int dump_info(void)
{
	int rc = 0;

	if (info_threads)
		dump_threads();
	else if (info_map)
		dump_map();
	else {
		rc = -1;
		pr_err("Unknown type of information\n");
	}

	return rc;
}

typedef int (*tracepoint_handler)(struct evsel *evsel,
				  struct perf_sample *sample);

static int process_sample_event(struct perf_tool *tool __maybe_unused,
				union perf_event *event,
				struct perf_sample *sample,
				struct evsel *evsel,
				struct machine *machine)
{
	int err = 0;
	struct thread *thread = machine__findnew_thread(machine, sample->pid,
							sample->tid);

	if (thread == NULL) {
		pr_debug("problem processing %d event, skipping it.\n",
			event->header.type);
		return -1;
	}

	if (evsel->handler != NULL) {
		tracepoint_handler f = evsel->handler;
		err = f(evsel, sample);
	}

	thread__put(thread);

	return err;
}

static void lock_stat_sort(void)
{
	unsigned int i;
	struct lock_stat *st;

	for (i = 0; i < LOCKHASH_SIZE; i++) {
		hlist_for_each_entry(st, &lockhash_table[i], hash_entry) {
			insert_to_result(st);
		}
	}
}

static const struct evsel_str_handler lock_tracepoints[] = {
	{ "lock:lock_acquire",	 evsel__process_lock_acquire,   }, /* CONFIG_LOCKDEP */
	{ "lock:lock_acquired",	 evsel__process_lock_acquired,  }, /* CONFIG_LOCKDEP, CONFIG_LOCK_STAT */
	{ "lock:lock_contended", evsel__process_lock_contended, }, /* CONFIG_LOCKDEP, CONFIG_LOCK_STAT */
	{ "lock:lock_release",	 evsel__process_lock_release,   }, /* CONFIG_LOCKDEP */
};

static bool force;

static int __cmd_report(bool display_info)
{
	int err = -EINVAL;
	struct perf_tool eops = {
		.sample		 = process_sample_event,
		.comm		 = perf_event__process_comm,
		.namespaces	 = perf_event__process_namespaces,
		.ordered_events	 = true,
	};
	struct perf_data data = {
		.path  = input_name,
		.mode  = PERF_DATA_MODE_READ,
		.force = force,
	};

	session = perf_session__new(&data, false, &eops);
	if (IS_ERR(session)) {
		pr_err("Initializing perf session failed\n");
		return PTR_ERR(session);
	}

	symbol__init(&session->header.env);

	if (!perf_session__has_traces(session, "lock record"))
		goto out_delete;

	if (perf_session__set_tracepoints_handlers(session, lock_tracepoints)) {
		pr_err("Initializing perf session tracepoint handlers failed\n");
		goto out_delete;
	}

	err = perf_session__process_events(session);
	if (err)
		goto out_delete;

	setup_pager();
	if (display_info) /* used for info subcommand */
		err = dump_info();
	else {
		lock_stat_sort();
		print_result();
	}

	lock_stat_del_all();
	thread_stat_purge();

out_delete:
	perf_session__delete(session);
	return err;
}

static int __cmd_record(int argc, const char **argv)
{
	const char *record_args[] = {
		"record", "-R", "-m", "1024", "-c", "1",
	};
	unsigned int rec_argc, i, j, ret;
	const char **rec_argv;

	for (i = 0; i < ARRAY_SIZE(lock_tracepoints); i++) {
		if (!is_valid_tracepoint(lock_tracepoints[i].name)) {
				pr_err("tracepoint %s is not enabled. "
				       "Are CONFIG_LOCKDEP and CONFIG_LOCK_STAT enabled?\n",
				       lock_tracepoints[i].name);
				return 1;
		}
	}

	rec_argc = ARRAY_SIZE(record_args) + argc - 1;
	/* factor of 2 is for -e in front of each tracepoint */
	rec_argc += 2 * ARRAY_SIZE(lock_tracepoints);

	rec_argv = calloc(rec_argc + 1, sizeof(char *));
	if (!rec_argv)
		return -ENOMEM;

	for (i = 0; i < ARRAY_SIZE(record_args); i++)
		rec_argv[i] = strdup(record_args[i]);

	for (j = 0; j < ARRAY_SIZE(lock_tracepoints); j++) {
		rec_argv[i++] = "-e";
		rec_argv[i++] = strdup(lock_tracepoints[j].name);
	}

	for (j = 1; j < (unsigned int)argc; j++, i++)
		rec_argv[i] = argv[j];

	BUG_ON(i != rec_argc);

	ret = cmd_record(i, rec_argv);
	free(rec_argv);
	return ret;
}

int cmd_lock(int argc, const char **argv)
{
	const struct option lock_options[] = {
	OPT_STRING('i', "input", &input_name, "file", "input file name"),
	OPT_INCR('v', "verbose", &verbose, "be more verbose (show symbol address, etc)"),
	OPT_BOOLEAN('D', "dump-raw-trace", &dump_trace, "dump raw trace in ASCII"),
	OPT_BOOLEAN('f', "force", &force, "don't complain, do it"),
	OPT_END()
	};

	const struct option info_options[] = {
	OPT_BOOLEAN('t', "threads", &info_threads,
		    "dump thread list in perf.data"),
	OPT_BOOLEAN('m', "map", &info_map,
		    "map of lock instances (address:name table)"),
	OPT_PARENT(lock_options)
	};

	const struct option report_options[] = {
	OPT_STRING('k', "key", &sort_key, "acquired",
		    "key for sorting (acquired / contended / avg_wait / wait_total / wait_max / wait_min)"),
	/* TODO: type */
	OPT_PARENT(lock_options)
	};

	const char * const info_usage[] = {
		"perf lock info [<options>]",
		NULL
	};
	const char *const lock_subcommands[] = { "record", "report", "script",
						 "info", NULL };
	const char *lock_usage[] = {
		NULL,
		NULL
	};
	const char * const report_usage[] = {
		"perf lock report [<options>]",
		NULL
	};
	int rc = 0;

	argc = parse_options_subcommand(argc, argv, lock_options, lock_subcommands,
					lock_usage, PARSE_OPT_STOP_AT_NON_OPTION);
	if (!argc)
		usage_with_options(lock_usage, lock_options);

	if (!strncmp(argv[0], "rec", 3)) {
		return __cmd_record(argc, argv);
	} else if (!strncmp(argv[0], "report", 6)) {
		trace_handler = &report_lock_ops;
		if (argc) {
			argc = parse_options(argc, argv,
					     report_options, report_usage, 0);
			if (argc)
				usage_with_options(report_usage, report_options);
		}
		rc = __cmd_report(false);
	} else if (!strcmp(argv[0], "script")) {
		/* Aliased to 'perf script' */
		return cmd_script(argc, argv);
	} else if (!strcmp(argv[0], "info")) {
		if (argc) {
			argc = parse_options(argc, argv,
					     info_options, info_usage, 0);
			if (argc)
				usage_with_options(info_usage, info_options);
		}
		/* recycling report_lock_ops */
		trace_handler = &report_lock_ops;
		rc = __cmd_report(true);
	} else {
		usage_with_options(lock_usage, lock_options);
	}

	return rc;
}
