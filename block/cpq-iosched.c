// SPDX-License-Identifier: GPL-2.0
/*
 * CPQ (Custom Priority Queue) I/O Scheduler
 * for the blk-mq scheduling framework
 *
 * Reverse-Engineered from decompiled CPQ binary
 * Based on analysis of cpq.ko and cpq_refined.c
 *
 * Copyright (C) 2025 Rasenkai <rasenkai99@gmail.com>
 */

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/bio.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/compiler.h>
#include <linux/rbtree.h>
#include <linux/sbitmap.h>
#include <linux/ioprio.h>
#include <linux/hashtable.h>
#include <linux/elevator.h>
#include <linux/jiffies.h>

#include <trace/events/block.h>

#include "blk.h"
#include "blk-mq.h"
#include "blk-mq-debugfs.h"
#include "blk-mq-tag.h"
#include "blk-mq-sched.h"

/*
 * Priority levels
 */
#define CPQ_PRIO_LEVELS 3
#define CPQ_PRIO_RT     0
#define CPQ_PRIO_BE     1
#define CPQ_PRIO_IDLE   2

/*
 * Group types
 */
#define CPQ_GROUP_FG    0  /* Foreground */
#define CPQ_GROUP_BG    1  /* Background */
#define CPQ_GROUPS      2

/*
 * Hash bits for request lookup
 */
#define CPQ_HASH_BITS   6

/*
 * Default tunables
 */
static const int read_expire = HZ / 8;        /* 125ms */
static const int write_expire = 2 * HZ;       /* 2s */
static const int writes_starved = 4;
static const int prio_aging_expire = 10 * HZ; /* 10s */
static const int fifo_batch = 8;

#define CPQ_FORE_TIMEOUT        (2 * HZ)       /* 2s */
#define CPQ_BACK_TIMEOUT        (HZ / 8)       /* 125ms */
#define CPQ_SLICE_IDLE          (4000000)      /* 4ms */
#define CPQ_IO_THRESHOLD        (3000000)      /* 3ms */
#define CPQ_ASYNC_DEPTH_MAX     (8)

/*
 * Request direction
 */
enum cpq_data_dir {
	CPQ_READ = READ,
	CPQ_WRITE = WRITE,
};

enum {
	CPQ_DIR_COUNT = 2,
};

/*
 * Per-priority-level queue structure
 */
struct cpq_queue {
	struct rb_root sort_list[CPQ_DIR_COUNT];
	struct list_head fifo_list[CPQ_DIR_COUNT];
	struct request *next_rq[CPQ_DIR_COUNT];

	/* Statistics */
	uint32_t inserted;
	uint32_t merged;
	uint32_t dispatched;
	atomic_t completed;

	unsigned long last_issue;
};

/*
 * Per-group data
 */
struct cpq_group {
	struct cpq_queue prio[CPQ_PRIO_LEVELS];
	unsigned int batched;
	unsigned int starved;
	unsigned long timeout;
};

/*
 * Main CPQ data
 */
struct cpq_data {
	struct cpq_group groups[CPQ_GROUPS];

	/* Hash table for request lookup */
	DECLARE_HASHTABLE(hash, CPQ_HASH_BITS);

	/* Dispatch state */
	unsigned int batching;
	unsigned int starved;
	enum cpq_data_dir last_dir;

	/* Group round-robin state (fore_timeout/back_timeout) */
	unsigned int active_group;
	unsigned long group_switch_time;

	/* Last time last_dir changed (slice_idle) */
	unsigned long dir_switch_time;

	/* Tunables */
	int fifo_expire[CPQ_DIR_COUNT];
	int fifo_batch;
	int writes_starved;
	int front_merges;
	u32 async_depth;
	int prio_aging_expire;
	u64 slice_idle;
	u64 io_threshold;
	unsigned int cpq_log;

	spinlock_t lock;
	spinlock_t zone_lock;
};

/*
 * Per-request data  
 */
struct cpq_rq {
	struct rb_node rb_node;
	struct list_head fifo;
	struct hlist_node hash;

	sector_t rb_key;
	unsigned long deadline;
	unsigned long issue_time;

	unsigned int group;
	unsigned int prio;
	unsigned int aged;
};

/*
 * Map ioprio class to CPQ priority - use function instead of array
 */
static inline unsigned int cpq_ioprio_class_to_prio(u8 class)
{
	switch (class) {
	case IOPRIO_CLASS_RT:
		return CPQ_PRIO_RT;
	case IOPRIO_CLASS_BE:
	case IOPRIO_CLASS_NONE:
		return CPQ_PRIO_BE;
	case IOPRIO_CLASS_IDLE:
	default:
		return CPQ_PRIO_IDLE;
	}
}

static inline u8 cpq_rq_ioclass(struct request *rq)
{
	return IOPRIO_PRIO_CLASS(req_get_ioprio(rq));
}

/*
 * Determine group from request
 */
static inline unsigned int cpq_determine_group(struct request *rq)
{
	u8 ioclass = cpq_rq_ioclass(rq);

	/* IDLE class goes to background */
	if (ioclass == IOPRIO_CLASS_IDLE)
		return CPQ_GROUP_BG;

	return CPQ_GROUP_FG;
}

/*
 * RB tree operations
 */
static inline struct rb_root *
cpq_rb_root(struct cpq_queue *cq, struct request *rq)
{
	return &cq->sort_list[rq_data_dir(rq)];
}

static void cpq_add_rq_rb(struct cpq_queue *cq, struct request *rq)
{
	struct rb_root *root = cpq_rb_root(cq, rq);
	struct cpq_rq *crq = rq->elv.priv[0];

	crq->rb_key = blk_rq_pos(rq) + blk_rq_sectors(rq);
	elv_rb_add(root, rq);
}

static inline void cpq_del_rq_rb(struct cpq_queue *cq, struct request *rq)
{
	const enum cpq_data_dir data_dir = rq_data_dir(rq);

	if (cq->next_rq[data_dir] == rq)
		cq->next_rq[data_dir] = elv_rb_latter_request(rq->q, rq);

	elv_rb_del(cpq_rb_root(cq, rq), rq);
}

static struct request *cpq_find_rq_rb(struct cpq_queue *cq, sector_t sector,
                                      enum cpq_data_dir dir)
{
	return elv_rb_find(&cq->sort_list[dir], sector);
}

/*
 * Get latter/former requests in rb tree
 */
static struct request *cpq_rb_latter_request(struct request_queue *q,
                                              struct request *rq)
{
	return elv_rb_latter_request(q, rq);
}

static struct request *cpq_rb_former_request(struct request_queue *q,
                                              struct request *rq)
{
	return elv_rb_former_request(q, rq);
}

/*
 * Remove request from queues
 */
static void cpq_remove_request(struct request_queue *q,
                               struct cpq_queue *cq,
                               struct request *rq)
{
	struct cpq_rq *crq = rq->elv.priv[0];

	list_del_init(&rq->queuelist);

	if (!RB_EMPTY_NODE(&rq->rb_node))
		cpq_del_rq_rb(cq, rq);

	if (crq && !hlist_unhashed(&crq->hash))
		hash_del(&crq->hash);

	elv_rqhash_del(q, rq);
	if (q->last_merge == rq)
		q->last_merge = NULL;
}

/*
 * True if group has any pending request, at any priority/direction.
 */
static bool cpq_group_has_work(struct cpq_data *cd, unsigned int group)
{
	int j, k;

	for (j = 0; j < CPQ_PRIO_LEVELS; j++) {
		struct cpq_queue *cq = &cd->groups[group].prio[j];

		for (k = 0; k < CPQ_DIR_COUNT; k++) {
			if (!list_empty(&cq->fifo_list[k]))
				return true;
		}
	}

	return false;
}

/*
 * Dispatch request with deadline and aging consideration
 */
static struct request *cpq_dispatch_request_from_queue(struct cpq_data *cd,
                                                        struct cpq_queue *cq,
                                                        unsigned long now)
{
	struct request *rq = NULL;
	struct cpq_rq *crq;
	int order[CPQ_DIR_COUNT];
	int dir, k;
	bool queue_hot;

	/* io_threshold gates the fast path: only a queue we issued from
	 * recently gets to skip straight to next_rq. 0 disables it. */
	queue_hot = cd->io_threshold &&
	            cq->last_issue &&
	            time_before(now, cq->last_issue +
	                         nsecs_to_jiffies(cd->io_threshold));

	if (queue_hot && cd->batching < cd->fifo_batch && cq->next_rq[cd->last_dir]) {
		dir = cd->last_dir;
		rq = cq->next_rq[dir];
		cq->next_rq[dir] = elv_rb_latter_request(rq->q, rq);
		cpq_remove_request(rq->q, cq, rq);
		cq->dispatched++;
		goto found;
	}

	/*
	 * Decide which direction to try first. Writes are starved of
	 * service by default (reads are always tried first below), so
	 * once cd->starved reaches cd->writes_starved we flip the order
	 * for this dispatch and let a write through. slice_idle damps
	 * that flip so it can't fire more than once per slice_idle.
	 */
	if (!list_empty(&cq->fifo_list[CPQ_WRITE]) &&
	    (list_empty(&cq->fifo_list[CPQ_READ]) ||
	     (cd->starved >= cd->writes_starved &&
	      time_after_eq(now, cd->dir_switch_time +
	                    nsecs_to_jiffies(cd->slice_idle))))) {
		order[0] = CPQ_WRITE;
		order[1] = CPQ_READ;
	} else {
		order[0] = CPQ_READ;
		order[1] = CPQ_WRITE;
	}

	for (k = 0; k < CPQ_DIR_COUNT; k++) {
		dir = order[k];

		if (list_empty(&cq->fifo_list[dir]))
			continue;

		/* Get first request in FIFO */
		rq = rq_entry_fifo(cq->fifo_list[dir].next);
		crq = rq->elv.priv[0];

		if (!crq)
			continue;

		/* Check if deadline expired or aged */
		if (time_after_eq(now, crq->deadline)) {
			cd->batching = 0;
			cq->next_rq[dir] = elv_rb_latter_request(rq->q, rq);
			cpq_remove_request(rq->q, cq, rq);
			cq->dispatched++;
			goto found;
		}

		/* Check priority aging */
		if (cd->prio_aging_expire && !crq->aged &&
		    time_after_eq(now, crq->issue_time + cd->prio_aging_expire)) {
			crq->aged = 1;
		}

		/* Try sector-ordered dispatch from rbtree */
		if (!RB_EMPTY_ROOT(&cq->sort_list[dir])) {
			struct rb_node *node = rb_first(&cq->sort_list[dir]);

			if (node) {
				rq = rb_entry_rq(node);
				cd->batching = 0;
				cq->next_rq[dir] = elv_rb_latter_request(rq->q, rq);
				cpq_remove_request(rq->q, cq, rq);
				cq->dispatched++;
				goto found;
			}
		}
	}

	return NULL;

found:
	if (dir == CPQ_WRITE)
		cd->starved = 0;
	else if (!list_empty(&cq->fifo_list[CPQ_WRITE]))
		cd->starved++;

	if (dir != cd->last_dir)
		cd->dir_switch_time = now;

	cd->last_dir = dir;
	cq->last_issue = now;
	return rq;
}

/*
 * Scan for requests that have aged past cd->prio_aging_expire in a
 * lower-than-RT queue and dispatch them ahead of strict group/priority
 * order, so continuous RT traffic can't starve BE/IDLE indefinitely.
 */
static struct request *cpq_dispatch_aged_requests(struct cpq_data *cd,
                                                   unsigned long now)
{
	struct request *rq;
	struct cpq_rq *crq;
	int i, j, dir;

	for (i = 0; i < CPQ_GROUPS; i++) {
		for (j = CPQ_PRIO_BE; j <= CPQ_PRIO_IDLE; j++) {
			struct cpq_queue *cq = &cd->groups[i].prio[j];

			for (dir = 0; dir < CPQ_DIR_COUNT; dir++) {
				if (list_empty(&cq->fifo_list[dir]))
					continue;

				rq = rq_entry_fifo(cq->fifo_list[dir].next);
				crq = rq->elv.priv[0];
				if (!crq)
					continue;

				if (cd->prio_aging_expire && !crq->aged &&
				    time_after_eq(now, crq->issue_time + cd->prio_aging_expire))
					crq->aged = 1;

				if (crq->aged) {
					cpq_remove_request(rq->q, cq, rq);
					cq->dispatched++;
					return rq;
				}
			}
		}
	}

	return NULL;
}

/*
 * Initialize scheduler
 */
static int cpq_init_sched(struct request_queue *q, struct elevator_type *e)
{
	struct cpq_data *cd;
	struct elevator_queue *eq;
	int i, j, k;

	eq = elevator_alloc(q, e);
	if (!eq)
		return -ENOMEM;

	cd = kzalloc(sizeof(*cd), GFP_KERNEL);
	if (!cd) {
		kobject_put(&eq->kobj);
		return -ENOMEM;
	}

	/* Initialize groups and queues */
	for (i = 0; i < CPQ_GROUPS; i++) {
		for (j = 0; j < CPQ_PRIO_LEVELS; j++) {
			for (k = 0; k < CPQ_DIR_COUNT; k++) {
				cd->groups[i].prio[j].sort_list[k] = RB_ROOT;
				INIT_LIST_HEAD(&cd->groups[i].prio[j].fifo_list[k]);
				cd->groups[i].prio[j].next_rq[k] = NULL;
			}
			cd->groups[i].prio[j].inserted = 0;
			cd->groups[i].prio[j].merged = 0;
			cd->groups[i].prio[j].dispatched = 0;
			atomic_set(&cd->groups[i].prio[j].completed, 0);
			cd->groups[i].prio[j].last_issue = jiffies;
		}
		cd->groups[i].batched = 0;
		cd->groups[i].starved = 0;
	}

	/* Initialize hash table */
	hash_init(cd->hash);

	/* Set group timeouts */
	cd->groups[CPQ_GROUP_FG].timeout = CPQ_FORE_TIMEOUT;
	cd->groups[CPQ_GROUP_BG].timeout = CPQ_BACK_TIMEOUT;

	spin_lock_init(&cd->lock);
	spin_lock_init(&cd->zone_lock);

	/* Initialize dispatch state */
	cd->batching = 0;
	cd->starved = 0;
	cd->last_dir = CPQ_WRITE;

	cd->active_group = CPQ_GROUP_FG;
	cd->group_switch_time = jiffies;
	cd->dir_switch_time = jiffies;

	/* Set tunables */
	cd->fifo_expire[CPQ_READ] = read_expire;
	cd->fifo_expire[CPQ_WRITE] = write_expire;
	cd->writes_starved = writes_starved;
	cd->front_merges = 1;
	cd->fifo_batch = fifo_batch;
	cd->prio_aging_expire = prio_aging_expire;
	cd->slice_idle = CPQ_SLICE_IDLE;
	cd->io_threshold = CPQ_IO_THRESHOLD;
	cd->async_depth = CPQ_ASYNC_DEPTH_MAX;
	cd->cpq_log = 0;

	eq->elevator_data = cd;
	q->elevator = eq;

	return 0;
}

/*
 * Exit scheduler
 */
static void cpq_exit_sched(struct elevator_queue *e)
{
	struct cpq_data *cd = e->elevator_data;
	int i, j;

	/* Verify queues are empty */
	for (i = 0; i < CPQ_GROUPS; i++) {
		for (j = 0; j < CPQ_PRIO_LEVELS; j++) {
			WARN_ON(!RB_EMPTY_ROOT(&cd->groups[i].prio[j].sort_list[0]));
			WARN_ON(!RB_EMPTY_ROOT(&cd->groups[i].prio[j].sort_list[1]));
			WARN_ON(!list_empty(&cd->groups[i].prio[j].fifo_list[0]));
			WARN_ON(!list_empty(&cd->groups[i].prio[j].fifo_list[1]));
		}
	}

	kfree(cd);
}

/*
 * 'depth' is a number in the range 1..INT_MAX representing a number of
 * requests. Scale it with a factor (1 << bt->sb.shift) / q->nr_requests
 * since 1..(1 << bt->sb.shift) is the range expected by
 * sbitmap_get_shallow(). Values larger than q->nr_requests have the same
 * effect as q->nr_requests. Mirrors mq-deadline's dd_to_word_depth().
 */
static int cpq_to_word_depth(struct blk_mq_hw_ctx *hctx, unsigned int qdepth)
{
	struct sbitmap_queue *bt = &hctx->sched_tags->bitmap_tags;
	const unsigned int nrr = hctx->queue->nr_requests;

	return ((qdepth << bt->sb.shift) + nrr - 1) / nrr;
}

/*
 * Compute async_depth from the current nr_requests. Called from
 * init_hctx() and from depth_updated() whenever nr_requests changes
 * via sysfs (blk_mq_update_nr_requests()).
 */
static void cpq_depth_updated(struct blk_mq_hw_ctx *hctx)
{
	struct cpq_data *cd = hctx->queue->elevator->elevator_data;
	unsigned int depth = hctx->queue->nr_requests;
	unsigned int shallow_depth = depth / 4;

	if (shallow_depth == 0)
		shallow_depth = 1;
	else if (shallow_depth > CPQ_ASYNC_DEPTH_MAX)
		shallow_depth = CPQ_ASYNC_DEPTH_MAX;

	cd->async_depth = shallow_depth;
	sbitmap_queue_min_shallow_depth(&hctx->sched_tags->bitmap_tags, 1);
}

/*
 * Initialize hardware context
 */
static int cpq_init_hctx(struct blk_mq_hw_ctx *hctx, unsigned int hctx_idx)
{
	cpq_depth_updated(hctx);
	return 0;
}

/*
 * Limit depth
 */
static void cpq_limit_depth(unsigned int op, struct blk_mq_alloc_data *data)
{
	struct cpq_data *cd = data->q->elevator->elevator_data;

	if (op_is_sync(op))
		return;

	data->shallow_depth = cpq_to_word_depth(data->hctx, cd->async_depth);
}

/*
 * Prepare request
 */
static void cpq_prepare_request(struct request *rq, struct bio *bio)
{
	struct cpq_rq *crq;

	crq = kzalloc(sizeof(*crq), GFP_ATOMIC);
	if (!crq) {
		rq->elv.priv[0] = NULL;
		return;
	}

	RB_CLEAR_NODE(&crq->rb_node);
	INIT_LIST_HEAD(&crq->fifo);
	INIT_HLIST_NODE(&crq->hash);

	crq->deadline = jiffies;
	crq->issue_time = jiffies;
	crq->aged = 0;
	crq->group = cpq_determine_group(rq);
	crq->prio = cpq_ioprio_class_to_prio(cpq_rq_ioclass(rq));

	rq->elv.priv[0] = crq;
}

/*
 * Finish request
 */
static void cpq_finish_request(struct request *rq)
{
	struct cpq_rq *crq = rq->elv.priv[0];
	struct cpq_data *cd;
	struct cpq_queue *cq;

	if (!crq)
		return;

	if (rq->q && rq->q->elevator) {
		cd = rq->q->elevator->elevator_data;
		cq = &cd->groups[crq->group].prio[crq->prio];
		atomic_inc(&cq->completed);
	}

	kfree(crq);
	rq->elv.priv[0] = NULL;
}

/*
 * Insert requests
 */
static void cpq_insert_requests(struct blk_mq_hw_ctx *hctx,
                                struct list_head *list, bool at_head)
{
	struct request_queue *q = hctx->queue;
	struct cpq_data *cd = q->elevator->elevator_data;
	struct request *rq, *next;
	unsigned long flags;

	spin_lock_irqsave(&cd->lock, flags);

	list_for_each_entry_safe(rq, next, list, queuelist) {
		struct cpq_rq *crq = rq->elv.priv[0];
		const enum cpq_data_dir dir = rq_data_dir(rq);
		struct cpq_queue *cq;

		if (!crq) {
			list_del_init(&rq->queuelist);
			blk_mq_request_bypass_insert(rq, false);
			continue;
		}

		cq = &cd->groups[crq->group].prio[crq->prio];

		list_del_init(&rq->queuelist);

		cpq_add_rq_rb(cq, rq);

		if (rq_mergeable(rq)) {
			elv_rqhash_add(q, rq);
			hash_add(cd->hash, &crq->hash, blk_rq_pos(rq));
		}

		if (!q->last_merge)
			q->last_merge = rq;

		rq->fifo_time = jiffies + cd->fifo_expire[dir];
		crq->deadline = rq->fifo_time;

		if (at_head)
			list_add(&rq->queuelist, &cq->fifo_list[dir]);
		else
			list_add_tail(&rq->queuelist, &cq->fifo_list[dir]);

		cq->inserted++;
	}

	spin_unlock_irqrestore(&cd->lock, flags);
}

/*
 * Dispatch request with full logic
 */
static struct request *cpq_dispatch_request(struct blk_mq_hw_ctx *hctx)
{
	struct request_queue *q = hctx->queue;
	struct cpq_data *cd = q->elevator->elevator_data;
	struct request *rq = NULL;
	unsigned long flags;
	unsigned long now = jiffies;
	unsigned int group_order[CPQ_GROUPS];
	unsigned int active, other, gi, i, j;
	bool active_timed_out;

	spin_lock_irqsave(&cd->lock, flags);

	/* Requests that aged past prio_aging_expire bypass strict order */
	rq = cpq_dispatch_aged_requests(cd, now);
	if (rq) {
		cd->batching++;
		goto out;
	}

	/* FG serviced first by default; once it holds past its own
	 * fore_timeout/back_timeout and BG actually has work, let BG in. */
	active = cd->active_group;
	other = active ^ 1;
	active_timed_out = time_after_eq(now, cd->group_switch_time +
	                                  cd->groups[active].timeout);

	if (active_timed_out && cpq_group_has_work(cd, other)) {
		group_order[0] = other;
		group_order[1] = active;
	} else {
		group_order[0] = active;
		group_order[1] = other;
	}

	/* Try to dispatch from queues with priority and aging */
	for (gi = 0; gi < CPQ_GROUPS; gi++) {
		i = group_order[gi];

		for (j = 0; j < CPQ_PRIO_LEVELS; j++) {
			struct cpq_queue *cq = &cd->groups[i].prio[j];

			rq = cpq_dispatch_request_from_queue(cd, cq, now);
			if (rq) {
				if (i != cd->active_group) {
					cd->groups[cd->active_group].starved++;
					cd->active_group = i;
					cd->group_switch_time = now;
					cd->groups[i].batched = 0;
				} else {
					cd->groups[i].batched++;
				}

				cd->batching++;
				goto out;
			}
		}
	}

out:
	spin_unlock_irqrestore(&cd->lock, flags);
	return rq;
}

/*
 * Has work
 */
static bool cpq_has_work(struct blk_mq_hw_ctx *hctx)
{
	struct cpq_data *cd = hctx->queue->elevator->elevator_data;
	int i, j, k;

	for (i = 0; i < CPQ_GROUPS; i++) {
		for (j = 0; j < CPQ_PRIO_LEVELS; j++) {
			for (k = 0; k < CPQ_DIR_COUNT; k++) {
				if (!list_empty(&cd->groups[i].prio[j].fifo_list[k]))
					return true;
			}
		}
	}

	return false;
}

/*
 * Bio merge - opportunistic front/back merge at bio submission time,
 * before a request is allocated. Without this hook blk_mq_sched_bio_merge()
 * always returns false and every bio ends up as its own request.
 */
static bool cpq_bio_merge(struct blk_mq_hw_ctx *hctx, struct bio *bio)
{
	struct request_queue *q = hctx->queue;
	struct cpq_data *cd = q->elevator->elevator_data;
	struct request *free = NULL;
	bool ret;

	spin_lock(&cd->lock);
	ret = blk_mq_sched_try_merge(q, bio, &free);
	spin_unlock(&cd->lock);

	if (free)
		blk_mq_free_request(free);

	return ret;
}

/*
 * Request merge
 */
static int cpq_request_merge(struct request_queue *q, struct request **req,
                             struct bio *bio)
{
	struct cpq_data *cd = q->elevator->elevator_data;
	sector_t sector = bio_end_sector(bio);
	const u8 ioclass = IOPRIO_PRIO_CLASS(bio->bi_ioprio);
	const unsigned int prio = cpq_ioprio_class_to_prio(ioclass);
	int dir = bio_data_dir(bio);
	struct request *__rq;
	int i;

	if (!cd->front_merges)
		return ELEVATOR_NO_MERGE;

	/* Try both groups */
	for (i = 0; i < CPQ_GROUPS; i++) {
		struct cpq_queue *cq = &cd->groups[i].prio[prio];

		__rq = cpq_find_rq_rb(cq, sector, dir);
		if (__rq) {
			BUG_ON(sector != blk_rq_pos(__rq));
			if (elv_bio_merge_ok(__rq, bio)) {
				*req = __rq;
				if (req_op(__rq) == REQ_OP_DISCARD)
					return ELEVATOR_DISCARD_MERGE;
				return ELEVATOR_FRONT_MERGE;
			}
		}
	}

	return ELEVATOR_NO_MERGE;
}

/*
 * Request merged
 */
static void cpq_request_merged(struct request_queue *q, struct request *req,
                               enum elv_merge type)
{
	struct cpq_data *cd = q->elevator->elevator_data;
	struct cpq_rq *crq = req->elv.priv[0];
	struct cpq_queue *cq;

	if (!crq)
		return;

	cq = &cd->groups[crq->group].prio[crq->prio];

	if (type == ELEVATOR_FRONT_MERGE) {
		elv_rb_del(cpq_rb_root(cq, req), req);
		cpq_add_rq_rb(cq, req);
	}
}

/*
 * Requests merged
 */
static void cpq_merged_requests(struct request_queue *q, struct request *rq,
                                struct request *next)
{
	struct cpq_data *cd = q->elevator->elevator_data;
	struct cpq_rq *crq_next = next->elv.priv[0];
	struct cpq_queue *cq;

	if (!crq_next)
		return;

	cq = &cd->groups[crq_next->group].prio[crq_next->prio];

	cpq_remove_request(q, cq, next);
	cq->merged++;
}

/*
 * Sysfs attributes
 */
#define SHOW_FUNCTION(__FUNC, __VAR, __CONV)                           \
static ssize_t __FUNC(struct elevator_queue *e, char *page)           \
{                                                                      \
	struct cpq_data *cd = e->elevator_data;                        \
	int __data = __VAR;                                            \
	if (__CONV)                                                    \
		__data = jiffies_to_msecs(__data);                     \
	return scnprintf(page, PAGE_SIZE, "%d\n", __data);             \
}

#define STORE_FUNCTION(__FUNC, __PTR, MIN, MAX, __CONV)                \
static ssize_t __FUNC(struct elevator_queue *e, const char *page,     \
                      size_t count)                                    \
{                                                                      \
	struct cpq_data *cd = e->elevator_data;                        \
	int __data;                                                    \
	int ret = kstrtoint(page, 0, &__data);                         \
	if (ret < 0)                                                   \
		return ret;                                            \
	if (__data < (MIN))                                            \
		__data = (MIN);                                        \
	else if (__data > (MAX))                                       \
		__data = (MAX);                                        \
	if (__CONV)                                                    \
		*(__PTR) = msecs_to_jiffies(__data);                   \
	else                                                           \
		*(__PTR) = __data;                                     \
	return count;                                                  \
}

SHOW_FUNCTION(cpq_read_expire_show, cd->fifo_expire[CPQ_READ], 1);
STORE_FUNCTION(cpq_read_expire_store, &cd->fifo_expire[CPQ_READ], 0, INT_MAX, 1);
SHOW_FUNCTION(cpq_write_expire_show, cd->fifo_expire[CPQ_WRITE], 1);
STORE_FUNCTION(cpq_write_expire_store, &cd->fifo_expire[CPQ_WRITE], 0, INT_MAX, 1);
SHOW_FUNCTION(cpq_writes_starved_show, cd->writes_starved, 0);
STORE_FUNCTION(cpq_writes_starved_store, &cd->writes_starved, 0, INT_MAX, 0);
SHOW_FUNCTION(cpq_front_merges_show, cd->front_merges, 0);
STORE_FUNCTION(cpq_front_merges_store, &cd->front_merges, 0, 1, 0);
SHOW_FUNCTION(cpq_fifo_batch_show, cd->fifo_batch, 0);
STORE_FUNCTION(cpq_fifo_batch_store, &cd->fifo_batch, 0, INT_MAX, 0);
SHOW_FUNCTION(cpq_async_depth_show, cd->async_depth, 0);
STORE_FUNCTION(cpq_async_depth_store, &cd->async_depth, 1, INT_MAX, 0);
SHOW_FUNCTION(cpq_prio_aging_expire_show, cd->prio_aging_expire, 1);
STORE_FUNCTION(cpq_prio_aging_expire_store, &cd->prio_aging_expire, 0, INT_MAX, 1);

/* Fore timeout */
static ssize_t cpq_fore_timeout_show(struct elevator_queue *e, char *page)
{
	struct cpq_data *cd = e->elevator_data;
	return scnprintf(page, PAGE_SIZE, "%d\n",
	                  jiffies_to_msecs(cd->groups[CPQ_GROUP_FG].timeout));
}

static ssize_t cpq_fore_timeout_store(struct elevator_queue *e,
                                      const char *page, size_t count)
{
	struct cpq_data *cd = e->elevator_data;
	int data;
	int ret = kstrtoint(page, 0, &data);

	if (ret < 0)
		return ret;

	cd->groups[CPQ_GROUP_FG].timeout = msecs_to_jiffies(data);
	return count;
}

/* Back timeout */
static ssize_t cpq_back_timeout_show(struct elevator_queue *e, char *page)
{
	struct cpq_data *cd = e->elevator_data;
	return scnprintf(page, PAGE_SIZE, "%d\n",
	                  jiffies_to_msecs(cd->groups[CPQ_GROUP_BG].timeout));
}

static ssize_t cpq_back_timeout_store(struct elevator_queue *e,
                                      const char *page, size_t count)
{
	struct cpq_data *cd = e->elevator_data;
	int data;
	int ret = kstrtoint(page, 0, &data);

	if (ret < 0)
		return ret;

	cd->groups[CPQ_GROUP_BG].timeout = msecs_to_jiffies(data);
	return count;
}

/* Slice idle */
static ssize_t cpq_slice_idle_show(struct elevator_queue *e, char *page)
{
	struct cpq_data *cd = e->elevator_data;
	return scnprintf(page, PAGE_SIZE, "%llu\n", cd->slice_idle / 1000);
}

static ssize_t cpq_slice_idle_store(struct elevator_queue *e,
                                    const char *page, size_t count)
{
	struct cpq_data *cd = e->elevator_data;
	u64 data;
	int ret = kstrtou64(page, 0, &data);

	if (ret < 0)
		return ret;

	cd->slice_idle = data * 1000;
	return count;
}

/* IO threshold */
static ssize_t cpq_io_threshold_show(struct elevator_queue *e, char *page)
{
	struct cpq_data *cd = e->elevator_data;
	return scnprintf(page, PAGE_SIZE, "%llu\n", cd->io_threshold);
}

static ssize_t cpq_io_threshold_store(struct elevator_queue *e,
                                      const char *page, size_t count)
{
	struct cpq_data *cd = e->elevator_data;
	u64 data;
	int ret = kstrtou64(page, 0, &data);

	if (ret < 0)
		return ret;

	cd->io_threshold = data;
	return count;
}

/* CPQ log */
static ssize_t cpq_cpq_log_show(struct elevator_queue *e, char *page)
{
	struct cpq_data *cd = e->elevator_data;
	return scnprintf(page, PAGE_SIZE, "%u\n", cd->cpq_log);
}

static ssize_t cpq_cpq_log_store(struct elevator_queue *e,
                                 const char *page, size_t count)
{
	struct cpq_data *cd = e->elevator_data;
	unsigned int data;
	int ret = kstrtouint(page, 0, &data);

	if (ret < 0)
		return ret;

	cd->cpq_log = (data != 0);
	return count;
}

#undef SHOW_FUNCTION
#undef STORE_FUNCTION

#define CPQ_ATTR(name) \
	__ATTR(name, 0644, cpq_##name##_show, cpq_##name##_store)

static struct elv_fs_entry cpq_attrs[] = {
	CPQ_ATTR(read_expire),
	CPQ_ATTR(write_expire),
	CPQ_ATTR(writes_starved),
	CPQ_ATTR(front_merges),
	CPQ_ATTR(fifo_batch),
	CPQ_ATTR(async_depth),
	CPQ_ATTR(prio_aging_expire),
	CPQ_ATTR(fore_timeout),
	CPQ_ATTR(back_timeout),
	CPQ_ATTR(slice_idle),
	CPQ_ATTR(io_threshold),
	CPQ_ATTR(cpq_log),
	__ATTR_NULL
};

/*
 * Elevator type
 */
static struct elevator_type cpq_mq = {
	.ops.mq = {
		.limit_depth = cpq_limit_depth,
		.depth_updated = cpq_depth_updated,
		.insert_requests = cpq_insert_requests,
		.dispatch_request = cpq_dispatch_request,
		.prepare_request = cpq_prepare_request,
		.finish_request = cpq_finish_request,
		.next_request = cpq_rb_latter_request,
		.former_request = cpq_rb_former_request,
		.bio_merge = cpq_bio_merge,
		.request_merge = cpq_request_merge,
		.requests_merged = cpq_merged_requests,
		.request_merged = cpq_request_merged,
		.has_work = cpq_has_work,
		.init_sched = cpq_init_sched,
		.exit_sched = cpq_exit_sched,
		.init_hctx = cpq_init_hctx,
	},
	.uses_mq = true,
	.elevator_attrs = cpq_attrs,
	.elevator_name = "cpq",
	.elevator_owner = THIS_MODULE,
};

static int __init cpq_init(void)
{
	return elv_register(&cpq_mq);
}

static void __exit cpq_exit(void)
{
	elv_unregister(&cpq_mq);
}

module_init(cpq_init);
module_exit(cpq_exit);

MODULE_AUTHOR("Rasenkai");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("CPQ I/O Scheduler");
MODULE_VERSION("2.0");
