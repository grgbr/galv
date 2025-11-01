/****************************************************************************** 
* SPDX-License-Identifier: LGPL-3.0-only
*
* This file is part of Galv.
* Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
*******************************************************************************/

/**
 * @file
 * Buffer interface
 *
 * @author    Grégor Boirie <gregor.boirie@free.fr>
 * @date      26 Oct 2025
 * @copyright Copyright (C) 2024 Grégor Boirie.
 * @license   [GNU Lesser General Public License (LGPL) v3]
 *            (https://www.gnu.org/licenses/lgpl+gpl-3.0.txt)
 */

#ifndef _GALV_BUFFER_H
#define _GALV_BUFFER_H

#include <galv/cdefs.h>
#include <stroll/buffer.h>
#include <stroll/slist.h>
#include <stroll/lalloc.h>

/**
 * Core network buffer fabric.
 */
struct galv_buff_fabric {
	struct stroll_lalloc base;
	size_t               capa;
};

#define galv_buff_fabric_assert_api(_fabric) \
	galv_assert_api(_fabric); \
	galv_assert_api((_fabric)->capa >= STROLL_BUFF_CAPACITY_MIN); \
	galv_assert_api((_fabric)->capa <= STROLL_BUFF_CAPACITY_MAX)

static inline
size_t
galv_buff_fabric_capacity(const struct galv_buff_fabric * __restrict fabric)
{
	galv_buff_fabric_assert_api(fabric);

	return fabric->capa;
}

extern int
galv_buff_init_fabric(struct galv_buff_fabric * __restrict fabric,
                      unsigned int                         nr,
                      size_t                               capacity)
	__export_public;

extern void
galv_buff_fini_fabric(struct galv_buff_fabric * __restrict fabric)
	__export_public;

/**
 * Core network buffer.
 *
 * A reference counted queueable contiguous memory area.
 */
struct galv_buff {
	struct stroll_buff        base;
	struct stroll_slist_node  queue;
	unsigned long             ref;
	struct galv_buff_fabric * fabric;
	uint8_t                   mem[0];
};

#define galv_buff_assert_api(_buff) \
	galv_assert_api(_buff); \
	galv_assert_api((_buff)->ref); \
	galv_assert_api((_buff)->fabric); \
	galv_assert_api(stroll_buff_capacity(&(_buff)->base) == \
	                galv_buff_fabric_capacity((_buff)->fabric))

static inline
size_t
galv_buff_capacity(const struct galv_buff * __restrict buffer)
{
	galv_buff_assert_api(buffer);

	return stroll_buff_capacity(&buffer->base);
}

static inline
uint8_t *
galv_buff_mem(const struct galv_buff * __restrict buffer)
{
	galv_buff_assert_api(buffer);

STROLL_IGNORE_WARN("-Wcast-qual")
	return (uint8_t *)buffer->mem;
STROLL_RESTORE_WARN
}

static inline
size_t
galv_buff_busy(const struct galv_buff * __restrict buffer)
{
	galv_buff_assert_api(buffer);

	return stroll_buff_busy(&buffer->base);
}

static inline
uint8_t *
galv_buff_data(const struct galv_buff * __restrict buffer)
{
	galv_buff_assert_api(buffer);
	galv_assert_api(galv_buff_busy(buffer));

	return stroll_buff_data(&buffer->base, buffer->mem);
}

static inline
size_t
galv_buff_avail_tail(const struct galv_buff * __restrict buffer)
{
	galv_buff_assert_api(buffer);

	return stroll_buff_avail_tail(&buffer->base);
}

static inline
void
galv_buff_grow_tail(struct galv_buff * __restrict buffer, size_t bytes)
{
	galv_buff_assert_api(buffer);
	galv_assert_api(bytes <= galv_buff_avail_tail(buffer));

	return stroll_buff_grow_tail(&buffer->base, bytes);
}

static inline
uint8_t *
galv_buff_tail(const struct galv_buff * __restrict buffer)
{
	galv_buff_assert_api(buffer);
	galv_assert_api(galv_buff_avail_tail(buffer) > 0);

	return stroll_buff_tail(&buffer->base, buffer->mem);
}

static inline
size_t
galv_buff_avail_head(const struct galv_buff * __restrict buffer)
{
	galv_buff_assert_api(buffer);

	return stroll_buff_avail_head(&buffer->base);
}

static inline
void
galv_buff_grow_head(struct galv_buff * __restrict buffer, size_t bytes)
{
	galv_buff_assert_api(buffer);
	galv_assert_api(bytes <= galv_buff_busy(buffer));

	return stroll_buff_grow_head(&buffer->base, bytes);
}

static inline
struct galv_buff *
galv_buff_next(struct galv_buff * __restrict buffer)
{
	struct stroll_slist_node * next = stroll_slist_next(&buffer->queue);

	return next ? stroll_slist_entry(next, struct galv_buff, queue) : NULL;
}

static inline
struct galv_buff *
galv_buff_acquire(struct galv_buff * __restrict buffer)
{
	galv_buff_assert_api(buffer);

	buffer->ref++;

	return buffer;
}

extern void
galv_buff_release(struct galv_buff * __restrict buffer)
	__export_public;

extern struct galv_buff *
galv_buff_summon(struct galv_buff_fabric * __restrict fabric)
	__export_public;

/**
 * Core network buffer queue
 */
struct galv_buff_queue {
	struct stroll_slist base;
	size_t              busy;
};

#define galv_buff_queue_assert_api(_buffq) \
	galv_assert_api(_buffq); \
	galv_assert_api((_buffq)->busy ^ stroll_slist_empty(&(_buffq)->base))

static inline
size_t
galv_buff_queue_busy(const struct galv_buff_queue * __restrict queue)
{
	galv_buff_queue_assert_api(queue);

	return queue->busy;
}

static inline
bool
galv_buff_queue_empty(const struct galv_buff_queue * __restrict queue)
{
	galv_buff_queue_assert_api(queue);

	return stroll_slist_empty(&queue->base);
}

static inline
struct galv_buff *
galv_buff_queue_first(const struct galv_buff_queue * __restrict queue)
{
	galv_buff_queue_assert_api(queue);
	galv_assert_api(!galv_buff_queue_empty(queue));
	galv_assert_api(queue->busy);

	return stroll_slist_first_entry(&queue->base, struct galv_buff, queue);
}

static inline
struct galv_buff *
galv_buff_queue_last(const struct galv_buff_queue * __restrict queue)
{
	galv_buff_queue_assert_api(queue);
	galv_assert_api(!galv_buff_queue_empty(queue));
	galv_assert_api(queue->busy);

	return stroll_slist_last_entry(&queue->base, struct galv_buff, queue);
}

static inline
void
galv_buff_grow_queue(struct galv_buff_queue * __restrict queue,
                     size_t                              bytes)
{
	galv_buff_queue_assert_api(queue);
	galv_assert_api(bytes);
	galv_assert_api((queue->busy + bytes) > queue->busy);

	queue->busy += bytes;
}

static inline
void
galv_buff_shrink_queue(struct galv_buff_queue * __restrict queue,
                       size_t                              bytes)
{
	galv_buff_queue_assert_api(queue);
	galv_assert_api(bytes);
	galv_assert_api(bytes <= queue->busy);

	queue->busy -= bytes;
}

extern void
galv_buff_nqueue(struct galv_buff_queue * __restrict queue,
                 struct galv_buff * __restrict       buffer)
	__export_public;

extern struct galv_buff *
galv_buff_dqueue(struct galv_buff_queue * __restrict queue)
	__export_public;

static inline
void
galv_buff_init_queue(struct galv_buff_queue * __restrict queue)
{
	galv_assert_api(queue);

	stroll_slist_init(&queue->base);
	queue->busy = 0;
}

static inline
void
galv_buff_fini_queue(struct galv_buff_queue * __restrict queue)
{
	galv_buff_queue_assert_api(queue);
	galv_assert_api(galv_buff_queue_empty(queue));
	galv_assert_api(!queue->busy);
}

#endif /* _GALV_BUFFER_H */
