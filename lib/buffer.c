/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "galv/buffer.h"
#include "common.h"

/******************************************************************************
 * Network buffer queue handling
 ******************************************************************************/

#define galv_buff_assert_queue_intern(_queue) \
	galv_assert_intern(_queue); \
	galv_assert_intern((_queue)->cnt ^ \
	                   stroll_slist_empty(&(_queue)->base)); \
	galv_assert_intern(!((_queue)->busy && !(_queue)->cnt))

static
void
galv_buff_grow_queue(struct galv_buff_queue * __restrict queue, size_t bytes)
{
	galv_buff_assert_queue_intern(queue);
	galv_assert_intern(!stroll_slist_empty(&queue->base));
	galv_assert_intern(queue->cnt);

	queue->busy += bytes;
}

static
void
galv_buff_shrink_queue(struct galv_buff_queue * __restrict queue, size_t bytes)
{
	galv_buff_assert_queue_intern(queue);
	galv_assert_intern(!stroll_slist_empty(&queue->base));
	galv_assert_intern(queue->cnt);
	galv_assert_intern(bytes <= queue->busy);

	queue->busy -= bytes;
}

void
galv_buff_nqueue(struct galv_buff_queue * __restrict queue,
                 struct galv_buff * __restrict       buffer)
{
	galv_buff_assert_queue_api(queue);
	galv_buff_assert_api(buffer);
	galv_assert_api(!buffer->queue);

	stroll_slist_nqueue_back(&queue->base, &buffer->node);

	queue->cnt++;
	queue->busy += galv_buff_busy(buffer);

	buffer->queue = queue;
}

struct galv_buff *
galv_buff_dqueue(struct galv_buff_queue * __restrict queue)
{
	galv_buff_assert_queue_api(queue);
	galv_assert_api(!stroll_slist_empty(&queue->base));
	galv_assert_api(queue->cnt);

	struct galv_buff * buff;

	buff = stroll_slist_entry(stroll_slist_dqueue_front(&queue->base),
	                          struct galv_buff,
	                          node);
	galv_buff_assert_api(buff);
	galv_assert_api(galv_buff_busy(buff) <= queue->busy);
	galv_assert_api(buff->queue);

	queue->cnt--;
	queue->busy -= galv_buff_busy(buff);

	buff->queue = NULL;

	return buff;
}

void
galv_buff_join_queue(struct galv_buff_queue * __restrict destination,
                     struct stroll_slist * __restrict    source)
{
	galv_buff_assert_queue_api(destination);
	galv_assert_api(!stroll_slist_empty(source));

	if (!stroll_slist_empty(source)) {
		struct galv_buff * buff;
		unsigned int       cnt = 0;
		size_t             busy = 0;

		stroll_slist_foreach_entry(source, buff, node) {
			galv_buff_assert_api(buff);
			galv_assert_api(galv_buff_busy(buff));

			buff->queue = destination;
			busy += galv_buff_busy(buff);
			cnt++;
		}

		stroll_slist_splice(&destination->base,
		                    stroll_slist_last(&destination->base),
		                    source,
		                    stroll_slist_first(source),
		                    stroll_slist_last(source));
		destination->cnt += cnt;
		destination->busy += busy;
	}
}

/******************************************************************************
 * Network buffer handling
 ******************************************************************************/

void
galv_buff_grow_tail(struct galv_buff * __restrict buffer, size_t bytes)
{
	galv_buff_assert_api(buffer);
	galv_assert_api(bytes <= galv_buff_avail_tail(buffer));

	if (buffer->queue)
		galv_buff_grow_queue(buffer->queue, bytes);

	stroll_buff_grow_tail(&buffer->base, bytes);
}

void
galv_buff_grow_head(struct galv_buff * __restrict buffer, size_t bytes)
{
	galv_buff_assert_api(buffer);
	galv_assert_api(bytes <= galv_buff_busy(buffer));

	if (buffer->queue)
		galv_buff_shrink_queue(buffer->queue, bytes);

	stroll_buff_grow_head(&buffer->base, bytes);
}

void
galv_buff_reset(struct galv_buff * __restrict buffer)
{
	galv_buff_assert_api(buffer);

	if (buffer->queue)
		galv_buff_shrink_queue(buffer->queue,
		                       stroll_buff_busy(&buffer->base));

	stroll_buff_setup(&buffer->base,
	                  stroll_buff_capacity(&buffer->base),
	                  0,
	                  0);
}

struct galv_buff *
galv_buff_summon(struct stroll_falloc * __restrict alloc, size_t capacity)
{
	galv_assert_api(alloc);
	galv_assert_api((capacity + sizeof(struct galv_buff)) <=
	                stroll_falloc_chunk_size(alloc));

	struct galv_buff * buff;

	buff = stroll_falloc_alloc(alloc);
	if (!buff)
		return NULL;

	stroll_buff_setup(&buff->base,
	                  capacity ? capacity
	                           : stroll_falloc_chunk_size(alloc) -
	                             sizeof(struct galv_buff),
	                  0,
	                  0);
	buff->queue = NULL;
	buff->ref = 1;
	buff->alloc = alloc;

	return buff;
}

unsigned long
galv_buff_release(struct galv_buff * __restrict buffer)
{
	galv_buff_assert_api(buffer);

	unsigned long ref = --buffer->ref;

	if (!ref) {
		galv_assert_api(!buffer->queue);
		stroll_falloc_free(buffer->alloc, buffer);
	}

	return ref;
}
