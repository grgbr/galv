/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "galv/buffer.h"
#include "common.h"
#include <stroll/palloc.h>
#include <stroll/falloc.h>
#include <stroll/lalloc.h>

/******************************************************************************
 * Network buffer allocator handling
 ******************************************************************************/

#define galv_buff_assert_alloc_intern(_alloc) \
	galv_assert_intern((_alloc)->stroll); \
	galv_assert_intern((_alloc)->capa >= STROLL_BUFF_CAPACITY_MIN); \
	galv_assert_intern((_alloc)->capa <= STROLL_BUFF_CAPACITY_MAX)

static
struct galv_buff *
galv_buff_alloc(struct galv_buff_alloc * __restrict alloc)
{
	galv_buff_assert_alloc_intern(alloc);

	return stroll_alloc(alloc->stroll);
}

static
void
galv_buff_free(struct galv_buff_alloc * __restrict alloc,
               struct galv_buff * __restrict       buffer)
{
	galv_buff_assert_alloc_intern(alloc);
	galv_assert_intern(buffer);

	return stroll_free(alloc->stroll, buffer);
}

int
galv_buff_init_palloc(struct galv_buff_alloc * __restrict alloc,
                      unsigned int                        nr,
                      size_t                              size)
{
	galv_assert_api(alloc);
	galv_assert_api(nr);
	galv_assert_api(size);

	struct stroll_alloc * stroll;

	stroll = stroll_palloc_create_alloc(nr,
	                                    sizeof(struct galv_buff) + size);
	if (!stroll)
		return -errno;

	alloc->stroll = stroll;
	alloc->capa = size;

	return 0;
}

int
galv_buff_init_falloc(struct galv_buff_alloc * __restrict alloc,
                      unsigned int                        nr,
                      unsigned int                        per_block,
                      size_t                              size)
{
	galv_assert_api(alloc);
	galv_assert_api(nr);
	galv_assert_api(per_block);
	galv_assert_api(nr > per_block);
	galv_assert_api(size);

	struct stroll_alloc * stroll;

	stroll = stroll_falloc_create_alloc(nr,
	                                    per_block,
	                                    sizeof(struct galv_buff) + size);
	if (!stroll)
		return -errno;

	alloc->stroll = stroll;
	alloc->capa = size;

	return 0;
}

int
galv_buff_init_lalloc(struct galv_buff_alloc * __restrict alloc,
                      unsigned int                        nr,
                      size_t                              size)
{
	galv_assert_api(alloc);
	galv_assert_api(nr);
	galv_assert_api(size);

	struct stroll_alloc * stroll;

	stroll = stroll_lalloc_create_alloc(nr,
	                                    sizeof(struct galv_buff) + size);
	if (!stroll)
		return -errno;

	alloc->stroll = stroll;
	alloc->capa = size;

	return 0;
}

/******************************************************************************
 * Network buffer queue handling
 ******************************************************************************/

static
void
galv_buff_grow_queue(struct galv_buff_queue * __restrict queue, size_t bytes)
{
	galv_buff_assert_queue_api(queue);
	galv_assert_api(!galv_buff_queue_empty(queue));
	galv_assert_api(queue->cnt);
	galv_assert_api(queue->busy);

	queue->busy += bytes;
}

static
void
galv_buff_shrink_queue(struct galv_buff_queue * __restrict queue, size_t bytes)
{
	galv_buff_assert_queue_api(queue);
	galv_assert_api(!galv_buff_queue_empty(queue));
	galv_assert_api(queue->cnt);
	galv_assert_api(queue->busy);
	galv_assert_api(bytes <= queue->busy);

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
	galv_assert_api(!galv_buff_queue_empty(queue));
	galv_assert_api(queue->cnt);

	struct galv_buff * buff;

	buff = stroll_slist_entry(stroll_slist_dqueue_front(&queue->base),
	                          struct galv_buff,
	                          queue);
	galv_buff_assert_api(buff);
	galv_assert_api(galv_buff_busy(buff) <= queue->busy);
	galv_assert_api(buff->queue);

	queue->cnt--;
	queue->busy -= galv_buff_busy(buff);

	buff->queue = NULL;

	return buff;
}

/******************************************************************************
 * Network buffer handling
 ******************************************************************************/

void
galv_buff_grow_tail(struct galv_buff * __restrict buffer, size_t bytes)
{
	galv_buff_assert_api(buffer);
	galv_assert_api(bytes <= galv_buff_avail_tail(buffer));

	stroll_buff_grow_tail(&buffer->base, bytes);

	if (buffer->queue)
		galv_buff_grow_queue(buffer->queue, bytes);
}

void
galv_buff_grow_head(struct galv_buff * __restrict buffer, size_t bytes)
{
	galv_buff_assert_api(buffer);
	galv_assert_api(bytes <= galv_buff_busy(buffer));

	stroll_buff_grow_head(&buffer->base, bytes);

	if (buffer->queue)
		galv_buff_shrink_queue(buffer->queue, bytes);
}

struct galv_buff *
galv_buff_summon(struct galv_buff_alloc * __restrict alloc)
{
	galv_buff_assert_alloc_intern(alloc);

	struct galv_buff * buff;

	buff = galv_buff_alloc(alloc);
	if (!buff)
		return NULL;

	stroll_buff_setup(&buff->base, galv_buff_alloc_capacity(alloc), 0, 0);
	buff->queue = NULL;
	buff->ref = 1;
	buff->alloc = alloc;

	return buff;
}

void
galv_buff_release(struct galv_buff * __restrict buffer)
{
	galv_buff_assert_api(buffer);
	galv_assert_api(!buffer->queue);

	if (!(--buffer->ref))
		galv_buff_free(buffer->alloc, buffer);
}
