/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "common.h"
#include "galv/buffer.h"

#define galv_buff_fabric_assert_intern(_fabric) \
	galv_assert_intern(_fabric); \
	galv_assert_intern((_fabric)->capa >= STROLL_BUFF_CAPACITY_MIN); \
	galv_assert_intern((_fabric)->capa <= STROLL_BUFF_CAPACITY_MAX)

static
struct galv_buff *
galv_buff_fabric_alloc(struct galv_buff_fabric * __restrict fabric)
{
	galv_buff_fabric_assert_intern(fabric);

	return stroll_lalloc_alloc(&fabric->base);
}

static
void
galv_buff_fabric_free(struct galv_buff_fabric * __restrict fabric,
                      struct galv_buff * __restrict        buffer)
{
	galv_buff_fabric_assert_intern(fabric);
	galv_assert_intern(buffer);

	stroll_lalloc_free(&fabric->base, buffer);
}

int
galv_buff_init_fabric(struct galv_buff_fabric * __restrict fabric,
                      unsigned int                         nr,
                      size_t                               capacity)
{
	galv_assert_api(fabric);
	galv_assert_api(nr);
	galv_assert_api(capacity >= STROLL_BUFF_CAPACITY_MIN);
	galv_assert_api(capacity <= STROLL_BUFF_CAPACITY_MAX);

	int err;

	err = stroll_lalloc_init(&fabric->base,
	                         nr,
	                         sizeof(struct galv_buff) + capacity);
	if (err)
		return err;

	fabric->capa = capacity;

	return 0;
}

void
galv_buff_fini_fabric(struct galv_buff_fabric * __restrict fabric)
{
	galv_buff_fabric_assert_api(fabric);

	stroll_lalloc_fini(&fabric->base);
}

struct galv_buff *
galv_buff_summon(struct galv_buff_fabric * __restrict fabric)
{
	galv_buff_fabric_assert_api(fabric);

	struct galv_buff * buff;

	buff = galv_buff_fabric_alloc(fabric);
	if (!buff)
		return NULL;

	stroll_buff_setup(&buff->base, galv_buff_fabric_capacity(fabric), 0, 0);
	buff->ref = 1;
	buff->fabric = fabric;

	return buff;
}

void
galv_buff_release(struct galv_buff * __restrict buffer)
{
	galv_buff_assert_api(buffer);

	if (!(--buffer->ref))
		galv_buff_fabric_free(buffer->fabric, buffer);
}

void
galv_buff_nqueue(struct galv_buff_queue * __restrict queue,
                 struct galv_buff * __restrict       buffer)
{
	galv_assert_api(queue);
	galv_assert_api(buffer);

	galv_buff_acquire(buffer);
	stroll_slist_nqueue_back(&queue->base, &buffer->queue);
}

struct galv_buff *
galv_buff_dqueue(struct galv_buff_queue * __restrict queue)
{
	galv_assert_api(!galv_buff_queue_empty(queue));

	struct galv_buff * buff;

	buff = stroll_slist_entry(stroll_slist_dqueue_front(&queue->base),
	                          struct galv_buff,
	                          queue);
	galv_buff_release(buff);

	return buff;
}
