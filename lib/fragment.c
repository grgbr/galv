/****************************************************************************** 
* SPDX-License-Identifier: LGPL-3.0-only
*
* This file is part of Galv.
* Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
*******************************************************************************/

#include "common.h"
#include "galv/priv/fragment.h"
#include <sys/user.h>

#define galv_frag_fabric_assert_intern(_fabric) \
	galv_assert_intern(_fabric); \
	galv_assert_intern((_fabric)->nr); \
	galv_assert_intern((_fabric)->cnt <= (_fabric)->nr)

static
struct galv_frag *
galv_frag_fabric_alloc(struct galv_frag_fabric * __restrict fabric)
{
	galv_frag_fabric_assert_intern(fabric);

	if (fabric->cnt < fabric->nr) {
		struct galv_frag * frag;

		frag = (struct galv_frag *)stroll_falloc_alloc(&fabric->base);
		if (frag)
			fabric->cnt++;

		return frag;
	}

	errno = ENOBUFS;

	return NULL;
}

static
void
galv_frag_fabric_free(struct galv_frag_fabric * __restrict fabric,
                      struct galv_frag * __restrict        fragment)
{
	galv_frag_fabric_assert_intern(fabric);
	galv_assert_intern(fragment);
	galv_assert_api(fabric->cnt);

	fabric->cnt--;
	stroll_falloc_free(&fabric->base, fragment);
}

void
galv_frag_init_fabric(struct galv_frag_fabric * __restrict fabric,
                      unsigned int                         nr)
{
	galv_assert_api(fabric);
	galv_assert_api(nr);

	fabric->cnt = 0;
	fabric->nr = stroll_round_upper(nr,
	                                PAGE_SIZE / sizeof(struct galv_frag));
	return stroll_falloc_init(&fabric->base,
	                          PAGE_SIZE / sizeof(struct galv_frag),
	                          sizeof(struct galv_frag));
}

size_t
galv_frag_load(struct galv_frag * __restrict fragment,
               struct galv_buff * __restrict buffer)
{
	galv_frag_assert_api(fragment);
	galv_assert_api(!galv_frag_full(fragment));
	galv_assert_api(buffer == fragment->buff);

	size_t bytes = stroll_min(galv_buff_busy(buffer),
	                          galv_frag_avail(fragment));
	
	stroll_buff_grow_tail(&fragment->base, bytes);

	return bytes;
}

static
void
galv_frag_init(struct galv_frag * __restrict fragment,
               size_t                        capacity,
               struct galv_buff * __restrict buffer)
{
	galv_assert_api(fragment);
	galv_assert_api(capacity);
	galv_assert_api(buffer);
	galv_assert_api(galv_buff_capacity(buffer));
	galv_assert_api(capacity <= galv_buff_capacity(buffer));

	size_t off = galv_buff_avail_head(buffer);
	size_t capa = stroll_min(off + capacity, galv_buff_capacity(buffer));

	galv_assert_intern(capa > off);

	stroll_buff_setup(&fragment->base, capa, off, 0);

	fragment->buff = galv_buff_acquire(buffer);
}

static
void
galv_frag_fini(struct galv_frag * __restrict fragment)
{
	galv_frag_assert_api(fragment);

	galv_buff_release(fragment->buff);
}

struct galv_frag *
galv_frag_create(struct galv_frag_fabric * __restrict fabric,
                 size_t                               capacity,
                 struct galv_buff * __restrict        buffer)
{
	galv_frag_fabric_assert_api(fabric);

	struct galv_frag * frag;

	frag = galv_frag_fabric_alloc(fabric);
	if (!frag)
		return NULL;

	galv_frag_init(frag, capacity, buffer);

	return frag;
}

void
galv_frag_destroy(struct galv_frag * __restrict fragment)
{
	galv_frag_assert_api(fragment);

	galv_frag_fini(fragment);
	galv_frag_fabric_free(fragment->fabric, fragment);
}
