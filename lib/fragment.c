/****************************************************************************** 
* SPDX-License-Identifier: LGPL-3.0-only
*
* This file is part of Galv.
* Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
*******************************************************************************/

#include "common.h"
#include "fragment.h"
#include <stroll/page.h>

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
