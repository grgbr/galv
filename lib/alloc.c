/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Stroll.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "common.h"
#include "alloc.h"
#include <stroll/page.h>
#include <stroll/palloc.h>
#include <stroll/falloc.h>

struct stroll_alloc *
galv_alloc_create(unsigned int nr, size_t size)
{
	galv_assert_api(nr);
	galv_assert_api(size);
	galv_assert_api(size < (stroll_page_size() / 8U));

	unsigned int per_blk = (unsigned int)
	                       (stroll_page_size() /
	                        stroll_falloc_align_chunk_size(size));

	if (nr > per_blk)
		return stroll_falloc_create_alloc(nr, per_blk, size);
	else
		return stroll_palloc_create_alloc(nr, size);
}
