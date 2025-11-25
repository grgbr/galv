/****************************************************************************** 
* SPDX-License-Identifier: LGPL-3.0-only
*
* This file is part of Galv.
* Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
*******************************************************************************/

#ifndef _GALV_LIB_BUFFER_H
#define _GALV_LIB_BUFFER_H

#include <galv/buffer.h>

#define galv_buff_assert_intern(_buff) \
	galv_assert_intern(_buff); \
	galv_assert_intern((_buff)->ref); \
	galv_assert_intern((_buff)->alloc); \
	galv_assert_intern(stroll_buff_capacity(&(_buff)->base) <= \
	                   stroll_falloc_chunk_size((_buff)->alloc))

#endif /* _GALV_LIB_BUFFER_H */
