/****************************************************************************** 
* SPDX-License-Identifier: LGPL-3.0-only
*
* This file is part of Galv.
* Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
*******************************************************************************/

#ifndef _GALV_LIB_FRAGMENT_H
#define _GALV_LIB_FRAGMENT_H

#include "buffer.h"
#include <galv/priv/fragment.h>

/**
 * @internal
 *
 * Core network fragment.
 *
 * Describe a contiguous data (sub)portion of a network byte stream. Data are
 * stored within an external galv_buff buffer (i.e., a contiguous memory block).
 *
 * Multiple galv_frag fragments may be chained in order within a galv_frag_list
 * list to describe a single consistent network message.
 *
 * @note
 * A galv_frag references a signe galv_buff.
 */
struct galv_frag {
	struct stroll_buff       base;
	struct stroll_slist_node list;
	struct galv_buff *       buff;
};

#define galv_frag_assert_api(_frag) \
	galv_assert_api(_frag); \
	galv_assert_api(stroll_buff_capacity(&(_frag)->base)); \
	galv_assert_api((_frag)->buff); \
	galv_assert_api(stroll_buff_capacity(&(_frag)->base) <= \
	                galv_buff_capacity((_frag)->buff))

#define galv_frag_assert_intern(_frag) \
	galv_assert_intern(_frag); \
	galv_assert_intern(stroll_buff_capacity(&(_frag)->base)); \
	galv_assert_intern((_frag)->buff); \
	galv_assert_intern(stroll_buff_capacity(&(_frag)->base) <= \
	                   galv_buff_capacity((_frag)->buff))

static inline
size_t
galv_frag_busy(const struct galv_frag * __restrict fragment)
{
	galv_frag_assert_api(fragment);

	return stroll_buff_busy(&fragment->base);
}

static inline
bool
galv_frag_full(const struct galv_frag * __restrict fragment)
{
	galv_frag_assert_api(fragment);

	return !stroll_buff_avail_tail(&fragment->base);
}

static inline
size_t
galv_frag_avail(const struct galv_frag * __restrict fragment)
{
	galv_frag_assert_api(fragment);

	return stroll_buff_avail_tail(&fragment->base);
}

static inline
uint8_t *
galv_frag_data(const struct galv_frag * __restrict fragment)
{
	galv_frag_assert_api(fragment);
	galv_assert_api(galv_frag_busy(fragment));

	return stroll_buff_data(&fragment->base, galv_buff_mem(fragment->buff));
}

extern size_t
galv_frag_load(struct galv_frag * __restrict fragment,
               struct galv_buff * __restrict buffer);

extern void
galv_frag_init(struct galv_frag * __restrict fragment,
               size_t                        capacity,
               struct galv_buff * __restrict buffer);

static inline
unsigned long
galv_frag_fini(const struct galv_frag * __restrict fragment)
{
	galv_frag_assert_api(fragment);

	return galv_buff_release(fragment->buff);
}

#define galv_frag_list_foreach(_list, _frag) \
	stroll_slist_foreach_entry(_list, _frag, list)

static inline
bool
galv_frag_list_empty(const struct galv_frag_list * __restrict list)
{
	galv_assert_api(list);

	return stroll_slist_empty(&list->base);
}

static inline
struct galv_frag *
galv_frag_list_first(const struct galv_frag_list * __restrict list)
{
	galv_assert_api(list);
	galv_assert_api(!galv_frag_list_empty(list));

	return stroll_slist_first_entry(&list->base, struct galv_frag, list);
}

static inline
struct galv_frag *
galv_frag_list_last(const struct galv_frag_list * __restrict list)
{
	galv_assert_api(list);
	galv_assert_api(!galv_frag_list_empty(list));

	return stroll_slist_last_entry(&list->base, struct galv_frag, list);
}

static inline
void
galv_frag_nlist(struct galv_frag_list * __restrict list,
                struct galv_frag * __restrict      fragment)
{
	galv_assert_api(list);
	galv_frag_assert_api(fragment);

	stroll_slist_nqueue_back(&list->base, &fragment->list);
}

static inline
struct galv_frag *
galv_frag_dlist(struct galv_frag_list * __restrict list)
{
	galv_assert_api(list);
	galv_assert_api(!galv_frag_list_empty(list));

	struct galv_frag * frag;

	frag = stroll_slist_entry(stroll_slist_dqueue_front(&list->base),
	                          struct galv_frag,
	                          list);
	galv_frag_assert_api(frag);

	return frag;
}

static inline
void
galv_frag_init_list(struct galv_frag_list * __restrict list)
{
	galv_assert_api(list);

	stroll_slist_init(&list->base);
}

static inline
void
galv_frag_fini_list(struct galv_frag_list * __restrict list)
{
	galv_assert_api(list);
	galv_assert_api(galv_frag_list_empty(list));
}

#endif /* _GALV_LIB_FRAGMENT_H */
