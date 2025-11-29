/****************************************************************************** 
* SPDX-License-Identifier: LGPL-3.0-only
*
* This file is part of Galv.
* Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
*******************************************************************************/

#ifndef _GALV_PRIV_SESSION_H
#define _GALV_PRIV_SESSION_H

#include <galv/accept.h>
#include <galv/priv/fragment.h>
#include <stroll/falloc.h>
#include <stroll/fbmap.h>

/******************************************************************************
 * Session connection acceptor
 ******************************************************************************/

struct galv_sess_accept {
	struct galv_accept           base;
	const struct galv_sess_ops * ops;
	struct stroll_falloc         msg_alloc;
	size_t                       max_pload;
	unsigned int                 frag_per_sess;
	struct stroll_falloc         frag_alloc;
	unsigned int                 buff_per_sess;
	struct stroll_falloc         buff_alloc;
	struct stroll_falloc         sess_alloc;
};

/******************************************************************************
 * Session protocol header
 ******************************************************************************/

enum galv_sess_head_multi {
	GALV_SESS_HEAD_CONT_MULTI = 0,
	GALV_SESS_HEAD_LAST_MULTI = 1,
	GALV_SESS_HEAD_MULTI_NR
};

struct galv_sess_head {
	uint8_t  flags;   /* Message flags */
	uint8_t  xchg;    /* eXCHGange identification number */
	uint16_t size;    /* Size of network data segment */
	char     data[0];
} __packed;

#define GALV_SESS_HEAD_MULTI_FLAG_BIT  (0U)
#define GALV_SESS_HEAD_MULTI_FLAG_MASK (0x1U)
#define GALV_SESS_HEAD_TYPE_FLAG_BIT   (1U)
#define GALV_SESS_HEAD_TYPE_FLAG_MASK  (0x3U)
#define GALV_SESS_HEAD_VALID_FLAG_MASK \
	((uint8_t) \
	 (GALV_SESS_HEAD_TYPE_FLAG_MASK << GALV_SESS_HEAD_TYPE_FLAG_BIT) || \
	 (GALV_SESS_HEAD_MULTI_FLAG_MASK << GALV_SESS_HEAD_MULTI_FLAG_BIT))

#define GALV_SESS_HEAD_XCHG_BITS \
	(sizeof_member(struct galv_sess_head, xchg) * CHAR_BIT)

#define GALV_SESS_HEAD_SIZE_BITS \
	(sizeof_member(struct galv_sess_head, size) * CHAR_BIT)

#define GALV_SESS_MSG_XCHG_NR \
	(1U << GALV_SESS_HEAD_XCHG_BITS)

/******************************************************************************
 * Session message
 ******************************************************************************/

struct galv_sess_sgmt {
	size_t size;
	size_t busy;
};

#define GALV_SESS_SGMT_SIZE_MAX \
	((1U << GALV_SESS_HEAD_SIZE_BITS) - 1)

#define galv_sess_assert_sgmt_api(_sgmt) \
	galv_assert_api(_sgmt); \
	galv_assert_api((_sgmt)->size <= GALV_SESS_SGMT_SIZE_MAX); \
	galv_assert_api((_sgmt)->busy <= (_sgmt)->size)

#warning Move sgmt to galv_sess_accept ?!
struct galv_sess_msg {
	size_t                    size;
	enum galv_sess_head_multi multi;
	enum galv_sess_head_type  type;
	unsigned int              xchg;
	struct galv_sess_sgmt     sgmt;
	struct galv_frag_list     frags;
	struct stroll_slist_node  queue;
};

#define galv_sess_assert_msg_api(_msg) \
	galv_assert_api(_msg); \
	galv_assert_api((_msg)->multi >= 0); \
	galv_assert_api((_msg)->multi <= GALV_SESS_HEAD_MULTI_NR); \
	galv_assert_api((_msg)->type >= 0); \
	galv_assert_api((_msg)->type <= GALV_SESS_HEAD_TYPE_NR); \
	galv_assert_api((_msg)->xchg < GALV_SESS_MSG_XCHG_NR); \
	galv_sess_assert_sgmt_api(&(_msg)->sgmt)

#endif /* _GALV_PRIV_SESSION_H */
