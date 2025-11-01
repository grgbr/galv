/****************************************************************************** 
* SPDX-License-Identifier: LGPL-3.0-only
*
* This file is part of Galv.
* Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
*******************************************************************************/

#ifndef _GALV_PRIV_SESSION_H
#define _GALV_PRIV_SESSION_H

#include <galv/priv/fragment.h>
#include <stroll/fbmap.h>
#include <stroll/palloc.h>
#include <stdint.h>

/**
 * @internal
 *
 * Session protocol header.
 */
struct galv_sess_head {
	uint8_t  flags;   /* Message flags */
	uint8_t  xchg;    /* eXCHGange identification number */
	uint16_t size;    /* Size of network data segment */
	char     data[0];
} __packed;

#define GALV_SESS_HEAD_XCHG_BITS \
	(sizeof_member(struct galv_sess_head, xchg) * CHAR_BIT)

#define GALV_SESS_HEAD_SIZE_BITS \
	(sizeof_member(struct galv_sess_head, size) * CHAR_BIT)

#define GALV_SESS_MSG_XCHG_NR \
	(1U << GALV_SESS_HEAD_XCHG_BITS)

/**
 * @internal
 *
 * Session message queue.
 */
struct galv_sess_msg_queue {
	struct stroll_slist base;
	unsigned long       bmap[STROLL_FBMAP_WORD_NR(GALV_SESS_MSG_XCHG_NR)];
};

struct galv_conn;

/**
 * @internal
 *
 * Session connection.
 */
struct galv_sess {
	struct galv_conn *         conn;
	struct galv_buff_queue     recv_buffq;
	struct galv_buff_fabric    buff_fab;
	struct galv_frag_fabric    frag_fab;
	struct galv_sess_msg_queue recv_msgq;
	struct stroll_palloc       msg_fab;
};

#define galv_sess_assert_api(_sess) \
	galv_assert_api(_sess); \
	galv_assert_api((_sess)->conn)

#endif /* _GALV_PRIV_SESSION_H */
