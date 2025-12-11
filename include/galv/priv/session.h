/****************************************************************************** 
* SPDX-License-Identifier: LGPL-3.0-only
*
* This file is part of Galv.
* Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
*******************************************************************************/

#ifndef _GALV_PRIV_SESSION_H
#define _GALV_PRIV_SESSION_H

#include <galv/accept.h>
#include <galv/conn.h>
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

static inline
struct galv_sess_accept *
galv_sess_from_accept(const struct galv_accept * __restrict acceptor)
{
	galv_assert_api(acceptor);

	return containerof(acceptor, struct galv_sess_accept, base);
}

/******************************************************************************
 * Session protocol header
 ******************************************************************************/

enum galv_sess_head_multi {
	GALV_SESS_HEAD_CONT_MULTI = 0,
	GALV_SESS_HEAD_LAST_MULTI = 1,
	GALV_SESS_HEAD_MULTI_NR
};

struct galv_sess_head {
	uint8_t  flags; /* Message flags */
	uint8_t  xchg;  /* eXCHGange identification number */
	uint16_t size;  /* Size of network data segment */
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

#define GALV_SESS_SGMT_SIZE_MAX \
	(1U << GALV_SESS_HEAD_SIZE_BITS)

/******************************************************************************
 * Session message
 ******************************************************************************/

enum galv_sess_sgmt_state {
	GALV_SESS_SGMT_PARTIAL_STAT = 0,
	GALV_SESS_SGMT_COMPLETE_STAT,
	GALV_SESS_SGMT_STAT_NR
};

struct galv_sess_send_ctx {
	uint8_t *           head;
	struct galv_buff *  buff;
	struct stroll_slist buffq;
};

struct galv_sess_recv_ctx {
	size_t                    busy;
	enum galv_sess_head_multi multi;
	struct galv_frag_list     frags;
	struct stroll_slist_node  queue;
};

struct galv_sess_conn;
struct galv_sess_msg;

typedef void galv_sess_msg_fini_fn(struct galv_sess_msg * __restrict,
                                   struct galv_sess_conn * __restrict,
                                   struct galv_sess_accept * __restrict);

struct galv_sess_msg {
	size_t                            size;
	enum galv_sess_head_type          type;
	unsigned int                      xchg;
	enum galv_sess_sgmt_state         state;
	union {
		struct galv_sess_send_ctx send;
		struct galv_sess_recv_ctx recv;
	};
	struct galv_sess_conn *           sess;
	galv_sess_msg_fini_fn *           fini;
};

#define galv_sess_assert_msg_api(_msg) \
	galv_assert_api(_msg); \
	galv_assert_api((_msg)->type >= 0); \
	galv_assert_api((_msg)->type <= GALV_SESS_HEAD_TYPE_NR); \
	galv_assert_api((_msg)->xchg < GALV_SESS_MSG_XCHG_NR); \
	galv_assert_api((_msg)->sess); \
	galv_assert_api((_msg)->fini)

#define galv_sess_assert_send_msg_api(_msg) \
	galv_sess_assert_msg_api(_msg); \
	galv_assert_api((_msg)->state >= 0); \
	galv_assert_api((_msg)->state <= GALV_SESS_SGMT_STAT_NR); \
	galv_assert_api(((_msg)->state == GALV_SESS_SGMT_STAT_NR) || \
	                ((_msg)->send.head && (_msg)->send.buff))

#define galv_sess_assert_recv_msg_api(_msg) \
	galv_sess_assert_msg_api(_msg); \
	galv_assert_api((_msg)->state >= 0); \
	galv_assert_api((_msg)->state <= GALV_SESS_SGMT_STAT_NR); \
	galv_assert_api((_msg)->recv.multi >= 0); \
	galv_assert_api((_msg)->recv.multi <= GALV_SESS_HEAD_MULTI_NR); \
	galv_assert_api(((_msg)->state == GALV_SESS_SGMT_STAT_NR) || \
	                (((_msg)->recv.multi != GALV_SESS_HEAD_MULTI_NR) && \
	                 (_msg)->size))

/******************************************************************************
 * Session connection
 ******************************************************************************/

struct galv_sess_conn {
	struct galv_conn *     conn;
	unsigned int           msg_cnt;
	unsigned int           frag_cnt;
	unsigned int           buff_cnt;
	unsigned long          xchg_map[STROLL_FBMAP_WORD_NR(GALV_SESS_MSG_XCHG_NR)];
	struct galv_sess_msg * recv_msg;
	struct stroll_slist    recv_msgq;
	struct galv_buff_queue recv_buffq;
	struct galv_buff_queue send_buffq;
};

#define galv_sess_assert_conn_api(_sess) \
	galv_assert_api(_sess); \
	galv_assert_api((_sess)->conn); \
	galv_assert_api((_sess)->msg_cnt <= GALV_SESS_MSG_XCHG_NR); \
	galv_assert_api((_sess)->frag_cnt <= \
	                galv_sess_conn_acceptor(_sess)->frag_per_sess); \
	galv_assert_api((_sess)->buff_cnt <= \
	                galv_sess_conn_acceptor(_sess)->buff_per_sess); \
	galv_assert_api((stroll_slist_empty(&(_sess)->recv_msgq) || \
	                 !galv_buff_queue_count(&(_sess)->send_buffq)) ^ \
	                _stroll_fbmap_test_all((_sess)->xchg_map, \
	                                       GALV_SESS_MSG_XCHG_NR))

static inline
struct galv_sess_accept *
galv_sess_conn_acceptor(const struct galv_sess_conn * __restrict session)
{
	galv_assert_api(session);

	return galv_sess_from_accept(galv_conn_acceptor(session->conn));
}

#endif /* _GALV_PRIV_SESSION_H */
