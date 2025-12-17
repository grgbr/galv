/****************************************************************************** 
* SPDX-License-Identifier: LGPL-3.0-only
*
* This file is part of Galv.
* Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
*******************************************************************************/

/**
 * @file
 * Session connection interface
 *
 * @author    Grégor Boirie <gregor.boirie@free.fr>
 * @date      26 Oct 2025
 * @copyright Copyright (C) 2024 Grégor Boirie.
 * @license   [GNU Lesser General Public License (LGPL) v3]
 *            (https://www.gnu.org/licenses/lgpl+gpl-3.0.txt)
 */

#ifndef _GALV_SESSION_H
#define _GALV_SESSION_H

#include <galv/buffer.h>

enum galv_sess_head_type {
	GALV_SESS_HEAD_REQUEST_TYPE = 0,
	GALV_SESS_HEAD_REPLY_TYPE   = 1,
	GALV_SESS_HEAD_NOTIF_TYPE   = 2,
	GALV_SESS_HEAD_TYPE_NR
};

#include <galv/priv/session.h>

/******************************************************************************
 * Session message
 ******************************************************************************/

static inline
size_t
galv_sess_msg_size(const struct galv_sess_msg * __restrict message)
{
	galv_sess_assert_msg_api(message);

	return message->size;
}

static inline
enum galv_sess_head_type
galv_sess_msg_type(const struct galv_sess_msg * __restrict message)
{
	galv_sess_assert_msg_api(message);

	return message->type;
}

static inline
unsigned int
galv_sess_msg_xchg(const struct galv_sess_msg * __restrict message)
{
	galv_sess_assert_msg_api(message);

	return message->xchg;
}

static inline
struct galv_sess_conn *
galv_sess_msg_conn(const struct galv_sess_msg * __restrict message)
{
	galv_sess_assert_msg_api(message);

	return message->sess;
}

/* Retrieve a pointer to user data from a message. */
extern ssize_t
galv_sess_msg_pull_head(struct galv_sess_msg * __restrict message,
                        const uint8_t ** __restrict       data,
                        size_t                            size)
	__export_public;

/* Reserve user data space from a message for later filling up operation. */
extern ssize_t
galv_sess_msg_push_tail(struct galv_sess_msg * __restrict message,
                        uint8_t ** __restrict             data,
                        size_t                            size)
	__export_public;

/* Release a message. */
extern void
galv_sess_drop_msg(struct galv_sess_msg * __restrict message)
	__export_public;

/******************************************************************************
 * Session connection
 ******************************************************************************/

typedef int galv_sess_connect_fn(struct galv_sess_conn * __restrict);

typedef int galv_sess_xfer_fn(struct galv_sess_conn * __restrict);

typedef void galv_sess_close_fn(struct galv_sess_conn * __restrict);

struct galv_sess_ops {
	galv_sess_connect_fn * connect;
	galv_sess_xfer_fn *    xfer;
	galv_sess_close_fn *   close;
};

/* Receive use case. */
static inline
bool
galv_sess_may_pull_msg(const struct galv_sess_conn * __restrict session)
{
	galv_sess_assert_conn_api(session);

	return !stroll_slist_empty(&session->recv_msgq);
}

/* Receive use case. */
extern struct galv_sess_msg *
galv_sess_pull_msg(struct galv_sess_conn * __restrict session)
	__export_public;

/* Emit use case. */
extern int
galv_sess_push_msg(struct galv_sess_msg * __restrict message)
	__export_public;

/* Allocate a fresh empty request message. */
extern struct galv_sess_msg *
galv_sess_create_request(struct galv_sess_conn * __restrict session)
	__export_public;

/* Allocate a fresh empty reply message. */
extern struct galv_sess_msg *
galv_sess_create_reply(struct galv_sess_conn * __restrict session,
                       unsigned int                       xchange)
	__export_public;

/* Allocate a fresh reply message to answer a specific request. */
extern int
galv_sess_make_reply(struct galv_sess_msg * __restrict request)
	__export_public;

/* Allocate a fresh empty notification message. */
extern struct galv_sess_msg *
galv_sess_create_notif(struct galv_sess_conn * __restrict session)
	__export_public;

static inline
void
galv_sess_establish(struct galv_sess_conn * __restrict session)
{
	galv_sess_assert_conn_api(session);

	galv_conn_switch_state(session->conn, GALV_CONN_ESTABLISHED_STATE);
}

/******************************************************************************
 * Session acceptor
 ******************************************************************************/

struct galv_sess_accept_conf {
	unsigned int backlog;
	int          conn_flags;
	size_t       max_pload;
	size_t       msg_size;
	size_t       buff_capa;
	size_t       conn_size;
};

/*
 * Restrict maximum payload size to prevent from integer addition overflow
 * during session message size computation. See galv_sess_recv_sgmt_head().
 */
#if CONFIG_GALV_SESS_PLOAD_SIZE_MAX > (SIZE_MAX - USHRT_MAX)
#error Invalid Maximum session message payload size !
#endif

#define GALV_SESS_PLOAD_SIZE_MAX \
	STROLL_CONCAT(CONFIG_GALV_SESS_PLOAD_SIZE_MAX, U)

#define GALV_SESS_BUFF_CAPA_MIN \
	(128U)

#define GALV_SESS_BUFF_CAPA_MAX \
	STROLL_CONCAT(CONFIG_GALV_SESS_BUFF_CAPA_MAX, U)

#define GALV_SESS_ACCEPT_CONF(_backlog, \
                              _conn_flags, \
                              _max_pload, \
                              _msg_size, \
                              _buff_capa, \
                              _conn_size) \
	{ \
		.backlog    = compile_eval( \
			(_backlog) <= (unsigned int)INT_MAX, \
			_backlog, \
			"invalid session backlog value"), \
		.conn_flags = compile_eval( \
			!((_conn_flags) & ETUX_SOCK_ACCEPT_INVALID_FLAGS), \
			_conn_flags, \
			"invalid session socket flags"), \
		.max_pload  = compile_eval( \
			(_max_pload) && \
			((_max_pload) <= GALV_SESS_PLOAD_SIZE_MAX), \
			stroll_align_upper(_max_pload, __WORDSIZE / CHAR_BIT), \
			"invalid maximum session payload size"), \
		.msg_size   = compile_eval( \
			((_msg_size) >= sizeof(struct galv_sess_msg)), \
			_msg_size, \
			"invalid session message size"), \
		.buff_capa  = compile_eval( \
			((_buff_capa) >= GALV_SESS_BUFF_CAPA_MIN) && \
			((_buff_capa) <= GALV_SESS_BUFF_CAPA_MAX), \
			stroll_align_upper(_buff_capa, __WORDSIZE / CHAR_BIT), \
			"invalid session buffer capacity"), \
		.conn_size  = compile_eval( \
			((_conn_size) >= sizeof(struct galv_sess_conn)), \
			_conn_size, \
			"invalid session connection size") \
	}

extern int
galv_sess_config_accept_backlog(
	struct galv_sess_accept_conf * __restrict config,
	const char * __restrict                   string)
	__export_public;

extern void
galv_sess_config_accept(
	struct galv_sess_accept_conf * __restrict config,
	unsigned int                              backlog,
	int                                       conn_flags,
	size_t                                    max_pload,
	size_t                                    msg_size,
	size_t                                    buff_capa,
	size_t                                    conn_size)
	__export_public;

struct galv_sess_accept;

extern int
galv_sess_open_accept(
	struct galv_sess_accept * __restrict            acceptor,
	const struct galv_sess_ops * __restrict         operations,
	struct galv_repo * __restrict                   repository,
	struct galv_adopt * __restrict                  adopter,
	const struct upoll * __restrict                 poller,
	const struct galv_sess_accept_conf * __restrict config)
	__export_public;

extern void
galv_sess_close_accept(struct galv_sess_accept * __restrict acceptor,
                       const struct upoll * __restrict      poller)
	__export_public;

#endif /* _GALV_SESSION_H */
