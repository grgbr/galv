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
#include <galv/priv/session.h>

/******************************************************************************
 * Session message
 ******************************************************************************/

struct galv_sess_msg;

/* Retrieve a pointer to user data from a message. */
extern ssize_t
galv_sess_msg_pull_head(struct galv_sess_msg * __restrict message,
                        uint8_t ** __restrict             data,
                        size_t                            size)
	__export_public;

/* Reserve user data space from a message for later filling up operation. */
extern ssize_t
galv_sess_msg_push_tail(struct galv_sess_msg * __restrict message,
                        uint8_t ** __restrict             data,
                        size_t                            size)
	__export_public;

/******************************************************************************
 * Session connection
 ******************************************************************************/

struct galv_sess_conn;

typedef int galv_sess_xfer_fn(struct galv_sess_conn * __restrict);

struct galv_sess_ops {
	galv_sess_xfer_fn * xfer;
};

/*
 * Receive use case.
 * Return -ENODATA if no more data available
 */
extern struct galv_sess_msg *
galv_sess_pull_msg(struct galv_sess_conn * __restrict session)
	__export_public;

/* Allocate a fresh empty message. */
extern struct galv_sess_msg *
galv_sess_alloc_msg(struct galv_sess_conn * __restrict session)
	__export_public;

/* Emit use case. */
extern void
galv_sess_push_msg(struct galv_sess_conn * __restrict session,
                   struct galv_sess_msg * __restrict  message)
	__export_public;

/* Release a message. */
extern void
galv_sess_drop_msg(struct galv_sess_conn * __restrict session,
                   struct galv_sess_msg * __restrict  message)
	__export_public;

/******************************************************************************
 * Session acceptor
 ******************************************************************************/

struct galv_sess_accept_conf {
	unsigned int backlog;
	int          conn_flags;
	size_t       max_pload;
	size_t       buff_capa;
};

#define GALV_SESS_PLOAD_SIZE_MAX \
	STROLL_CONCAT(CONFIG_GALV_SESS_PLOAD_SIZE_MAX, U)

#define GALV_SESS_BUFF_CAPA_MIN \
	(128U)

#define GALV_SESS_BUFF_CAPA_MAX \
	STROLL_CONCAT(CONFIG_GALV_SESS_BUFF_CAPA_MAX, U)

#define GALV_SESS_ACCEPT_CONF(_backlog, _conn_flags, _max_pload, _buff_capa) \
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
			stroll_align_upper(_max_pload, __WORDSIZE), \
			"invalid maximum session payload size"), \
		.buff_capa  = compile_eval( \
			((_buff_capa) >= GALV_SESS_BUFF_CAPA_MIN) && \
			((_buff_capa) <= GALV_SESS_BUFF_CAPA_MAX), \
			stroll_align_upper(_buff_capa, __WORDSIZE), \
			"invalid session buffer capacity") \
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
	size_t                                    buff_capa)
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
