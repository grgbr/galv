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
 * Session connection allocator
 ******************************************************************************/

extern struct stroll_alloc *
galv_sess_create_conn_alloc(unsigned int nr, size_t size)
	__export_public;

/******************************************************************************
 * Session acceptor
 ******************************************************************************/

struct galv_sess_accept;

extern int
galv_sess_open_accept(struct galv_sess_accept * __restrict    acceptor,
                      struct galv_repo * __restrict           repository,
                      struct stroll_alloc * __restrict        allocator,
                      struct galv_adopt * __restrict          adopter,
                      unsigned int                            backlog,
                      int                                     flags,
                      const struct upoll * __restrict         poller)
	__export_public;

extern void
galv_sess_close_accept(const struct galv_sess_accept * __restrict acceptor,
                       const struct upoll * __restrict            poller)
	__export_public;

#endif /* _GALV_SESSION_H */
