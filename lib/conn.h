/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _GALV_LIB_CONN_H
#define _GALV_LIB_CONN_H

#include "common.h"
#include "galv/conn.h"
#include <stroll/palloc.h>

struct galv_accept;

/******************************************************************************
 * Generic connection handling
 ******************************************************************************/

#define galv_conn_assert_ops_intern(_ops) \
	galv_assert_intern(_ops); \
	galv_assert_intern((_ops)->on_may_xfer); \
	galv_assert_intern((_ops)->on_connecting); \
	galv_assert_intern((_ops)->on_send_closed); \
	galv_assert_intern((_ops)->on_recv_closed); \
	galv_assert_intern((_ops)->on_error)

#define galv_conn_assert_intern(_conn) \
	galv_assert_intern(_conn); \
	galv_conn_assert_ops_intern((_conn)->ops); \
	galv_assert_intern((_conn)->state >= 0); \
	galv_assert_intern((_conn)->state < GALV_CONN_STATE_NR)

static inline
void
galv_conn_setup(struct galv_conn * __restrict           connection,
                int                                     fd,
                const struct galv_conn_ops * __restrict operations,
                struct galv_accept * __restrict         acceptor)
{
	galv_assert_intern(connection);
	galv_assert_intern(fd >= 0);
	galv_conn_assert_ops_intern(operations);
	galv_assert_intern(acceptor);

	connection->ops = operations;
	connection->state = GALV_CONN_CLOSED_STATE;
	connection->fd = fd;
	connection->accept = acceptor;
}

#endif /* _GALV_LIB_CONN_H */
