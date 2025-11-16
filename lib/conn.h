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
	galv_assert_intern((_ops)->on_connect); \
	galv_assert_intern((_ops)->on_send_shut); \
	galv_assert_intern((_ops)->on_recv_shut); \
	galv_assert_intern((_ops)->halt); \
	galv_assert_intern((_ops)->close); \
	galv_assert_intern((_ops)->on_error)

#define galv_conn_assert_intern(_conn) \
	galv_assert_intern(_conn); \
	galv_conn_assert_ops_intern((_conn)->ops); \
	galv_assert_intern((_conn)->state >= 0); \
	galv_assert_intern((_conn)->state < GALV_CONN_STATE_NR); \
	galv_assert_intern((_conn)->link >= 0); \
	galv_assert_intern((_conn)->link <= GALV_CONN_ENDED_LINK); \
	galv_assert_intern((_conn)->accept)

static inline
struct galv_accept *
galv_conn_acceptor(const struct galv_conn * __restrict connection)
{
	galv_conn_assert_api(connection);
	galv_assert_api(connection->state != GALV_CONN_CLOSED_STATE);

	return connection->accept;
}

static inline
int
galv_conn_on_may_xfer(struct galv_conn * __restrict   connection,
                      uint32_t                        events,
                      const struct upoll * __restrict poller)
{
	galv_conn_assert_api(connection);
	galv_assert_api(connection->state != GALV_CONN_CLOSED_STATE);
	galv_assert_api(!(events & ~((uint32_t)(EPOLLIN | EPOLLPRI |
	                                        EPOLLOUT | EPOLLHUP))));
	galv_assert_api(events);
	galv_assert_api(poller);

	return connection->ops->on_may_xfer(connection, events, poller);
}

static inline
int
galv_conn_on_connect(struct galv_conn * __restrict   connection,
                     uint32_t                        events,
                     const struct upoll * __restrict poller)
{
	galv_conn_assert_api(connection);
	galv_assert_api(connection->state == GALV_CONN_CLOSED_STATE);
	galv_assert_api(!(events & ~((uint32_t)(EPOLLIN | EPOLLPRI |
	                                        EPOLLOUT))));
	galv_assert_api(poller);

	connection->state = GALV_CONN_CONNECTING_STATE;

	return connection->ops->on_connect(connection, events, poller);
}

static inline
int
galv_conn_on_error(struct galv_conn * __restrict   connection,
                   uint32_t                        events,
                   const struct upoll * __restrict poller)
{
	galv_conn_assert_api(connection);
	galv_assert_api(connection->state != GALV_CONN_CLOSED_STATE);
	galv_assert_api(!(events & ~GALV_CONN_POLL_VALID_EVENTS));
	galv_assert_api(events & EPOLLERR);
	galv_assert_api(poller);

	return connection->ops->on_error(connection, events, poller);
}

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
	connection->link = GALV_CONN_FLOWING_LINK;
}

#endif /* _GALV_LIB_CONN_H */
