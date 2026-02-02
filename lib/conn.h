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
	galv_assert_intern((_conn)->dispatch)

static inline
int
galv_conn_on_may_xfer(struct galv_conn * __restrict   connection,
                      uint32_t                        events,
                      const struct upoll * __restrict poller)
{
	galv_conn_assert_intern(connection);
	galv_assert_intern(connection->state >= GALV_CONN_CONNECTING_STATE);
	galv_assert_intern(!(events & ~((uint32_t)(EPOLLIN | EPOLLPRI |
	                                           EPOLLOUT | EPOLLHUP))));
	galv_assert_intern(events);
	galv_assert_intern(poller);

	return connection->ops->on_may_xfer(connection, events, poller);
}

static inline
int
galv_conn_on_connect(struct galv_conn * __restrict   connection,
                     uint32_t                        events,
                     const struct upoll * __restrict poller)
{
	galv_conn_assert_intern(connection);
	galv_assert_intern(connection->state <= GALV_CONN_BINDING_STATE);
	galv_assert_intern(!(events &
	                     ~((uint32_t)(EPOLLIN | EPOLLPRI | EPOLLOUT))));
	galv_assert_intern(poller);

	int ret;

	connection->state = GALV_CONN_CONNECTING_STATE;
	ret = connection->ops->on_connect(connection, events, poller);

	/*
	 * Client connection on_connect() handler must have enabled polling
	 * watches...
	 */
	galv_assert_api(ret <= 0);
	galv_assert_api(ret || galv_conn_watched(connection));

	return ret;
}

static inline
int
galv_conn_on_error(struct galv_conn * __restrict   connection,
                   int                             error,
                   uint32_t                        events,
                   const struct upoll * __restrict poller)
{
	galv_conn_assert_intern(connection);
	galv_assert_intern(error);
	galv_assert_intern(events & EPOLLERR);
	galv_assert_intern(!(events & ~GALV_CONN_POLL_VALID_EVENTS));
	galv_assert_intern(poller);

	return connection->ops->on_error(connection,
	                                 error,
	                                 events,
	                                 poller);
}

/**
 * @return A non zero number of bytes sent upon success, a negative `errno`
 *         like code otherwise.
 * @retval -ENOMEM No more memory available
 * @retval -ENOSPC Maximum system number of per-user (UID) pollable file
 *         descriptors reached (see @man{epoll_ctl(2)} and @man{epoll(7)})
 */
static inline
int
galv_conn_poll(struct galv_conn * __restrict   connection,
               const struct upoll * __restrict poller,
               uint32_t                        events,
               upoll_dispatch_fn *             dispatch)
{
	galv_conn_assert_intern(connection);
	galv_assert_intern(connection->fd >= 0);
	galv_assert_intern(connection->state >= GALV_CONN_BINDING_STATE);
	galv_assert_intern(!(events & ~GALV_CONN_POLL_VALID_EVENTS));
	galv_assert_intern(dispatch);

	int ret;

	ret = upoll_register_dispatch(poller,
	                              connection->fd,
	                              events,
	                              &connection->work,
	                              dispatch);
	galv_assert_intern((ret == -ENOMEM) || (ret == -ENOSPC));

	return ret;
}

static inline
void
galv_conn_unpoll(struct galv_conn * __restrict   connection,
                 const struct upoll * __restrict poller)
{
	galv_conn_assert_api(connection);
	galv_assert_api(connection->fd >= 0);
	galv_assert_api(connection->state >= GALV_CONN_BINDING_STATE);
	galv_assert_api(poller);

	upoll_unregister(poller, connection->fd);
}

extern void
galv_conn_setup(struct galv_conn * __restrict           connection,
                int                                     fd,
                const struct galv_conn_ops * __restrict operations,
                struct galv_dispatch * __restrict       dispatcher);

#endif /* _GALV_LIB_CONN_H */
