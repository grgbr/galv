/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _GALV_COMMON_CONN_H
#define _GALV_COMMON_CONN_H

#include "common/common.h"
#include "galv/conn.h"
#include <stroll/palloc.h>

/******************************************************************************
 * Generic connection handling
 ******************************************************************************/

#if 0
#define galv_conn_assert_ops_intern(_ops) \
	galv_assert_intern(_ops); \
	galv_assert_intern((_ops)->on_may_xfer); \
	galv_assert_intern((_ops)->on_connect); \
	galv_assert_intern((_ops)->on_send_shut); \
	galv_assert_intern((_ops)->on_recv_shut); \
	galv_assert_intern((_ops)->halt); \
	galv_assert_intern((_ops)->close); \
	galv_assert_intern((_ops)->on_error)
#else
#define galv_conn_assert_ops_intern(_ops) \
	galv_assert_intern(_ops); \
	galv_assert_intern((_ops)->on_bound); \
	galv_assert_intern((_ops)->halt); \
	galv_assert_intern((_ops)->close)
#endif

#define galv_conn_assert_intern(_conn) \
	galv_assert_intern(_conn); \
	galv_conn_assert_ops_intern((_conn)->ops); \
	galv_assert_intern((_conn)->state >= 0); \
	galv_assert_intern((_conn)->state < GALV_CONN_STATE_NR); \
	galv_assert_intern((_conn)->link >= 0); \
	galv_assert_intern((_conn)->link <= GALV_CONN_ENDED_LINK); \
	galv_assert_intern((_conn)->dispatch)

#if 0
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
#endif

static inline
int
galv_conn_on_bound(struct galv_conn * __restrict   connection,
                   const struct upoll * __restrict poller)
{
	galv_conn_assert_intern(connection);
	galv_assert_intern(connection->state != GALV_CONN_CONNECTING_STATE);
	galv_assert_intern(connection->state != GALV_CONN_ESTABLISHED_STATE);
	galv_assert_intern(connection->state != GALV_CONN_CLOSING_STATE);
	galv_assert_intern(connection->fd >= 0);
	galv_assert_intern(connection->work.dispatch);
	galv_assert_intern(poller);

	int ret;

	ret = connection->ops->on_bound(connection, poller);

	/*
	 * Client connection on_bound() handler must have enabled polling
	 * watches...
	 */
	galv_assert_api(ret <= 0);
	galv_assert_api(connection->state < GALV_CONN_STATE_NR);
	galv_assert_api(ret || (connection->state != GALV_CONN_OPENED_STATE));
	galv_assert_api(ret || (connection->state != GALV_CONN_BINDING_STATE));
	galv_assert_api(ret || galv_conn_watched(connection));

	return ret;
}

#if 0
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
#endif

extern int
galv_conn_invalid_dispatch(struct upoll_worker * worker,
                           uint32_t              events,
                           const struct upoll *  poller)
	__export_public __noreturn;

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
	galv_assert_intern(connection->state != GALV_CONN_CONNECTING_STATE);
	galv_assert_intern(connection->state != GALV_CONN_ESTABLISHED_STATE);
	galv_assert_intern(connection->state != GALV_CONN_CLOSING_STATE);
	galv_assert_intern(!(events & ~GALV_CONN_POLL_VALID_EVENTS));
	galv_assert_intern(dispatch);

	int ret;

	ret = upoll_register_dispatch(poller,
	                              connection->fd,
	                              events,
	                              &connection->work,
	                              dispatch);
	galv_assert_intern(!ret || (ret == -ENOMEM) || (ret == -ENOSPC));

	return ret;
}

static inline
void
galv_conn_unpoll(struct galv_conn * __restrict   connection,
                 const struct upoll * __restrict poller)
{
	galv_conn_assert_api(connection);
	galv_assert_api(connection->fd >= 0);
	galv_assert_intern(connection->state != GALV_CONN_OPENED_STATE);
	galv_assert_api(poller);

	upoll_unregister(poller, connection->fd);
}

extern void
galv_conn_setup(struct galv_conn * __restrict           connection,
                int                                     fd,
                const struct galv_conn_ops * __restrict operations,
                struct galv_dispatch * __restrict       dispatcher)
	__export_public;

#endif /* _GALV_COMMON_CONN_H */
