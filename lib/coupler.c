/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "coupler.h"

static
int
galv_coupler_dispatch(struct upoll_worker * worker,
                      uint32_t              events,
                      const struct upoll *  poller)
{
	galv_assert_intern(worker);
	galv_assert_intern(poller);
	galv_assert_intern(events);
	galv_assert_intern(!(events & ~(EPOLLERR | EPOLLOUT | EPOLLHUP)));

	struct galv_conn * conn;
	socklen_t          sz;
	int                ret;

	conn = galv_conn_from_worker(worker);
	galv_conn_assert_intern(conn);
	galv_assert_intern(conn->state == GALV_CONN_CLOSED_STATE);
	galv_assert_intern(conn->fd >= 0);
	galv_assert_intern(conn->work.dispatch);
	galv_assert_intern(conn->coupler);

TODO: destroy on error (see lib/accept.c:93)
	if (events & (EPOLLERR | EPOLLHUP)) {
		ret = galv_conn_on_error(conn, events, poller);
		if (ret)
			return ret;

		events &= ~((uint32_t)(EPOLLERR));
	}

	sz = sizeof(ret);
	etux_sock_getopt(connection->fd, SOL_SOCKET, SO_ERROR, &ret, &sz);
	if (!ret) {
		ret = galv_conn_on_connect(connection, events, poller);
		if (!ret)
			galv_conn_repo_register(coupler->repo, connection);
	}

	return ret;
}

static
int
galv_coupler_connect(struct galv_coupler * __restrict   coupler,
                     struct galv_conn * __restrict      connection,
                     const struct sockaddr * __restrict peer,
                     const struct upoll * __restric     poller)
{
	int ret;

	ret = coupler->ops->connect(coupler, connection peer, poller);
	if (!ret) {
#warning check return code ?
		ret = galv_conn_on_connect(connection, 0, poller);
		if (!ret)
			galv_conn_repo_register(coupler->repo, connection);
		return ret;
	}

	switch (ret) {
	case -EINPROGRESS:
		/*
		 * Nonblocking UNIX domain sockets return -EAGAIN (instead of
		 * -EINPROGRESS when the connection cannot be completed
		 * immediately.
		 */
		break;

	case -EINTR:
	case -EAGAIN:
	case -EACCES:
	case -EPERM:
	case -EINPROGRESS:
	case -EPROTOTYPE:
	case -ETIMEDOUT:
		return err;

	default:
		galv_assert_intern(0);
		return ret;
	}

	return galv_conn_enable_dispatch(connection,
	                                 poller,
	                                 EPOLLOUT,
	                                 galv_coupler_dispatch,
	                                 NULL);
}
