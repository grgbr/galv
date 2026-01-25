/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "galv/coupler.h"
#include "binder.h"
#include "repo.h"

#define galv_coupler_assert_intern(_coupler) \
	galv_assert_intern(_coupler); \
	galv_binder_assert_intern((_coupler)->bind); \
	galv_repo_assert_intern((_coupler)->repo); \
	galv_conn_assert_ops_intern((_coupler)->conn_ops); \
	galv_assert_intern((_coupler)->conn_type)

static
int
galv_coupler_on_connect(const struct galv_coupler * __restrict coupler,
                        struct galv_conn * __restrict          connection,
                        uint32_t                               events,
                        const struct upoll *                   poller)
{
	galv_coupler_assert_intern(coupler);
	galv_conn_assert_intern(connection);
	galv_assert_intern(events);
	galv_assert_intern(!(events &
	                     ~((uint32_t)(EPOLLIN | EPOLLPRI | EPOLLOUT))));
	galv_assert_intern(poller);

	const struct galv_binder * __restrict bind = coupler->bind;
	int                                   ret;

	galv_binder_on_connected(bind, connection);

	ret = galv_conn_on_connect(connection, events, poller);
	if (!ret || (ret == -EINTR)) {
		galv_conn_repo_register(coupler->repo, connection);
		return ret;
	}

	return galv_conn_on_error(connection, -ret, EPOLLERR, poller);
}

static
int
galv_coupler_dispatch(struct upoll_worker * worker,
                      uint32_t              events,
                      const struct upoll *  poller)
{
	galv_assert_intern(worker);
	galv_assert_intern(poller);
	galv_assert_intern(events);
	galv_assert_intern(!(events & ~((uint32_t)(EPOLLERR | EPOLLOUT))));

	struct galv_conn * conn;
	int                ret;

	conn = galv_conn_from_worker(worker);
	galv_conn_assert_intern(conn);
	galv_assert_intern(conn->state == GALV_CONN_CLOSED_STATE);
	galv_assert_intern(conn->fd >= 0);
	galv_assert_intern(conn->work.dispatch);
	galv_assert_intern(conn->coupler);

	ret = galv_conn_async_error(conn);
	if (!ret) {
		galv_assert_intern(!(events & EPOLLERR));

		return galv_coupler_on_connect(conn->coupler,
		                               conn,
		                               events,
		                               poller);
	}

	return galv_conn_on_error(conn, ret, EPOLLERR | events, poller);
}

int
galv_coupler_connect_conn(const struct galv_coupler * __restrict coupler,
                          struct galv_conn * __restrict          connection,
                          const struct sockaddr * __restrict     peer,
                          const struct upoll * __restrict        poller)
{
	galv_coupler_assert_api(coupler);
	galv_conn_assert_api(connection);
	galv_assert_api(peer);
	galv_assert_api(poller);

	const struct galv_binder * __restrict bind = coupler->bind;
	int                                   ret;

	ret = galv_binder_connect_conn(bind, connection, peer);
	galv_assert_intern(ret <= 0);
	if (!ret)
		return galv_coupler_on_connect(coupler,
		                               connection,
		                               EPOLLIN | EPOLLOUT,
		                               poller);

	switch (ret) {
	case -EINPROGRESS:
		return galv_conn_enable_dispatch(connection,
		                                 poller,
		                                 EPOLLOUT,
		                                 galv_coupler_dispatch,
		                                 NULL);

	case -EINTR:
		/* Interrupted by a signal before connect(2) started. */
	case -EACCES:
	case -EPERM:
		/*
		 * Tried connect to a broadcast address without having the
		 * socket broadcast flag enabled or the connection request
		 * failed because of a local firewall rule.
		 */
	case -EAGAIN:
		/* There are insufficient entries in the routing cache. */
	case -EPROTOTYPE:
		/*
		 * The peer socket does not support the requested communications
		 * protocol type.
		 */
		return ret;

	case -ETIMEDOUT:
		/*  Timeout while attempting connection (server busy ?). */
		break;

	default:
		galv_assert_intern(0);
		break;
	}

	return galv_conn_on_error(connection, -ret, EPOLLERR, poller);
}

struct galv_conn *
galv_coupler_create_conn(struct galv_coupler * __restrict coupler,
                         int                              flags)
{
	galv_coupler_assert_api(coupler);
	galv_assert_api(!(flags & ETUX_SOCK_OPEN_INVALID_FLAGS));

	return galv_binder_create_conn(coupler->bind,
	                               coupler->conn_ops,
	                               coupler->conn_type,
	                               SOCK_NONBLOCK | flags,
	                               coupler);
}

int
galv_coupler_destroy_conn(const struct galv_coupler * __restrict coupler,
                          struct galv_conn * __restrict          connection)
{
	galv_coupler_assert_api(coupler);
	galv_conn_assert_api(connection);

	return galv_binder_destroy_conn(coupler->bind, connection);
}

void
galv_coupler_setup(struct galv_coupler * __restrict        coupler,
	           struct galv_binder * __restrict         binder,
	           struct galv_repo * __restrict           repo,
	           const struct galv_conn_ops * __restrict operations,
	           int                                     type)
{
	galv_assert_api(coupler);
	galv_binder_assert_api(binder);
	galv_repo_assert_api(repo);
	galv_conn_assert_ops_api(operations);
	galv_assert_api(type);

	coupler->bind = binder;
	coupler->repo = repo;
	coupler->conn_ops = operations;
	coupler->conn_type = type;
}
