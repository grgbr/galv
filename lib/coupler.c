/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "galv/coupler.h"
#include "dispatch.h"
#include "binder.h"
#include "repo.h"

#define galv_coupler_assert_api(_coupler) \
	galv_assert_api(_coupler); \
	galv_dispatch_assert_api(&(_coupler)->base); \
	galv_binder_assert_api((_coupler)->bind); \
	galv_repo_assert_api((_coupler)->repo); \
	galv_conn_assert_ops_api((_coupler)->conn_ops); \
	galv_assert_api((_coupler)->conn_type)

#define galv_coupler_assert_intern(_coupler) \
	galv_assert_intern(_coupler); \
	galv_dispatch_assert_intern(&(_coupler)->base); \
	galv_binder_assert_intern((_coupler)->bind); \
	galv_repo_assert_intern((_coupler)->repo); \
	galv_conn_assert_ops_intern((_coupler)->conn_ops); \
	galv_assert_intern((_coupler)->conn_type)

static
int
galv_coupler_process_established_clnt(struct galv_conn * __restrict connection,
                                      uint32_t                      events,
                                      const struct upoll *          poller)
{
	galv_assert_intern(connection);
	galv_assert_intern(events);
	galv_assert_intern(poller);

	int ret;

	if (events & EPOLLHUP)
		ret = galv_conn_on_send_shut(connection, events, poller);
	else if (events & EPOLLRDHUP)
		ret = galv_conn_on_recv_shut(connection, events, poller);
	else
		ret = galv_conn_on_may_xfer(connection, events, poller);

	return ret;
}

static
void
galv_coupler_rebind(struct galv_coupler * __restrict coupler,
                    struct galv_conn * __restrict    client,
                    const struct upoll * __restrict  poller)

{
	int ret;

	ret = galv_binder_reconnect(coupler->bind, client);
	galv_assert_intern(ret <= 0);
	switch (ret) {
	case 0:
		galv_binder_on_connected(coupler->bind, client);
		ret =  galv_conn_on_connect(client, EPOLLIN | EPOLLOUT, poller);
		if (!ret) {
			galv_conn_cancel_timer(client);
			return 0;
		}
		if (!galv_conn_arm_timer(client))
			return;
		break;

	case -EINPROGRESS:
		client->state = GALV_CONN_BINDING_STATE;
		ret = galv_conn_enable_dispatch(client,
		                                poller,
		                                EPOLLOUT,
		                                galv_coupler_dispatch);
		if (!ret && !galv_conn_arm_timer(client))
			return;
		break;

	case -EINTR:
		/* Interrupted by a signal before connect(2) started. */
		break;

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
		break;

	case -ECONNREFUSED:
		/* No remote peer is listening. */
	case -ETIMEDOUT:
		/*  Timeout while attempting connection (server busy ?). */
		if (!galv_conn_arm_timer(client))
			return;
		break;

	default:
		galv_assert_intern(0);
		break;
	}

	galv_coupler_on_conn_term(&coupler->base, client, poller);
}

static
void
galv_coupler_expire_binding(struct etux_timer * __restrict timer)
{
	galv_assert_intern(timer)

	struct galv_conn * clnt = galv_conn_from_timer(timer);
	galv_conn_assert_intern(clnt);
	galv_assert_intern(clnt->tmout);
	galv_assert_intern(clnt->tries);

	if (!timer->tries) {
		galv_coupler_on_conn_term(clnt->dispatch, clnt, timer->poll);
		return;
	}

	if (timer->tries > 0)
		clnt->tries--;

	galv_coupler_rebind(clnt, timer->poll);
}

static
int
galv_coupler_process_connecting_clnt(struct galv_conn * __restrict connection,
                                     uint32_t                      events,
                                     const struct upoll *          poller)
{
	galv_assert_intern(connection);
	galv_assert_intern(events);
	galv_assert_intern(poller);

	int ret;

	if (!(events & (EPOLLHUP | EPOLLRDHUP)))
		ret = galv_conn_on_may_xfer(connection, events, poller);
	else
		ret = galv_conn_close(connection, poller);

	return ret;
}


static
int
galv_coupler_dispatch_clnt(struct upoll_worker * worker,
                           uint32_t              events,
                           const struct upoll *  poller)
{
	galv_assert_intern(worker);
	galv_assert_intern(poller);
	galv_assert_intern(events);
	galv_assert_intern(!(events & ~GALV_CONN_POLL_VALID_EVENTS));

	struct galv_conn * clnt;
	int                ret;

	clnt = galv_conn_from_worker(worker);
	galv_conn_assert_intern(clnt);
	galv_assert_intern(clnt->state != GALV_CONN_CLOSED_STATE);
	galv_assert_intern(clnt->fd >= 0);
	galv_assert_intern(clnt->work.dispatch);
	galv_assert_intern(clnt->dispatch);

	if (events & EPOLLERR) {
		ret = galv_conn_on_error(clnt,
		                         galv_conn_async_error(clnt),
		                         events,
		                         poller);
		if (ret)
			return ret;

		events &= ~((uint32_t)(EPOLLERR));
	}

	switch (galv_conn_state(clnt)) {
	case GALV_CONN_ESTABLISHED_STATE:
		ret = galv_coupler_process_established_clnt(clnt,
		                                            events,
		                                            poller);
		break;

	case GALV_CONN_CONNECTING_STATE:
		ret = galv_coupler_process_connecting_clnt(clnt,
		                                           events,
		                                           poller);
		break;

	case GALV_CONN_CLOSING_STATE:
		ret = galv_coupler_process_closing_clnt(clnt, events, poller);
		break;

	case GALV_CONN_BINDING_STATE:
		ret = galv_coupler_process_binding_clnt(clnt, events, poller);
		break;

	case GALV_CONN_CLOSED_STATE:
	default:
		galv_assert_intern(0);
	}

	return ret;
}






















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

	int ret;

	galv_binder_on_connected(coupler->bind, connection);

	ret = galv_conn_on_connect(connection, events, poller);
	if (!ret || (ret == -EINTR))
		return ret;

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
	galv_assert_intern(conn->state == GALV_CONN_BINDING_STATE);
	galv_assert_intern(conn->fd >= 0);
	galv_assert_intern(conn->work.dispatch);
	galv_assert_intern(conn->dispatch);

	ret = galv_conn_async_error(conn);
	if (!ret) {
		galv_assert_intern(!(events & EPOLLERR));

		return galv_coupler_on_connect((const struct galv_coupler *)
		                               galv_conn_dispatcher(conn),
		                               conn,
		                               events,
		                               poller);
	}

	return galv_conn_on_error(conn, ret, EPOLLERR | events, poller);
}

static
int
galv_coupler_on_conn_term(struct galv_dispatch * __restrict dispatcher,
                          struct galv_conn * __restrict     connection,
                          const struct upoll * __restrict   poller)
{
	galv_coupler_assert_intern((struct galv_coupler *)dispatcher);
	galv_conn_assert_intern(connection);
	galv_assert_intern(connection->fd >= 0);
	galv_assert_intern(poller);

	struct galv_coupler * cpl = (struct galv_coupler *)dispatcher;

	galv_conn_repo_unregister(cpl->repo, connection);

	return galv_binder_destroy_conn(cpl->bind, connection);
}

int
galv_coupler_connect(struct galv_coupler * __restrict   coupler,
                     const struct sockaddr * __restrict peer,
                     int                                flags,
                     const struct upoll * __restrict    poller)
{
	galv_coupler_assert_api(coupler);
	galv_assert_api(peer);
	galv_assert_api(!(flags & ETUX_SOCK_OPEN_INVALID_FLAGS));
	galv_assert_api(poller);

	struct galv_conn * conn;
	int                ret;

	conn = galv_binder_create_conn(coupler->bind,
	                               coupler->conn_ops,
	                               coupler->conn_type,
	                               SOCK_NONBLOCK | flags,
	                               coupler);
	if (!conn)
		return -errno;

	galv_conn_repo_register(coupler->repo, conn);

	ret = galv_binder_connect_conn(coupler->bind, conn, peer);
	galv_assert_intern(ret <= 0);
	switch (ret) {
	case 0:
		return galv_coupler_on_connect(coupler,
		                               conn,
		                               EPOLLIN | EPOLLOUT,
		                               poller);

	case -EINPROGRESS:
		return galv_conn_bind(conn,
		                      poller,
		                      galv_coupler_dispatch);

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
		galv_coupler_on_conn_term(&coupler->base, conn, poller);
		return ret;

	case -ECONNREFUSED:
		/* No remote peer is listening. */
	case -ETIMEDOUT:
		/*  Timeout while attempting connection (server busy ?). */
		break;

	default:
		galv_assert_intern(0);
		break;
	}

	return galv_conn_on_error(conn, -ret, EPOLLERR, poller);
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

	coupler->base.on_conn_term = galv_coupler_on_conn_term;
	coupler->bind = binder;
	coupler->repo = repo;
	coupler->conn_ops = operations;
	coupler->conn_type = type;
}
