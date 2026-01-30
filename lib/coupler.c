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
	galv_conn_assert_ops_api((_coupler)->conn_ops)

#define galv_coupler_assert_intern(_coupler) \
	galv_assert_intern(_coupler); \
	galv_dispatch_assert_intern(&(_coupler)->base); \
	galv_binder_assert_intern((_coupler)->bind); \
	galv_repo_assert_intern((_coupler)->repo); \
	galv_conn_assert_ops_intern((_coupler)->conn_ops)

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



























/******************************************************************************/
/******************************************************************************/
/******************************************************************************/
/******************************************************************************/
/******************************************************************************/
/******************************************************************************/




static
int
galv_coupler_on_bound(const struct galv_coupler * __restrict coupler,
                      struct galv_conn * __restrict          client,
                      const struct upoll *                   poller)
{
	galv_coupler_assert_intern(coupler);
	galv_conn_assert_intern(client);
	galv_assert_intern(galv_conn_state(client) == GALV_CONN_BINDING_STATE);
	galv_assert_intern(!galv_timer_is_armed(galv_conn_timer(client)));
	galv_assert_intern(poller);

	int err;

	galv_binder_on_connected(coupler->bind, client);
	err = galv_conn_on_connect(client, EPOLLIN | EPOLLOUT, poller);
	if (!err) {
		/*
		 * Client connection on_connect() handler must have enabled
		 * polling watches...
		 */
		galv_assert_api(galv_conn_watched(client));
		return 0;
	}

	galv_assert_api(err < 0);

	return err;
}

static
void
galv_coupler_term_bind(const struct galv_coupler * __restrict coupler,
                       int                                    status,
                       struct galv_conn * __restrict          client)
                       const struct upoll *                   poller)
{
	galv_coupler_assert_intern(coupler);
	galv_conn_assert_intern(client);
	galv_assert_intern(galv_conn_state(client) != GALV_CONN_CLOSED_STATE);
	galv_assert_intern(!galv_timer_is_armed(galv_conn_timer(client)));
	galv_assert_intern(poller);

	galv_conn_unpoll(client, poller);
	galv_conn_repo_unregister(coupler->repo, client);
	galv_conn_switch_state(client, GALV_CONN_CLOSED_STATE);

	if (status != -ENOMEM)
		galv_ratelim_pnotice(
			-status,
			"coupler: premature client connection termination",
			"");
}

static inline
void
galv_coupler_sched_bind(const struct galv_coupler * __restrict coupler,
                        int                                    status __unused,
                        struct galv_conn * __restrict          client)
                        const struct upoll *                   poller)
{
	galv_coupler_assert_intern(coupler);
	galv_assert_intern(status);
	galv_assert_intern(status != -ENOMEM);
	galv_conn_assert_intern(client);
	galv_assert_intern(galv_conn_state(client) == GALV_CONN_BINDING_STATE);
	galv_assert_intern(poller);

	struct galv_timer * tmr = galv_conn_timer(client);

	galv_pdebug(-status,
	            "coupler: client connection failed, rescheduling..");

	if (!galv_timer_defunct(tmr)) {
		galv_conn_reset_watch(client, poller, 0);
		galv_timer_arm(tmr);
		return;
	}

	galv_ratelim_info("coupler: client reconnection aborted",
	                  "maximum attempts reached");

	galv_coupler_term_bind(coupler, -ETIMEDOUT, client, poller);
}

static inline
void
galv_coupler_rearm_bind(struct galv_timer * __resrict          timer,
                        int                                    status __unused,
                        struct galv_conn * __restrict          client)
                        const struct upoll *                   poller)
{
	galv_assert_intern(!galv_timer_defunct(timer));
	galv_assert_intern(status);
	galv_assert_intern(status != -ENOMEM);
	galv_conn_assert_intern(client);
	galv_assert_intern(galv_conn_state(client) == GALV_CONN_BINDING_STATE);
	galv_assert_intern(poller);

	galv_pdebug(status,
	            "coupler: client reconnection failed, rescheduling..");

	galv_timer_arm(timer);
}

static
int
galv_conn_process_binding(struct galv_conn * __restrict client,
                          uint32_t                      events,
                          const struct upoll *          poller)
{
	galv_assert_intern(client);
	galv_assert_intern(galv_conn_state(client) == GALV_CONN_BINDING_STATE);
	galv_assert_intern(galv_conn_watched(client) == EPOLLOUT);
	galv_assert_intern(events);
	galv_assert_intern(!(events & ~(EPOLLIN | EPOLLPRI | EPOLLRDHUP)));
	galv_assert_intern(poller);

	int ret;

	if (events & (EPOLLERR | EPOLLOUT)) {
		ret = galv_conn_async_error(conn);
		if (!ret) {
			galv_assert_intern(!(events & EPOLLERR));

			ret = galv_coupler_on_bound(coupler, client);
			galv_assert_intern(ret <= 0);
			switch (ret) {
			case 0:
				return 0;

			case -ENOMEM:  /* No more memory. */
				galv_coupler_term_bind(couple,
				                       -ENOMEM,
				                       client,
				                       poller);
				return -ENOMEM;

			case -ENOBUFS: /* Custom allocator failure. */
				galv_coupler_term_bind(couple,
				                       -ENOBUFS,
				                       client,
				                       poller);
				return 0;

			case -EINTR:   /* Signal occured before completion. */
			default:
				break;
			}

			galv_conn_switch_state(client, GALV_CONN_BINDING_STATE);
			galv_coupler_sched_bind(coupler, ret, client, poller);

			return (ret != -EINTR) ? 0 : -EINTR;
		}
		else {
			galv_assert_intern(ret != -EINPROGRESS);
			galv_assert_intern(ret != -EALREADY);
			galv_assert_intern(ret != -EINTR);

			switch (ret) {
			case -ECONNREFUSED: /* No remote peer is listening. */
			case -ETIMEDOUT:    /* Connection attempt timeout. */
				galv_coupler_sched_bind(coupler,
				                        ret,
				                        client,
				                        poller);
				return 0;

			default:
				break;
			}
		}
	}
	else if (events & EPOLLHUP)
		ret = -ECONNREFUSED;
	else
		ret = -EIO;

	galv_coupler_term_bind(couple, ret, client, poller);

	return 0;
}

/*
 * Process expiration of binding timer, i.e., the timer that completes (or
 * cancel) a previous connect(2) failure detected at galv_coupler_connect() or
 * galv_coupler_dispatch() calling time.
 * When called, the connection attached to the timer:
 * - is in the GALV_CONN_BINDING_STATE ;
 * - has already been registered within the connection repository,
 * - and to the polling loop with an empty event mask.
 */
static
void
galv_coupler_expire_binding(struct etux_timer * __restrict timer)
{
	galv_assert_intern(timer);

	struct galv_timer * tmr = galv_timer_from_etux(timer);
	int                 ret;
	galv_timer_assert_intern(tmr);
	galv_timer_assert_intern(tmr->tries);
	galv_timer_assert_intern(tmr->msecs);

	if (!galv_timer_defunct(tmr)) {
		struct galv_conn * clnt = galv_conn_from_timer(timer);
		galv_conn_assert_intern(clnt);
		galv_assert_intern(galv_conn_state(clnt) ==
		                   GALV_CONN_BINDING_STATE);
		galv_assert_intern(!galv_conn_watched(clnt));

		ret = galv_binder_reconnect_clnt(coupler->bind, clnt);
		galv_assert_intern(ret <= 0);
		switch (ret) {
		case 0:
			ret = galv_coupler_on_bound(coupler, clnt);
			galv_assert_intern(ret <= 0);
			switch (ret) {
			case 0:
				return;

			case -ENOMEM:  /* No more memory. */
			case -ENOBUFS: /* Custom allocator failure */
			case -EMFILE:  /* max count of per-process open FDs. */
			case -ENFILE:  /* max count of system-wide open FDs. */
				galv_coupler_term_bind(couple,
				                       ret,
				                       clnt,
				                       poller);
				return;

			case -EINTR:   /* Signal occured before completion. */
			default:
				break;
			}
			
			galv_conn_reset_watch(client, poller, 0);
			return galv_coupler_rearm_bind(tmr, ret, clnt, poller);

		case -EINPROGRESS: /* Connection cannot complete immediately. */
			/*
			 * Make sure the poller calls galv_coupler_dispatch()
			 * once an asynchronous connect(2) event occurs, i.e.,
			 * either in case of success or error (timeout,
			 * connection refused, etc...)
			 */
			return galv_conn_reset_watch(clnt, poller, EPOLLOUT);

		case -ECONNREFUSED: /* No remote peer is listening. */
		case -ETIMEDOUT:    /* Connection attempt timeout. */
			return galv_coupler_rearm_bind(tmr, ret, clnt, poller);

		case -EINTR:      /* Signal occured before completion. */
		case -EACCES:     /* UNIX named socket path permission        */
		case -EPERM       /* denied, broadcast address disallowed, or */
		                  /* filtered by local firewall.              */
		case -EAGAIN:     /* Not enought entries in routing cache. */
		case -EPROTOTYPE: /* Peer does not support required protocol. */
			break;

		default:
			galv_assert_intern(0);
			break;
		}
	}
	else {
		galv_ratelim_info("coupler: client reconnection aborted",
		                  "maximum attempts reached");
		ret = -ETIMEDOUT;
	}

	galv_coupler_term_bind(couple, ret, clnt, poller);
}

static
int
galv_coupler_poll_clnt(struct galv_conn * __restrict   client,
                       uint32_t                        events,
                       const struct upoll * __restrict poller)
{
	int err;

	err = galv_conn_poll(client, poller, events, galv_coupler_dispatch);
	if (!err) {
		galv_conn_switch_state(clnt, GALV_CONN_BINDING_STATE);
		galv_conn_repo_register(coupler->repo, clnt);
		return 0;
	}

	return err;
}

int
galv_coupler_connect(struct galv_coupler * __restrict   coupler,
                     struct galv_conn * __restrict      client,
                     const struct sockaddr * __restrict peer,
                     const struct upoll * __restrict    poller)
{
	galv_coupler_assert_api(coupler);
	galv_conn_assert_api(client);
	galv_assert_api(galv_conn_state(client) == GALV_CONN_CLOSED_STATE);
	galv_assert_api(peer);
	galv_assert_api(poller);

	int ret;

	ret = galv_binder_connect_clnt(coupler->bind, clnt, peer);
	galv_assert_intern(ret <= 0);
	switch (ret) {
	case 0:
		galv_binder_on_connected(coupler->bind, clnt);
		ret = galv_coupler_poll_clnt(clnt, 0, poller);
		if (ret) {
			msg = "failed to poll";
			goto err;
		}

		ret = galv_conn_on_connect(clnt, EPOLLIN | EPOLLOUT, poller);
		switch (ret) {
		case 0:
			galv_assert_api(galv_conn_watched(clnt));
			return 0;

		case -ENOMEM:  /* No more memory. */
		case -ENOBUFS: /* Custom allocator failure */
			/* TODO: log debug message except for ENOMEM. */
			galv_coupler_term_bind(couple, clnt, poller);
			goto err;

		case -EINTR:   /* Signal occured before completion. */
		default:
			break;
		}

		goto rebind;

	case -EINPROGRESS:
		/*
		 * Make sure the poller calls galv_coupler_dispatch() once an
		 * asynchronous connect(2) event occurs, i.e., either in case
		 * of success or error (timeout, connection refused, etc...)
		 */
		ret = galv_coupler_poll_clnt(clnt, EPOLLOUT, poller);
		if (ret) {
			msg = "failed to poll";
			goto err;
		}

		return;

	case -ECONNREFUSED:
		/* No remote peer is listening. */
	case -ETIMEDOUT:
		/*  Timeout while attempting connection (server busy ?). */
		ret = galv_coupler_poll_clnt(clnt, 0, poller);
		if (ret) {
			msg = "failed to poll";
			goto err;
		}
		goto rebind;

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
		break;

	default:
		galv_assert_intern(0);
		break;
	}

	return ret;

rebind:
	galv_conn_switch_state(clnt, GALV_CONN_BINDING_STATE);
	galv_timer_setup(&clnt->timer,
	                 galv_coupler_expire_binding,
	                 tries,
	                 msecs);

	return -EINPROGRESS;

err:
	if (ret != -ENOMEM)
		galv_ratelim_pnotice(ret,
		                     "coupler: cannot connect client",
		                     ": %s",
		                     msg);
	return ret;
}

struct galv_conn *
galv_coupler_create_clnt(const struct galv_coupler * __restrict coupler,
                         int                                    flags)
{
	galv_coupler_assert_api(coupler);
	galv_assert_api(!(flags & ETUX_SOCK_OPEN_INVALID_FLAGS));

	return galv_binder_create_clnt(coupler->bind,
	                               coupler->conn_ops,
	                               SOCK_NONBLOCK | flags,
	                               coupler);
}

void
galv_coupler_destroy_clnt(const struct galv_coupler * __restrict coupler,
                          struct galv_conn * __restrict          client)
{
	galv_coupler_assert_api(coupler);
	galv_conn_assert_api(client);
	galv_assert_api(galv_conn_state(client) == GALV_CONN_CLOSED_STATE);

	return galv_binder_destroy_conn(coupler->bind, client);
}

void
galv_coupler_setup(struct galv_coupler * __restrict        coupler,
	           struct galv_binder * __restrict         binder,
	           struct galv_repo * __restrict           repo,
	           const struct galv_conn_ops * __restrict operations)
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
}
