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
galv_coupler_process_clnt_error(struct galv_conn * __restrict client,
                                uint32_t * __restrict         events,
                                const struct upoll *          poller)
{
	galv_assert_intern(client);
	galv_assert_intern(events);
	galv_assert_intern(*events);
	galv_assert_intern(poller);

	if (stroll_unlikely(*events & EPOLLERR)) {
		int ret;

		ret = galv_conn_on_error(client,
		                         galv_conn_async_error(client),
		                         *events,
		                         poller);
		if (ret)
			return ret;

		*events &= ~((uint32_t)(EPOLLERR));
	}

	return 0;
}

static
int
galv_coupler_process_established_clnt(struct galv_conn * __restrict client,
                                      uint32_t                      events,
                                      const struct upoll *          poller)
{
	galv_assert_intern(client);
	galv_assert_intern(events);
	galv_assert_intern(poller);

	int ret;

	ret = galv_coupler_process_clnt_error(client, &events, poller);
	if (ret)
		return ret;

	if (events & EPOLLHUP)
		ret = galv_conn_on_send_shut(client, events, poller);
	else if (events & EPOLLRDHUP)
		ret = galv_conn_on_recv_shut(client, events, poller);
	else if (events & (EPOLLIN | EPOLLPRI | EPOLLOUT))
		ret = galv_conn_on_may_xfer(client, events, poller);

	return ret;
}

static
int
galv_coupler_process_connecting_clnt(struct galv_conn * __restrict client,
                                     uint32_t                      events,
                                     const struct upoll *          poller)
{
	galv_assert_intern(client);
	galv_assert_intern(events);
	galv_assert_intern(poller);

	int ret;

	ret = galv_coupler_process_clnt_error(client, &events, poller);
	if (ret)
		return ret;

	if (events & (EPOLLHUP | EPOLLRDHUP))
		ret = galv_conn_close(client, poller);
	else if (events & (EPOLLIN | EPOLLPRI | EPOLLOUT))
		ret = galv_conn_on_may_xfer(client, events, poller);

	return ret;
}

static
int
galv_coupler_process_closing_clnt(struct galv_conn * __restrict client,
                                  uint32_t                      events,
                                  const struct upoll *          poller)
{
	galv_assert_intern(client);
	galv_assert_intern(events);
	galv_assert_intern(poller);

	int ret;

	ret = galv_coupler_process_clnt_error(client, &events, poller);
	if (ret)
		return ret;

	if (events & EPOLLHUP)
		ret = galv_conn_close(client, poller);
	else if (events & EPOLLRDHUP)
		ret = galv_conn_on_recv_shut(client, events, poller);
	else if (events & (EPOLLIN | EPOLLPRI | EPOLLOUT))
		ret = galv_conn_on_may_xfer(client, events, poller);

	return ret;
}

/*
 * @return 0 in case of success, a negative errno-like value otherwise.
 * @retval -EINTR  Signal occured before connect(2) started.
 * @retval -ENOMEM No more memory
 */
static
int
galv_coupler_process_binding_clnt(struct galv_conn * __restrict client,
                                  uint32_t                      events,
                                  const struct upoll *          poller)
{
	galv_assert_intern(client);
	galv_assert_intern(galv_conn_state(client) == GALV_CONN_BINDING_STATE);
	galv_assert_intern(galv_conn_watched(client) == EPOLLOUT);
	galv_assert_intern(galv_timer_is_armed(galv_conn_timer(client)));
	galv_assert_intern(events);
	galv_assert_intern(!(events & ~(EPOLLOUT | EPOLLHUP | EPOLLERR)));
	galv_assert_intern(poller);

	int                 ret;
	struct galv_timer * tmr = galv_conn_timer(client);
	const char *        msg;

	galv_timer_cancel(tmr);

	if (events & (EPOLLERR | EPOLLOUT)) {
		ret = - galv_conn_async_error(conn);
		if (!ret) {
			galv_assert_intern(!(events & EPOLLERR));
			
			ret = galv_coupler_on_bound(coupler, client);
			switch (ret) {
			case 0:
				return 0;

			case -ENOBUFS: /* Custom allocator failure. */
				msg = "unrecoverable upper layer error";
				goto err;

			case -ENOMEM:  /* No more memory. */
				goto term;
			}

			galv_conn_switch_state(client, GALV_CONN_BINDING_STATE);
			goto rebind;
		}
		else {
			galv_assert_intern(ret != -EINPROGRESS);
			galv_assert_intern(ret != -EALREADY);
			switch (ret) {
			case -ECONNREFUSED: /* No remote peer is listening. */
			case -ETIMEDOUT:    /* Connection attempt timeout. */
				goto rebind;

			case -ENOMEM:       /* No more memory. */
				goto term;
			}

			msg = "unrecoverable error";
			goto err;
		}
	}
	else if (!(events & EPOLLHUP)) {
		ret = -EIO;
		msg = "unexpected socket event";
		goto err;
	}

	/* events & EPOLLHUP */
	ret = -ECONNREFUSED;

rebind:
	galv_pdebug(-ret, "coupler: differed client connection failed");
	if (!galv_coupler_rearm_bind(client, tmr, poller))
		return 0;

	msg = "maximum reconnection attempts reached";

err:
	galv_assert_intern(msg);
	galv_assert_intern(msg[0]);
	galv_ratelim_pnotice(-ret,
	                     "coupler: cannot complete client connection",
	                     ": %s",
	                     msg);
term:
	galv_coupler_term_bind(coupler, client, poller);

	switch (ret) {
	case -EINTR:
	case -ENOMEM:
		return ret;

	default:
		return 0;
	}
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
galv_coupler_poll_clnt(struct galv_conn * __restrict   client,
                       uint32_t                        events,
                       const struct upoll * __restrict poller)
{
	galv_coupler_assert_intern(coupler);
	galv_conn_assert_intern(client);
	galv_assert_intern(client->fd >= 0);
	galv_assert_intern(galv_conn_state(client) == GALV_CONN_BINDING_STATE);
	galv_assert_intern(!galv_conn_watched(client));
	galv_assert_intern(!galv_timer_is_armed(galv_conn_timer(client)));
	galv_assert_intern(!(events & ~EPOLLOUT));
	galv_conn_assert_intern(poller);

	int err;

	err = galv_conn_poll(client,
	                     poller,
	                     events,
	                     galv_coupler_dispatch_clnt);
	if (!err) {
		galv_conn_switch_state(clnt, GALV_CONN_BINDING_STATE);
		galv_conn_repo_register(coupler->repo, clnt);
		return 0;
	}

	return err;
}

static
int
galv_coupler_reconnect_clnt(const struct galv_coupler * __restrict coupler,
                            struct galv_conn * __restrict          client,
                            const struct upoll *                   poller)
{
	galv_coupler_assert_intern(coupler);
	galv_conn_assert_intern(client);
	galv_assert_intern(client->fd >= 0);
	galv_assert_intern(galv_conn_state(client) == GALV_CONN_BINDING_STATE);
	galv_assert_intern(!galv_conn_watched(client));
	galv_assert_intern(!galv_timer_is_armed(galv_conn_timer(client)));
	galv_conn_assert_intern(poller);

	int ret;

	ret = galv_binder_reconnect_clnt(coupler->bind, client);
	if (!ret)
		ret = galv_coupler_poll_clnt(client, 0, poller);

	return ret;
}

static
int
galv_coupler_on_bound(const struct galv_coupler * __restrict coupler,
                      struct galv_conn * __restrict          client,
                      const struct upoll *                   poller)
{
	galv_coupler_assert_intern(coupler);
	galv_conn_assert_intern(client);
	galv_assert_intern(client->fd >= 0);
	galv_assert_intern(galv_conn_state(client) == GALV_CONN_BINDING_STATE);
	galv_assert_intern(!galv_timer_is_armed(galv_conn_timer(client)));
	galv_assert_intern(poller);

	galv_binder_on_connected(coupler->bind, client);

	return galv_conn_on_connect(client, EPOLLIN | EPOLLOUT, poller);
}

static
int
galv_coupler_rearm_bind(struct galv_conn * __restrict client,
                        struct galv_timer * __resrict timer,
                        const struct upoll *          poller)
{
	galv_conn_assert_intern(client);
	galv_assert_intern(client->fd >= 0);
	galv_assert_intern(galv_conn_state(client) == GALV_CONN_BINDING_STATE);
	galv_assert_intern(!galv_timer_is_armed(timer));
	galv_assert_intern(poller);


	if (!galv_timer_defunct(tmr)) {
		galv_conn_reset_watch(client, poller, 0);
		galv_timer_arm(timer);

		galv_debug("coupler: client reconnection scheduled");

		return 0;
	}

	return -ETIMEDOUT;
}

static
void
galv_coupler_term_bind(const struct galv_coupler * __restrict coupler,
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
}

/*
 * Process expiration of binding timer, i.e., the timer that completes (or
 * cancel) a previous connect(2) failure detected at galv_coupler_connect() or
 * galv_coupler_dispatch_clnt() calling time.
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
	struct galv_conn *  clnt = galv_conn_from_timer(timer);
	int                 ret;
	const char *        msg = "maximum reconnection attempts reached";

	ret = galv_coupler_reconnect_clnt(coupler->bind, clnt, poll);
	switch (ret) {
	case 0:
		ret = galv_coupler_on_bound(coupler, clnt);
		switch (ret) {
		case 0:
			return;

		case -ENOBUFS: /* Custom allocator failure */
			msg = "unrecoverable upper layer error";
			goto err;

		case -ENOMEM:  /* No more memory. */
			goto term;
		}
		
		if (!galv_coupler_rearm_bind(clnt, tmr, poll))
			return;
		goto err;

	case -EINPROGRESS: /* Connection cannot complete immediately. */
		/*
		 * Make sure the poller calls
		 * galv_coupler_dispatch_clnt() once an asynchronous
		 * connect(2) event occurs, i.e., either in case of
		 * success or error (timeout, connection refused,
		 * etc...)
		 */
		return galv_conn_reset_watch(clnt, poll, EPOLLOUT);

	case -ECONNREFUSED: /* No remote peer is listening. */
	case -ETIMEDOUT:    /* Connection attempt timeout. */
	case -EINTR:      /* Signal occured before completion. */
		if (!galv_coupler_rearm_bind(clnt, tmr, poll))
			return;
		goto err;
	}

	msg = "unrecoverable error";

err:
	galv_ratelim_pnotice(-ret,
	                     "coupler: cannot reconnect client",
	                     ": %s",
	                     msg);
term:
	galv_coupler_term_bind(coupler, clnt, poller);
}

/* TODO: make a galv_coupler_reconnect()/galv_clnt_reconnect() API */

/*
 * @return 0 in case of success, a negative errno-like value otherwise.
 * @retval -EINTR          Signal occured before connect(2) started.
 * @retval -ENOBUFS        Some custom allocator failed to allocate object(s)
 * @retval -ENOMEM         No more memory
 * @retval -EACCES, -EPERM UNIX named socket path permission denied broadcast
 *                         address disallowed, or filtered by local firewall
 *                         rules.
 * @retval -EAGAIN         Not enought entries in routing cache.
 * @retval -EPROTOTYPE     Peer does not support required protocol.
 * @retval -EINPROGRESS    Automatic reconnection logic started.
 * @retval -ECONNREFUSED   No remote peer is listening and could not start
 *                         automatic reconnection logic
 * @ret    -ETIMEDOUT:     Underlying connection attempt timed out and could not
 *                         start automatic reconnection logic.
 */
int
galv_coupler_connect(struct galv_coupler * __restrict   coupler,
                     struct galv_conn * __restrict      client,
                     const struct sockaddr * __restrict peer,
                     const struct upoll * __restrict    poller,
                     int                                retries,
                     int                                msecs)
{
	galv_coupler_assert_api(coupler);
	galv_conn_assert_api(client);
	galv_assert_api(galv_conn_state(client) == GALV_CONN_CLOSED_STATE);
	galv_assert_api(peer);
	galv_assert_api(poller);
	galv_assert_api(!retries || msecs);

	int          ret;
	const char * msg = "failed to poll";

	ret = galv_binder_connect_clnt(coupler->bind, clnt, peer);
	switch (ret) {
	case 0:
		galv_binder_on_connected(coupler->bind, clnt);
		ret = galv_coupler_poll_clnt(clnt, 0, poller);
		if (ret)
			goto err;

		ret = galv_conn_on_connect(clnt, EPOLLIN | EPOLLOUT, poller);
		switch (ret) {
		case 0:
			return 0;

		case -ENOBUFS: /* Custom allocator failure */
			galv_coupler_term_bind(coupler, clnt, poller);
			msg = "unrecoverable upper layer error";
			goto err;

		case -ENOMEM:  /* No more memory. */
			galv_coupler_term_bind(coupler, clnt, poller);
			return -ENOMEM;
		}

		if (retries)
			goto rebind;
		galv_coupler_term_bind(coupler, clnt, poller);
		msg = "reconnection disabled";
		goto err;

	case -EINPROGRESS: /* Connection cannot complete immediately. */
		/*
		 * Make sure the poller calls galv_coupler_dispatch_clnt() once
		 * an asynchronous connect(2) event occurs, i.e., either in case
		 * of success or error (timeout, connection refused, etc...)
		 */
		ret = galv_coupler_poll_clnt(clnt, EPOLLOUT, poller);
		if (!ret)
			goto differ;
		goto err;

	case -ECONNREFUSED: /* No remote peer is listening. */
	case -ETIMEDOUT:    /* Connection attempt timeout (server busy ?). */
		if (retries) {
			ret = galv_coupler_poll_clnt(clnt, 0, poller);
			if (!ret)
				goto rebind;
		}
		else
			msg = "reconnection disabled";
		goto err;

	case -EINTR:      /* Signal occured before connect(2) started. */
		return -EINTR;
	}

	msg = "unrecoverable error";

err:
	galv_ratelim_pnotice(-ret,
	                     "coupler: cannot connect client",
	                     ": %s",
	                     msg);
	return ret;

rebind:
	galv_pdebug(-ret, "coupler: initial client connection failed");
	galv_debug("coupler: client reconnection scheduled");
differ:
	galv_conn_switch_state(client, GALV_CONN_BINDING_STATE);
	galv_timer_setup(galv_conn_timer(client),
	                 galv_coupler_expire_binding,
	                 retries,
	                 msecs);
	galv_timer_arm(galv_conn_timer(client));

	return -EINPROGRESS;
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
