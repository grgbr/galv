/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "galv/coupler.h"
#include "binder.h"
#include "bkoff.h"
#include "common/dispatch.h"
#include "common/conn.h"
#include "common/repo.h"

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
galv_coupler_rearm_bind(struct galv_conn * __restrict  client,
                        struct galv_timer * __restrict timer,
                        const struct upoll *           poller)
{
	galv_conn_assert_intern(client);
	galv_assert_intern(client->fd >= 0);
	galv_assert_intern(galv_conn_state(client) == GALV_CONN_BINDING_STATE);
	galv_assert_intern(!galv_timer_bkoff_armed(timer));
	galv_assert_intern(poller);


	if (!galv_timer_bkoff_defunct(timer)) {
		galv_conn_reset_watch(client, poller, 0);
		galv_timer_arm_bkoff(timer);

		galv_debug("coupler: client reconnection scheduled");

		return 0;
	}

	return -ETIMEDOUT;
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
	galv_assert_intern(!galv_timer_bkoff_armed(galv_conn_timer(client)));
	galv_assert_intern(poller);

	galv_binder_on_connected(coupler->bind, client);

	return galv_conn_on_bound(client, poller);
}

static
void
galv_coupler_term_bind(const struct galv_coupler * __restrict coupler,
                       struct galv_conn * __restrict          client,
                       const struct upoll *                   poller)
{
	galv_coupler_assert_intern(coupler);
	galv_conn_assert_intern(client);
	galv_assert_intern(galv_conn_state(client) != GALV_CONN_OPENED_STATE);
	galv_assert_intern(!galv_timer_bkoff_armed(galv_conn_timer(client)));
	galv_assert_intern(poller);

	galv_conn_repo_unregister(coupler->repo, client);
	galv_conn_unpoll(client);
	galv_conn_set_state(client, GALV_CONN_OPENED_STATE);
}

/*
 * @return 0 in case of success, a negative errno-like value otherwise.
 * @retval -EINTR  Signal occured before connect(2) started.
 * @retval -ENOMEM No more memory
 */
static
int
galv_coupler_dispatch_clnt(struct upoll_worker * worker,
                           uint32_t              events,
                           const struct upoll *  poller)
{
	galv_assert_intern(worker);
	galv_assert_intern(poller);
	galv_assert_intern(events);
	galv_assert_intern(events);
	galv_assert_intern(!(events &
	                     ~((uint32_t)(EPOLLOUT | EPOLLHUP | EPOLLERR))));
	galv_assert_intern(poller);

	struct galv_conn *          clnt = galv_conn_from_worker(worker);
	struct galv_timer *         tmr = galv_conn_timer(clnt);
	const struct galv_coupler * cpl = (const struct galv_coupler *)
	                                  galv_conn_dispatcher(clnt);
	int                         ret;
	const char *                msg;

	galv_conn_assert_intern(clnt);
	galv_assert_intern(clnt->state == GALV_CONN_BINDING_STATE);
	galv_assert_intern(clnt->fd >= 0);
	galv_assert_intern(clnt->work.dispatch);
	galv_assert_intern(galv_conn_watched(clnt) == EPOLLOUT);
	galv_coupler_assert_intern(cpl);

	galv_timer_cancel_bkoff(tmr);

	if (events & (EPOLLERR | EPOLLOUT)) {
		ret = - galv_conn_async_error(clnt);
		if (!ret) {
			galv_assert_intern(!(events & EPOLLERR));
			
			ret = galv_coupler_on_bound(cpl, clnt, poller);
			switch (ret) {
			case 0:
				return 0;

			case -ENOBUFS: /* Custom allocator failure. */
				msg = "unrecoverable upper layer error";
				goto err;

			case -ENOMEM:  /* No more memory. */
				goto term;
			}

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
	if (!galv_coupler_rearm_bind(clnt, tmr, poller))
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
	galv_coupler_term_bind(cpl, clnt, poller);

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
galv_coupler_poll_clnt(const struct galv_coupler * __restrict coupler,
                       struct galv_conn * __restrict          client,
                       uint32_t                               events,
                       const struct upoll * __restrict        poller)
{
	galv_coupler_assert_intern(coupler);
	galv_conn_assert_intern(client);
	galv_assert_intern(client->fd >= 0);
	galv_assert_api(client->state != GALV_CONN_CONNECTING_STATE);
	galv_assert_api(client->state != GALV_CONN_ESTABLISHED_STATE);
	galv_assert_intern(!(events & ~((uint32_t)EPOLLOUT)));
	galv_assert_intern(poller);

	int err;

	err = galv_conn_poll(client,
	                     poller,
	                     events,
	                     galv_coupler_dispatch_clnt);
	if (!err) {
		galv_conn_set_state(client, GALV_CONN_BINDING_STATE);
		galv_conn_repo_register(coupler->repo, client);
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
	galv_assert_intern(!galv_timer_bkoff_armed(galv_conn_timer(client)));
	galv_assert_intern(poller);

	int ret;

	ret = galv_binder_reconnect_clnt(coupler->bind, client, poller);
	if (!ret)
		ret = galv_coupler_poll_clnt(coupler, client, 0, poller);

	return ret;
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

	struct galv_timer *         tmr = galv_timer_from_etux(timer);
	struct galv_conn *          clnt = galv_conn_from_timer(tmr);
	const struct galv_coupler * cpl = (const struct galv_coupler *)
	                                  galv_conn_dispatcher(clnt);
	const struct upoll *        poll = galv_conn_poller(clnt);
	int                         ret;
	const char *                msg = "maximum reconnection "
	                                  "attempts reached";

	ret = galv_coupler_reconnect_clnt(cpl, clnt, poll);
	switch (ret) {
	case 0:
		ret = galv_coupler_on_bound(cpl, clnt, poll);
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
	galv_coupler_term_bind(cpl, clnt, poll);
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
                     int                                tries,
                     int                                msecs)
{
	galv_coupler_assert_api(coupler);
	galv_conn_assert_api(client);
	galv_assert_api(galv_conn_state(client) == GALV_CONN_OPENED_STATE);
	galv_assert_api(peer);
	galv_assert_api(poller);
	galv_assert_api(!tries || msecs);

	int          ret;
	const char * msg = "failed to poll";

	ret = galv_binder_connect_clnt(coupler->bind, client, peer);
	switch (ret) {
	case 0:
		galv_binder_on_connected(coupler->bind, client);
		ret = galv_coupler_poll_clnt(coupler, client, 0, poller);
		if (ret)
			goto err;

		ret = galv_conn_on_bound(client, poller);
		switch (ret) {
		case 0:
			return 0;

		case -ENOBUFS: /* Custom allocator failure */
			galv_coupler_term_bind(coupler, client, poller);
			msg = "unrecoverable upper layer error";
			goto err;

		case -ENOMEM:  /* No more memory. */
			galv_coupler_term_bind(coupler, client, poller);
			return -ENOMEM;
		}

		if (tries)
			goto rebind;
		galv_coupler_term_bind(coupler, client, poller);
		msg = "reconnection disabled";
		goto err;

	case -EINPROGRESS: /* Connection cannot complete immediately. */
		/*
		 * Make sure the poller calls galv_coupler_dispatch_clnt() once
		 * an asynchronous connect(2) event occurs, i.e., either in case
		 * of success or error (timeout, connection refused, etc...)
		 */
		ret = galv_coupler_poll_clnt(coupler, client, EPOLLOUT, poller);
		if (!ret)
			goto differ;
		goto err;

	case -ECONNREFUSED: /* No remote peer is listening. */
	case -ETIMEDOUT:    /* Connection attempt timeout (server busy ?). */
		if (tries) {
			/*
			 * Do not register to poller yet since the socket would
			 * be notified with an EPOLLHUP event within
			 * galv_coupler_dispatch_clnt() at first polling round:
			 * we could not connect indeed...
			 */
			galv_conn_set_state(client, GALV_CONN_BINDING_STATE);
			galv_conn_repo_register(coupler->repo, client);

			/* Arm the reconnection timer and get out. */
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
	galv_timer_setup_bkoff_tries(galv_conn_timer(client),
	                             galv_coupler_expire_binding,
	                             tries,
	                             msecs);
	galv_timer_arm_bkoff(galv_conn_timer(client));

	return -EINPROGRESS;
}

struct galv_conn *
galv_coupler_create_clnt(struct galv_coupler * __restrict coupler,
                         int                              flags)
{
	galv_coupler_assert_api(coupler);
	galv_assert_api(!(flags & ETUX_SOCK_OPEN_INVALID_FLAGS));

	return galv_binder_create_clnt(coupler->bind,
	                               coupler->conn_ops,
	                               SOCK_NONBLOCK | flags,
	                               coupler);
}

int
galv_coupler_destroy_clnt(const struct galv_coupler * __restrict coupler,
                          struct galv_conn * __restrict          client)
{
	galv_coupler_assert_api(coupler);
	galv_conn_assert_api(client);
	galv_assert_api(galv_conn_state(client) == GALV_CONN_OPENED_STATE);

	return galv_binder_destroy_clnt(coupler->bind, client);
}

static
int
galv_coupler_on_conn_term(struct galv_dispatch * __restrict dispatcher,
                          struct galv_conn * __restrict     client,
                          const struct upoll * __restrict   poller)
{
	galv_assert_intern(dispatcher);
	galv_assert_intern(client);
	galv_assert_intern(poller);

	galv_coupler_term_bind((const struct galv_coupler *)dispatcher,
	                       client,
	                       poller);

	return 0;
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

	coupler->base.on_conn_term = galv_coupler_on_conn_term;
	coupler->bind = binder;
	coupler->repo = repo;
	coupler->conn_ops = operations;
}
