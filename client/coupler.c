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

	if (events & EPOLLERR)
		/*
		 * Nothing specific to do as next syscall called with our socket
		 * fd as argument should return the error as errno...
		 */
		galv_conn_debug(clnt, "coupler", "socket error ignored");

	if (events & EPOLLHUP) {
		ret = -ECONNRESET;
		goto rebind;
	}

	galv_assert_intern(events & (EPOLLERR | EPOLLOUT));
	ret = - galv_conn_async_error(clnt);
	if (!ret) {
		galv_binder_on_connected(cpl->bind, clnt);
		ret = galv_conn_on_bound(clnt, poller);
		if (!ret || (ret == -EINTR))
			/*
			 * When -EINTR is returned, galv_conn_on_bound() *MUST*
			 * have completed its logic !
			 * See definition of on_bound() connection operations
			 * function pointer in <galv/conn.h> for more infos.
			 */
			return ret;

		if ((ret != -ENOBUFS) && (ret != -ENOMEM))
			goto rebind;
	}
	else if ((ret == -ECONNREFUSED) || (ret == -ETIMEDOUT))
		goto rebind;

	/*
	 * Should never happen in non-blocking mode ?
	 * See connect(2), connect(3p) and:
	 * http://www.madore.org/~david/computers/connect-intr.html
	 */
	galv_assert_intern(ret != -EINTR);

	msg = "unrecoverable error";
	goto term;

rebind:
	if (!galv_timer_bkoff_defunct(galv_conn_timer(clnt))) {
		/*
		 * Schedule a reconnection operation.
		 * Do not register to poller yet since the socket would be
		 * notified with an EPOLLHUP event at next polling round.
		 * Arm the reconnection timer instead and get out.
		 */
		galv_conn_unpoll(clnt);
		galv_timer_arm_bkoff(galv_conn_timer(clnt));
		galv_conn_pdebug(clnt,
		                 -ret,
		                 "coupler",
		                 "cannot complete client connection: "
		                 "reconnection scheduled");
		return 0;
	}

	msg = "maximum attempts reached";

term:
	galv_conn_pnotice(clnt,
	                  -ret,
	                  "coupler",
	                  "cannot complete client connection: %s",
	                  msg);
	galv_conn_repo_unregister(cpl->repo, clnt);
	galv_conn_unpoll(clnt);
	galv_conn_set_state(clnt, GALV_CONN_OPENED_STATE);

	return (ret != -ENOMEM) ? 0 : ret;
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
	const char *                msg = "unrecoverable error";

	ret = galv_binder_reconnect_clnt(cpl->bind, clnt);
	switch (ret) {
	case 0:
		ret = galv_conn_poll(clnt,
		                     poll,
		                     EPOLLOUT,
		                     galv_coupler_dispatch_clnt);
		if (!ret) {
			galv_binder_on_connected(cpl->bind, clnt);
			ret = galv_conn_on_bound(clnt, poll);
			if (!ret || (ret == -EINTR))
				/*
				 * When -EINTR is returned, galv_conn_on_bound()
				 * *MUST* have completed its logic !
				 * See definition of on_bound() connection
				 * operations function pointer in <galv/conn.h>
				 * for more infos.
				 */
				return;

			galv_conn_unpoll(clnt);

			if ((ret != -ENOBUFS) && (ret != -ENOMEM))
				break;
		}
		else if (ret != -ENOMEM) {
			msg = "failed to poll";
			goto err;
		}

		goto term;

	case -EINPROGRESS: /* Connection cannot complete immediately. */
		/*
		 * Make sure the poller calls galv_coupler_dispatch_clnt() once
		 * an asynchronous connect(2) event occurs, i.e., either in case
		 * of success or error (timeout, connection refused, etc...)
		 */
		ret = galv_conn_poll(clnt,
		                     poll,
		                     EPOLLOUT,
		                     galv_coupler_dispatch_clnt);
		if (!ret)
			return;

		msg = "failed to poll";
		goto err;

	case -ECONNREFUSED: /* No remote peer is listening. */
	case -ETIMEDOUT:    /* Connection attempt timeout. */
		break;

	default:
		/*
		 * Should never happen in non-blocking mode ?
		 * See connect(2), connect(3p) and:
		 * http://www.madore.org/~david/computers/connect-intr.html
		 */
		galv_assert_intern(ret != -EINTR);

		goto err;
	}

	if (!galv_timer_bkoff_defunct(tmr)) {
		/*
		 * Reschedule a reconnection operation.
		 * Do not register to poller yet since the socket would be
		 * notified with an EPOLLHUP event at next polling round.
		 * Arm the reconnection timer instead and get out.
		 */
		galv_timer_arm_bkoff(tmr);
		galv_conn_pdebug(clnt,
		                 -ret,
		                 "coupler",
		                 "client connection timer: "
		                 "reconnection scheduled");
		return;
	}

	msg = "maximum attempts reached";

err:
	galv_conn_pnotice(clnt,
	                  -ret,
	                  "coupler",
	                  "client connection timer: %s",
	                  msg);
term:
	galv_conn_repo_unregister(cpl->repo, clnt);
	galv_conn_set_state(clnt, GALV_CONN_OPENED_STATE);

	return;
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
	galv_assert_api(galv_conn_state(client) == GALV_CONN_OPENED_STATE);
	galv_assert_api(peer);
	galv_assert_api(poller);
	galv_assert_api(!retries || msecs);

	struct galv_timer * tmr = galv_conn_timer(client);
	int                 ret;
	const char *        msg = "unrecoverable error";

	galv_timer_setup_bkoff_tries(tmr,
	                             galv_coupler_expire_binding,
	                             retries,
	                             msecs);
	galv_conn_set_poller(client, poller);

	ret = galv_binder_connect_clnt(coupler->bind, client, peer);
	switch (ret) {
	case 0:
		ret = galv_conn_poll(client,
		                     poller,
		                     EPOLLOUT,
		                     galv_coupler_dispatch_clnt);
		if (!ret) {
			galv_conn_set_state(client, GALV_CONN_BINDING_STATE);
			galv_binder_on_connected(coupler->bind, client);
			galv_conn_repo_register(coupler->repo, client);
			ret = galv_conn_on_bound(client, poller);
			if (!ret || (ret == -EINTR))
				/*
				 * When -EINTR is returned, galv_conn_on_bound()
				 * *MUST* have completed its logic !
				 * See definition of on_bound() connection
				 * operations function pointer in <galv/conn.h>
				 * for more infos.
				 */
				return ret;

			galv_conn_unpoll(client);

			if (retries) {
				if ((ret != -ENOBUFS) && (ret != -ENOMEM))
					break;
			}
			else
				msg = "reconnection disabled";

			galv_conn_repo_unregister(coupler->repo, client);
			galv_conn_set_state(client, GALV_CONN_OPENED_STATE);

			goto err;
		}
		else if (ret != -ENOMEM) {
			msg = "failed to poll";
			goto err;
		}
		else
			return ret;

	case -EINPROGRESS: /* Connection cannot complete immediately. */
		/*
		 * Make sure the poller calls galv_coupler_dispatch_clnt() once
		 * an asynchronous connect(2) event occurs, i.e., either in case
		 * of success or error (timeout, connection refused, etc...)
		 */
		ret = galv_conn_poll(client,
		                     poller,
		                     EPOLLOUT,
		                     galv_coupler_dispatch_clnt);
		if (!ret) {
			galv_conn_set_state(client, GALV_CONN_BINDING_STATE);
			galv_conn_repo_register(coupler->repo, client);
			return -EINPROGRESS;
		}

		msg = "failed to poll";
		goto err;

	case -ECONNREFUSED: /* No remote peer is listening. */
	case -ETIMEDOUT:    /* Connection attempt timeout (server busy ?). */
		if (retries) {
			galv_conn_set_poller(client, poller);
			galv_conn_repo_register(coupler->repo, client);
			break;
		}
		else
			msg = "reconnection disabled";

		goto err;

	default:
		/*
		 * Should never happen in non-blocking mode ?
		 * See connect(2), connect(3p) and:
		 * http://www.madore.org/~david/computers/connect-intr.html
		 */
		galv_assert_intern(ret != -EINTR);

		goto err;
	}

	/*
	 * Schedule a reconnection operation.
	 * Do not register to poller yet since the socket would be notified with
	 * an EPOLLHUP event at next polling round.
	 * Arm the reconnection timer instead and get out.
	 */
	galv_timer_arm_bkoff(tmr);
	galv_conn_pdebug(client,
	                 -ret,
	                 "coupler",
	                 "cannot connect client: reconnection scheduled");

	return -EINPROGRESS;

err:
	galv_conn_pnotice(client,
	                  -ret,
	                  "coupler",
	                  "cannot connect client: %s",
	                  msg);

	return ret;
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
	galv_conn_assert_intern(client);
	galv_assert_intern(poller);

	const struct galv_coupler * cpl = (const struct galv_coupler *)
	                                  dispatcher;
	galv_coupler_assert_intern(cpl);

	galv_timer_cancel_bkoff(galv_conn_timer(client));
	galv_conn_repo_unregister(cpl->repo, client);
	galv_conn_unpoll(client);
	galv_conn_set_state(client, GALV_CONN_OPENED_STATE);

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
