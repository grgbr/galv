/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2026 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "common/unix.h"
#include "binder.h"

/******************************************************************************
 * Unix (client-side) connection binder handling
 ******************************************************************************/

static
int
_galv_unix_binder_connect_clnt(
	const struct galv_binder * __restrict binder __unused,
	struct galv_unix_conn * __restrict    client)
{
	const struct galv_unix_addr * addr = &client->peer.addr;
	int                           ret;
	char                          str[UNSK_NAMED_PATH_MAX];

	galv_assert_intern(addr->data.sun_family == AF_UNIX);
	galv_assert_intern(unsk_is_named_addr(&addr->data, addr->size));

	ret = unsk_connect(client->base.fd, &addr->data, addr->size);
	galv_assert_intern(ret <= 0);
	if (!ret)
		return 0;

	if (ret == -EAGAIN) {
		/*
		 * Nonblocking UNIX domain sockets return -EAGAIN (instead of
		 * -EINPROGRESS when the connection cannot be completed
		 * immediately.
		 */
		galv_debug("unix: differing client connection establishment to"
		           "[addr:%s]..",
		           unsk_make_addr_string(str, &addr->data, addr->size));
		return -EINPROGRESS;
	}

	galv_ratelim_pinfo(-ret,
	                   "unix: cannot establish client connection",
	                   " to [addr:%s]",
	                   unsk_make_addr_string(str, &addr->data, addr->size));

	/*
	 * When no one is listening, i.e, no (named) socket file is existing,
	 * connect(2) on a UNIX socket returns ENOENT.
	 * Make error code consistent with other socket types by returning
	 * ECONNREFUSED.
	 */
	return (ret == -ENOENT) ? -ECONNREFUSED : ret;
}

static
int
galv_unix_binder_connect_clnt(
	const struct galv_binder * __restrict binder __unused,
	struct galv_conn * __restrict         client,
	const struct sockaddr * __restrict    peer)
{
	struct galv_unix_conn *       clnt = (struct galv_unix_conn *)client;
	const struct galv_unix_addr * addr = (const struct galv_unix_addr *)
	                                     peer;

	galv_assert_api(addr->data.sun_family == AF_UNIX);
	galv_assert_api(unsk_is_named_addr(&addr->data, addr->size));
	clnt->peer.addr = *addr;

	return _galv_unix_binder_connect_clnt(binder, clnt);
}

static
void
galv_unix_binder_on_connected(
	const struct galv_binder * __restrict binder __unused,
	struct galv_conn * __restrict         client)
{
	struct galv_unix_conn *       clnt = (struct galv_unix_conn *)client;
	const struct galv_unix_addr * addr = &clnt->peer.addr;
	struct ucred *                cred = &clnt->peer.cred;
	socklen_t                     sz = sizeof(*cred);
	char                          str[UNSK_NAMED_PATH_MAX];

	galv_assert_intern(addr->data.sun_family == AF_UNIX);
	galv_assert_intern(unsk_is_named_addr(&addr->data, addr->size));

	unsk_getsockopt(client->fd, SO_PEERCRED, cred, &sz);
	galv_assert_intern(sz == sizeof(*cred));

	galv_ratelim_info("unix: client connection established",
	                  " to [addr:%s pid:%d uid:%d]",
	                   unsk_make_addr_string(str, &addr->data, addr->size),
	                   cred->pid,
	                   cred->uid);
}

static
int
galv_unix_binder_reconnect_clnt(
	const struct galv_binder * __restrict binder __unused,
	struct galv_conn * __restrict         client,
	const struct upoll * __restrict       poller)
{
	galv_assert_intern((binder->sock_type == SOCK_STREAM) ||
	                   (binder->sock_type == SOCK_SEQPACKET));

	struct galv_unix_conn * clnt = (struct galv_unix_conn *)client;
	int                     ret;
	const char *            msg;

	/*
	 * As stated into connect(2), we should consider the state of the socket
	 * as unspecified in case of failure: open a new socket, close the old
	 * one and try to perform the connect(2) again.
	 *
	 * Note that we prefer to open the new socket first and close the old
	 * one afterward so that a potential socket(2) failure does not leave
	 * the whole Galv internal state machine with no valid file descriptor
	 * at all upon return from this function (galv_coupler, galv_conn and
	 * galv_unix_conn highly depend on its presence).
	 */

	/*
	 * Open the new socket first using the flags that were passed at initial
	 * opening time...
	 */
	ret = unsk_open(binder->sock_type,
	                SOCK_NONBLOCK | etux_sock_getfd(client->fd));
	if (ret < 0) {
		msg = "failed to reopen";
		goto err;
	}

	/*
	 *  ... then close the old one to keep a valid file descriptor in
	 * `client->fd' in case of failure.
	 *
	 * In addition, we *MUST* also remove the old file descriptor from the
	 * epoll(7) interest list.
	 * See section `Questions and answers' of epoll(7) man page to
	 * understand why.
	 */
	upoll_unregister(poller, client->fd);
	unsk_close(client->fd);
	client->fd = ret;

	/* Connect(2) again using currently stored remote peer address. */
	ret = _galv_unix_binder_connect_clnt(binder, clnt);
	if (ret)
		goto err;

	return 0;

err:
	if (ret != -ENOMEM)
		galv_ratelim_pnotice(ret,
		                     "unix: cannot reconnect client connection",
		                     ": %s",
		                     msg);
	return ret;
}

static
struct galv_conn *
galv_unix_binder_create_clnt(struct galv_binder * __restrict         binder,
                             const struct galv_conn_ops * __restrict operations,
                             int                                     flags,
                             struct galv_coupler * __restrict        coupler)
{
	galv_assert_intern((binder->sock_type == SOCK_STREAM) ||
	                   (binder->sock_type == SOCK_SEQPACKET));

	int                     sk;
	int                     err;
	struct galv_unix_conn * clnt;
	const char *            msg;

	sk = unsk_open(binder->sock_type, SOCK_NONBLOCK | flags);
	if (sk < 0) {
		if (sk == -ENOMEM) {
			errno = ENOMEM;
			return NULL;
		}

		err = -sk;
		msg = "failed to open";
		goto err;
	}

	/* Allocate UNIX connection. */
	clnt = stroll_falloc_alloc(&binder->alloc);
	if (!clnt) {
		err = errno;
		unsk_close(sk);
		if (err == ENOMEM)
			return NULL;

		msg = "failed to allocate";
		goto err;
	}

	galv_conn_setup(&clnt->base,
	                sk,
	                operations,
	                (struct galv_dispatch *)coupler);
	clnt->peer.addr.size = 0;
	clnt->peer.cred.pid = 0;
	clnt->peer.cred.uid = 0;

	galv_debug("unix: client connection created");

	return &clnt->base;

err:
	galv_ratelim_pnotice(err,
	                     "unix: cannot create client connection",
	                     ": %s",
	                     msg);
	errno = err;

	return NULL;
}

static
int
galv_unix_binder_destroy_clnt(struct galv_binder * __restrict binder,
                              struct galv_conn * __restrict   client)
{
	int ret;

	ret = unsk_close(client->fd);
	if (ret && (ret != -EINTR))
		galv_ratelim_pnotice(-ret,
		                     "unix: failed to close client socket",
		                     "");

	stroll_falloc_free(&binder->alloc, client);

	galv_unix_conn_debug(&((const struct galv_unix_conn *)client)->peer,
	                     "client connection destroyed");

	return ret;
}

static const struct galv_binder_ops galv_unix_binder_ops = {
	.create_clnt    = galv_unix_binder_create_clnt,
	.connect_clnt   = galv_unix_binder_connect_clnt,
	.reconnect_clnt = galv_unix_binder_reconnect_clnt,
	.on_connected   = galv_unix_binder_on_connected,
	.destroy_clnt   = galv_unix_binder_destroy_clnt
};

void
galv_unix_binder_open(struct galv_binder * __restrict binder,
                      int                             sock_type,
                      unsigned int                    max_conn)
{
	galv_assert_api((sock_type == SOCK_STREAM) ||
	                (sock_type == SOCK_SEQPACKET));

	galv_binder_open(binder,
	                 &galv_unix_binder_ops,
	                 sock_type,
	                 max_conn,
	                 sizeof(struct galv_conn));

	galv_debug("unix: binder opened");
}

void
galv_unix_binder_close(struct galv_binder * __restrict binder)
{
	galv_binder_close(binder);

	galv_debug("unix: binder closed");
}
