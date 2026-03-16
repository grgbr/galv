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
		galv_conn_debug(&client->base,
		                "unix",
		                "differing client connection..");
		return -EINPROGRESS;
	}

	galv_conn_pinfo(&client->base,
	                -ret,
	                "unix",
	                "cannot establish client connection");

	/*
	 * When no one is listen(2)'ing, i.e, no (named) socket file is
	 * existing, connect(2) on a UNIX socket returns ENOENT.
	 * Also note that, connect(2) may return ECONNREFUSED when the named
	 * socket filesystem path exists without any process listen(2)'ing on
	 * it...
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
	galv_assert_api((binder->sock_type == SOCK_STREAM) ||
	                (binder->sock_type == SOCK_SEQPACKET));
	galv_unix_assert_conn_api((struct galv_unix_conn *)client);
	galv_unix_assert_addr_api((const struct galv_unix_addr *)peer);

	struct galv_unix_conn *       clnt = (struct galv_unix_conn *)client;
	const struct galv_unix_addr * addr = (const struct galv_unix_addr *)
	                                     peer;

	clnt->peer.addr = *addr;
	galv_unix_make_endpt_string(client->peer, &clnt->peer);

	clnt->local.addr.data.sun_family = AF_UNIX;
	clnt->local.addr.size = sizeof(sa_family_t);
	galv_unix_setup_cred(&clnt->local.cred);
	galv_unix_make_endpt_string(client->local, &clnt->local);

	return _galv_unix_binder_connect_clnt(binder, clnt);
}

static
int
galv_unix_binder_reconnect_clnt(
	const struct galv_binder * __restrict binder __unused,
	struct galv_conn * __restrict         client)
{
	galv_assert_api((binder->sock_type == SOCK_STREAM) ||
	                (binder->sock_type == SOCK_SEQPACKET));
	galv_unix_assert_conn_api((struct galv_unix_conn *)client);

	galv_conn_debug(client, "unix", "retrying client connection..");

	/* Connect(2) again using currently stored remote peer address. */
	return _galv_unix_binder_connect_clnt(binder,
	                                      (struct galv_unix_conn *)client);
}

static
void
galv_unix_binder_on_connected(
	const struct galv_binder * __restrict binder __unused,
	struct galv_conn * __restrict         client)
{
	galv_assert_api((binder->sock_type == SOCK_STREAM) ||
	                (binder->sock_type == SOCK_SEQPACKET));
	galv_unix_assert_conn_api((struct galv_unix_conn *)client);

	struct galv_unix_conn * clnt = (struct galv_unix_conn *)client;

	galv_unix_load_peer_cred(client->fd, &clnt->peer.cred);
	galv_unix_make_endpt_string(client->peer, &clnt->peer);

	galv_conn_info(client, "unix", "client connection established");
}

static
void
galv_unix_binder_clear_endpt(char * __restrict                   string,
                             struct galv_unix_endpt * __restrict endpoint)
{
	galv_assert_intern(string);
	galv_assert_intern(endpoint);

	memcpy(string, "??[?]", sizeof("??[?]"));

	endpoint->addr.data.sun_family = AF_UNIX;
	endpoint->addr.size = sizeof(sa_family_t);

	memset(&endpoint->cred, 0, sizeof(endpoint->cred));
}

static
struct galv_conn *
galv_unix_binder_create_clnt(struct galv_binder * __restrict         binder,
                             const struct galv_conn_ops * __restrict operations,
                             int                                     flags,
                             struct galv_coupler * __restrict        coupler)
{
	galv_assert_api((binder->sock_type == SOCK_STREAM) ||
	                (binder->sock_type == SOCK_SEQPACKET));

	int                     fd;
	int                     err;
	struct galv_unix_conn * clnt;
	const char *            msg;

	fd = unsk_open(binder->sock_type, SOCK_NONBLOCK | flags);
	if (fd < 0) {
		if (fd == -ENOMEM) {
			errno = ENOMEM;
			return NULL;
		}

		err = -fd;
		msg = "failed to open";
		goto err;
	}

	/* Allocate UNIX connection. */
	clnt = galv_unix_create_conn(&binder->alloc,
	                             fd,
	                             operations,
	                             (struct galv_dispatch *)coupler);
	if (!clnt) {
		err = errno;
		unsk_close(fd);
		if (err == ENOMEM)
			return NULL;

		msg = "failed to allocate";
		goto err;
	}

	galv_unix_binder_clear_endpt(clnt->base.peer, &clnt->peer);
	galv_unix_binder_clear_endpt(clnt->base.local, &clnt->local);

	galv_conn_debug(&clnt->base, "unix", "client connection created");

	return &clnt->base;

err:
	galv_pnotice(err,
	             "unix: cannot create client connection: %s",
	             msg);

	errno = err;
	return NULL;
}

static
int
galv_unix_binder_destroy_clnt(struct galv_binder * __restrict binder,
                              struct galv_conn * __restrict   client)
{
	galv_unix_assert_conn_api((struct galv_unix_conn *)client);

	galv_conn_info(client, "unix", "destroying client connection..");

	return galv_unix_destroy_conn(&binder->alloc,
	                              (struct galv_unix_conn *)client);
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
