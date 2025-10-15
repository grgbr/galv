/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "echosvc.h"
#include "utest.h"
#include "galv/acceptor.h"
#include "cute/check.h"

void
galvut_echosvc_setup_ctx(struct galvut_echosvc_context * __restrict context,
                         unsigned int                               bulk_count,
                         unsigned int                               max_conn)
{
	galv_conn_repo_init(&context->conns, max_conn);
	context->bulk_cnt = bulk_count;
}

static
int
galvut_echosvc_on_may_xfer(struct galv_conn * __restrict   conn,
                           uint32_t                        events,
                           const struct upoll * __restrict poller)
{
	const struct galv_acceptor *          accept;
	const struct galvut_echosvc_context * ctx;
	unsigned int                          cnt;

	if (events & EPOLLOUT)
		galv_conn_unwatch(conn, EPOLLOUT);

	if (!(events & EPOLLIN))
		return 0;

	accept = galv_conn_acceptor(conn);
	ctx = galv_acceptor_context(accept);
	cnt = ctx->bulk_cnt;

	do {
		ssize_t bytes;
		char    buff[GALVUT_ECHOSVC_MSG_SIZE_MAX];

		bytes = galv_conn_recv(conn, buff, sizeof(buff), MSG_TRUNC);
		cute_check_sint(bytes, unequal, 0);
		if (bytes < 0) {
			switch (bytes) {
			case -EAGAIN:
				galv_conn_watch(conn, EPOLLIN);
				return 0;

			case -ECONNREFUSED:
				return galv_conn_on_recv_closed(conn,
				                                events,
				                                poller);

			case -EINTR:
			case -ENOMEM:
				return (int)bytes;

			default:
				/* Unexpected receive failure */
				break;
			}

			continue;
		}
		else if ((size_t)bytes <= sizeof(buff)) {
			ssize_t ret;

			ret = galv_conn_send(conn,
			                     buff,
			                     (size_t)bytes,
			                     MSG_NOSIGNAL);
			cute_check_sint(ret, unequal, 0);
			if (ret < 0) {
				switch (ret) {
				case -EAGAIN:
				case -ENOBUFS:
					galv_conn_unwatch(conn, EPOLLIN);
					galv_conn_watch(conn, EPOLLOUT);
					return 0;

				case -EPIPE:
				case -ECONNRESET:
					return galv_conn_on_send_closed(conn,
					                                events,
					                                poller);

				case -EINTR:
				case -ENOMEM:
					return (int)ret;

				default:
					/* Unexpected send failure */
					break;
				}

				continue;
			}

			cute_check_sint(ret, equal, bytes);
		}
	} while (--cnt);

	return 0;
}

static
int
galvut_echosvc_on_connecting(struct galv_conn * __restrict   conn,
                             uint32_t                        events __unused,
                             const struct upoll * __restrict poller)
{
	int err;

	err = galv_conn_poll(conn, galv_conn_dispatch, poller, EPOLLIN);
	if (!err) {
		struct galv_acceptor *        accept;
		struct galvut_echosvc_context * ctx;

		accept = galv_conn_acceptor(conn);
		ctx = galv_acceptor_context(accept);
		galv_conn_repo_register(&ctx->conns, conn);

		galv_conn_switch_state(conn, GALV_CONN_ESTABLISHED_STATE);

		galvut_debug("unix:echosvc: connection established");

		return 0;
	}

	galvut_warn("unix:echosvc: "
	            "failed to enable connection polling: %s (%d)",
	            strerror(-err),
	            -err);

	return err;
}

static
int
galvut_echosvc_on_send_closed(struct galv_conn * __restrict   conn,
                              uint32_t                        events __unused,
                              const struct upoll * __restrict poller __unused)
{
	galv_conn_launch_close(conn);

	return 0;
}

static
int
galvut_echosvc_on_recv_closed(struct galv_conn * __restrict   conn,
                            uint32_t                        events __unused,
                            const struct upoll * __restrict poller __unused)
{
	galv_conn_launch_close(conn);

	return 0;
}

static
int
galvut_echosvc_on_error(struct galv_conn * __restrict   conn __unused,
                      uint32_t                        events __unused,
                      const struct upoll * __restrict poller __unused)
{
	/* Unexpected socket error. */
	return 0;
}

const struct galv_conn_ops galvut_echosvc_ops = {
	.on_may_xfer    = galvut_echosvc_on_may_xfer,
	.on_connecting  = galvut_echosvc_on_connecting,
	.on_send_closed = galvut_echosvc_on_send_closed,
	.on_recv_closed = galvut_echosvc_on_recv_closed,
	.on_error       = galvut_echosvc_on_error
};

int
galvut_echosvc_on_close(
	struct galv_acceptor * __restrict acceptor,
	struct galv_conn * __restrict     conn,
	const struct upoll * __restrict   poller)
{
	struct galvut_echosvc_context * ctx = galv_acceptor_context(acceptor);

	galv_conn_repo_unregister(&ctx->conns, conn);
	galv_conn_unpoll(conn, poller);
	galv_conn_complete_close(conn);
	free(conn);

	return 0;
}
