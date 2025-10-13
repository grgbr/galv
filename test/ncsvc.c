/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "ncsvc.h"
#include "utest.h"
#include "galv/acceptor.h"

void
galvut_ncsvc_setup_ctx(struct galvut_ncsvc_context * __restrict context,
                       unsigned int                             bulk_count,
                       unsigned int                             max_conn)
{
	galv_conn_repo_init(&context->conns, max_conn);
	context->bulk_cnt = bulk_count;
	context->msg_cnt = 0;
	memset(context->msgs, 0, sizeof(context->msgs));
}

static
int
galvut_ncsvc_process_msg(struct galv_conn * __restrict   conn,
                         uint32_t                        events __unused,
                         const struct upoll * __restrict poller __unused)
{
	const struct galv_acceptor *  accept;
	struct galvut_ncsvc_context * ctx;
	unsigned int                  cnt;
	ssize_t                       ret;

	accept = galv_conn_acceptor(conn);
	ctx = galv_acceptor_context(accept);
	cnt = ctx->bulk_cnt;

	/* Get at most ctx->bulk_cnt messages in a row. */
	do {
		ret = galv_conn_recv(conn,
		                     ctx->msgs[ctx->msg_cnt],
		                     sizeof(ctx->msgs[0]),
		                     MSG_TRUNC);
		if (ret < 0)
			return (int)ret;

		if ((size_t)ret >= sizeof(sizeof(ctx->msgs[0])))
			return -EMSGSIZE;

		//printf("received --%s--\n", buff);
		ctx->msg_cnt++;
	} while (--cnt);

	return 0;
}

static
int
galvut_ncsvc_on_may_xfer(struct galv_conn * __restrict   conn,
                         uint32_t                        events,
                         const struct upoll * __restrict poller)
{
	int ret;

	ret = galvut_ncsvc_process_msg(conn, events, poller);
	switch (ret) {
	case 0:
		break;

	case -EAGAIN:
		galv_conn_watch(conn, EPOLLIN);
		ret = 0;
		break;

	case -ECONNREFUSED:
		ret = galv_conn_on_recv_closed(conn, events, poller);
		break;

	case -EINTR:
	case -ENOMEM:
		break;

	default:
		/* Unexpected receive failure */
		return -EIO;
	}

	return ret;
}

static
int
galvut_ncsvc_on_connecting(struct galv_conn * __restrict   conn,
                           uint32_t                        events __unused,
                           const struct upoll * __restrict poller)
{
	int err;

	err = galv_conn_poll(conn, galv_conn_dispatch, poller, EPOLLIN);
	if (!err) {
		struct galv_acceptor *        accept;
		struct galvut_ncsvc_context * ctx;

		accept = galv_conn_acceptor(conn);
		ctx = galv_acceptor_context(accept);
		galv_conn_repo_register(&ctx->conns, conn);

		galv_conn_switch_state(conn, GALV_CONN_ESTABLISHED_STATE);

		galvut_debug("unix:ncsvc: connection established");

		return 0;
	}

	galvut_warn("unix:ncsvc: failed to enable connection polling: %s (%d)",
	            strerror(-err),
	            -err);

	return err;
}

static
int
galvut_ncsvc_on_send_closed(struct galv_conn * __restrict   conn,
                            uint32_t                        events,
                            const struct upoll * __restrict poller)
{
	if (events & EPOLLIN)
		return galvut_ncsvc_on_may_xfer(conn, events, poller);

	return 0;
}

static
int
galvut_ncsvc_on_recv_closed(struct galv_conn * __restrict   conn,
                            uint32_t                        events __unused,
                            const struct upoll * __restrict poller __unused)
{
	galv_conn_launch_close(conn);

	return 0;
}

static
int
galvut_ncsvc_on_error(struct galv_conn * __restrict   conn __unused,
                      uint32_t                        events __unused,
                      const struct upoll * __restrict poller __unused)
{
	/* Unexpected socket error. */
	return -EIO;
}

const struct galv_conn_ops galvut_ncsvc_ops = {
	.on_may_xfer    = galvut_ncsvc_on_may_xfer,
	.on_connecting  = galvut_ncsvc_on_connecting,
	.on_send_closed = galvut_ncsvc_on_send_closed,
	.on_recv_closed = galvut_ncsvc_on_recv_closed,
	.on_error       = galvut_ncsvc_on_error
};

int
galvut_ncsvc_on_close(
	struct galv_acceptor * __restrict acceptor,
	struct galv_conn * __restrict     conn,
	const struct upoll * __restrict   poller)
{
	struct galvut_ncsvc_context * ctx = galv_acceptor_context(acceptor);

	galv_conn_repo_unregister(&ctx->conns, conn);
	galv_conn_unpoll(conn, poller);
	galv_conn_complete_close(conn);
	free(conn);

	return 0;
}
