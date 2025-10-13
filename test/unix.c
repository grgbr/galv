/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "utest.h"
#include "ncsvc.h"
#include "galv/unix.h"
#include <utils/unsk.h>
#include <cute/cute.h>
#include <cute/check.h>
#include <cute/expect.h>
#include <stdlib.h>

#define GALVUT_NCSVC_UNIX_PATH    "./sock"

/******************************************************************************
 * Netcat service implementation
 ******************************************************************************/

static
int
galvut_unix_ncsvc_on_accept(struct galv_acceptor * __restrict acceptor,
                            uint32_t                          events __unused,
                            const struct upoll * __restrict   poller)
{
	const struct galvut_ncsvc_context * ctx;
	struct galv_unix_conn *             conn;
	int                                 err;

	ctx = galv_acceptor_context(acceptor);
	if (galv_conn_repo_full(&ctx->conns)) {
		err = galv_acceptor_reject_conn(acceptor);
		if (err != -EAGAIN)
			galvut_notice("unix:ncsvc: "
			              "connection request rejected: "
			              "max number of connections reached");
		return err;
	}

	conn = malloc(sizeof(*conn));
	if (!conn) {
		/*
		 * When a connection request cannot be handled, we accept() and
		 * close() it. Otherwise, it would sit in the kernel listen
		 * backlog till next call to accept().
		 */
		galv_acceptor_reject_conn(acceptor);
		return -ENOMEM;
	}

	err = galv_unix_conn_accept(conn,
	                            acceptor,
	                            SOCK_CLOEXEC,
	                            &galvut_ncsvc_ops);
	if (err) {
		if (err == -ECONNABORTED)
			/*
			 * Connection has been aborted: ignore and tell caller
			 * to keep processing connection requests normally.
			 */
			err = 0;
		goto free;
	}

	err = galv_conn_on_connecting(&conn->base, 0, poller);
	switch (err) {
	case 0:
		break;

	case -ENOMEM: /* No more memory. */
		goto close;

	case -ENOSPC: /* Cannot register new fd to poll loop. */
		goto close;

	default:
		/* Ensure poll loop keeps processing events. */
		err = 0;
		goto close;
	}

	return 0;

close:
	galv_conn_complete_close(&conn->base);
free:
	free(conn);

	return err;
}

static const struct galv_acceptor_ops galvut_unix_ncsvc_acceptor_ops = {
	.on_accept_conn = galvut_unix_ncsvc_on_accept,
	.on_close_conn  = galvut_ncsvc_on_close
};

static
int
galvut_unix_ncsvc_open(struct galv_unix_acceptor * __restrict   acceptor,
                       int                                      type,
                       const struct upoll * __restrict          poller,
                       struct galvut_ncsvc_context * __restrict ctx)
{
	cute_check_ptr(acceptor, unequal, NULL);
	cute_check_assert((type == SOCK_SEQPACKET) || (type == SOCK_STREAM));
	cute_check_ptr(poller, unequal, NULL);
	cute_check_ptr(ctx, unequal, NULL);

	cute_check_uint(ctx->bulk_cnt, greater, 0);
	cute_check_uint(ctx->bulk_cnt, lower_equal, GALVUT_NCSVC_MSG_NR);

	return galv_unix_acceptor_open(acceptor,
	                               GALVUT_NCSVC_UNIX_PATH,
	                               type,
	                               SOCK_CLOEXEC,
	                               GALVUT_NCSVC_BACKLOG,
	                               poller,
	                               &galvut_unix_ncsvc_acceptor_ops,
	                               ctx);
}

static
int
galvut_unix_ncsvc_close(struct galv_unix_acceptor * __restrict acceptor,
                        const struct upoll * __restrict        poller)
{
	return galv_unix_acceptor_close(acceptor, poller);
}

/******************************************************************************
 * Netcat client implementation
 ******************************************************************************/

static
int
galvut_unix_ncsvc_connect_clnt(int sock_type)
{
	int                      sk;
	int                      ret;
	const struct sockaddr_un peer = UNSK_NAMED_ADDR(GALVUT_NCSVC_UNIX_PATH);

	sk = unsk_open(sock_type, SOCK_CLOEXEC);
	if (sk < 0)
		return sk;

	ret = unsk_connect(sk,
	                   &peer,
	                   (socklen_t)(offsetof(typeof(peer), sun_path) +
	                               sizeof(GALVUT_NCSVC_UNIX_PATH)));
	if (!ret)
		return sk;

	unsk_close(sk);

	return ret;
}

static
void
galvut_unix_ncsvc_close_clnt(int fd)
{
	unsk_close(fd);
}

/******************************************************************************
 * Netcat tests
 ******************************************************************************/

struct galvut_unix_ncsvc_test {
	int                         clnt;
	struct upoll                poll;
	int                         sock_type;
	struct galv_unix_acceptor   accept;
	struct galvut_ncsvc_context ctx;
};

static struct galvut_unix_ncsvc_test galvut_unix_ncsvc_the_test;

static
int
galvut_unix_ncsvc_test_process(const struct galvut_unix_ncsvc_test * test)
{
	int ret;

	ret = upoll_process(&test->poll, 0);

	return ((ret != -EINTR) && (ret != -ETIME)) ? ret : 0;
}

static
int
galvut_unix_ncsvc_test_open(struct galvut_unix_ncsvc_test * test,
                            unsigned int                    max_conn)
{
	int ret;

	cute_check_ptr(test, unequal, NULL);

	/* Max number of connections + 1 for acceptor socket. */
	ret = upoll_open(&test->poll, max_conn + 1);
	if (ret)
		return ret;

	ret = galvut_unix_ncsvc_open(&test->accept,
	                             test->sock_type,
	                             &test->poll,
	                             &test->ctx);
	if (ret)
		goto fini_poll;

	return 0;

fini_poll:
	upoll_close(&test->poll);

	return ret;
}

static
int
galvut_unix_ncsvc_test_close(struct galvut_unix_ncsvc_test * test)
{
	int ret;

	while (!galv_conn_repo_empty(&test->ctx.conns)) {
		struct galv_conn * conn;

		conn = galv_conn_repo_pop(&test->ctx.conns);
		galvut_ncsvc_on_close((struct galv_acceptor *)&test->accept,
		                      conn,
		                      &test->poll);
	}

	ret = galvut_unix_ncsvc_close(&test->accept, &test->poll);
	if (ret == -EINTR)
		ret = 0;

	upoll_close(&test->poll);

	return ret;
}

static
void
galvut_unix_ncsvc_test_setup(int sock_type, unsigned int bulk_count)
{
	int ret;

	galvut_unix_ncsvc_the_test.sock_type = sock_type;
	galvut_ncsvc_setup_ctx(&galvut_unix_ncsvc_the_test.ctx,
	                       bulk_count,
	                       1);

	ret = galvut_unix_ncsvc_test_open(&galvut_unix_ncsvc_the_test, 1);
	cute_check_sint(ret, equal, 0);
}

static
void
galvut_unix_ncsvc_test_teardown(void)
{
	int          ret;
	unsigned int cnt;

	cnt = galv_conn_repo_count(&galvut_unix_ncsvc_the_test.ctx.conns);

	ret = galvut_unix_ncsvc_test_close(&galvut_unix_ncsvc_the_test);

	cute_check_uint(cnt, equal, 0);
	cute_check_sint(ret, equal, 0);
}

CUTE_TEST(galvut_unix_ncsvc_open_close)
{
	int ret;
	int clnt;

	/* Open netcat service. */
	galvut_unix_ncsvc_test_setup(SOCK_SEQPACKET, 1);

	/* Open netcat client connection. */
	clnt = galvut_unix_ncsvc_connect_clnt(
		galvut_unix_ncsvc_the_test.sock_type);
	cute_check_sint(clnt, greater_equal, 0);

	/* Let netcat service accept connection. */
	ret = galvut_unix_ncsvc_test_process(&galvut_unix_ncsvc_the_test);
	cute_check_sint(ret, equal, 0);
	cute_check_uint(
		galv_conn_repo_count(&galvut_unix_ncsvc_the_test.ctx.conns),
		equal,
		1);

	/* Close netcat client connection. */
	galvut_unix_ncsvc_close_clnt(clnt);

	/* Let netcat service close connection. */
	ret = galvut_unix_ncsvc_test_process(&galvut_unix_ncsvc_the_test);
	cute_check_sint(ret, equal, 0);
	cute_check_uint(
		galv_conn_repo_count(&galvut_unix_ncsvc_the_test.ctx.conns),
		equal,
		0);
}

CUTE_TEST(galvut_unix_ncsvc_open_shutrd)
{
	int ret;
	int clnt;

	/* Open netcat service. */
	galvut_unix_ncsvc_test_setup(SOCK_SEQPACKET, 1);

	/* Open netcat client connection. */
	clnt = galvut_unix_ncsvc_connect_clnt(
		galvut_unix_ncsvc_the_test.sock_type);
	cute_check_sint(clnt, greater_equal, 0);

	/* Let netcat service accept connection. */
	ret = galvut_unix_ncsvc_test_process(&galvut_unix_ncsvc_the_test);
	cute_check_sint(ret, equal, 0);
	cute_check_uint(
		galv_conn_repo_count(&galvut_unix_ncsvc_the_test.ctx.conns),
		equal,
		1);

	/* Perform a local read end closure. */
	unsk_shutdown(clnt, SHUT_RD);

	ret = galvut_unix_ncsvc_test_process(&galvut_unix_ncsvc_the_test);
	cute_check_sint(ret, equal, 0);

	/* Close netcat client connection. */
	galvut_unix_ncsvc_close_clnt(clnt);

	/* Let netcat service close connection. */
	ret = galvut_unix_ncsvc_test_process(&galvut_unix_ncsvc_the_test);
	cute_check_sint(ret, equal, 0);
	cute_check_uint(
		galv_conn_repo_count(&galvut_unix_ncsvc_the_test.ctx.conns),
		equal,
		0);
}

#if 0
CUTE_TEST(galvut_unix_ncsvc_open_shutwr)
{
	int                           ret;
	struct galvut_unix_ncsvc_test test =
		GALVUT_UNIX_NCSVC_TEST_SETUP(test, SOCK_SEQPACKET, 1);

	ret = galvut_unix_ncsvc_test_open(&test);
	cute_check_sint(ret, equal, 0);

	unsk_shutdown(test.clnt, SHUT_WR);

	galvut_unix_ncsvc_test_close(&test);
}

CUTE_TEST(galvut_unix_ncsvc_open_send_one_close)
{
	int                           ret;
	ssize_t                       sz;
	struct galvut_unix_ncsvc_test test =
		GALVUT_UNIX_NCSVC_TEST_SETUP(test, SOCK_SEQPACKET, 1);

	ret = galvut_unix_ncsvc_test_open(&test);
	cute_check_sint(ret, equal, 0);

	sz = unsk_send(test.clnt, "msg0", sizeof("msg0"), MSG_NOSIGNAL);

	/* Let ncsvc service accept connection. */
	ret = galvut_unix_ncsvc_test_process(&test);
	/* Let ncsvc service receive message. */
	ret = galvut_unix_ncsvc_test_process(&test);

	galvut_unix_ncsvc_test_close(&test);

	cute_check_sint(sz, equal, sizeof("msg0"));
	cute_check_sint(ret, equal, 0);
	cute_check_uint(test.ctx.msg_cnt, equal, 1);
	cute_check_str(test.ctx.msgs[0], equal, "msg0");

	cute_check_uint(galv_conn_repo_count(&test.ctx.conns), equal, 0);
	cute_check_bool(galv_conn_repo_empty(&test.ctx.conns), is, true);
}
#endif

CUTE_GROUP(galvut_unix_ncsvc_group) = {
	CUTE_REF(galvut_unix_ncsvc_open_close),
	CUTE_REF(galvut_unix_ncsvc_open_shutrd),
#if 0
	CUTE_REF(galvut_unix_ncsvc_open_shutwr),
	CUTE_REF(galvut_unix_ncsvc_open_send_one_close),
#endif
};

CUTE_SUITE_STATIC(galvut_unix_ncsvc_suite,
                  galvut_unix_ncsvc_group,
                  CUTE_NULL_SETUP,
                  galvut_unix_ncsvc_test_teardown,
                  CUTE_DFLT_TMOUT);

/******************************************************************************
 * Top-level Unix connection support
 ******************************************************************************/

CUTE_GROUP(galvut_unix_conn_group) = {
	CUTE_REF(galvut_unix_ncsvc_suite),
};

CUTE_SUITE_EXTERN(galvut_unix_conn_suite,
                  galvut_unix_conn_group,
                  CUTE_NULL_SETUP,
                  CUTE_NULL_TEARDOWN,
                  CUTE_DFLT_TMOUT);
