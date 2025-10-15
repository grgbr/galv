/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "utest.h"
#include "ncsvc.h"
#include "echosvc.h"
#include "galv/unix.h"
#include <utils/unsk.h>
#include <cute/cute.h>
#include <cute/check.h>
#include <cute/expect.h>
#include <stdlib.h>

#define GALVUT_UNIX_PATH "./sock"

/******************************************************************************
 * Common tests logic
 ******************************************************************************/

struct galvut_unix_test {
	int                         clnt;
	struct upoll                poll;
	int                         sock_type;
	struct galv_unix_acceptor   accept;
	union {
		struct galvut_ncsvc_context   nc;
		struct galvut_echosvc_context echo;
	};
};

static struct galvut_unix_test galvut_unix_the_test;

static
int
galvut_unix_test_process(const struct galvut_unix_test * test)
{
	int ret;

	ret = upoll_process(&test->poll, 0);

	return ((ret != -EINTR) && (ret != -ETIME)) ? ret : 0;
}

static
int
galvut_unix_connect_clnt(int sock_type)
{
	int                      sk;
	int                      ret;
	const struct sockaddr_un peer = UNSK_NAMED_ADDR(GALVUT_UNIX_PATH);

	sk = unsk_open(sock_type, SOCK_CLOEXEC);
	if (sk < 0)
		return sk;

	ret = unsk_connect(sk,
	                   &peer,
	                   (socklen_t)(offsetof(typeof(peer), sun_path) +
	                               sizeof(GALVUT_UNIX_PATH)));
	if (!ret)
		return sk;

	unsk_close(sk);

	return ret;
}

static
void
galvut_unix_close_clnt(int fd)
{
	unsk_close(fd);
}


/******************************************************************************
 * Netcat service tests
 ******************************************************************************/

static
int
galvut_unix_ncsvc_on_accept(struct galv_acceptor * __restrict acceptor,
                            uint32_t                          events __unused,
                            const struct upoll * __restrict   poller)
{
	struct galv_unix_acceptor *         unacc =
		(struct galv_unix_acceptor *)acceptor;
	struct galv_unix_attrs              attrs;
	int                                 fd;
	const struct galvut_ncsvc_context * ctx;
	struct galv_unix_conn *             conn;
	int                                 err;

	fd = galv_unix_acceptor_grab(unacc, &attrs, SOCK_CLOEXEC);
	if (fd < 0)
		return fd;

	ctx = galv_acceptor_context(acceptor);
	if (galv_conn_repo_full(&ctx->conns)) {
		err = -EPERM;
		goto close;
	}

	conn = malloc(sizeof(*conn));
	if (!conn) {
		err = -ENOMEM;
		goto close;
	}

	galv_unix_conn_setup(conn, fd, unacc, &galvut_ncsvc_ops, &attrs);

	err = galv_conn_on_connecting(&conn->base, 0, poller);
	if (err)
		goto free;

	return 0;

free:
	free(conn);
close:
	etux_sock_close(fd);

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
	                               GALVUT_UNIX_PATH,
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

static
int
galvut_unix_ncsvc_test_open(struct galvut_unix_test * test,
                            unsigned int              max_conn)
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
	                             &test->nc);
	if (ret)
		goto fini_poll;

	return 0;

fini_poll:
	upoll_close(&test->poll);

	return ret;
}

static
int
galvut_unix_ncsvc_test_close(struct galvut_unix_test * test)
{
	int ret;

	while (!galv_conn_repo_empty(&test->nc.conns)) {
		struct galv_conn * conn;

		conn = galv_conn_repo_pop(&test->nc.conns);
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

	galvut_unix_the_test.sock_type = sock_type;
	galvut_ncsvc_setup_ctx(&galvut_unix_the_test.nc, bulk_count, 1);

	ret = galvut_unix_ncsvc_test_open(&galvut_unix_the_test, 1);
	cute_check_sint(ret, equal, 0);
}

static
void
galvut_unix_ncsvc_test_teardown(void)
{
	galvut_unix_ncsvc_test_close(&galvut_unix_the_test);
}

CUTE_TEST(galvut_unix_ncsvc_open_close)
{
	int ret;
	int clnt;

	/* Open netcat service. */
	galvut_unix_ncsvc_test_setup(SOCK_SEQPACKET, 1);

	/* Open netcat client connection. */
	clnt = galvut_unix_connect_clnt(galvut_unix_the_test.sock_type);
	cute_check_sint(clnt, greater_equal, 0);

	/* Let netcat service accept connection. */
	ret = galvut_unix_test_process(&galvut_unix_the_test);
	cute_check_sint(ret, equal, 0);
	cute_check_uint(galv_conn_repo_count(&galvut_unix_the_test.nc.conns),
	                equal,
	                1);

	/* Close netcat client connection. */
	galvut_unix_close_clnt(clnt);

	/* Let netcat service close connection. */
	ret = galvut_unix_test_process(&galvut_unix_the_test);
	cute_check_sint(ret, equal, 0);
	cute_check_uint(galv_conn_repo_count(&galvut_unix_the_test.nc.conns),
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
	clnt = galvut_unix_connect_clnt(galvut_unix_the_test.sock_type);
	cute_check_sint(clnt, greater_equal, 0);

	/* Let netcat service accept connection. */
	ret = galvut_unix_test_process(&galvut_unix_the_test);
	cute_check_sint(ret, equal, 0);
	cute_check_uint(galv_conn_repo_count(&galvut_unix_the_test.nc.conns),
	                equal,
	                1);

	/* Perform a local read end closure. */
	unsk_shutdown(clnt, SHUT_RD);

	ret = galvut_unix_test_process(&galvut_unix_the_test);
	cute_check_sint(ret, equal, 0);

	/* Close netcat client connection. */
	galvut_unix_close_clnt(clnt);

	/* Let netcat service close connection. */
	ret = galvut_unix_test_process(&galvut_unix_the_test);
	cute_check_sint(ret, equal, 0);
	cute_check_uint(galv_conn_repo_count(&galvut_unix_the_test.nc.conns),
	                equal,
	                0);
}

CUTE_TEST(galvut_unix_ncsvc_open_shutwr)
{
	int ret;
	int clnt;

	/* Open netcat service. */
	galvut_unix_ncsvc_test_setup(SOCK_SEQPACKET, 1);

	/* Open netcat client connection. */
	clnt = galvut_unix_connect_clnt(galvut_unix_the_test.sock_type);
	cute_check_sint(clnt, greater_equal, 0);

	/* Let netcat service accept connection. */
	ret = galvut_unix_test_process(&galvut_unix_the_test);
	cute_check_sint(ret, equal, 0);
	cute_check_uint(galv_conn_repo_count(&galvut_unix_the_test.nc.conns),
	                equal,
	                1);

	/* Perform a local read end closure. */
	unsk_shutdown(clnt, SHUT_WR);

	ret = galvut_unix_test_process(&galvut_unix_the_test);
	cute_check_sint(ret, equal, 0);

	/* Close netcat client connection. */
	galvut_unix_close_clnt(clnt);

	/* Let netcat service close connection. */
	ret = galvut_unix_test_process(&galvut_unix_the_test);
	cute_check_sint(ret, equal, 0);
	cute_check_uint(galv_conn_repo_count(&galvut_unix_the_test.nc.conns),
	                equal,
	                0);
}

CUTE_TEST(galvut_unix_ncsvc_open_send_one_close)
{
	int     ret;
	int     clnt;
	ssize_t sz;

	/* Open netcat service. */
	galvut_unix_ncsvc_test_setup(SOCK_SEQPACKET, 1);

	/* Open netcat client connection. */
	clnt = galvut_unix_connect_clnt(galvut_unix_the_test.sock_type);
	cute_check_sint(clnt, greater_equal, 0);

	/* Let netcat service accept connection. */
	ret = galvut_unix_test_process(&galvut_unix_the_test);
	cute_check_sint(ret, equal, 0);
	cute_check_uint(galv_conn_repo_count(&galvut_unix_the_test.nc.conns),
	                equal,
	                1);

	/* Send a simple message. */
	sz = unsk_send(clnt, "msg0", sizeof("msg0"), MSG_NOSIGNAL);
	cute_check_sint(sz, equal, sizeof("msg0"));

	/* Let netcat service receive the message. */
	ret = galvut_unix_test_process(&galvut_unix_the_test);
	cute_check_sint(ret, equal, 0);
	cute_check_uint(galv_conn_repo_count(&galvut_unix_the_test.nc.conns),
	                equal,
	                1);

	/* Close netcat client connection. */
	galvut_unix_close_clnt(clnt);

	/* Let netcat service close connection. */
	ret = galvut_unix_test_process(&galvut_unix_the_test);
	cute_check_sint(ret, equal, 0);
	cute_check_uint(galv_conn_repo_count(&galvut_unix_the_test.nc.conns),
	                equal,
	                0);

	cute_check_uint(galvut_unix_the_test.nc.msg_cnt, equal, 1);
	cute_check_str(galvut_unix_the_test.nc.msgs[0], equal, "msg0");
}

CUTE_TEST(galvut_unix_ncsvc_open_send_one_shutrd)
{
	int     ret;
	int     clnt;
	ssize_t sz;

	/* Open netcat service. */
	galvut_unix_ncsvc_test_setup(SOCK_SEQPACKET, 1);

	/* Open netcat client connection. */
	clnt = galvut_unix_connect_clnt(galvut_unix_the_test.sock_type);
	cute_check_sint(clnt, greater_equal, 0);

	/* Let netcat service accept connection. */
	ret = galvut_unix_test_process(&galvut_unix_the_test);
	cute_check_sint(ret, equal, 0);
	cute_check_uint(galv_conn_repo_count(&galvut_unix_the_test.nc.conns),
	                equal,
	                1);

	/* Send a simple message. */
	sz = unsk_send(clnt, "msg0", sizeof("msg0"), MSG_NOSIGNAL);
	cute_check_sint(sz, equal, sizeof("msg0"));

	/* Perform a local read end closure. */
	unsk_shutdown(clnt, SHUT_RD);

	/* Let netcat service receive the message. */
	ret = galvut_unix_test_process(&galvut_unix_the_test);
	cute_check_sint(ret, equal, 0);
	cute_check_uint(galv_conn_repo_count(&galvut_unix_the_test.nc.conns),
	                equal,
	                1);

	/* Close netcat client connection. */
	galvut_unix_close_clnt(clnt);

	/* Let netcat service close connection. */
	ret = galvut_unix_test_process(&galvut_unix_the_test);
	cute_check_sint(ret, equal, 0);
	cute_check_uint(galv_conn_repo_count(&galvut_unix_the_test.nc.conns),
	                equal,
	                0);

	cute_check_uint(galvut_unix_the_test.nc.msg_cnt, equal, 1);
	cute_check_str(galvut_unix_the_test.nc.msgs[0], equal, "msg0");
}

CUTE_TEST(galvut_unix_ncsvc_open_send_one_shutwr)
{
	int     ret;
	int     clnt;
	ssize_t sz;

	/* Open netcat service. */
	galvut_unix_ncsvc_test_setup(SOCK_SEQPACKET, 1);

	/* Open netcat client connection. */
	clnt = galvut_unix_connect_clnt(galvut_unix_the_test.sock_type);
	cute_check_sint(clnt, greater_equal, 0);

	/* Let netcat service accept connection. */
	ret = galvut_unix_test_process(&galvut_unix_the_test);
	cute_check_sint(ret, equal, 0);
	cute_check_uint(galv_conn_repo_count(&galvut_unix_the_test.nc.conns),
	                equal,
	                1);

	/* Send a simple message. */
	sz = unsk_send(clnt, "msg0", sizeof("msg0"), MSG_NOSIGNAL);
	cute_check_sint(sz, equal, sizeof("msg0"));

	/* Perform a local read end closure. */
	unsk_shutdown(clnt, SHUT_WR);

	/* Let netcat service receive the message. */
	ret = galvut_unix_test_process(&galvut_unix_the_test);
	cute_check_sint(ret, equal, 0);
	cute_check_uint(galv_conn_repo_count(&galvut_unix_the_test.nc.conns),
	                equal,
	                1);

	/* Close netcat client connection. */
	galvut_unix_close_clnt(clnt);

	/* Let netcat service close connection. */
	ret = galvut_unix_test_process(&galvut_unix_the_test);
	cute_check_sint(ret, equal, 0);
	cute_check_uint(galv_conn_repo_count(&galvut_unix_the_test.nc.conns),
	                equal,
	                0);

	cute_check_uint(galvut_unix_the_test.nc.msg_cnt, equal, 1);
	cute_check_str(galvut_unix_the_test.nc.msgs[0], equal, "msg0");
}

static
void
galvut_unix_ncsvc_send_bulk(int sk, unsigned int nr)
{
	cute_check_sint(sk, greater_equal, 0);
	cute_check_uint(nr, greater, 0);
	cute_check_uint(nr, lower_equal, GALVUT_NCSVC_MSG_NR);

	ssize_t      ret;
	char         buff[] = "msgxxx";
	unsigned int cnt;

	for (cnt = 0; cnt < nr; cnt++) {
STROLL_IGNORE_WARN("-Wformat-overflow")
		sprintf(buff, "msg%03u", cnt);
STROLL_RESTORE_WARN
		ret = unsk_send(sk, buff, sizeof(buff), MSG_NOSIGNAL);
		cute_check_sint(ret, equal, (ssize_t)sizeof(buff));
	}
}

CUTE_TEST(galvut_unix_ncsvc_send_bulk_full)
{
	int          ret;
	int          clnt;
	unsigned int m;

	/* Open netcat service. */
	galvut_unix_ncsvc_test_setup(SOCK_SEQPACKET, GALVUT_NCSVC_MSG_NR);

	/* Open netcat client connection. */
	clnt = galvut_unix_connect_clnt(galvut_unix_the_test.sock_type);
	cute_check_sint(clnt, greater_equal, 0);

	/* Let netcat service accept connection. */
	ret = galvut_unix_test_process(&galvut_unix_the_test);
	cute_check_sint(ret, equal, 0);
	cute_check_uint(galv_conn_repo_count(&galvut_unix_the_test.nc.conns),
	                equal,
	                1);

	/* Send a multiple messages. */
	galvut_unix_ncsvc_send_bulk(clnt, GALVUT_NCSVC_MSG_NR);

	/* Let netcat service receive messages. */
	ret = galvut_unix_test_process(&galvut_unix_the_test);
	cute_check_sint(ret, equal, 0);
	cute_check_uint(galv_conn_repo_count(&galvut_unix_the_test.nc.conns),
	                equal,
	                1);

	/* Close netcat client connection. */
	galvut_unix_close_clnt(clnt);

	/* Let netcat service close connection. */
	ret = galvut_unix_test_process(&galvut_unix_the_test);
	cute_check_sint(ret, equal, 0);
	cute_check_uint(galv_conn_repo_count(&galvut_unix_the_test.nc.conns),
	                equal,
	                0);

	cute_check_uint(galvut_unix_the_test.nc.msg_cnt,
	                equal,
	                GALVUT_NCSVC_MSG_NR);
	for (m = 0; m < galvut_unix_the_test.nc.msg_cnt; m++) {
		char         ref[] = "msgxxx";
		const char * str = galvut_unix_the_test.nc.msgs[m];

STROLL_IGNORE_WARN("-Wformat-overflow")
		sprintf(ref, "msg%03u", m);
STROLL_RESTORE_WARN
		cute_check_str(str, equal, ref);
	}
}

CUTE_TEST(galvut_unix_ncsvc_send_bulk_partial)
{
	int          ret;
	int          clnt;
	unsigned int m;
	unsigned int cnt = 3;
	unsigned int loop = GALVUT_NCSVC_MSG_NR / cnt;

	/* Open netcat service. */
	galvut_unix_ncsvc_test_setup(SOCK_SEQPACKET, cnt);

	/* Open netcat client connection. */
	clnt = galvut_unix_connect_clnt(galvut_unix_the_test.sock_type);
	cute_check_sint(clnt, greater_equal, 0);

	/* Let netcat service accept connection. */
	ret = galvut_unix_test_process(&galvut_unix_the_test);
	cute_check_sint(ret, equal, 0);
	cute_check_uint(galv_conn_repo_count(&galvut_unix_the_test.nc.conns),
	                equal,
	                1);

	/* Send a multiple messages. */
	galvut_unix_ncsvc_send_bulk(clnt, GALVUT_NCSVC_MSG_NR);

	while (loop--) {
		/* Let netcat service receive messages. */
		ret = galvut_unix_test_process(&galvut_unix_the_test);
		cute_check_sint(ret, equal, 0);
		cute_check_uint(
			galv_conn_repo_count(&galvut_unix_the_test.nc.conns),
			equal,
			1);
	}

	/* Close netcat client connection. */
	galvut_unix_close_clnt(clnt);

	/* Let netcat service close connection. */
	ret = galvut_unix_test_process(&galvut_unix_the_test);
	cute_check_sint(ret, equal, 0);
	cute_check_uint(galv_conn_repo_count(&galvut_unix_the_test.nc.conns),
	                equal,
	                0);

	cute_check_uint(galvut_unix_the_test.nc.msg_cnt,
	                equal,
	                GALVUT_NCSVC_MSG_NR);
	for (m = 0; m < galvut_unix_the_test.nc.msg_cnt; m++) {
		char         ref[] = "msgxxx";
		const char * str = galvut_unix_the_test.nc.msgs[m];

STROLL_IGNORE_WARN("-Wformat-overflow")
		sprintf(ref, "msg%03u", m);
STROLL_RESTORE_WARN
		cute_check_str(str, equal, ref);
	}
}

CUTE_GROUP(galvut_unix_ncsvc_group) = {
	CUTE_REF(galvut_unix_ncsvc_open_close),
	CUTE_REF(galvut_unix_ncsvc_open_shutrd),
	CUTE_REF(galvut_unix_ncsvc_open_shutwr),
	CUTE_REF(galvut_unix_ncsvc_open_send_one_close),
	CUTE_REF(galvut_unix_ncsvc_open_send_one_shutrd),
	CUTE_REF(galvut_unix_ncsvc_open_send_one_shutwr),
	CUTE_REF(galvut_unix_ncsvc_send_bulk_full),
	CUTE_REF(galvut_unix_ncsvc_send_bulk_partial),
};

CUTE_SUITE_STATIC(galvut_unix_ncsvc_suite,
                  galvut_unix_ncsvc_group,
                  CUTE_NULL_SETUP,
                  galvut_unix_ncsvc_test_teardown,
                  CUTE_DFLT_TMOUT);

/******************************************************************************
 * Echo service tests
 ******************************************************************************/

static
int
galvut_unix_echosvc_on_accept(struct galv_acceptor * __restrict acceptor,
                              uint32_t                          events __unused,
                              const struct upoll * __restrict   poller)
{
	struct galv_unix_acceptor *           unacc =
		(struct galv_unix_acceptor *)acceptor;
	struct galv_unix_attrs                attrs;
	int                                   fd;
	const struct galvut_echosvc_context * ctx;
	struct galv_unix_conn *               conn;
	int                                   err;

	fd = galv_unix_acceptor_grab(unacc, &attrs, SOCK_CLOEXEC);
	if (fd < 0)
		return fd;

	ctx = galv_acceptor_context(acceptor);
	if (galv_conn_repo_full(&ctx->conns)) {
		err = -EPERM;
		goto close;
	}

	conn = malloc(sizeof(*conn));
	if (!conn) {
		err = -ENOMEM;
		goto close;
	}

	galv_unix_conn_setup(conn, fd, unacc, &galvut_echosvc_ops, &attrs);

	err = galv_conn_on_connecting(&conn->base, 0, poller);
	if (err)
		goto free;

	return 0;

free:
	free(conn);
close:
	etux_sock_close(fd);

	return err;
}

static const struct galv_acceptor_ops galvut_unix_echosvc_acceptor_ops = {
	.on_accept_conn = galvut_unix_echosvc_on_accept,
	.on_close_conn  = galvut_echosvc_on_close
};

static
int
galvut_unix_echosvc_open(struct galv_unix_acceptor * __restrict   acceptor,
                       int                                        type,
                       const struct upoll * __restrict            poller,
                       struct galvut_echosvc_context * __restrict ctx)
{
	cute_check_ptr(acceptor, unequal, NULL);
	cute_check_assert((type == SOCK_SEQPACKET) || (type == SOCK_STREAM));
	cute_check_ptr(poller, unequal, NULL);
	cute_check_ptr(ctx, unequal, NULL);

	cute_check_uint(ctx->bulk_cnt, greater, 0);

	return galv_unix_acceptor_open(acceptor,
	                               GALVUT_UNIX_PATH,
	                               type,
	                               SOCK_CLOEXEC,
	                               GALVUT_NCSVC_BACKLOG,
	                               poller,
	                               &galvut_unix_echosvc_acceptor_ops,
	                               ctx);
}

static
int
galvut_unix_echosvc_close(struct galv_unix_acceptor * __restrict acceptor,
                          const struct upoll * __restrict        poller)
{
	return galv_unix_acceptor_close(acceptor, poller);
}

static
int
galvut_unix_echosvc_test_open(struct galvut_unix_test * test,
                              unsigned int              max_conn)
{
	int ret;

	cute_check_ptr(test, unequal, NULL);

	/* Max number of connections + 1 for acceptor socket. */
	ret = upoll_open(&test->poll, max_conn + 1);
	if (ret)
		return ret;

	ret = galvut_unix_echosvc_open(&test->accept,
	                               test->sock_type,
	                               &test->poll,
	                               &test->echo);
	if (ret)
		goto fini_poll;

	return 0;

fini_poll:
	upoll_close(&test->poll);

	return ret;
}

static
int
galvut_unix_echosvc_test_close(struct galvut_unix_test * test)
{
	int ret;

	while (!galv_conn_repo_empty(&test->echo.conns)) {
		struct galv_conn * conn;

		conn = galv_conn_repo_pop(&test->echo.conns);
		galvut_echosvc_on_close((struct galv_acceptor *)&test->accept,
		                        conn,
		                        &test->poll);
	}

	ret = galvut_unix_echosvc_close(&test->accept, &test->poll);
	if (ret == -EINTR)
		ret = 0;

	upoll_close(&test->poll);

	return ret;
}

static
void
galvut_unix_echosvc_test_setup(int sock_type, unsigned int bulk_count)
{
	int ret;

	galvut_unix_the_test.sock_type = sock_type;
	galvut_echosvc_setup_ctx(&galvut_unix_the_test.echo, bulk_count, 1);

	ret = galvut_unix_echosvc_test_open(&galvut_unix_the_test, 1);
	cute_check_sint(ret, equal, 0);
}

static
void
galvut_unix_echosvc_test_teardown(void)
{
	galvut_unix_echosvc_test_close(&galvut_unix_the_test);
}

CUTE_TEST(galvut_unix_echosvc_open_close)
{
	int ret;
	int clnt;

	/* Open echo service. */
	galvut_unix_echosvc_test_setup(SOCK_SEQPACKET, 1);

	/* Open echo client connection. */
	clnt = galvut_unix_connect_clnt(galvut_unix_the_test.sock_type);
	cute_check_sint(clnt, greater_equal, 0);

	/* Let echo service accept connection. */
	ret = galvut_unix_test_process(&galvut_unix_the_test);
	cute_check_sint(ret, equal, 0);
	cute_check_uint(galv_conn_repo_count(&galvut_unix_the_test.echo.conns),
	                equal,
	                1);

	/* Close echo client connection. */
	galvut_unix_close_clnt(clnt);

	/* Let echo service close connection. */
	ret = galvut_unix_test_process(&galvut_unix_the_test);
	cute_check_sint(ret, equal, 0);
	cute_check_uint(galv_conn_repo_count(&galvut_unix_the_test.echo.conns),
	                equal,
	                0);
}

CUTE_TEST(galvut_unix_echosvc_open_shutrd)
{
	int ret;
	int clnt;

	/* Open echo service. */
	galvut_unix_echosvc_test_setup(SOCK_SEQPACKET, 1);

	/* Open echo client connection. */
	clnt = galvut_unix_connect_clnt(galvut_unix_the_test.sock_type);
	cute_check_sint(clnt, greater_equal, 0);

	/* Let echo service accept connection. */
	ret = galvut_unix_test_process(&galvut_unix_the_test);
	cute_check_sint(ret, equal, 0);
	cute_check_uint(galv_conn_repo_count(&galvut_unix_the_test.echo.conns),
	                equal,
	                1);

	/* Perform a local read end closure. */
	unsk_shutdown(clnt, SHUT_RD);

	ret = galvut_unix_test_process(&galvut_unix_the_test);
	cute_check_sint(ret, equal, 0);

	/* Close echo client connection. */
	galvut_unix_close_clnt(clnt);

	/* Let echo service close connection. */
	ret = galvut_unix_test_process(&galvut_unix_the_test);
	cute_check_sint(ret, equal, 0);
	cute_check_uint(galv_conn_repo_count(&galvut_unix_the_test.echo.conns),
	                equal,
	                0);
}

CUTE_TEST(galvut_unix_echosvc_open_shutwr)
{
	int ret;
	int clnt;

	/* Open echo service. */
	galvut_unix_echosvc_test_setup(SOCK_SEQPACKET, 1);

	/* Open echo client connection. */
	clnt = galvut_unix_connect_clnt(galvut_unix_the_test.sock_type);
	cute_check_sint(clnt, greater_equal, 0);

	/* Let echo service accept connection. */
	ret = galvut_unix_test_process(&galvut_unix_the_test);
	cute_check_sint(ret, equal, 0);
	cute_check_uint(galv_conn_repo_count(&galvut_unix_the_test.echo.conns),
	                equal,
	                1);

	/* Perform a local read end closure. */
	unsk_shutdown(clnt, SHUT_WR);

	ret = galvut_unix_test_process(&galvut_unix_the_test);
	cute_check_sint(ret, equal, 0);

	/* Close echo client connection. */
	galvut_unix_close_clnt(clnt);

	/* Let echo service close connection. */
	ret = galvut_unix_test_process(&galvut_unix_the_test);
	cute_check_sint(ret, equal, 0);
	cute_check_uint(galv_conn_repo_count(&galvut_unix_the_test.echo.conns),
	                equal,
	                0);
}

CUTE_TEST(galvut_unix_echosvc_open_send_one_close)
{
	int     ret;
	int     clnt;
	ssize_t sz;
	char    buff[GALVUT_ECHOSVC_MSG_SIZE_MAX];

	/* Open echo service. */
	galvut_unix_echosvc_test_setup(SOCK_SEQPACKET, 1);

	/* Open echo client connection. */
	clnt = galvut_unix_connect_clnt(galvut_unix_the_test.sock_type);
	cute_check_sint(clnt, greater_equal, 0);

	/* Let echo service accept connection. */
	ret = galvut_unix_test_process(&galvut_unix_the_test);
	cute_check_sint(ret, equal, 0);
	cute_check_uint(galv_conn_repo_count(&galvut_unix_the_test.echo.conns),
	                equal,
	                1);

	/* Send a simple message. */
	sz = unsk_send(clnt, "msg0", sizeof("msg0"), MSG_NOSIGNAL);
	cute_check_sint(sz, equal, sizeof("msg0"));

	/* Let echo service receive the message. */
	ret = galvut_unix_test_process(&galvut_unix_the_test);
	cute_check_sint(ret, equal, 0);
	cute_check_uint(galv_conn_repo_count(&galvut_unix_the_test.echo.conns),
	                equal,
	                1);

	sz = unsk_recv(clnt, buff, sizeof(buff), MSG_TRUNC);
	cute_check_sint(sz, equal, sizeof("msg0"));
	cute_check_str(buff, equal, "msg0");

	/* Close echo client connection. */
	galvut_unix_close_clnt(clnt);

	/* Let echo service close connection. */
	ret = galvut_unix_test_process(&galvut_unix_the_test);
	cute_check_sint(ret, equal, 0);
	cute_check_uint(galv_conn_repo_count(&galvut_unix_the_test.echo.conns),
	                equal,
	                0);
}

CUTE_TEST(galvut_unix_echosvc_open_send_one_shutrd)
{
	int     ret;
	int     clnt;
	ssize_t sz;

	/* Open echo service. */
	galvut_unix_echosvc_test_setup(SOCK_SEQPACKET, 1);

	/* Open echo client connection. */
	clnt = galvut_unix_connect_clnt(galvut_unix_the_test.sock_type);
	cute_check_sint(clnt, greater_equal, 0);

	/* Let echo service accept connection. */
	ret = galvut_unix_test_process(&galvut_unix_the_test);
	cute_check_sint(ret, equal, 0);
	cute_check_uint(galv_conn_repo_count(&galvut_unix_the_test.echo.conns),
	                equal,
	                1);

	/* Send a simple message. */
	sz = unsk_send(clnt, "msg0", sizeof("msg0"), MSG_NOSIGNAL);
	cute_check_sint(sz, equal, sizeof("msg0"));

	/* Perform a local read end closure. */
	unsk_shutdown(clnt, SHUT_RD);

	/* Let echo service receive the message and close connection. */
	ret = galvut_unix_test_process(&galvut_unix_the_test);
	cute_check_sint(ret, equal, 0);
	cute_check_uint(galv_conn_repo_count(&galvut_unix_the_test.echo.conns),
	                equal,
	                0);

	/* Close echo client connection. */
	galvut_unix_close_clnt(clnt);

	/* Let echo service close connection. */
	ret = galvut_unix_test_process(&galvut_unix_the_test);
	cute_check_sint(ret, equal, 0);
}

CUTE_TEST(galvut_unix_echosvc_open_send_one_shutwr)
{
	int     ret;
	int     clnt;
	ssize_t sz;
	char    buff[GALVUT_ECHOSVC_MSG_SIZE_MAX];

	/*
	 *  Open echo service, allowing it to perform multiple read/write at
	 * once.
	 */
	galvut_unix_echosvc_test_setup(SOCK_SEQPACKET, 3);

	/* Open echo client connection. */
	clnt = galvut_unix_connect_clnt(galvut_unix_the_test.sock_type);
	cute_check_sint(clnt, greater_equal, 0);

	/* Let echo service accept connection. */
	ret = galvut_unix_test_process(&galvut_unix_the_test);
	cute_check_sint(ret, equal, 0);
	cute_check_uint(galv_conn_repo_count(&galvut_unix_the_test.echo.conns),
	                equal,
	                1);

	/* Send a simple message. */
	sz = unsk_send(clnt, "msg0", sizeof("msg0"), MSG_NOSIGNAL);
	cute_check_sint(sz, equal, sizeof("msg0"));

	/* Perform a local sending end closure. */
	unsk_shutdown(clnt, SHUT_WR);

	/* Let echo service receive the message and close connection. */
	ret = galvut_unix_test_process(&galvut_unix_the_test);
	cute_check_sint(ret, equal, 0);
	cute_check_uint(galv_conn_repo_count(&galvut_unix_the_test.echo.conns),
	                equal,
	                0);

	sz = unsk_recv(clnt, buff, sizeof(buff), MSG_TRUNC);
	cute_check_sint(sz, equal, sizeof("msg0"));
	cute_check_str(buff, equal, "msg0");

	/* Close echo client connection. */
	galvut_unix_close_clnt(clnt);

	/* Let echo service close connection. */
	ret = galvut_unix_test_process(&galvut_unix_the_test);
	cute_check_sint(ret, equal, 0);
	cute_check_uint(galv_conn_repo_count(&galvut_unix_the_test.echo.conns),
	                equal,
	                0);
}

static
void
galvut_unix_echosvc_send_bulk(int sk, unsigned int start, unsigned int nr)
{
	unsigned int cnt;

	cute_check_sint(sk, greater_equal, 0);
	cute_check_uint(nr, greater, 0);
	cute_check_uint(start + nr, lower_equal, 1000);

	for (cnt = start; cnt < (start + nr); cnt++) {
		char    buff[GALVUT_ECHOSVC_MSG_SIZE_MAX];
		int     bytes;
		ssize_t ret;

STROLL_IGNORE_WARN("-Wformat-overflow")
		bytes = sprintf(buff, "msg%03u", cnt);
STROLL_RESTORE_WARN
		cute_check_sint(bytes, greater_equal, 6);
		bytes++;

		ret = unsk_send(sk, buff, (size_t)bytes, MSG_NOSIGNAL);
		cute_check_sint(ret, equal, (ssize_t)bytes);
	}
}

static
void
galvut_unix_echosvc_recv_bulk(int sk, unsigned int start, unsigned int nr)
{
	unsigned int cnt;

	cute_check_sint(sk, greater_equal, 0);
	cute_check_uint(nr, greater, 0);
	cute_check_uint(start + nr, lower_equal, 1000);

	for (cnt = start; cnt < (start + nr); cnt++) {
		char         ref[GALVUT_ECHOSVC_MSG_SIZE_MAX];
		char         buff[GALVUT_ECHOSVC_MSG_SIZE_MAX];
		int          bytes;
		ssize_t      ret;

STROLL_IGNORE_WARN("-Wformat-overflow")
		bytes = sprintf(ref, "msg%03u", cnt);
STROLL_RESTORE_WARN
		cute_check_sint(bytes, greater_equal, 6);
		bytes++;

		ret = unsk_recv(sk, buff, (size_t)bytes, MSG_TRUNC);
		cute_check_sint(ret, equal, (ssize_t)bytes);
		cute_check_str(buff, equal, ref);
	}
}

CUTE_TEST(galvut_unix_echosvc_send_bulk_full)
{
	int ret;
	int clnt;

	/* Open echo service. */
	galvut_unix_echosvc_test_setup(SOCK_SEQPACKET, 16);

	/* Open echo client connection. */
	clnt = galvut_unix_connect_clnt(galvut_unix_the_test.sock_type);
	cute_check_sint(clnt, greater_equal, 0);

	/* Let echo service accept connection. */
	ret = galvut_unix_test_process(&galvut_unix_the_test);
	cute_check_sint(ret, equal, 0);
	cute_check_uint(galv_conn_repo_count(&galvut_unix_the_test.nc.conns),
	                equal,
	                1);

	/* Send a multiple messages. */
	galvut_unix_echosvc_send_bulk(clnt, 0, 16);

	/* Let echo service receive messages. */
	ret = galvut_unix_test_process(&galvut_unix_the_test);
	cute_check_sint(ret, equal, 0);
	cute_check_uint(galv_conn_repo_count(&galvut_unix_the_test.nc.conns),
	                equal,
	                1);

	galvut_unix_echosvc_recv_bulk(clnt, 0, 16);

	/* Close echo client connection. */
	galvut_unix_close_clnt(clnt);

	/* Let echo service close connection. */
	ret = galvut_unix_test_process(&galvut_unix_the_test);
	cute_check_sint(ret, equal, 0);
	cute_check_uint(galv_conn_repo_count(&galvut_unix_the_test.nc.conns),
	                equal,
	                0);
}

CUTE_TEST(galvut_unix_echosvc_send_bulk_full_shutwr)
{
	int ret;
	int clnt;

	/* Open echo service. */
	galvut_unix_echosvc_test_setup(SOCK_SEQPACKET, 16);

	/* Open echo client connection. */
	clnt = galvut_unix_connect_clnt(galvut_unix_the_test.sock_type);
	cute_check_sint(clnt, greater_equal, 0);

	/* Let echo service accept connection. */
	ret = galvut_unix_test_process(&galvut_unix_the_test);
	cute_check_sint(ret, equal, 0);
	cute_check_uint(galv_conn_repo_count(&galvut_unix_the_test.nc.conns),
	                equal,
	                1);

	/* Send a multiple messages. */
	galvut_unix_echosvc_send_bulk(clnt, 0, 15);

	/* Perform a local sending end closure. */
	unsk_shutdown(clnt, SHUT_WR);

	/* Let echo service receive messages and close connection. */
	ret = galvut_unix_test_process(&galvut_unix_the_test);
	cute_check_sint(ret, equal, 0);
	cute_check_uint(galv_conn_repo_count(&galvut_unix_the_test.nc.conns),
	                equal,
	                0);

	galvut_unix_echosvc_recv_bulk(clnt, 0, 15);

	/* Close echo client connection. */
	galvut_unix_close_clnt(clnt);

	/* Let echo service close connection. */
	ret = galvut_unix_test_process(&galvut_unix_the_test);
	cute_check_sint(ret, equal, 0);
	cute_check_uint(galv_conn_repo_count(&galvut_unix_the_test.nc.conns),
	                equal,
	                0);
}

CUTE_GROUP(galvut_unix_echosvc_group) = {
	CUTE_REF(galvut_unix_echosvc_open_close),
	CUTE_REF(galvut_unix_echosvc_open_shutrd),
	CUTE_REF(galvut_unix_echosvc_open_shutwr),
	CUTE_REF(galvut_unix_echosvc_open_send_one_close),
	CUTE_REF(galvut_unix_echosvc_open_send_one_shutrd),
	CUTE_REF(galvut_unix_echosvc_open_send_one_shutwr),
	CUTE_REF(galvut_unix_echosvc_send_bulk_full),
	CUTE_REF(galvut_unix_echosvc_send_bulk_full_shutwr),
};

CUTE_SUITE_STATIC(galvut_unix_echosvc_suite,
                  galvut_unix_echosvc_group,
                  CUTE_NULL_SETUP,
                  galvut_unix_echosvc_test_teardown,
                  CUTE_DFLT_TMOUT);

/******************************************************************************
 * Top-level Unix connection support
 ******************************************************************************/

CUTE_GROUP(galvut_unix_conn_group) = {
	CUTE_REF(galvut_unix_ncsvc_suite),
	CUTE_REF(galvut_unix_echosvc_suite),
};

CUTE_SUITE_EXTERN(galvut_unix_conn_suite,
                  galvut_unix_conn_group,
                  CUTE_NULL_SETUP,
                  CUTE_NULL_TEARDOWN,
                  CUTE_DFLT_TMOUT);
