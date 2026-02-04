/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "common.h"
#include "galv/unix.h"
#include "galv/conn.h"
#include "galv/accept.h"
#include "galv/gate.h"

#define GALVSMPL_DISC_PATH           "sock"
#define GALVSMPL_DISC_BACKLOG        16
#define GALVSMPL_DISC_CONN_NR        (32U)
#define GALVSMPL_DISC_PERPID_CONN_NR (2U)
#define GALVSMPL_DISC_PERUID_CONN_NR (16U)
#define GALVSMPL_DISC_BULK_NR        (4U)

static
int
galvsmpl_disc_bytes(struct galv_conn * connection)
{
	unsigned int cnt = GALVSMPL_DISC_BULK_NR;
	static char  buff[1024];
	ssize_t      ret;
	size_t       bytes = 0;

	/* Restrict to GALVSMPL_DISC_BULK_NR receive operations in a row. */
	do {
		/*
		 * For TCP stream sockets (only), give MSG_TRUNC to request
		 * discarding of received bytes rather than passing data back in
		 * the `buff' supplied buffer.
		 * See tcp(7).
		 */
		ret = galv_conn_recv(connection, buff, sizeof(buff), MSG_TRUNC);
		galvsmpl_assert(ret);
		if (ret > 0)
			bytes += (size_t)ret;
	} while ((ret == sizeof(buff)) && --cnt);

	if (bytes) {
		unsigned long sum = (unsigned long)
		                    galv_conn_context(connection);

		galv_conn_set_context(connection,
		                      (void *)(sum + (unsigned long)bytes));
		galvsmpl_debug("%zu bytes discarded", bytes);
	}

	if (ret == sizeof(buff))
		return 0;
	else if ((ret > 0) || (ret == -EAGAIN))
		return -EAGAIN;
	else
		return (int)ret;
}

static
int
galvsmpl_disc_process_closing(struct upoll_worker * worker,
                              uint32_t              events,
                              const struct upoll *  poller)
{
	galvsmpl_assert(!(events &
	                  ~((uint32_t)(EPOLLIN | EPOLLHUP | EPOLLERR))));

	struct galv_conn * conn = galv_conn_from_worker(worker);
	int                ret;

	if (events & EPOLLERR) {
		galvsmpl_pwarn(galv_conn_async_error(conn),
		               "unexpected asynchronous socket error");
	}

	if (events & EPOLLHUP) {
		galvsmpl_info("peer connection shut down");
		goto close;
	}

	/* (events & EPOLLIN) */
	ret = galvsmpl_disc_bytes(conn);
	switch (ret) {
	case 0:
		return 0;

	case -EAGAIN:
	case -ECONNREFUSED:
		/* No more data to read and peer closed its writing end. */
		galvsmpl_info("incoming connection shut down");
		goto close;

	case -EINTR:
	case -ENOMEM:
		return ret;

	default:
		/* Unexpected receive failure. */
		galvsmpl_perr(-(int)ret, "unexpected receive failure");
	}

	return 0;

close:
	return galv_conn_close(conn, poller);
}

static
int
galvsmpl_disc_process_established(struct upoll_worker * worker,
                                  uint32_t              events,
                                  const struct upoll *  poller)
{
	galvsmpl_assert(!(events &
	                  ~((uint32_t)
	                    (EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR))));

	struct galv_conn * conn = galv_conn_from_worker(worker);
	int                ret;

	if (events & EPOLLERR) {
		galvsmpl_pwarn(galv_conn_async_error(conn),
		               "unexpected asynchronous socket error");
	}

	if (events & EPOLLHUP) {
		galvsmpl_info("peer connection shut down");
		goto close;
	}

	if (events & EPOLLRDHUP) {
		galvsmpl_info("shuting down incoming connection..");
		galv_conn_switch_state(conn,
		                       GALV_CONN_CLOSING_STATE,
		                       galvsmpl_disc_process_closing);
		galv_conn_reset_watch(conn, poller, EPOLLIN);

		return galvsmpl_disc_process_closing(worker,
		                                     events &
		                                     ~(uint32_t)EPOLLRDHUP,
		                                     poller);
	}

	/* (events & EPOLLIN) */
	ret = galvsmpl_disc_bytes(conn);
	switch (ret) {
	case 0:
		return 0;

	case -EAGAIN:
		galv_conn_watch(conn, EPOLLIN);
		galv_conn_apply_watch(conn, poller);
		break;

	case -ECONNREFUSED:
		/* No more data to read and peer closed its writing end. */
		galvsmpl_info("incoming connection shut down");
		goto close;

	case -EINTR:
	case -ENOMEM:
		return ret;

	default:
		/* Unexpected receive failure. */
		galvsmpl_perr(-(int)ret, "unexpected receive failure");
	}

	return 0;

close:
	return galv_conn_close(conn, poller);
}

static
int
galvsmpl_disc_on_bound(struct galv_conn *   connection,
                       const struct upoll * poller)
{
	galv_conn_set_context(connection, (void *)0);
	galv_conn_switch_state(connection,
	                       GALV_CONN_ESTABLISHED_STATE,
	                       galvsmpl_disc_process_established);
	galv_conn_reset_watch(connection, poller, EPOLLIN | EPOLLRDHUP);
	galvsmpl_info("connection established");

	return 0;
}

static
void
galvsmpl_disc_close(struct galv_conn *   connection,
                    const struct upoll * poller __unused)
{
	unsigned long sum = (unsigned long)galv_conn_context(connection);

	galvsmpl_info("read %lu bytes overall", sum);
}

static const struct galv_conn_ops galvsmpl_disc_conn_ops = {
	.on_bound = galvsmpl_disc_on_bound,
	.halt     = galv_conn_close,
	.close    = galvsmpl_disc_close
};

static
int
galvsmpl_loop(struct galv_repo *   repository, struct upoll * poller)
{
	struct galvsmpl_sigchan sigs;
	int                     ret;

	ret = galvsmpl_open_sigchan(&sigs, poller);
	if (ret)
		return ret;

	do {
		ret = upoll_process(poller, -1);
	} while (!ret || (ret == -EINTR));
	switch (ret) {
	case -ESHUTDOWN:
	case -EINTR:
		ret = 0;
		break;
	}

	galv_conn_repo_close(repository, poller);
	galvsmpl_close_sigchan(&sigs, poller);

	if (ret)
		galvsmpl_perr(-ret, "some errors occured");

	return ret;
}

static const struct galv_unix_adopt_conf galvsmpl_disc_conf =
	GALV_UNIX_ADOPT_CONF(SOCK_STREAM,
	                     SOCK_CLOEXEC,
	                     GALVSMPL_DISC_PATH,
	                     GALVSMPL_DISC_CONN_NR);

int
main(void)
{
	struct galv_unix_adopt adopt;
	struct upoll           poll;
	struct galv_repo       repo = GALV_REPO_INIT(repo,
	                                             GALVSMPL_DISC_CONN_NR);
	struct galv_accept     accept;
	int                    ret;

	galvsmpl_init();

	ret = galv_unix_adopt_open(&adopt,
	                           GALV_GATE_DUMMY,
	                           &galvsmpl_disc_conf);
	if (ret) {
		galvsmpl_perr(errno, "failed to create UNIX socket adopter");
		goto fini;
	}

	/* Max number of connections + 1 for acceptor / adopter socket. */
	ret = upoll_open(&poll, GALVSMPL_DISC_CONN_NR + 1);
	if (ret) {
		galvsmpl_perr(-ret, "failed to open poller");
		goto close_adopt;
	}

	ret = galv_accept_open(&accept,
	                       &repo,
	                       (struct galv_adopt *)&adopt,
	                       GALVSMPL_DISC_BACKLOG,
	                       &galvsmpl_disc_conn_ops,
	                       SOCK_CLOEXEC,
	                       &poll);
	if (ret) {
		galvsmpl_perr(-ret, "failed to open socket acceptor");
		goto close_poll;
	}

	ret = galvsmpl_loop(&repo, &poll);

	galv_accept_close(&accept, &poll);

close_poll:
	upoll_close(&poll);
close_adopt:
	if (!ret)
		ret = galv_unix_adopt_close(&adopt);
	else
		galv_unix_adopt_close(&adopt);
fini:
	galv_repo_fini(&repo);
	galvsmpl_fini();

	return !ret ? EXIT_SUCCESS : EXIT_FAILURE;
}
