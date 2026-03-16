/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "common.h"
#include "galv/unix.h"
#include "galv/accept.h"

#define GALVSMPL_ECHOS_PATH    "sock"
#define GALVSMPL_ECHO_BACKLOG  16
#define GALVSMPL_ECHOS_CONN_NR (32U)
#define GALVSMPL_ECHOS_BULK_NR (4U)

struct galvsmpl_echos {
	struct galv_conn * conn;
	size_t             busy;
	char               buff[1024];
};

static
struct galvsmpl_echos *
galvsmpl_echos_from_conn(const struct galv_conn * connection)
{
	return (struct galvsmpl_echos *)galv_conn_context(connection);
}

static
int
galvsmpl_echos_recv(struct galvsmpl_echos * echo)
{
	ssize_t ret = 0;

	if (echo->busy < sizeof(echo->buff)) {
		size_t  sz = sizeof(echo->buff) - echo->busy;

		ret = galv_conn_recv(echo->conn, echo->buff, sz, 0);
		galvsmpl_assert(ret);
		if (ret > 0) {
			echo->busy += (size_t)ret;
			if ((size_t)ret < sz)
				return -EAGAIN;
			else
				return 0;
		}
	}

	return (int)ret;
}

static
int
galvsmpl_echos_send(struct galvsmpl_echos * echo)
{
	ssize_t ret = 0;

	if (echo->busy) {
		size_t sz = echo->busy;

		ret = galv_conn_send(echo->conn, echo->buff, sz, MSG_NOSIGNAL);
		galvsmpl_assert(ret);
		if (ret > 0) {
			echo->busy -= (size_t)ret;
			if ((size_t)ret < sz) {
				memmove(echo->buff,
				        &echo->buff[ret],
				        sz - (size_t)ret);
				return -EAGAIN;
			}
			else
				return 0;
		}
	}

	return (int)ret;
}

static
int
galvsmpl_echos_back(struct galvsmpl_echos * echo)
{
	int ret;

	ret = galvsmpl_echos_recv(echo);
	if (ret < 0) {
		switch (ret) {
		case -EAGAIN:
			galv_conn_watch(echo->conn, EPOLLIN);
			break;

		case -ECONNREFUSED:
		case -EINTR:
		case -ENOMEM:
			return ret;

		default:
			galvsmpl_pwarn(-ret, "unexpected receive failure");
		}
	}

	if (!echo->busy)
		return -EAGAIN;

	ret = galvsmpl_echos_send(echo);
	if (ret < 0) {
		switch (ret) {
STROLL_IGNORE_WARN("-Wimplicit-fallthrough")
		case -ENOBUFS:
			galv_conn_unwatch(echo->conn, EPOLLIN);
STROLL_RESTORE_WARN
		case -EAGAIN:
			galv_conn_watch(echo->conn, EPOLLOUT);
			break;

		case -EPIPE:
		case -ECONNRESET:
		case -EINTR:
		case -ENOMEM:
			return ret;

		default:
			galvsmpl_pwarn(-ret, "unexpected emit failure");
			ret = 0;
		}
	}

	return ret;
}

static
int
galvsmpl_echos_process_closing(struct upoll_worker * worker,
                               uint32_t              events,
                               const struct upoll *  poller)
{
	galvsmpl_assert(!(events &
	                  ~((uint32_t)(EPOLLOUT | EPOLLHUP | EPOLLERR))));

	struct galv_conn *      conn = galv_conn_from_worker(worker);
	struct galvsmpl_echos * echo = galvsmpl_echos_from_conn(conn);
	int                     ret;

	if (events & EPOLLERR)
		galvsmpl_pwarn(galv_conn_async_error(conn),
		               "unexpected asynchronous socket error");

	if (events & EPOLLHUP) {
		/*
		 * We can no more echo back since writing to the connection is
		 * no more possible: just close, even if there are still some
		 * more data left to be read from the underlying socket.
		 */
		galvsmpl_info("connection reset");
		goto close;
	}

	if (events & EPOLLOUT)
		galv_conn_unwatch(echo->conn, EPOLLOUT);

	ret = galvsmpl_echos_send(echo);
	if (!ret)
		goto close;

	galvsmpl_assert(ret < 0);
	switch (ret) {
	case -EAGAIN:
	case -ENOBUFS:
		galv_conn_watch(echo->conn, EPOLLOUT);
		ret = 0;
		break;

	case -EPIPE:
	case -ECONNRESET:
		galvsmpl_info("outgoing connection shut down");
		goto close;

	case -EINTR:
	case -ENOMEM:
		break;

	default:
		galvsmpl_pwarn(-ret, "unexpected emit failure");
		ret = 0;
	}

	galv_conn_apply_watch(echo->conn, poller);

	return ret;

close:
	return galv_conn_close(echo->conn, poller);
}

static
int
galvsmpl_echos_process_established(struct upoll_worker * worker,
                                   uint32_t              events,
                                   const struct upoll *  poller)
{
	galvsmpl_assert(!(events &
	                  ~((uint32_t)(EPOLLIN | EPOLLRDHUP |
	                               EPOLLOUT | EPOLLHUP |
	                               EPOLLERR))));

	struct galv_conn *      conn = galv_conn_from_worker(worker);
	struct galvsmpl_echos * echo = galvsmpl_echos_from_conn(conn);
	int                     ret;

	if (events & EPOLLERR)
		galvsmpl_pwarn(galv_conn_async_error(conn),
		               "unexpected asynchronous socket error");

	if (events & EPOLLHUP) {
		/*
		 * We can no more echo back since writing to the connection is
		 * no more possible: just close, even if there are still some
		 * more data left to be read from the underlying socket.
		 */
		galvsmpl_info("connection reset");
		goto close;
	}

	if (events & EPOLLRDHUP) {
		/*
		 * Peer closed its connection writing end in a graceful manner.
		 * Note that there still may be data left to be read from the
		 * underlying socket.
		 */
		galvsmpl_debug("shutting down incoming connection..");
		events |= EPOLLIN;
	}

	if (events & EPOLLOUT)
		galv_conn_unwatch(echo->conn, EPOLLOUT);

	if (events & EPOLLIN) {
		unsigned int cnt = GALVSMPL_ECHOS_BULK_NR;

		/* Restrict to GALVSMPL_ECHOS_BULK_NR operations in a row. */
		do {
			ret = galvsmpl_echos_back(echo);
		} while (!ret && --cnt);
	}
	else
		ret = galvsmpl_echos_send(echo);

	switch (ret) {
	case 0:
		break;

	case -ECONNREFUSED:
		galvsmpl_info("incoming connection shut down");
		galv_conn_unwatch(echo->conn, EPOLLIN | EPOLLRDHUP);
		galv_conn_switch_state(conn,
		                       GALV_CONN_CLOSING_STATE,
		                       galvsmpl_echos_process_closing);
		return galvsmpl_echos_process_closing(
			worker,
			events & ~((uint32_t)(EPOLLIN | EPOLLRDHUP)),
			poller);

	case -EPIPE:
	case -ECONNRESET:
		galvsmpl_info("outgoing connection shut down");
		goto close;

	case -EINTR:
	case -ENOMEM:
		break;

	case -EAGAIN:
	case -ENOBUFS:
	default:
		ret = 0;
	}

	galv_conn_apply_watch(echo->conn, poller);

	return ret;

close:
	return galv_conn_close(conn, poller);
}

static
int
galvsmpl_echos_on_bound(struct galv_conn *   connection,
                        const struct upoll * poller)
{
	struct galvsmpl_echos * echo;

	echo = malloc(sizeof(*echo));
	if (!echo)
		return -errno;

	echo->conn = connection;
	echo->busy = 0;

	galv_conn_set_context(connection, echo);
	galv_conn_switch_state(connection,
	                       GALV_CONN_ESTABLISHED_STATE,
	                       galvsmpl_echos_process_established);
	galv_conn_reset_watch(connection, poller, EPOLLIN | EPOLLRDHUP);

	return 0;
}

static
int
galvsmpl_echos_halt(struct galv_conn *   connection,
                    const struct upoll * poller)
{
	struct galvsmpl_echos * echo = galvsmpl_echos_from_conn(connection);

	galvsmpl_debug("connection halt requested: closing..");

	galv_conn_switch_state(connection,
	                       GALV_CONN_CLOSING_STATE,
	                       galvsmpl_echos_process_closing);
	galv_conn_unwatch(echo->conn, EPOLLIN | EPOLLRDHUP);

	return galvsmpl_echos_process_closing(&connection->work, 0, poller);
}

static
void
galvsmpl_echos_close(struct galv_conn *   connection,
                     const struct upoll * poller __unused)
{
	free(galvsmpl_echos_from_conn(connection));
}

static const struct galv_conn_ops galvsmpl_echos_conn_ops = {
	.on_bound = galvsmpl_echos_on_bound,
	.halt     = galvsmpl_echos_halt,
	.close    = galvsmpl_echos_close,
};

static
int
galvsmpl_echos_loop(struct galv_repo *   repository,
                    struct galv_accept * acceptor,
                    struct upoll *       poller)
{
	struct galvsmpl_sigchan sigs;
	int                     ret;
	int                     err;

	ret = galvsmpl_open_sigchan(&sigs, poller);
	if (ret)
		return ret;

	do {
		ret = upoll_process(poller, -1);
	} while (!ret || (ret == -EINTR));
	if (ret == -ESHUTDOWN)
		ret = 0;

	galv_accept_suspend(acceptor, poller);
	galv_conn_repo_halt(repository, poller);
	err = 0;
	while (!galv_repo_empty(repository)) {
		/*
		 * To be safe, a timer should be armed here to prevent from
		 * blocking into epoll_wait() forever...
		 */
		err = upoll_process(poller, -1);
		if (err)
			break;
	}
	if (err == -ESHUTDOWN)
		err = -EINTR;
	if (!ret)
		ret = err;

	galv_conn_repo_close(repository, poller);
	galvsmpl_close_sigchan(&sigs, poller);

	if (ret)
		galvsmpl_pdebug(-ret, "failed to gracefully halt");

	return ret;
}

static const struct galv_unix_adopt_conf galvsmpl_echo_conf =
	GALV_UNIX_ADOPT_CONF(SOCK_STREAM,
	                     SOCK_CLOEXEC,
	                     GALVSMPL_ECHOS_PATH,
	                     GALVSMPL_ECHOS_CONN_NR);

int
main(void)
{
	struct galv_unix_adopt  adopt;
	struct upoll            poll;
	struct galv_repo        repo = GALV_REPO_INIT(repo,
	                                              GALVSMPL_ECHOS_CONN_NR);
	struct galv_accept      accept;
	int                     ret;

	galvsmpl_init();

	ret = galv_unix_adopt_open(&adopt,
	                           GALV_GATE_DUMMY,
	                           &galvsmpl_echo_conf);
	if (ret) {
		galvsmpl_perr(errno, "failed to create UNIX socket adopter");
		goto fini;
	}

	/*
	 * Max number of connections
	 * + 1 for acceptor / adopter socket
	 * + 1 for signal channel
	 */
	ret = upoll_open(&poll, GALVSMPL_ECHOS_CONN_NR + 2);
	if (ret) {
		galvsmpl_perr(-ret, "failed to open poller");
		goto close_adopt;
	}

	ret = galv_accept_open(&accept,
	                       &repo,
	                       (struct galv_adopt *)&adopt,
	                       GALVSMPL_ECHO_BACKLOG,
	                       &galvsmpl_echos_conn_ops,
	                       SOCK_CLOEXEC,
	                       &poll);
	if (ret) {
		galvsmpl_perr(-ret, "failed to open socket acceptor");
		goto close_poll;
	}

	ret = galvsmpl_echos_loop(&repo, &accept, &poll);

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
