/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "common.h"
#include "galv/unix.h"
#include "galv/accept.h"

#define GALVSMPL_ECHO_PATH           "sock"
#define GALVSMPL_ECHO_BACKLOG        16
#define GALVSMPL_ECHO_CONN_NR        (32U)
#define GALVSMPL_ECHO_PERPID_CONN_NR (2U)
#define GALVSMPL_ECHO_PERUID_CONN_NR (16U)
#define GALVSMPL_ECHO_BULK_NR        (4U)

struct galvsmpl_echo {
	struct galv_conn * conn;
	size_t             busy;
	char               buff[1024];
};

static
struct galvsmpl_echo *
galvsmpl_echo_from_conn(const struct galv_conn * connection)
{
	return (struct galvsmpl_echo *)galv_conn_context(connection);
}

static
int
galvsmpl_echo_recv(struct galvsmpl_echo * echo)
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
galvsmpl_echo_send(struct galvsmpl_echo * echo)
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
galvsmpl_echo_process_closing(struct galvsmpl_echo * echo,
                              const struct upoll *   poller)
{
	int ret;

	ret = galvsmpl_echo_send(echo);
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
		goto close;

	case -EINTR:
	case -ENOMEM:
		break;

	default:
		galvsmpl_perr(-ret, "unexpected emit failure");
	}

	galv_conn_apply_watch(echo->conn, poller);

	return ret;

close:
	return galv_conn_close(echo->conn, poller);
}

static
int
galvsmpl_echo_back(struct galvsmpl_echo * echo)
{
	int ret;

	ret = galvsmpl_echo_recv(echo);
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
			galvsmpl_perr(-ret, "unexpected receive failure");
		}
	}

	if (!echo->busy)
		return -EAGAIN;

	ret = galvsmpl_echo_send(echo);
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
			galvsmpl_perr(-ret, "unexpected emit failure");
			ret = 0;
		}
	}

	return ret;
}

static
int
galvsmpl_echo_process_established(struct galvsmpl_echo * echo,
                                  uint32_t               events,
                                  const struct upoll *   poller)
{
	int ret;

	if (events & EPOLLOUT)
		galv_conn_unwatch(echo->conn, EPOLLOUT);

	if (events & EPOLLIN) {
		unsigned int cnt = GALVSMPL_ECHO_BULK_NR;

		/* Restrict to GALVSMPL_ECHO_BULK_NR operations in a row. */
		do {
			ret = galvsmpl_echo_back(echo);
		} while (!ret && --cnt);
	}
	else
		ret = galvsmpl_echo_send(echo);

	switch (ret) {
	case 0:
		break;

	case -ECONNREFUSED:
		return galv_conn_on_recv_shut(echo->conn, events, poller);

	case -EPIPE:
	case -ECONNRESET:
		return galv_conn_on_send_shut(echo->conn, events, poller);

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
}

static
int
galvsmpl_echo_on_may_xfer(struct galv_conn *   connection,
                          uint32_t             events,
                          const struct upoll * poller)
{
	struct galvsmpl_echo * echo = galvsmpl_echo_from_conn(connection);

	switch (galv_conn_state(connection)) {
	case GALV_CONN_ESTABLISHED_STATE:
		return galvsmpl_echo_process_established(echo, events, poller);

	case GALV_CONN_CLOSING_STATE:
		return galvsmpl_echo_process_closing(echo, poller);

	default:
		galvsmpl_assert(0);
	}

	unreachable();
}

static
int
galvsmpl_echo_on_connect(struct galv_conn *   connection,
                         uint32_t             events __unused,
                         const struct upoll * poller)
{
	struct galvsmpl_echo * echo;
	int                    err;

	echo = malloc(sizeof(*echo));
	if (!echo)
		return -errno;

	err = galv_conn_poll(connection, poller, EPOLLIN, echo);
	if (!err) {
		echo->conn = connection;
		echo->busy = 0;

		galv_conn_switch_state(connection, GALV_CONN_ESTABLISHED_STATE);
		galvsmpl_debug("connection established");

		return 0;
	}

	free(echo);

	galvsmpl_perr(-err, "failed to enable connection polling");

	return err;
}

static
int
galvsmpl_echo_on_send_shut(struct galv_conn *   connection,
                           uint32_t             events __unused,
                           const struct upoll * poller)
{
	galvsmpl_debug("connection transmit end shut down: closing..");

	return galv_conn_close(connection, poller);
}

static
int
galvsmpl_echo_on_recv_shut(struct galv_conn *   connection,
                           uint32_t             events __unused,
                           const struct upoll * poller)
{
	struct galvsmpl_echo * echo = galvsmpl_echo_from_conn(connection);

	galvsmpl_debug("connection receive end shut down: closing..");

	return galvsmpl_echo_process_closing(echo, poller);
}

static
int
galvsmpl_echo_halt(struct galv_conn *   connection,
                   const struct upoll * poller)
{
	struct galvsmpl_echo * echo = galvsmpl_echo_from_conn(connection);

	galvsmpl_debug("connection halt requested: closing..");

	return galvsmpl_echo_process_closing(echo, poller);
}

static
void
galvsmpl_echo_close(struct galv_conn *   connection,
                    const struct upoll * poller)
{
	/*
	 * Unregister from poller since we registered at connect time, see
	 * galvsmpl_echo_on_connect().
	 */
	galv_conn_unpoll(connection, poller);

	free(galvsmpl_echo_from_conn(connection));
}

static
int
galvsmpl_echo_on_error(struct galv_conn *   connection __unused,
                       int                  error,
                       uint32_t             events __unused,
                       const struct upoll * poller __unused)
{
	galvsmpl_pdebug(error, "unexpected connection socket error");

	return 0;
}

static const struct galv_conn_ops galvsmpl_echo_conn_ops = {
	.on_may_xfer  = galvsmpl_echo_on_may_xfer,
	.on_connect   = galvsmpl_echo_on_connect,
	.on_send_shut = galvsmpl_echo_on_send_shut,
	.on_recv_shut = galvsmpl_echo_on_recv_shut,
	.halt         = galvsmpl_echo_halt,
	.close        = galvsmpl_echo_close,
	.on_error     = galvsmpl_echo_on_error
};

static
int
galvsmpl_loop(struct galv_repo *   repository,
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
	                     GALVSMPL_ECHO_PATH,
	                     GALVSMPL_ECHO_CONN_NR);

int
main(void)
{
	struct galv_unix_adopt  adopt;
	struct upoll            poll;
	struct galv_repo        repo = GALV_REPO_INIT(repo,
	                                              GALVSMPL_ECHO_CONN_NR);
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
	ret = upoll_open(&poll, GALVSMPL_ECHO_CONN_NR + 2);
	if (ret) {
		galvsmpl_perr(-ret, "failed to open poller");
		goto close_adopt;
	}

	ret = galv_accept_open(&accept,
	                       &repo,
	                       (struct galv_adopt *)&adopt,
	                       GALVSMPL_ECHO_BACKLOG,
	                       &galvsmpl_echo_conn_ops,
	                       SOCK_CLOEXEC,
	                       &poll);
	if (ret) {
		galvsmpl_perr(-ret, "failed to open socket acceptor");
		goto close_poll;
	}

	ret = galvsmpl_loop(&repo, &accept, &poll);

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
