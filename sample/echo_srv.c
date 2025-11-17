/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "common.h"
#include "galv/unix.h"
#include "galv/accept.h"
#include <stroll/alloc.h>

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
galvsmpl_echo_from_conn(const struct galv_conn * __restrict connection)
{
	return (struct galvsmpl_echo *)galv_conn_context(connection);
}

static
int
galvsmpl_echo_recv(struct galv_echo * __restrict echo)
{
	ssize_t ret = 0;

	if (echo->busy < sizeof(buff)) {
		size_t  sz = sizeof(echo->buff) - echo->busy;

		ret = galv_conn_recv(echo->conn, echo->buff, sz, 0);
		galvsmpl_assert(ret);
		if (ret > 0) {
			echo->busy += (size_t)ret;
			if ((size_t)ret < sz)
				ret = -EAGAIN;
			else
				ret = 0;
		}
	}

	return ret;
}

static
int
galvsmpl_echo_send(struct galv_echo * __restrict echo)
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
				ret = -EAGAIN;
			}
			else
				ret = 0;
		}
	}

	return ret;
}

static
int
galvsmpl_echo_on_may_xfer(struct galv_conn * __restrict   connection,
                          uint32_t                        events,
                          const struct upoll * __restrict poller)
{
	struct galvsmpl_echo * echo;
	unsigned int           cnt = GALVSMPL_ECHO_BULK_NR;
	bool                   recvon = true;
	bool                   sendon = true;
	ssize_t                ret;


	if (events & EPOLLOUT)
		galv_conn_unwatch(echo->conn, EPOLLOUT);

	if (!(events & EPOLLIN))
		FLUSH OUTPUT;

	/* Restrict to GALVSMPL_ECHO_BULK_NR echo operations in a row. */
	do {
		if (recvon) {
			ret = galvsmpl_echo_recv(echo);
			if (ret < 0) {
				if (ret == -EAGAIN) {
					recvon = false;
					galv_conn_watch(connection, EPOLLIN);
				}
				else if (ret == -ECONNREFUSED)
					return galv_conn_on_recv_shut(
						connection,
						events,
						poller);
				else if ((ret == -EINTR) || (ret == -ENOMEM))
					goto apply;
				else {
					recvon = false;
					galvsmpl_perr(
						-ret,
						"unexpected receive failure");
				}

				ret = 0;
			}
		}

		if (sendon && echo->busy) {
			ret = galvsmpl_echo_send(echo);
			if (ret < 0) {
				if (ret == -EAGAIN) {
					sendon = false;
					galv_conn_watch(conn, EPOLLOUT);
				}
				else if ((ret == -EPIPE) ||
				         (ret == -ECONNRESET))
					return galv_conn_on_send_shut(
						connection,
						events,
						poller);
				else if ((ret == -EINTR) || (ret == -ENOMEM))
					goto apply;
				else {
					sendon = false;
					galvsmpl_perr(
						-ret,
						"unexpected emit failure");
				}

				ret = 0;
			}
		}
	} while ((recvon || sendon) && --cnt);

	galvsmpl_assert(!ret);

apply:
	galv_conn_apply_watch(connection, poller);

	return (int)ret;
}

static
int
galvsmpl_echo_on_connect(struct galv_conn * __restrict   connection,
                         uint32_t                        events __unused,
                         const struct upoll * __restrict poller)
{
	int err;

	err = galv_conn_poll(connection, poller, EPOLLIN, NULL);
	if (!err) {
		galv_conn_switch_state(connection, GALV_CONN_ESTABLISHED_STATE);
		galvsmpl_debug("connection established");

		return 0;
	}

	galvsmpl_perr(-err, "failed to enable connection polling");

	return err;
}

static
int
galvsmpl_echo_on_send_shut(struct galv_conn * __restrict   connection,
                           uint32_t                        events __unused,
                           const struct upoll * __restrict poller)
{
	galvsmpl_debug("connection transmit end shut down: closing...");

	return galv_conn_close(connection, poller);
}

static
int
galvsmpl_echo_on_recv_shut(struct galv_conn * __restrict   connection,
                           uint32_t                        events __unused,
                           const struct upoll * __restrict poller)
{
	galvsmpl_debug("connection receive end shut down: closing...");

	return galv_conn_close(connection, poller);
}

static
void
galvsmpl_echo_close(struct galv_conn * __restrict   connection,
                    const struct upoll * __restrict poller)
{
	/*
	 * Unregister from poller since we registered at connect time, see
	 * galvsmpl_echo_on_connect().
	 */
	galv_conn_unpoll(connection, poller);
}

static
int
galvsmpl_echo_on_error(struct galv_conn * __restrict   connection __unused,
                       uint32_t                        events __unused,
                       const struct upoll * __restrict poller __unused)
{
	galvsmpl_debug("unexpected connection socket error");

	return 0;
}

static const struct galv_conn_ops galvsmpl_echo_conn_ops = {
	.on_may_xfer  = galvsmpl_echo_on_may_xfer,
	.on_connect   = galvsmpl_echo_on_connect,
	.on_send_shut = galvsmpl_echo_on_send_shut,
	.on_recv_shut = galvsmpl_echo_on_recv_shut,
	.halt         = galv_conn_close,
	.close        = galvsmpl_echo_close,
	.on_error     = galvsmpl_echo_on_error
};

static
int
galvsmpl_loop(struct galv_repo * __restrict   repository,
              struct galv_accept * __restrict acceptor,
              struct upoll * __restrict       poller)
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
	switch (ret) {
	case -ESHUTDOWN:
	case -EINTR:
		ret = 0;
		break;
	}

	galv_accept_suspend(acceptor, poller);
	galv_conn_repo_halt(repository, poller);
	err = 0;
	while (!galv_repo_empty(repository)) {
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

int
main(void)
{
	struct stroll_alloc *   alloc;
	struct galv_unix_adopt  adopt;
	struct upoll            poll;
	struct galv_repo        repo = GALV_REPO_INIT(repo,
	                                              GALVSMPL_ECHO_CONN_NR);
	struct galv_accept      accept;
	int                     ret;

	galvsmpl_init();

	alloc = galv_unix_create_conn_alloc(GALVSMPL_ECHO_CONN_NR);
	if (!alloc) {
		ret = -errno;
		galvsmpl_perr(errno, "failed to create UNIX socket allocator");
		goto out;
	}

	ret = galv_unix_adopt_open(&adopt,
	                           GALVSMPL_ECHO_PATH,
	                           SOCK_STREAM,
	                           SOCK_CLOEXEC,
	                           alloc,
	                           GALV_GATE_DUMMY);
	if (ret) {
		galvsmpl_perr(errno, "failed to create UNIX socket adopter");
		goto destroy_alloc;
	}

	/* Max number of connections + 1 for acceptor / adopter socket. */
	ret = upoll_open(&poll, GALVSMPL_ECHO_CONN_NR + 1);
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
destroy_alloc:
	stroll_alloc_destroy(alloc);
	galv_repo_fini(&repo);
out:
	galvsmpl_fini();

	return !ret ? EXIT_SUCCESS : EXIT_FAILURE;
}
