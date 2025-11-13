/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "accept.h"

static inline
struct galv_accept *
galv_accept_from_worker(const struct upoll_worker * __restrict worker)
{
	galv_assert_intern(worker);

	return containerof(worker, struct galv_accept, work);
}

static
int
galv_accept_on_conn_request(struct galv_accept * __restrict acceptor,
                            uint32_t                        events,
                            const struct upoll * __restrict poller)
{
	galv_accept_assert_api(acceptor);
	galv_assert_api(events & (uint32_t)EPOLLIN);
	galv_assert_api(!(events & ~((uint32_t)(EPOLLIN | EPOLLERR))));
	galv_assert_api(poller);

	struct galv_conn * conn;

	if (galv_repo_full(acceptor->repo)) {
		galv_ratelim_info("acceptor: connection request denied",
		                  ": maximum number of connections reached");
		upoll_disable_watch(&acceptor->work, EPOLLIN);
		return -EPERM;
	}

	conn = acceptor->ops->on_conn_request(acceptor, events, poller);
	if (!conn) {
		int err = errno;

		galv_assert_api(err);
		switch (err) {
		case EAGAIN: /* All queued connection requests processed. */
			upoll_enable_watch(&acceptor->work, EPOLLIN);
			return -EAGAIN;

		case EINTR:  /* Interrupted by a signal */
		case ENOMEM: /* No more memory available. */
		case EMFILE: /* Too many open files by process. */
		case ENFILE: /* Too many open files in system. */
		case ENOSPC: /* Too many epoll file descriptors registered. */
			return -err;

		default:
			break;
		}

		return 0;
	}

	galv_conn_repo_register(acceptor->repo, conn);

	return 0;
}

int
galv_accept_on_conn_term(struct galv_accept * __restrict acceptor,
                         struct galv_conn * __restrict   connection,
                         const struct upoll * __restrict poller)
{
	galv_accept_assert_intern(acceptor);
	galv_conn_assert_intern(connection);
	galv_assert_intern(poller);

	int ret;

	galv_conn_repo_unregister(acceptor->repo, connection);

	ret = acceptor->ops->on_conn_term(acceptor, connection, poller);

	upoll_enable_watch(&acceptor->work, EPOLLIN);
	upoll_apply(poller, galv_adopt_fd(acceptor->adopt), &acceptor->work);

	return ret;
}

static
int
galv_accept_dispatch(struct upoll_worker * worker,
                     uint32_t              events,
                     const struct upoll *  poller)
{
	galv_assert_intern(worker);
	galv_assert_intern(events);
	galv_assert_intern(!(events & ~((uint32_t)(EPOLLIN | EPOLLERR))));
	galv_assert_intern(poller);

	struct galv_accept * acc;
	int                  ret;

	acc = galv_accept_from_worker(worker);
	galv_accept_assert_intern(acc);

	if (events & EPOLLERR) {
		/*
		 * Nothing specific to do as next syscall called with our socket
		 * fd as argument should return the error as errno...
		 */
		galv_ratelim_notice("acceptor: socket error ignored", "");

		if (!(events & EPOLLIN))
			return 0;
	}

	/* events & EPOLLIN is true. */
	do {
		ret = galv_accept_on_conn_request(acc, events, poller);
	} while (!ret);

	upoll_apply(poller, galv_adopt_fd(acc->adopt), &acc->work);

	return (ret != -EAGAIN) ? ret : 0;
}

static
struct galv_conn *
galv_accept_handle_conn_request_event(struct galv_accept * __restrict acceptor,
                                      uint32_t                        events,
                                      const struct upoll * __restrict poller)
{
	galv_accept_assert_api(acceptor);
	galv_assert_api(events & (uint32_t)EPOLLIN);
	galv_assert_api(!(events & ~((uint32_t)(EPOLLIN | EPOLLERR))));
	galv_assert_api(poller);

	struct galv_conn * conn;
	int                err;

	conn = galv_adopt_create_conn(acceptor->adopt,
	                              acceptor->conn_ops,
	                              acceptor->conn_flags,
	                              acceptor);
	if (!conn)
		return NULL;

	err = galv_conn_on_connecting(conn, events, poller);
	if (err)
		goto destroy;

	return conn;

destroy:
	galv_adopt_destroy_conn(acceptor->adopt, conn);

	errno = -err;
	return NULL;
}

static
int
galv_accept_handle_conn_term_event(
	struct galv_accept * __restrict acceptor,
	struct galv_conn * __restrict   connection,
	const struct upoll * __restrict poller __unused)
{
	galv_accept_assert_api(acceptor);
	galv_conn_assert_api(connection);
	galv_assert_api(poller);

	return galv_adopt_destroy_conn(acceptor->adopt, connection);
}

static const struct galv_accept_ops galv_accept_event_ops = {
	.on_conn_request = galv_accept_handle_conn_request_event,
	.on_conn_term    = galv_accept_handle_conn_term_event
};

int
galv_accept_open(struct galv_accept * __restrict         acceptor,
                 struct galv_repo * __restrict           repository,
                 struct galv_adopt * __restrict          adopter,
                 unsigned int                            backlog,
                 const struct galv_conn_ops * __restrict operations,
                 int                                     flags,
                 const struct upoll * __restrict         poller)
{
	galv_assert_api(acceptor);
	galv_repo_assert_api(repository);
	galv_adopt_assert_api(adopter);
	galv_assert_api(backlog <= INT_MAX);
	galv_conn_assert_ops_api(operations);
	galv_assert_api(!(flags & ~(SOCK_NONBLOCK | SOCK_CLOEXEC)));
	galv_assert_api(poller);

	int fd = galv_adopt_fd(adopter);
	int err;

	err = etux_sock_listen(fd, (int)backlog);
	if (err)
		return err;

	acceptor->work.dispatch = galv_accept_dispatch;
	acceptor->ops = &galv_accept_event_ops;
	acceptor->repo = repository;
	acceptor->adopt = adopter;
	acceptor->conn_ops = operations;
	acceptor->conn_flags = SOCK_NONBLOCK | flags;

	return upoll_register(poller, fd, EPOLLIN, &acceptor->work);
}

void
galv_accept_close(const struct galv_accept * __restrict acceptor,
                  const struct upoll * __restrict       poller)
{
	galv_accept_assert_api(acceptor);
	galv_assert_api(poller);

	upoll_unregister(poller, galv_adopt_fd(acceptor->adopt));
}
