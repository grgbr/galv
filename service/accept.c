/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "accept.h"

/******************************************************************************/
/******************************************************************************/
/******************************************************************************/
/******************************************************************************/

static
int
galv_conn_process_connecting(struct galv_conn * __restrict connection,
                             uint32_t                      events,
                             const struct upoll *          poller)
{
	galv_assert_intern(connection);
	galv_assert_intern(events);
	galv_assert_intern(poller);

	int ret;

	if (!(events & (EPOLLHUP | EPOLLRDHUP)))
		ret = galv_conn_on_may_xfer(connection, events, poller);
	else
		ret = galv_conn_close(connection, poller);

	return ret;
}

static
int
galv_conn_process_established(struct galv_conn * __restrict connection,
                              uint32_t                      events,
                              const struct upoll *          poller)
{
	galv_assert_intern(connection);
	galv_assert_intern(events);
	galv_assert_intern(poller);

	int ret;

	if (events & EPOLLHUP)
		ret = galv_conn_on_send_shut(connection, events, poller);
	else if (events & EPOLLRDHUP)
		ret = galv_conn_on_recv_shut(connection, events, poller);
	else
		ret = galv_conn_on_may_xfer(connection, events, poller);

	return ret;
}

static
int
galv_conn_process_closing(struct galv_conn * __restrict connection,
                          uint32_t                      events,
                          const struct upoll *          poller)
{
	galv_assert_intern(connection);
	galv_assert_intern(events);
	galv_assert_intern(poller);

	int ret = 0;

	if (events & EPOLLHUP)
		ret = galv_conn_close(connection, poller);
	else if (events & EPOLLRDHUP)
		ret = galv_conn_on_recv_shut(connection, events, poller);
	else
		ret = galv_conn_on_may_xfer(connection, events, poller);

	return ret;
}

static
int
galv_conn_dispatch(struct upoll_worker * worker,
                   uint32_t              events,
                   const struct upoll *  poller)
{
	galv_assert_intern(worker);
	galv_assert_intern(poller);
	galv_assert_intern(events);
	galv_assert_intern(!(events & ~GALV_CONN_POLL_VALID_EVENTS));

	struct galv_conn * conn;
	int                ret;

	conn = galv_conn_from_worker(worker);
	galv_conn_assert_intern(conn);
	galv_assert_intern(conn->state != GALV_CONN_CLOSED_STATE);
	galv_assert_intern(conn->fd >= 0);
	galv_assert_intern(conn->work.dispatch);
	galv_assert_intern(conn->dispatch);

	if (events & EPOLLERR) {
		ret = galv_conn_on_error(conn,
		                         galv_conn_async_error(conn),
		                         events,
		                         poller);
		if (ret)
			return ret;

		events &= ~((uint32_t)(EPOLLERR));
	}

	switch (galv_conn_state(conn)) {
	case GALV_CONN_ESTABLISHED_STATE:
		ret = galv_conn_process_established(conn, events, poller);
		break;

	case GALV_CONN_CONNECTING_STATE:
		ret = galv_conn_process_connecting(conn, events, poller);
		break;

	case GALV_CONN_CLOSING_STATE:
		ret = galv_conn_process_closing(conn, events, poller);
		break;

	case GALV_CONN_BINDING_STATE:
	case GALV_CONN_CLOSED_STATE:
	default:
		galv_assert_intern(0);
	}

	return ret;
}

/******************************************************************************/
/******************************************************************************/
/******************************************************************************/
/******************************************************************************/

static inline
struct galv_accept *
galv_accept_from_worker(const struct upoll_worker * __restrict worker)
{
	galv_assert_intern(worker);

	return containerof(worker, struct galv_accept, work);
}

int
galv_accept_resume(struct galv_accept * __restrict acceptor,
                    const struct upoll * __restrict poller)
{
	galv_accept_assert_api(acceptor);
	galv_assert_api(poller);
	galv_assert_api(acceptor->state == GALV_ACCEPT_SUSPENDED_STATE);

	acceptor->state = GALV_ACCEPT_RUNNING_STATE;
	return upoll_register(poller,
	                      galv_adopt_fd(acceptor->adopt),
	                      EPOLLIN,
	                      &acceptor->work);
}

void
galv_accept_suspend(struct galv_accept * __restrict acceptor,
                    const struct upoll * __restrict poller)
{
	galv_accept_assert_api(acceptor);
	galv_assert_api(poller);
	galv_assert_api(acceptor->state != GALV_ACCEPT_SUSPENDED_STATE);

	acceptor->state = GALV_ACCEPT_SUSPENDED_STATE;
	upoll_unregister(poller, galv_adopt_fd(acceptor->adopt));
}

void
galv_accept_halt(struct galv_accept * __restrict acceptor,
                 const struct upoll * __restrict poller)
{
	galv_accept_assert_api(acceptor);
	galv_assert_api(poller);

	struct galv_conn * conn;
	struct galv_conn * tmp;

	if (acceptor->state == GALV_ACCEPT_RUNNING_STATE)
		galv_accept_suspend(acceptor, poller);

	galv_conn_repo_foreach_safe(acceptor->repo, conn, tmp) {
		if ((const struct galv_accept *)
		    galv_conn_dispatcher(conn) == acceptor)
			galv_conn_close(conn, poller);
	}
}

static
int
galv_accept_on_conn_request(struct galv_accept * __restrict acceptor,
                            const struct upoll * __restrict poller)
{
	galv_accept_assert_intern(acceptor);
	galv_assert_intern(acceptor->state == GALV_ACCEPT_RUNNING_STATE);
	galv_assert_intern(poller);

	struct galv_conn * conn;
	int                ret;

	conn = galv_adopt_create_conn(acceptor->adopt,
	                              acceptor->conn_ops,
	                              acceptor->conn_flags,
	                              acceptor);
	if (!conn)
		return -errno;

	ret = galv_conn_poll(conn, poller, 0, galv_conn_dispatch);
	if (ret)
		goto destroy;

	ret = galv_conn_on_connect(conn, EPOLLIN | EPOLLOUT, poller);
	if (ret && (ret != -EINTR))
		goto unpoll;

	galv_conn_repo_register(acceptor->repo, conn);

	return ret;

unpoll:
	galv_conn_unpoll(conn, poller);
destroy:
	galv_adopt_destroy_conn(acceptor->adopt, conn);

	return ret;
}

static
int
galv_accept_on_conn_term(struct galv_dispatch * __restrict dispatcher,
                         struct galv_conn * __restrict     connection,
                         const struct upoll * __restrict   poller)
{
	galv_accept_assert_intern((struct galv_accept *)dispatcher);
	galv_conn_assert_intern(connection);
	galv_assert_intern(connection->fd >= 0);
	galv_assert_intern(poller);

	struct galv_accept * accept = (struct galv_accept *)dispatcher;
	int                  ret;

	galv_conn_repo_unregister(accept->repo, connection);
	galv_conn_unpoll(connection, poller);
	ret = galv_adopt_destroy_conn(accept->adopt, connection);

	upoll_enable_watch(&accept->work, EPOLLIN);
	if (accept->state == GALV_ACCEPT_RUNNING_STATE)
		upoll_apply(poller,
		            galv_adopt_fd(accept->adopt),
		            &accept->work);

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

	acc = galv_accept_from_worker(worker);
	galv_accept_assert_intern(acc);
	galv_assert_intern(acc->state == GALV_ACCEPT_RUNNING_STATE);

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
	while (true) {
		int ret;

		if (galv_repo_full(acc->repo)) {
			galv_ratelim_info(
				"acceptor: connection request denied",
				": maximum number of connections reached");

			upoll_disable_watch(&acc->work, EPOLLIN);
			upoll_apply(poller,
			            galv_adopt_fd(acc->adopt),
			            &acc->work);

			return 0;
		}

		ret = galv_accept_on_conn_request(acc, poller);
		switch (ret) {
		case -EAGAIN: /* All queued connection requests processed. */
			upoll_enable_watch(&acc->work, EPOLLIN);
			upoll_apply(poller,
			            galv_adopt_fd(acc->adopt),
			            &acc->work);
			return 0;

		case -EINTR:  /* Interrupted by a signal */
		case -ENOMEM: /* No more memory available. */
		case -EMFILE: /* Too many open files by process. */
		case -ENFILE: /* Too many open files in system. */
		case -ENOSPC: /* Too many epoll file descriptors registered. */
			return ret;
		}
	}

	unreachable();
}

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
	galv_assert_api(!(flags & ETUX_SOCK_ACCEPT_INVALID_FLAGS));
	galv_assert_api(poller);

	int fd = galv_adopt_fd(adopter);
	int err;

	err = etux_sock_listen(fd, (int)backlog);
	if (err)
		return err;

	acceptor->base.on_conn_term = galv_accept_on_conn_term;
	acceptor->work.dispatch = galv_accept_dispatch;
	acceptor->repo = repository;
	acceptor->adopt = adopter;
	acceptor->conn_ops = operations;
	acceptor->conn_flags = SOCK_NONBLOCK | flags;
	acceptor->state = GALV_ACCEPT_RUNNING_STATE;

	return upoll_register(poller, fd, EPOLLIN, &acceptor->work);
}

void
galv_accept_close(const struct galv_accept * __restrict acceptor,
                  const struct upoll * __restrict       poller)
{
	galv_accept_assert_api(acceptor);
	galv_assert_api(poller);

	if (acceptor->state != GALV_ACCEPT_SUSPENDED_STATE)
		upoll_unregister(poller, galv_adopt_fd(acceptor->adopt));
}
