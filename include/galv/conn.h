/******************************************************************************
 * Asynchronous connection handling
 ******************************************************************************/

#ifndef _GALV_CONN_H
#define _GALV_CONN_H

#include <galv/cdefs.h>
#include <utils/sock.h>
#include <utils/poll.h>
#include <stroll/dlist.h>

struct galv_conn;
struct galv_accept;

/******************************************************************************
 * Generic connection handling
 ******************************************************************************/

typedef int galv_conn_handle_fn(struct galv_conn * __restrict,
                                uint32_t,
                                const struct upoll * __restrict);

/*
 * TODO: document state chart.
 *
 * on_error(): 
 * - called upon socket error state when returning from upoll() ;
 * - SO_ERROR socket options might be useful here (see socket(7)).
 */
struct galv_conn_ops {
	galv_conn_handle_fn * on_may_xfer;
	galv_conn_handle_fn * on_connecting;
	galv_conn_handle_fn * on_send_closed;
	galv_conn_handle_fn * on_recv_closed;
	galv_conn_handle_fn * on_error;
};

#define galv_conn_assert_ops_api(_ops) \
	galv_assert_api(_ops); \
	galv_assert_api((_ops)->on_may_xfer); \
	galv_assert_api((_ops)->on_connecting); \
	galv_assert_api((_ops)->on_send_closed); \
	galv_assert_api((_ops)->on_recv_closed); \
	galv_assert_api((_ops)->on_error)

enum galv_conn_state {
	GALV_CONN_CLOSED_STATE      = 0,
	GALV_CONN_CONNECTING_STATE  = 1,
	GALV_CONN_ESTABLISHED_STATE = 2,
	GALV_CONN_SENDSHUT_STATE    = 3,
	GALV_CONN_RECVSHUT_STATE    = 4,
	GALV_CONN_CLOSING_STATE     = 5,
	GALV_CONN_STATE_NR
};

struct galv_conn {
	const struct galv_conn_ops * ops;
	enum galv_conn_state         state;
	int                          fd;
	struct upoll_worker          work;
	struct galv_accept *         accept;
	void *                       ctx;
	struct stroll_dlist_node     repo;
};

#define galv_conn_assert_api(_conn) \
	galv_assert_api(_conn); \
	galv_conn_assert_ops_api((_conn)->ops); \
	galv_assert_api((_conn)->state >= 0); \
	galv_assert_api((_conn)->state < GALV_CONN_STATE_NR); \
	galv_assert_api((_conn)->accept)

#define GALV_CONN_POLL_VALID_EVENTS \
	((uint32_t)(EPOLLIN | EPOLLPRI | EPOLLRDHUP | \
	            EPOLLOUT | EPOLLHUP | EPOLLERR))

static inline
struct galv_conn *
galv_conn_from_worker(const struct upoll_worker * __restrict worker)
{
	galv_assert_api(worker);

	return containerof(worker, struct galv_conn, work);
}

static inline
struct galv_accept *
galv_conn_acceptor(const struct galv_conn * __restrict connection)
{
	galv_conn_assert_api(connection);
	galv_assert_api(connection->state != GALV_CONN_CLOSED_STATE);

	return connection->accept;
}

static inline
void *
galv_conn_context(const struct galv_conn * __restrict connection)
{
	galv_conn_assert_api(connection);
	galv_assert_api(connection->state != GALV_CONN_CLOSED_STATE);

	return connection->ctx;
}

static inline
enum galv_conn_state
galv_conn_state(const struct galv_conn * __restrict connection)
{
	galv_conn_assert_api(connection);

	return connection->state;
}

static inline
void
galv_conn_switch_state(struct galv_conn * __restrict connection,
                       enum galv_conn_state          state)
{
	galv_conn_assert_api(connection);
	galv_assert_api(state >= 0);
	galv_assert_api(state < GALV_CONN_STATE_NR);

	connection->state = state;
}

static inline
uint32_t
galv_conn_watched(const struct galv_conn * __restrict connection)
{
	galv_conn_assert_api(connection);
	galv_assert_api(connection->fd >= 0);
	galv_assert_api(connection->state != GALV_CONN_CLOSED_STATE);
	galv_assert_api(connection->state != GALV_CONN_CLOSING_STATE);

	return upoll_watched_events(&connection->work);
}

static inline
void
galv_conn_watch(struct galv_conn * __restrict connection,
                uint32_t                      events)
{
	galv_conn_assert_api(connection);
	galv_assert_api(connection->fd >= 0);
	galv_assert_api(connection->state != GALV_CONN_CLOSED_STATE);
	galv_assert_api(connection->state != GALV_CONN_CLOSING_STATE);

	upoll_enable_watch(&connection->work, events);
}

static inline
void
galv_conn_unwatch(struct galv_conn * __restrict connection,
                  uint32_t                      events)
{
	galv_conn_assert_api(connection);
	galv_assert_api(connection->fd >= 0);
	galv_assert_api(connection->state != GALV_CONN_CLOSED_STATE);
	galv_assert_api(connection->state != GALV_CONN_CLOSING_STATE);

	upoll_disable_watch(&connection->work, events);
}

static inline
int
galv_conn_on_may_xfer(struct galv_conn * __restrict   connection,
                      uint32_t                        events,
                      const struct upoll * __restrict poller)
{
	galv_conn_assert_api(connection);
	galv_assert_api(connection->state != GALV_CONN_CLOSING_STATE);
	galv_assert_api(connection->state != GALV_CONN_CLOSED_STATE);
	galv_assert_api(!(events & ~((uint32_t)(EPOLLIN | EPOLLPRI |
	                                        EPOLLOUT | EPOLLHUP))));
	galv_assert_api(events);
	galv_assert_api(poller);

	return connection->ops->on_may_xfer(connection, events, poller);
}

static inline
int
galv_conn_on_connecting(struct galv_conn * __restrict   connection,
                        uint32_t                        events,
                        const struct upoll * __restrict poller)
{
	galv_conn_assert_api(connection);
	galv_assert_api(connection->state == GALV_CONN_CLOSED_STATE);
	galv_assert_api(!(events & ~((uint32_t)(EPOLLIN | EPOLLPRI |
	                                        EPOLLOUT))));
	galv_assert_api(poller);

	connection->state = GALV_CONN_CONNECTING_STATE;

	return connection->ops->on_connecting(connection, events, poller);
}

static inline
int
galv_conn_on_send_closed(struct galv_conn * __restrict   connection,
                         uint32_t                        events,
                         const struct upoll * __restrict poller)
{
	galv_conn_assert_api(connection);
	galv_assert_api(connection->state != GALV_CONN_CLOSING_STATE);
	galv_assert_api(connection->state != GALV_CONN_CLOSED_STATE);
	galv_assert_api(!(events & ~GALV_CONN_POLL_VALID_EVENTS));
	galv_assert_api(events & (EPOLLIN | EPOLLPRI | EPOLLHUP));
	galv_assert_api(poller);

	galv_conn_unwatch(connection, EPOLLOUT);
	connection->state = GALV_CONN_SENDSHUT_STATE;

	return connection->ops->on_send_closed(connection, events, poller);
}

static inline
int
galv_conn_on_recv_closed(struct galv_conn * __restrict   connection,
                         uint32_t                        events,
                         const struct upoll * __restrict poller)
{
	galv_conn_assert_api(connection);
	galv_assert_api(connection->state != GALV_CONN_CLOSING_STATE);
	galv_assert_api(connection->state != GALV_CONN_CLOSED_STATE);
	galv_assert_api(!(events & ~GALV_CONN_POLL_VALID_EVENTS));
	galv_assert_api(events & (EPOLLIN | EPOLLRDHUP));
	galv_assert_api(poller);

	galv_conn_unwatch(connection, EPOLLIN | EPOLLPRI | EPOLLRDHUP);
	connection->state = GALV_CONN_RECVSHUT_STATE;

	return connection->ops->on_recv_closed(connection, events, poller);
}

static inline
int
galv_conn_on_error(struct galv_conn * __restrict   connection,
                   uint32_t                        events,
                   const struct upoll * __restrict poller)
{
	galv_conn_assert_api(connection);
	galv_assert_api(connection->state != GALV_CONN_CLOSED_STATE);
	galv_assert_api(!(events & ~GALV_CONN_POLL_VALID_EVENTS));
	galv_assert_api(events & EPOLLERR);
	galv_assert_api(poller);

	return connection->ops->on_error(connection, events, poller);
}

/**
 * @return A non zero number of bytes sent upon success, a negative `errno`
 *         like code otherwise.
 * @retval -EAGAIN     Underlying socket buffer full, try again later
 * @retval -EMSGSIZE   Message could not be sent atomically (MTU ?)
 * @retval -EPIPE      Remote peer consumed all of its data and closed
 * @retval -ECONNRESET Remote peer (unexpectedly) closed while there were still
 *                     unhandled data in its socket buffer
 * @retval -ENOBUFS    Underlying network interface output queue full, i.e,
 *                     transient congestion or interface stopped
 *                     (administratively ?)
 * @retval -EINTR      Interrupted by a signal before any data was transmitted
 * @retval -ENOMEM     No more memory available
 */
static inline
ssize_t
galv_conn_send(struct galv_conn * __restrict connection,
               const void * __restrict       buff,
               size_t                        size,
               int                           flags)
{
#define GALV_CONN_SEND_FLAGS \
	(MSG_DONTWAIT | MSG_EOR |MSG_MORE | MSG_NOSIGNAL | MSG_OOB)
	galv_conn_assert_api(connection);
	galv_assert_api(connection->fd >= 0);
	galv_assert_api(connection->state != GALV_CONN_CLOSED_STATE);
	galv_assert_api(connection->state != GALV_CONN_CONNECTING_STATE);
	galv_assert_api(connection->state != GALV_CONN_CLOSING_STATE);
	galv_assert_api(buff); /* prohibit empty packets ! */
	galv_assert_api(size); /* prohibit empty packets ! */
	galv_assert_api(size <= SSIZE_MAX);
	galv_assert_api(!(flags & ~GALV_CONN_SEND_FLAGS));

	ssize_t ret;

	ret = etux_sock_send(connection->fd, buff, size, MSG_NOSIGNAL | flags);
	if (ret >= 0) {
		/* Empty packets prohibited. */
		galv_assert_api(ret);
		return ret;
	}

	/* Disable TCP fast open support for now. */
	galv_assert_api(ret != -EALREADY);

	return ret;
}

/**
 * @return A non zero number of bytes received upon success, a negative `errno`
 *         like code otherwise.
 * @retval -EAGAIN       Underlying socket incoming buffer empty, try again
 *                       later
 * @retval -ECONNREFUSED Remote peer closed its connection
 * @retval -EINTR        Interrupted by a signal before any data was received
 * @retval -ENOMEM       No more memory available
 */
static inline
ssize_t
galv_conn_recv(struct galv_conn * __restrict connection,
               void * __restrict             buff,
               size_t                        size,
               int                           flags)
{
#define GALV_CONN_RECV_VALID_FLAGS \
	(MSG_DONTWAIT | MSG_ERRQUEUE | MSG_OOB | MSG_PEEK | MSG_TRUNC)
	galv_conn_assert_api(connection);
	galv_assert_api(connection->fd >= 0);
	galv_assert_api(connection->state != GALV_CONN_CLOSED_STATE);
	galv_assert_api(connection->state != GALV_CONN_CONNECTING_STATE);
	galv_assert_api(connection->state != GALV_CONN_CLOSING_STATE);
	galv_assert_api(buff);
	galv_assert_api(size);
	galv_assert_api(size <= SSIZE_MAX);
	galv_assert_api(!(flags & ~GALV_CONN_RECV_VALID_FLAGS));

	ssize_t ret;

	ret = etux_sock_recv(connection->fd, buff, size, flags);
	if (ret)
		return ret;

	/*
	 * Either:
	 * - empty (seqpacket) payload,
	 * - or remote peer closed its sending end, meaning that our
	 *   local incoming stream is over.
	 * As we cannot reliably distinguish between these 2 cases, just
	 * probihit empty payloads and always consider this situation as
	 * a remote peer socket closure.
	 */
	return -ECONNREFUSED;
}

/**
 * @return A non zero number of bytes received upon success, a negative `errno`
 *         like code otherwise.
 * @retval -EAGAIN       Underlying socket incoming buffer empty, try again
 *                       later
 * @retval -ECONNREFUSED Remote peer closed its connection
 * @retval -EINTR        Interrupted by a signal before any data was received
 * @retval -ENOMEM       No more memory available
 */
static inline
ssize_t
galv_conn_recvmsg(struct galv_conn * __restrict connection,
                  struct msghdr * __restrict    msg,
                  int                           flags)
{
#define GALV_CONN_RECVMSG_VALID_FLAGS \
	(MSG_CMSG_CLOEXEC | GALV_CONN_RECV_VALID_FLAGS)
	galv_conn_assert_api(connection);
	galv_assert_api(connection->fd >= 0);
	galv_assert_api(connection->state != GALV_CONN_CLOSED_STATE);
	galv_assert_api(connection->state != GALV_CONN_CONNECTING_STATE);
	galv_assert_api(connection->state != GALV_CONN_CLOSING_STATE);
	galv_assert_api(msg);
	galv_assert_api(!msg->msg_name);
	galv_assert_api(msg->msg_iov || msg->msg_control);
	galv_assert_api(!msg->msg_iov || msg->msg_iovlen);
	galv_assert_api(!msg->msg_control || msg->msg_controllen);
	galv_assert_api(!(flags & ~ETUX_SOCK_RECVMSG_VALID_FLAGS));

	ssize_t ret;

	ret = etux_sock_recvmsg(connection->fd, msg, flags);
	if (ret)
		return ret;

	return -ECONNREFUSED;
}

/**
 * @return A non zero number of bytes sent upon success, a negative `errno`
 *         like code otherwise.
 * @retval -ENOMEM No more memory available
 * @retval -ENOSPC Maximum system number of per-user (UID) pollable file
 *         descriptors reached (see @man{epoll_ctl(2)} and @man{epoll(7)})
 */
extern int
galv_conn_poll(struct galv_conn * __restrict   connection,
               const struct upoll * __restrict poller,
               uint32_t                        events,
               void * __restrict               context)
	__export_public;

static inline
void
galv_conn_unpoll(const struct galv_conn * __restrict connection,
                 const struct upoll * __restrict     poller)
{
	galv_conn_assert_api(connection);
	galv_assert_api(connection->fd >= 0);
	galv_assert_api(connection->state != GALV_CONN_CLOSED_STATE);
	galv_assert_api(poller);

	upoll_unregister(poller, connection->fd);
}

static inline
void
galv_conn_launch_close(struct galv_conn * __restrict connection)
{
	galv_conn_assert_api(connection);
	galv_assert_api(connection->fd >= 0);
	galv_assert_api(connection->state != GALV_CONN_CLOSING_STATE);
	galv_assert_api(connection->state != GALV_CONN_CLOSED_STATE);

	connection->state = GALV_CONN_CLOSING_STATE;
}

/**
 * Close an asynchronous socket.
 *
 * @return 0 if succesful, a negative `errno` like code otherwise.
 * @retval -EINTR A signal raised during closure
 * @retval -EIO   An I/O error occured
 *
 * On Linux, in case of error, *DO NOT* ever retry to close the same file
 * descriptor again. This is useless and the error code is returned for
 * informational purpose only.
 *
 * See section *Dealing with error returns from close()* of @man{close(2)} for
 * further details.
 */
static inline
int
galv_conn_complete_close(struct galv_conn * __restrict connection)
{
	galv_conn_assert_api(connection);
	galv_assert_api(connection->fd >= 0);
	galv_assert_api(connection->state != GALV_CONN_CLOSED_STATE);

	int ret;

	ret = etux_sock_close(connection->fd);

	connection->state = GALV_CONN_CLOSED_STATE;

	return ret;
}

/******************************************************************************
 * Generic connection repository
 ******************************************************************************/

#include <galv/repo.h>

static inline
void
galv_conn_repo_register(struct galv_repo * __restrict repository,
                        struct galv_conn * __restrict connection)
{
	galv_repo_assert_api(repository);
	galv_conn_assert_api(connection);

	galv_repo_register(repository, &connection->repo);
}

static inline
struct galv_conn *
galv_conn_repo_pop(struct galv_repo * __restrict repository)
{
	galv_assert_api(repository);

	return stroll_dlist_entry(galv_repo_pop(repository),
	                          struct galv_conn,
	                          repo);
}

static inline
void
galv_conn_repo_unregister(struct galv_repo * __restrict repository,
                          struct galv_conn * __restrict connection)
{
	galv_repo_assert_api(repository);
	galv_conn_assert_api(connection);

	galv_repo_unregister(repository, &connection->repo);
}

#endif /* _GALV_CONN_H */
