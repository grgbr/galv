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
struct galv_acceptor;

typedef int galv_conn_handle_fn(struct galv_conn * __restrict,
		                uint32_t,
		                const struct upoll * __restrict);

/*
 * TODO: document state chart.
 *
 * on_error(): 
 * - called upon socket error state when returning from upoll() ;
 * - SO_ERROR socket options might be useful here (see socket(7).
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
	struct galv_acceptor *       accept;
	struct stroll_dlist_node     repo;
};

#define galv_conn_assert_iface_api(_conn) \
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
struct galv_acceptor *
galv_conn_acceptor(const struct galv_conn * __restrict conn)
{
	galv_conn_assert_iface_api(conn);
	galv_assert_api(conn->state != GALV_CONN_CLOSED_STATE);

	return conn->accept;
}

static inline
enum galv_conn_state
galv_conn_state(const struct galv_conn * __restrict conn)
{
	galv_conn_assert_iface_api(conn);

	return conn->state;
}

static inline
void
galv_conn_switch_state(struct galv_conn * __restrict conn,
                       enum galv_conn_state          state)
{
	galv_conn_assert_iface_api(conn);
	galv_assert_api(state >= 0);
	galv_assert_api(state < GALV_CONN_STATE_NR);

	conn->state = state;
}

static inline
void
galv_conn_watch(struct galv_conn * __restrict conn,
                uint32_t                      events)
{
	galv_conn_assert_iface_api(conn);
	galv_assert_api(conn->fd >= 0);
	galv_assert_api(conn->state != GALV_CONN_CLOSED_STATE);
	galv_assert_api(conn->state != GALV_CONN_CLOSING_STATE);

	upoll_enable_watch(&conn->work, events);
}

static inline
void
galv_conn_unwatch(struct galv_conn * __restrict conn,
                  uint32_t                      events)
{
	galv_conn_assert_iface_api(conn);
	galv_assert_api(conn->fd >= 0);
	galv_assert_api(conn->state != GALV_CONN_CLOSED_STATE);
	galv_assert_api(conn->state != GALV_CONN_CLOSING_STATE);

	upoll_disable_watch(&conn->work, events);
}

static inline
int
galv_conn_on_may_xfer(struct galv_conn * __restrict   conn,
		      uint32_t                        events,
		      const struct upoll * __restrict poller)
{
	galv_conn_assert_iface_api(conn);
	galv_assert_api(conn->state != GALV_CONN_CLOSING_STATE);
	galv_assert_api(conn->state != GALV_CONN_CLOSED_STATE);
	galv_assert_api(!(events & ~((uint32_t)(EPOLLIN | EPOLLPRI |
	                                        EPOLLOUT | EPOLLHUP))));
	galv_assert_api(events);
	galv_assert_api(poller);

	return conn->ops->on_may_xfer(conn, events, poller);
}

static inline
int
galv_conn_on_connecting(struct galv_conn * __restrict   conn,
		        uint32_t                        events,
		        const struct upoll * __restrict poller)
{
	galv_conn_assert_iface_api(conn);
	galv_assert_api(conn->state == GALV_CONN_CLOSED_STATE);
	galv_assert_api(!(events & ~((uint32_t)(EPOLLIN | EPOLLPRI |
	                                        EPOLLOUT))));
	galv_assert_api(poller);

	conn->state = GALV_CONN_CONNECTING_STATE;

	return conn->ops->on_connecting(conn, events, poller);
}

static inline
int
galv_conn_on_send_closed(struct galv_conn * __restrict   conn,
		         uint32_t                        events,
		         const struct upoll * __restrict poller)
{
	galv_conn_assert_iface_api(conn);
	galv_assert_api(conn->state != GALV_CONN_CLOSING_STATE);
	galv_assert_api(conn->state != GALV_CONN_CLOSED_STATE);
	galv_assert_api(!(events & ~GALV_CONN_POLL_VALID_EVENTS));
	galv_assert_api(events & EPOLLHUP);
	galv_assert_api(poller);

	galv_conn_unwatch(conn, EPOLLOUT);
	conn->state = GALV_CONN_SENDSHUT_STATE;

	return conn->ops->on_send_closed(conn, events, poller);
}

static inline
int
galv_conn_on_recv_closed(struct galv_conn * __restrict   conn,
		         uint32_t                        events,
		         const struct upoll * __restrict poller)
{
	galv_conn_assert_iface_api(conn);
	galv_assert_api(conn->state != GALV_CONN_CLOSING_STATE);
	galv_assert_api(conn->state != GALV_CONN_CLOSED_STATE);
	galv_assert_api(!(events & ~GALV_CONN_POLL_VALID_EVENTS));
	galv_assert_api(events & (EPOLLIN | EPOLLRDHUP));
	galv_assert_api(poller);

	galv_conn_unwatch(conn, EPOLLIN | EPOLLPRI | EPOLLRDHUP);
	conn->state = GALV_CONN_RECVSHUT_STATE;

	return conn->ops->on_recv_closed(conn, events, poller);
}

static inline
int
galv_conn_on_error(struct galv_conn * __restrict   conn,
		   uint32_t                        events,
		   const struct upoll * __restrict poller)
{
	galv_conn_assert_iface_api(conn);
	galv_assert_api(conn->state != GALV_CONN_CLOSED_STATE);
	galv_assert_api(!(events & ~GALV_CONN_POLL_VALID_EVENTS));
	galv_assert_api(events & EPOLLERR);
	galv_assert_api(poller);

	return conn->ops->on_error(conn, events, poller);
}

extern int
galv_conn_dispatch(struct upoll_worker * worker,
                   uint32_t              events,
                   const struct upoll *  poller)
	__export_public;

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
galv_conn_send(struct galv_conn * __restrict conn,
               const void * __restrict       buff,
               size_t                        size,
               int                           flags)
{
	galv_conn_assert_iface_api(conn);
	galv_assert_api(conn->fd >= 0);
	galv_assert_api(conn->state != GALV_CONN_CLOSED_STATE);
	galv_assert_api(conn->state != GALV_CONN_CONNECTING_STATE);
	galv_assert_api(conn->state != GALV_CONN_CLOSING_STATE);
	galv_assert_api(buff); /* prohibit empty packets ! */
	galv_assert_api(size); /* prohibit empty packets ! */
	galv_assert_api(size <= SSIZE_MAX);
	galv_assert_api(!(flags & ~(MSG_MORE | MSG_NOSIGNAL | MSG_OOB)));

	ssize_t ret;

	ret = etux_sock_send(conn->fd, buff, size, MSG_NOSIGNAL | flags);
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
galv_conn_recv(struct galv_conn * __restrict conn,
               void * __restrict             buff,
               size_t                        size,
               int                           flags)
{
	galv_conn_assert_iface_api(conn);
	galv_assert_api(conn->fd >= 0);
	galv_assert_api(conn->state != GALV_CONN_CLOSED_STATE);
	galv_assert_api(conn->state != GALV_CONN_CONNECTING_STATE);
	galv_assert_api(conn->state != GALV_CONN_CLOSING_STATE);
	galv_assert_api(buff);
	galv_assert_api(size);
	galv_assert_api(size <= SSIZE_MAX);

	ssize_t ret;

	ret = etux_sock_recv(conn->fd, buff, size, flags);
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
 * @return A non zero number of bytes sent upon success, a negative `errno`
 *         like code otherwise.
 * @retval -ENOMEM No more memory available
 * @retval -ENOSPC Maximum system number of per-user (UID) pollable file
 *         descriptors reached (see @man{epoll_ctl(2)} and @man{epoll(7)})
 */
static inline
int
galv_conn_poll(struct galv_conn * __restrict   conn,
               upoll_dispatch_fn *             dispatch,
               const struct upoll * __restrict poller,
               uint32_t                        events)
{
	galv_conn_assert_iface_api(conn);
	galv_assert_api(conn->fd >= 0);
	galv_assert_api(conn->state != GALV_CONN_CLOSED_STATE);
	galv_assert_api(dispatch);
	galv_assert_api(poller);
	galv_assert_api(events);
	galv_assert_api(!(events & ~GALV_CONN_POLL_VALID_EVENTS));

	conn->work.dispatch = dispatch;
	return upoll_register(poller, conn->fd, events, &conn->work);
}

static inline
void
galv_conn_unpoll(const struct galv_conn * __restrict conn,
                 const struct upoll * __restrict     poller)
{
	galv_conn_assert_iface_api(conn);
	galv_assert_api(conn->fd >= 0);
	galv_assert_api(conn->state != GALV_CONN_CLOSED_STATE);
	galv_assert_api(poller);

	upoll_unregister(poller, conn->fd);
}

static inline
void
galv_conn_launch_close(struct galv_conn * __restrict conn)
{
	galv_conn_assert_iface_api(conn);
	galv_assert_api(conn->fd >= 0);
	galv_assert_api(conn->state != GALV_CONN_CLOSING_STATE);
	galv_assert_api(conn->state != GALV_CONN_CLOSED_STATE);

	conn->state = GALV_CONN_CLOSING_STATE;
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
galv_conn_complete_close(struct galv_conn * __restrict conn)
{
	galv_conn_assert_iface_api(conn);
	galv_assert_api(conn->fd >= 0);
	galv_assert_api(conn->state != GALV_CONN_CLOSED_STATE);

	int ret;

	ret = etux_sock_close(conn->fd);

	conn->state = GALV_CONN_CLOSED_STATE;

	return ret;
}

#endif /* _GALV_CONN_H */
