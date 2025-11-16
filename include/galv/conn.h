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

typedef int galv_conn_handle_events_fn(struct galv_conn * __restrict,
                                       uint32_t,
                                       const struct upoll * __restrict);

typedef int galv_conn_halt_fn(struct galv_conn * __restrict,
                              const struct upoll * __restrict);

typedef void galv_conn_close_fn(struct galv_conn * __restrict,
                                const struct upoll * __restrict);

/*
 * TODO: document state chart.
 *
 * on_error(): 
 * - called upon socket error state when returning from upoll() ;
 * - SO_ERROR socket options might be useful here (see socket(7)).
 */
struct galv_conn_ops {
	galv_conn_handle_events_fn * on_may_xfer;
	galv_conn_handle_events_fn * on_connect;
	galv_conn_handle_events_fn * on_send_shut;
	galv_conn_handle_events_fn * on_recv_shut;
	galv_conn_halt_fn *          halt;
	galv_conn_close_fn *         close;
	galv_conn_handle_events_fn * on_error;
};

#define galv_conn_assert_ops_api(_ops) \
	galv_assert_api(_ops); \
	galv_assert_api((_ops)->on_may_xfer); \
	galv_assert_api((_ops)->on_connect); \
	galv_assert_api((_ops)->on_send_shut); \
	galv_assert_api((_ops)->on_recv_shut); \
	galv_assert_api((_ops)->halt); \
	galv_assert_api((_ops)->close); \
	galv_assert_api((_ops)->on_error)

enum galv_conn_state {
	GALV_CONN_CLOSED_STATE      = 0,
	GALV_CONN_CONNECTING_STATE,
	GALV_CONN_ESTABLISHED_STATE,
	GALV_CONN_CLOSING_STATE,
	GALV_CONN_STATE_NR
};

enum galv_conn_link {
	GALV_CONN_FLOWING_LINK  = 0,
	GALV_CONN_RECVSHUT_LINK = (1U << 0),
	GALV_CONN_SENDSHUT_LINK = (1U << 1),
	GALV_CONN_ENDED_LINK    = GALV_CONN_RECVSHUT_LINK |
	                          GALV_CONN_SENDSHUT_LINK
};

struct galv_conn {
	const struct galv_conn_ops * ops;
	enum galv_conn_state         state;
	int                          fd;
	struct upoll_worker          work;
	enum galv_conn_link          link;
	struct galv_accept *         accept;
	void *                       ctx;
	struct stroll_dlist_node     repo;
};

#define galv_conn_assert_api(_conn) \
	galv_assert_api(_conn); \
	galv_conn_assert_ops_api((_conn)->ops); \
	galv_assert_api((_conn)->state >= 0); \
	galv_assert_api((_conn)->state < GALV_CONN_STATE_NR); \
	galv_assert_api((_conn)->link >= 0); \
	galv_assert_api((_conn)->link <= GALV_CONN_ENDED_LINK); \
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
void
galv_conn_apply_watch(struct galv_conn * __restrict connection,
                      const struct upoll * __restrict poller)
{
	galv_conn_assert_api(connection);
	galv_assert_api(connection->fd >= 0);
	galv_assert_api(connection->state != GALV_CONN_CLOSED_STATE);

	upoll_apply(poller, connection->fd, &connection->work);
}

extern int
galv_conn_on_send_shut(struct galv_conn * __restrict   connection,
                       uint32_t                        events,
                       const struct upoll * __restrict poller)
	__export_public;

extern int
galv_conn_on_recv_shut(struct galv_conn * __restrict   connection,
                       uint32_t                        events,
                       const struct upoll * __restrict poller)
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
	galv_assert_api(!(connection->link & GALV_CONN_SENDSHUT_LINK));
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
	galv_assert_api(!(connection->link & GALV_CONN_RECVSHUT_LINK));
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
	galv_assert_api(!(connection->link & GALV_CONN_RECVSHUT_LINK));
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
int
galv_conn_halt(struct galv_conn * __restrict   connection,
               const struct upoll * __restrict poller)
{
	galv_conn_assert_api(connection);
	galv_assert_api(connection->state != GALV_CONN_CLOSING_STATE);
	galv_assert_api(connection->state != GALV_CONN_CLOSED_STATE);

	connection->state = GALV_CONN_CLOSING_STATE;

	return connection->ops->halt(connection, poller);
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
extern int
galv_conn_close(struct galv_conn * __restrict   connection,
                const struct upoll * __restrict poller)
	__export_public;

/******************************************************************************
 * Generic connection repository
 ******************************************************************************/

#include <galv/repo.h>

#define galv_conn_repo_foreach(_repo, _conn) \
	galv_repo_foreach_entry(_repo, _conn, repo)

#define galv_conn_repo_foreach_safe(_repo, _conn, _tmp) \
	galv_repo_foreach_entry_safe(_repo, _conn, repo, _tmp)

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

extern void
galv_conn_repo_halt(struct galv_repo * __restrict   repository,
                    const struct upoll * __restrict poller)
	__export_public;

extern void
galv_conn_repo_close(struct galv_repo * __restrict   repository,
                     const struct upoll * __restrict poller)
	__export_public;

#endif /* _GALV_CONN_H */
