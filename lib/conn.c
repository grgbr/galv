#include "conn.h"
#include "accept.h"
#include <stroll/page.h>
#include <stroll/falloc.h>

/******************************************************************************
 * Generic connection handling
 ******************************************************************************/

int
galv_conn_async_error(const struct galv_conn * __restrict connection)
{
	galv_conn_assert_api(connection);

	int       stat;
	socklen_t sz = sizeof(stat);

	etux_sock_getopt(connection->fd, SOL_SOCKET, SO_ERROR, &stat, &sz);
	galv_assert_intern(sz == sizeof(stat));

	return stat;
}

int
galv_conn_on_send_shut(struct galv_conn * __restrict   connection,
                       uint32_t                        events,
                       const struct upoll * __restrict poller)
{
	galv_conn_assert_api(connection);
	galv_assert_api(connection->fd >= 0);
	galv_assert_api(connection->state >= GALV_CONN_CONNECTING_STATE);
	galv_assert_api(!(connection->link & GALV_CONN_SENDSHUT_LINK));
	galv_assert_api(!(events & ~GALV_CONN_POLL_VALID_EVENTS));
	galv_assert_api(events & (EPOLLIN | EPOLLPRI | EPOLLHUP));
	galv_assert_api(poller);

	if (connection->link & GALV_CONN_RECVSHUT_LINK)
		return galv_conn_close(connection, poller);

	galv_conn_unwatch(connection, EPOLLOUT);
	connection->link |= GALV_CONN_SENDSHUT_LINK;

	return connection->ops->on_send_shut(connection, events, poller);
}

int
galv_conn_on_recv_shut(struct galv_conn * __restrict   connection,
                       uint32_t                        events,
                       const struct upoll * __restrict poller)
{
	galv_conn_assert_api(connection);
	galv_assert_api(connection->fd >= 0);
	galv_assert_api(connection->state >= GALV_CONN_CONNECTING_STATE);
	galv_assert_api(!(connection->link & GALV_CONN_RECVSHUT_LINK));
	galv_assert_api(!(events & ~GALV_CONN_POLL_VALID_EVENTS));
	galv_assert_api(events & (EPOLLIN | EPOLLRDHUP));
	galv_assert_api(poller);

	if (connection->link & GALV_CONN_SENDSHUT_LINK)
		return galv_conn_close(connection, poller);

	galv_conn_unwatch(connection, EPOLLIN | EPOLLPRI | EPOLLRDHUP);
	connection->link |= GALV_CONN_RECVSHUT_LINK;

	return connection->ops->on_recv_shut(connection, events, poller);
}

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

int
galv_conn_connect(struct galv_conn * __restrict   connection,
                  struct sockaddr * __restrict    peer,
                  int                             retries,
                  int                             msecs,
                  const struct upoll * __restrict poller)
{
	galv_conn_assert_api(connection);
	galv_assert_api(connection->fd >= 0);
	galv_assert_api(connection->state == GALV_CONN_CLOSED_STATE);
	galv_assert_api(peer);
	galv_assert_api(retries);
	galv_assert_api(!retries || (msecs > 0));
	galv_assert_api(poller);

	return galv_coupler_connect((struct galv_coupler *)connection->dispatch,
	                            connection,
	                            peer,
	                            poller,
	                            retries,
	                            msecs);
}

void
galv_conn_setup(struct galv_conn * __restrict           connection,
                int                                     fd,
                const struct galv_conn_ops * __restrict operations,
                struct galv_dispatch * __restrict       dispatcher)
{
	galv_assert_intern(connection);
	galv_assert_intern(fd >= 0);
	galv_conn_assert_ops_intern(operations);
	galv_dispatch_assert_intern(dispatcher);

	connection->ops = operations;
	connection->state = GALV_CONN_CLOSED_STATE;
	connection->fd = fd;
	connection->work.dispatch = NULL;
	connection->link = GALV_CONN_FLOWING_LINK;
	connection->dispatch = dispatcher;
	connection->ctx = NULL;
}

static
int
galv_conn_do_close(struct galv_conn * __restrict   connection,
                   const struct upoll * __restrict poller)
{
	galv_conn_assert_api(connection);
	galv_assert_api(connection->fd >= 0);
	galv_assert_api(poller);

#warning try to substitute with coupler/acceptor on_term callback
	galv_conn_unpoll(connection, poller);

	return galv_dispatch_on_conn_term(connection->dispatch,
	                                  connection,
	                                  poller);
}

int
galv_conn_halt(struct galv_conn * __restrict   connection,
               const struct upoll * __restrict poller)
{
	galv_conn_assert_api(connection);
	galv_assert_api(connection->state >= GALV_CONN_BINDING_STATE);
	galv_assert_api(connection->state != GALV_CONN_CLOSING_STATE);

	if (connection->state >= GALV_CONN_CONNECTING_STATE) {
		connection->state = GALV_CONN_CLOSING_STATE;
		return connection->ops->halt(connection, poller);
	}

	return galv_conn_do_close(connection, poller);
}

int
galv_conn_close(struct galv_conn * __restrict   connection,
                const struct upoll * __restrict poller)
{
	galv_conn_assert_api(connection);
	galv_assert_api(connection->fd >= 0);
	galv_assert_api(poller);

	if (connection->state >= GALV_CONN_CONNECTING_STATE)
		connection->ops->close(connection, poller);

	return galv_conn_do_close(connection, poller);
}

void
galv_conn_repo_halt(struct galv_repo * __restrict   repository,
                    const struct upoll * __restrict poller)
{
	galv_repo_assert_api(repository);
	galv_assert_api(poller);

	struct galv_conn * conn;
	struct galv_conn * tmp;

	galv_conn_repo_foreach_safe(repository, conn, tmp)
		galv_conn_halt(conn, poller);
}

void
galv_conn_repo_close(struct galv_repo * __restrict   repository,
                     const struct upoll * __restrict poller)
{
	galv_repo_assert_api(repository);
	galv_assert_api(poller);

	struct galv_conn * conn;
	struct galv_conn * tmp;

	galv_conn_repo_foreach_safe(repository, conn, tmp)
		galv_conn_close(conn, poller);
}
