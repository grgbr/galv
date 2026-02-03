#include "conn.h"
#include "dispatch.h"
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

int
galv_conn_halt(struct galv_conn * __restrict   connection,
               const struct upoll * __restrict poller)
{
	galv_conn_assert_api(connection);
	galv_assert_api(connection->fd >= 0);
	galv_assert_api(connection->state >= GALV_CONN_BINDING_STATE);
	galv_assert_api(connection->state != GALV_CONN_CLOSING_STATE);

	if (connection->state >= GALV_CONN_CONNECTING_STATE) {
		connection->state = GALV_CONN_CLOSING_STATE;
		return connection->ops->halt(connection, poller);
	}

	return galv_dispatch_on_conn_term(connection->dispatch,
	                                  connection,
	                                  poller);
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

	return galv_dispatch_on_conn_term(connection->dispatch,
	                                  connection,
	                                  poller);
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
