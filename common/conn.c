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

#if 0
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
#endif

#if defined(CONFIG_GALV_ASSERT_INTERN)

int
galv_conn_invalid_dispatch(struct upoll_worker * worker,
                           uint32_t              events,
                           const struct upoll *  poller)
{
	galv_assert_intern(worker);
	galv_assert_intern(poller);
	galv_assert_intern(events);
	galv_assert_intern(!(events & ~GALV_CONN_POLL_VALID_EVENTS));

	struct galv_conn * conn;

	conn = galv_conn_from_worker(worker);
	galv_conn_assert_intern(conn);
	galv_assert_intern(conn->state != GALV_CONN_OPENED_STATE);
	galv_assert_intern(conn->fd >= 0);
	galv_assert_intern(conn->dispatch);

	stroll_assert_fail("galv",
	                   "BUG: running invalid connection dispatcher",
	                   __FILE__,
	                   __LINE__,
	                   __func__);
}

#else  /* !defined(CONFIG_GALV_ASSERT_INTERN) */

static inline __noreturn
int
galv_conn_invalid_dispatch(struct upoll_worker * worker __unused,
                           uint32_t              events __unused,
                           const struct upoll *  poller __unused)
{
	abort();
}

#endif /* defined(CONFIG_GALV_ASSERT_INTERN) */

int
galv_conn_poll(struct galv_conn * __restrict   connection,
               const struct upoll * __restrict poller,
               uint32_t                        events,
               upoll_dispatch_fn *             dispatch)
{
	galv_conn_assert_intern(connection);
	galv_assert_intern(connection->fd >= 0);
	galv_assert_intern(!(events & ~GALV_CONN_POLL_VALID_EVENTS));
	galv_assert_intern(dispatch);

	int ret;

	ret = upoll_register_dispatch(poller,
	                              connection->fd,
	                              events,
	                              &connection->work,
	                              dispatch);
	if (!ret) {
		connection->poll = poller;
		return 0;
	}

	galv_assert_intern(!ret || (ret == -ENOMEM) || (ret == -ENOSPC));

	return ret;
}

void
galv_conn_unpoll(struct galv_conn * __restrict connection)
{
	galv_conn_assert_intern(connection);
	galv_assert_intern(connection->fd >= 0);

	if (connection->state >= GALV_CONN_BINDING_STATE) {
		galv_assert_intern(connection->poll);
		upoll_unregister(connection->poll, connection->fd);
	}
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
	connection->state = GALV_CONN_OPENED_STATE;
	connection->fd = fd;
	connection->poll = NULL;
	connection->link = GALV_CONN_FLOWING_LINK;
	connection->dispatch = dispatcher;
}

int
galv_conn_halt(struct galv_conn * __restrict   connection,
               const struct upoll * __restrict poller)
{
	galv_conn_assert_api(connection);
	galv_assert_api(connection->fd >= 0);
	galv_assert_api(connection->state != GALV_CONN_OPENED_STATE);
	galv_assert_api(connection->state != GALV_CONN_CLOSING_STATE);

	if (connection->state >= GALV_CONN_CONNECTING_STATE) {
#if 0
		connection->state = GALV_CONN_CLOSING_STATE;
#endif
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
