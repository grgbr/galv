#include "conn.h"
#include "accept.h"
#include <stroll/page.h>
#include <stroll/falloc.h>

/******************************************************************************
 * Generic connection handling
 ******************************************************************************/

static
int
galv_conn_process_steady(struct galv_conn * __restrict connection,
                         uint32_t                      events,
                         const struct upoll *          poller)
{
	galv_assert_intern(connection);
	galv_assert_intern(events);
	galv_assert_intern(poller);

	int ret = 0;

	if (events & EPOLLHUP)
		ret = galv_conn_on_send_closed(connection, events, poller);
	else if (events & EPOLLRDHUP)
		ret = galv_conn_on_recv_closed(connection, events, poller);
	else
		ret = galv_conn_on_may_xfer(connection, events, poller);

	return ret;
}

static
int
galv_conn_process_sendshut(struct galv_conn * __restrict connection,
                           uint32_t                      events,
                           const struct upoll *          poller)
{
	galv_assert_intern(connection);
	galv_assert_intern(!(events & EPOLLOUT));
	galv_assert_intern(events);
	galv_assert_intern(poller);

	int ret = 0;

	if (events & EPOLLRDHUP)
		galv_conn_launch_close(connection);
	else
		ret = galv_conn_on_may_xfer(connection, events, poller);

	return ret;
}

static
int
galv_conn_process_recvshut(struct galv_conn * __restrict connection,
                           uint32_t                      events,
                           const struct upoll *          poller)
{
	galv_assert_intern(connection);
	galv_assert_intern(!(events & (EPOLLIN | EPOLLPRI | EPOLLRDHUP)));
	galv_assert_intern(events);
	galv_assert_intern(poller);

	int ret = 0;

	if (events & EPOLLHUP)
		galv_conn_launch_close(connection);
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
	galv_assert_intern(conn->accept);

	if (events & EPOLLERR) {
		ret = galv_conn_on_error(conn, events, poller);
		if (ret)
			return ret;

		events &= ~((uint32_t)(EPOLLERR));
	}

	switch (galv_conn_state(conn)) {
	case GALV_CONN_ESTABLISHED_STATE:
	case GALV_CONN_CONNECTING_STATE:
		ret = galv_conn_process_steady(conn, events, poller);
		break;

	case GALV_CONN_SENDSHUT_STATE:
		ret = galv_conn_process_sendshut(conn, events, poller);
		break;

	case GALV_CONN_RECVSHUT_STATE:
		ret = galv_conn_process_recvshut(conn, events, poller);
		break;

	case GALV_CONN_CLOSING_STATE:
		return galv_accept_on_conn_term(conn->accept, conn, poller);

	case GALV_CONN_CLOSED_STATE:
	default:
		galv_assert_intern(0);
	}

	if (conn->state != GALV_CONN_CLOSING_STATE) {
		upoll_apply(poller, conn->fd, &conn->work);
		return ret;
	}

	if (ret)
		return ret;

	return galv_accept_on_conn_term(conn->accept, conn, poller);
}

int
galv_conn_poll(struct galv_conn * __restrict   connection,
               const struct upoll * __restrict poller,
               uint32_t                        events,
               void * __restrict               context)
{
	galv_conn_assert_api(connection);
	galv_assert_api(connection->fd >= 0);
	galv_assert_api(connection->state != GALV_CONN_CLOSED_STATE);
	galv_assert_api(poller);
	galv_assert_api(events);
	galv_assert_api(!(events & ~GALV_CONN_POLL_VALID_EVENTS));

	connection->work.dispatch = galv_conn_dispatch;
	connection->ctx = context;

	return upoll_register(poller,
	                      connection->fd,
	                      events,
	                      &connection->work);
}
