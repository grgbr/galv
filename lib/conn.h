#ifndef _GALV_LIB_CONN_H
#define _GALV_LIB_CONN_H

#include "common.h"
#include "galv/conn.h"

#define galv_conn_assert_ops_intern(_ops) \
	galv_assert_intern(_ops); \
	galv_assert_intern((_ops)->on_may_xfer); \
	galv_assert_intern((_ops)->on_connecting); \
	galv_assert_intern((_ops)->on_send_closed); \
	galv_assert_intern((_ops)->on_recv_closed); \
	galv_assert_intern((_ops)->on_error)

#define galv_conn_assert_iface_intern(_conn) \
	galv_assert_intern(_conn); \
	galv_conn_assert_ops_intern((_conn)->ops); \
	galv_assert_intern((_conn)->state >= 0); \
	galv_assert_intern((_conn)->state < GALV_CONN_STATE_NR)

static inline
void
galv_conn_setup(struct galv_conn * __restrict           conn,
                int                                     fd,
                struct galv_service * __restrict        service,
                const struct galv_conn_ops * __restrict ops)
{
	galv_assert_intern(conn);
	galv_assert_intern(service);
	galv_assert_intern(fd >= 0);
	galv_conn_assert_ops_intern(ops);

	conn->ops = ops;
	conn->state = GALV_CONN_CLOSED_STATE;
	conn->fd = fd;
	conn->svc = service;
}

int
galv_conn_destroy(struct galv_conn * __restrict   conn,
                  struct galv_fabric * __restrict fabric)
{
	galv_conn_assert_iface_intern(conn);
	galv_fabric_assert_intern(fabric);

	int ret;

	ret = galv_conn_complete_close(conn);

	galv_fabric_free(fabric, conn);

	return ret;
}

#endif /* _GALV_LIB_CONN_H */
