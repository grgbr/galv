/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _GALV_LIB_ACCEPTOR_H
#define _GALV_LIB_ACCEPTOR_H

#include "common.h"
#include "galv/acceptor.h"
#include "galv/fabric.h"
#include <utils/sock.h>

typedef struct galv_conn *
        galv_acceptor_create_conn_fn(struct galv_acceptor * __restrict,
                                     int,
                                     struct galv_fabric * __restrict,
                                     const struct galv_conn_ops * __restrict,
                                     struct galv_service * __restrict);

typedef int
        galv_acceptor_destroy_conn_fn(struct galv_acceptor * __restrict,
                                      struct galv_conn * __restrict,
                                      struct galv_fabric * __restrict);

struct galv_acceptor_ops {
	galv_acceptor_create_conn_fn *  create_conn;
	galv_acceptor_destroy_conn_fn * destroy_conn;
}

#define galv_acceptor_assert_ops_api(_ops) \
	galv_assert_api(_ops); \
	galv_assert_api((_ops)->create_conn); \
	galv_assert_api((_ops)->destroy_conn)

#define galv_acceptor_assert_ops_intern(_ops) \
	galv_assert_intern(_ops); \
	galv_assert_intern((_ops)->create_conn); \
	galv_assert_intern((_ops)->destroy_conn)

#define galv_acceptor_assert_intern(_accept) \
	galv_assert_intern(_accept); \
	galv_acceptor_assert_ops_intern((_accept)->ops); \
	galv_assert_intern((_accept)->fd >= 0)

struct galv_acceptor {
	const struct galv_acceptor_ops * ops;
	int                              fd;
};

#define galv_acceptor_assert_api(_accept) \
	galv_assert_api(_accept); \
	galv_acceptor_assert_ops_api((_accept)->ops); \
	galv_assert_api((_accept)->fd >= 0)

static inline
int
galv_acceptor_listen(const struct galv_acceptor * __restrict acceptor,
                     int                                     backlog)
{
	galv_acceptor_assert_api(acceptor);
	galv_assert_api(backlog >= 0);

	return etux_sock_listen(acceptor->fd, backlog);
}

static inline
struct galv_conn *
galv_acceptor_create_conn(struct galv_acceptor * __restrict       acceptor,
                          int                                     flags,
                          struct galv_fabric * __restrict         fabric,
                          const struct galv_conn_ops * __restrict ops,
                          struct galv_service * __restrict        service)
{
	galv_unix_assert_acceptor_api((struct galv_unix_acceptor *)acceptor);
	galv_assert_api(!(flags & ~(SOCK_NONBLOCK | SOCK_CLOEXEC)));
	galv_fabric_assert_api(fabric);
	galv_conn_assert_ops_api(ops);
	galv_service_assert_api(service);

	return acceptor->ops->create_conn(acceptor,
	                                  flags,
	                                  fabric,
	                                  ops,
	                                  service);
}

static inline
int
galv_acceptor_destroy_conn(struct galv_acceptor * __restrict acceptor,
                           struct galv_conn * __restrict     conn,
                           struct galv_fabric * __restrict   fabric)
{
	galv_acceptor_assert_api(acceptor);
	galv_conn_assert_api(conn);
	galv_fabric_assert_api(fabric);

	return acceptor->ops->destroy_conn(acceptor, conn, fabric);
}

static inline
void
galv_acceptor_setup(const struct galv_acceptor * __restrict acceptor,
                    int                                     fd,
                    const struct galv_acceptor_ops *        ops)
{
	galv_assert_api(acceptor);
	galv_assert_api(fd >= 0);
	galv_acceptor_assert_ops_api(ops);

	acceptor->ops = ops;
	acceptor->fd = fd;
}

static inline
int
galv_acceptor_close(const struct galv_acceptor * __restrict acceptor)
{
	galv_acceptor_assert_api(acceptor);

	return etux_sock_close(acceptor->fd);
}

#if 0
#include "common.h"
#include "galv/acceptor.h"

#define galv_acceptor_assert_ops_intern(_ops) \
	galv_assert_intern(_ops); \
	galv_assert_intern((_ops)->on_accept_conn); \
	galv_assert_intern((_ops)->on_close_conn)

#define galv_acceptor_assert_iface_intern(_accept) \
	galv_assert_intern(_accept); \
	galv_assert_intern((_accept)->fd >= 0); \
	galv_acceptor_assert_ops_intern((_accept)->ops); \
	galv_assert_intern((_accept)->work.dispatch)

static inline
int
galv_acceptor_on_accept_conn(struct galv_acceptor * __restrict acceptor,
                             uint32_t                          events,
                             const struct upoll * __restrict   poller)
{
	galv_acceptor_assert_iface_intern(acceptor);

	return acceptor->ops->on_accept_conn(acceptor, events, poller);
}

static inline
int
galv_acceptor_on_close_conn(struct galv_acceptor * __restrict acceptor,
                            struct galv_conn * __restrict     conn,
                            const struct upoll * __restrict   poller)
{
	galv_acceptor_assert_iface_intern(acceptor);

	return acceptor->ops->on_close_conn(acceptor, conn, poller);
}

extern int
galv_acceptor_turn_on(struct galv_acceptor * __restrict           acceptor,
                      int                                         fd,
                      int                                         backlog,
                      const struct upoll * __restrict             poller,
                      upoll_dispatch_fn *                         dispatch,
                      const struct galv_acceptor_ops * __restrict ops,
                      void * __restrict                           context);
#endif

#endif /* _GALV_LIB_ACCEPTOR_H */
