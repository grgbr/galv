/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _GALV_LIB_SERVICE_H
#define _GALV_LIB_SERVICE_H

#include "common.h"
#include "galv/service.h"

#define galv_service_assert_intern(_service) \
	galv_assert_intern(_service); \
	galv_service_assert_ops_intern((_service)->ops); \
	galv_service_assert_ctx_intern((_service)->ctx)

static inline
int
galv_service_on_accept_conn(struct galv_service * __restrict service,
                            uint32_t                         events,
                            const struct upoll * __restrict  poller)
{
	galv_service_assert_intern(service);
	galv_assert_intern(!(events & ~((uint32_t)(EPOLLIN | EPOLLERR))));
	galv_assert_intern(poller);

	return service->ops->on_accept_conn(service, events, poller);
}

static inline
int
galv_service_on_close_conn(struct galv_service * __restrict service,
                           struct galv_conn * __restrict    conn,
                           const struct upoll * __restrict  poller)
{
	galv_service_assert_intern(service);
	galv_conn_assert_intern(conn);
	galv_assert_intern(poller);

	return service->ops->on_close_conn(service, conn, poller);
}

#endif /* _GALV_LIB_SERVICE_H */
