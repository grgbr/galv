/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _GALV_LIB_DISPATCH_H
#define _GALV_LIB_DISPATCH_H

#include "galv/priv/dispatch.h"
#include "conn.h"

#define galv_dispatch_assert_api(_dispatch) \
	galv_assert_api(_dispatch); \
	galv_assert_api((_dispatch)->on_conn_term)

#define galv_dispatch_assert_intern(_dispatch) \
	galv_assert_intern(_dispatch); \
	galv_assert_intern((_dispatch)->on_conn_term)

static inline
int
galv_dispatch_on_conn_term(struct galv_dispatch * __restrict dispatch,
                           struct galv_conn * __restrict     connection,
                           const struct upoll * __restrict   poller)
{
	galv_dispatch_assert_intern(dispatch);
	galv_conn_assert_intern(connection);
	galv_assert_intern(connection->fd >= 0);
	galv_assert_intern(poller);

	return dispatch->on_conn_term(dispatch, connection, poller);
}

#endif /* _GALV_LIB_DISPATCH_H */
