/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "adopt.h"

struct galv_conn *
galv_adopt_create_conn(const struct galv_adopt * __restrict    adopter,
                       const struct galv_conn_ops * __restrict operations,
                       int                                     flags,
                       struct galv_accept * __restrict         acceptor)
{
	galv_adopt_assert_api(adopter);
	galv_assert_api(operations);
	galv_assert_api(!(flags & ~(SOCK_NONBLOCK | SOCK_CLOEXEC)));
	galv_assert_api(acceptor);

	struct galv_conn * conn;
	int                err;

	conn = adopter->ops->create_conn(adopter,
	                                 operations,
	                                 flags,
	                                 acceptor);
	if (!conn)
		return NULL;

	err = galv_gate_track(adopter->gate, conn);
	if (err)
		goto err;

	return conn;

err:
	adopter->ops->destroy_conn(adopter, conn);
	errno = -err;

	return NULL;
}

int
galv_adopt_destroy_conn(const struct galv_adopt * __restrict adopter,
                        struct galv_conn * __restrict        connection)
{
	galv_adopt_assert_api(adopter);
	galv_assert_api(connection);

	galv_gate_untrack(adopter->gate, connection);

	return adopter->ops->destroy_conn(adopter, connection);
}
