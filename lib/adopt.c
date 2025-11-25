/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "adopt.h"
#include <stroll/page.h>

struct galv_conn *
galv_adopt_create_conn(const struct galv_adopt * __restrict    adopter,
                       const struct galv_conn_ops * __restrict operations,
                       int                                     flags,
                       struct galv_accept * __restrict         acceptor)
{
	galv_adopt_assert_api(adopter);
	galv_assert_api(operations);
	galv_assert_api(!(flags & ETUX_SOCK_ACCEPT_INVALID_FLAGS));
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

void
galv_adopt_setup(struct galv_adopt * __restrict           adopter,
                 const struct galv_adopt_ops * __restrict operations,
                 int                                      fd,
                 unsigned int                             max_conn,
                 size_t                                   conn_size,
                 struct galv_gate * __restrict            gate)
{
	galv_assert_intern(adopter);
	galv_adopt_assert_ops_intern(operations);
	galv_assert_intern(fd >= 0);
	galv_assert_intern(max_conn);
	galv_assert_intern(conn_size >= sizeof(struct galv_conn));
	galv_assert_intern(conn_size < (stroll_page_size() / 8));
	galv_gate_assert_intern(gate);

	adopter->ops = operations;
	adopter->fd = fd;
	stroll_falloc_init_block_size(&adopter->alloc,
	                              max_conn,
	                              conn_size,
	                              stroll_page_size());
	adopter->gate = gate;
}

int
galv_adopt_close(struct galv_adopt * __restrict adopter)
{
	galv_adopt_assert_api(adopter);

	int ret;

	ret = etux_sock_close(adopter->fd);

	stroll_falloc_fini(&adopter->alloc);

	return ret;
}
