/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _GALV_ACCEPT_H
#define _GALV_ACCEPT_H

#include <galv/cdefs.h>
#include <utils/poll.h>

struct galv_accept_ops;
struct galv_conn_repo;
struct galv_adopt;
struct galv_conn;

struct galv_accept {
	struct upoll_worker            work;
	const struct galv_accept_ops * ops;
	struct galv_repo *             repo;
	struct galv_adopt *            adopt;
	const struct galv_conn_ops *   conn_ops;
	int                            conn_flags;
};

extern int
galv_accept_open(struct galv_accept * __restrict         acceptor,
                 struct galv_repo * __restrict           repository,
                 struct galv_adopt * __restrict          adopter,
                 unsigned int                            backlog,
                 const struct galv_conn_ops * __restrict operations,
                 int                                     flags,
                 const struct upoll * __restrict         poller)
	__export_public;

extern void
galv_accept_close(const struct galv_accept * __restrict acceptor,
                  const struct upoll * __restrict       poller)
	__export_public;

#endif /* _GALV_ACCEPT_H */
