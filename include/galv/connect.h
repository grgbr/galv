/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _GALV_CONNECT_H
#define _GALV_CONNECT_H

#include <galv/cdefs.h>
#include <utils/poll.h>

struct galv_repo;
struct galv_link;
struct galv_conn;

enum galv_connect_state {
	GALV_CONNECT_RUNNING_STATE   = 0,
	GALV_CONNECT_SUSPENDED_STATE,
	GALV_CONNECT_STATE_NR
};

struct galv_connect {
	struct upoll_worker          work;
	struct galv_repo *           repo;
	struct galv_link *           link;
	const struct galv_conn_ops * conn_ops;
	int                          conn_flags;
	enum galv_connect_state      state;
};

extern int
galv_connect_resume(struct galv_connect * __restrict connector,
                    const struct upoll * __restrict  poller)
	__export_public;

extern void
galv_connect_suspend(struct galv_connect * __restrict connector,
                     const struct upoll * __restrict  poller)
	__export_public;

extern void
galv_connect_halt(struct galv_connect * __restrict connector,
                  const struct upoll * __restrict  poller)
	__export_public;

extern int
galv_connect_open(struct galv_connect * __restrict        connector,
                  struct galv_repo * __restrict           repository,
                  struct galv_link * __restrict           link,
                  const struct galv_conn_ops * __restrict operations,
                  int                                     flags,
                  const struct upoll * __restrict         poller)
	__export_public;

extern void
galv_connect_close(const struct galv_connect * __restrict connector,
                   const struct upoll * __restrict        poller)
	__export_public;

#endif /* _GALV_CONNECT_H */
