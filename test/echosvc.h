/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _GALVUT_ECHOSVC_H
#define  _GALVUT_ECHOSVC_H

#include "galv/conn.h"
#include "galv/repo.h"

#define GALVUT_ECHOSVC_MSG_SIZE_MAX (8U)
#define GALVUT_ECHOSVC_CONN_NR      (5U)
#define GALVUT_ECHOSVC_BACKLOG      (2)

struct galvut_echosvc_context {
	struct galv_conn_repo conns;
	unsigned int          bulk_cnt;
};

extern void
galvut_echosvc_setup_ctx(struct galvut_echosvc_context * __restrict context,
                         unsigned int                               bulk_count,
                         unsigned int                               max_conn);

extern const struct galv_conn_ops galvut_echosvc_ops;

extern int
galvut_echosvc_on_close(
	struct galv_acceptor * __restrict acceptor __unused,
	struct galv_conn * __restrict     conn,
	const struct upoll * __restrict   poller);

#endif /* _GALVUT_ECHOSVC_H */
