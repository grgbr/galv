/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _GALVUT_NCSVC_H
#define  _GALVUT_NCSVC_H

#include "galv/conn.h"
#include "galv/repo.h"

#define GALVUT_NCSVC_MSG_NR       (16U)
#if GALVUT_NCSVC_MSG_NR >= 1000
#error Cannot process more than 1000 messages !
#endif /* GALVUT_NCSVC_MSG_NR >= 1000 */
#define GALVUT_NCSVC_MSG_SIZE_MAX (8U)
#define GALVUT_NCSVC_CONN_NR      (5U)
#define GALVUT_NCSVC_BACKLOG      (2)

struct galvut_ncsvc_context {
	struct galv_conn_repo conns;
	unsigned int          bulk_cnt;
	unsigned int          msg_cnt;
	char                  msgs[GALVUT_NCSVC_MSG_NR][GALVUT_NCSVC_MSG_SIZE_MAX];
};

extern void
galvut_ncsvc_setup_ctx(struct galvut_ncsvc_context * __restrict context,
                       unsigned int                             bulk_count,
                       unsigned int                             max_conn);

extern const struct galv_conn_ops galvut_ncsvc_ops;

extern int
galvut_ncsvc_on_close(
	struct galv_acceptor * __restrict acceptor __unused,
	struct galv_conn * __restrict     conn,
	const struct upoll * __restrict   poller);

#endif /* _GALVUT_NCSVC_H */
