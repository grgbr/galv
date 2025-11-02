/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

/**
 * @file
 * Unix connection
 *
 * @author    Grégor Boirie <gregor.boirie@free.fr>
 * @date      13 Oct 2025
 * @copyright Copyright (C) 2024 Grégor Boirie.
 * @license   [GNU Lesser General Public License (LGPL) v3]
 *            (https://www.gnu.org/licenses/lgpl+gpl-3.0.txt)
 */

#ifndef _GALV_UNIX_H
#define _GALV_UNIX_H

#include <galv/acceptor.h>
#include <galv/conn.h>
#include <sys/un.h>
#include <sys/socket.h>

struct galv_unix_acceptor;

/******************************************************************************
 * Asynchronous unix connection handling
 ******************************************************************************/

struct galv_unix_attrs {
	socklen_t          peer_size;
	struct sockaddr_un peer_addr;
	struct ucred       peer_cred;
};

struct galv_unix_conn {
	struct galv_conn       base;
	struct galv_unix_attrs attrs;
};

static inline
struct galv_unix_conn *
galv_unix_conn_from_worker(const struct upoll_worker * __restrict worker)
{
	galv_assert_api(worker);

	return containerof(worker, struct galv_unix_conn, base.work);
}

extern void
galv_unix_conn_setup(struct galv_unix_conn * __restrict        conn,
                     int                                       fd,
                     struct galv_unix_acceptor * __restrict    acceptor,
                     const struct galv_conn_ops * __restrict   ops,
                     const struct galv_unix_attrs * __restrict attrs)
	__export_public;

/******************************************************************************
 * Asynchronous unix connection acceptor handling
 ******************************************************************************/

struct galv_unix_acceptor {
	struct galv_acceptor base;
	socklen_t            bind_size;
	struct sockaddr_un   bind_addr;
};

extern int
galv_unix_acceptor_grab(const struct galv_unix_acceptor * __restrict acceptor,
                        struct galv_unix_attrs * __restrict          attrs,
                        int                                          flags)
	__export_public;

extern int
galv_unix_acceptor_open(struct galv_unix_acceptor * __restrict      acceptor,
                        const char * __restrict                     path,
                        int                                         type,
                        int                                         flags,
                        int                                         backlog,
                        const struct upoll * __restrict             poller,
                        const struct galv_acceptor_ops * __restrict ops,
                        void * __restrict                           context)
	__export_public;

extern int
galv_unix_acceptor_close(const struct galv_unix_acceptor * __restrict acceptor,
                         const struct upoll * __restrict              poller)
	__export_public;

/******************************************************************************
 * Credential based unix connection gate handling
 ******************************************************************************/

#if defined(CONFIG_GALV_GATE)

#include "galv/gate.h"
#include <stroll/hlist.h>
#include <stroll/palloc.h>

struct galv_unix_gate_ucred {
	struct galv_gate      base;
	unsigned int          cnt;
	unsigned int          nr;
	unsigned int          bits;
	unsigned int          per_pid;
	struct stroll_hlist * pids;
	unsigned int          per_uid;
	struct stroll_hlist * uids;
	struct stroll_palloc  alloc;
};

extern int
galv_unix_gate_ucred_init(struct galv_unix_gate_ucred * __restrict gate,
                          unsigned int                             max_conn,
                          unsigned int                             max_per_pid,
                          unsigned int                             max_per_uid)
	__export_public;

extern void
galv_unix_gate_ucred_fini(struct galv_unix_gate_ucred * __restrict gate)
	__export_public;

#endif /* defined(CONFIG_GALV_GATE) */

/******************************************************************************
 * Asynchronous Unix connection oriented service
 ******************************************************************************/

#if defined(CONFIG_GALV_SVC)

struct galv_conn_repo;
struct galv_fabric;

struct galv_unix_svc_context {
	struct galv_conn_repo * repo;
	struct galv_fabric *    fab;
	struct galv_gate *      gate;
};

#define galv_unix_assert_svc_ctx_api(_ctx) \
	galv_assert_api(_ctx); \
	galv_assert_api((_ctx)->repo); \
	galv_assert_api((_ctx)->fab); \
	galv_assert_api((_ctx)->gate)

struct galv_unix_svc {
	struct galv_unix_acceptor    base;
	const struct galv_conn_ops * conn_ops;
};

extern int
galv_unix_svc_open(struct galv_unix_svc * __restrict         service,
                   const char * __restrict                   path,
                   int                                       type,
                   int                                       flags,
                   int                                       backlog,
                   const struct upoll * __restrict           poller,
                   const struct galv_conn_ops * __restrict   ops,
                   struct galv_unix_svc_context * __restrict context)
	__export_public;

extern int
galv_unix_svc_close(const struct galv_unix_svc * __restrict service,
                    const struct upoll * __restrict         poller)
	__export_public;

#endif /* defined(CONFIG_GALV_SVC) */

#endif /* _GALV_UNIX_H */
