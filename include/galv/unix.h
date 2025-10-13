/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _GALV_UNIX_H
#define _GALV_UNIX_H

#include <galv/acceptor.h>
#include <galv/conn.h>
#include <sys/un.h>
#include <sys/socket.h>

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

extern int
galv_unix_conn_accept(struct galv_unix_conn * __restrict      conn,
                      struct galv_acceptor * __restrict       acceptor,
                      int                                     flags,
                      const struct galv_conn_ops * __restrict ops)
	__export_public;

/******************************************************************************
 * Asynchronous unix connection acceptor handling
 ******************************************************************************/

struct galv_unix_acceptor;

struct galv_unix_acceptor {
	struct galv_acceptor base;
	socklen_t            bind_size;
	struct sockaddr_un   bind_addr;
};

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

#endif /* _GALV_UNIX_H */
