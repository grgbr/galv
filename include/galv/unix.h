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

struct galv_unix_acceptor;

/******************************************************************************
 * Asynchronous unix connection handling
 ******************************************************************************/

struct galv_unix_attrs {
	socklen_t          peer_size;
	struct sockaddr_un peer_addr;
	struct ucred       peer_cred;
};

#define galv_unix_assert_attrs_api(_attrs) \
	galv_assert_api(_attrs); \
	galv_assert_api((_attrs)->peer_size >= sizeof(sa_family_t)); \
	galv_assert_api((_attrs)->peer_addr.sun_family == AF_UNIX); \
	galv_assert_api((_attrs)->peer_cred.pid > 0)

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
 * Unix connection gate interface handling
 ******************************************************************************/

#if defined(CONFIG_GALV_UNIX_CONN_GATE)

struct galv_unix_gate;

typedef int
        galv_unix_gate_track_fn(struct galv_unix_gate * __restrict,
                                const struct galv_unix_attrs * __restrict);

typedef void
        galv_unix_gate_untrack_fn(struct galv_unix_gate * __restrict,
                                  const struct galv_unix_attrs * __restrict);

struct galv_unix_gate_ops {
        galv_unix_gate_track_fn *   track;
        galv_unix_gate_untrack_fn * untrack;
};

#define galv_unix_gate_assert_ops_api(_gate) \
	galv_assert_api(_gate); \
	galv_assert_api((_gate)->track); \
	galv_assert_api((_gate)->untrack);

struct galv_unix_gate {
	const struct galv_unix_gate_ops * ops;
};

#define galv_unix_gate_assert_iface_api(_gate) \
	galv_assert_api(_gate); \
	galv_unix_gate_assert_ops_api((_gate)->ops)

static inline
int
galv_unix_gate_track(struct galv_unix_gate * __restrict        gate,
                     const struct galv_unix_attrs * __restrict attrs)
{
	galv_unix_gate_assert_iface_api(gate);
	galv_unix_assert_attrs_api(attrs);

	return gate->ops->track(gate, attrs);
}

static inline
void
galv_unix_gate_untrack(struct galv_unix_gate * __restrict        gate,
                       const struct galv_unix_attrs * __restrict attrs)
{
	galv_unix_gate_assert_iface_api(gate);
	galv_unix_assert_attrs_api(attrs);

	return gate->ops->untrack(gate, attrs);
}

/******************************************************************************
 * Credential based unix connection gate interface handling
 ******************************************************************************/

#include <stroll/hlist.h>
#include <stroll/palloc.h>

struct galv_unix_gate_ucred {
	struct galv_unix_gate base;
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
                          unsigned int                             max_per_uid);

extern void
galv_unix_gate_ucred_fini(struct galv_unix_gate_ucred * __restrict gate);

#endif /* defined(CONFIG_GALV_UNIX_CONN_GATE) */

#endif /* _GALV_UNIX_H */
