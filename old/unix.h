/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _GALV_UNSK_H
#define _GALV_UNSK_H

#include <galv/conn.h>
#include <stroll/palloc.h>
#include <utils/unsk.h>
#include <utils/poll.h>

#define galv_unix_assert_api(_expr) \
	galv_assert_api("galv:unix", _expr)

/******************************************************************************
 * Unix gate interface
 ******************************************************************************/

struct galv_unix_gate;

typedef int
        galv_unix_gate_track_fn(struct galv_unix_gate * __restrict,
                                const struct sockaddr_un * __restrict,
                                socklen_t,
                                const struct ucred * __restrict);

typedef void
        galv_unix_gate_untrack_fn(struct galv_unix_gate * __restrict,
                                  const struct sockaddr_un * __restrict,
                                  socklen_t,
                                  const struct ucred * __restrict);

struct galv_unix_gate {
        galv_unix_gate_track_fn *   track;
        galv_unix_gate_untrack_fn * untrack;
};

static inline
int
galv_unix_gate_track(struct galv_unix_gate * __restrict    gate,
                     const struct sockaddr_un * __restrict peer_addr,
                     socklen_t                             peer_size,
                     const struct ucred * __restrict       peer_cred)
{
	galv_unix_assert_api(gate);
	galv_unix_assert_api(gate->track);
	galv_unix_assert_api(gate->untrack);
	galv_unix_assert_api(peer_addr);
	galv_unix_assert_api(peer_size >= sizeof(sa_family_t));
	galv_unix_assert_api(peer_cred);

	return gate->track(gate, peer_addr, peer_size, peer_cred);
}

static inline
void
galv_unix_gate_untrack(struct galv_unix_gate * __restrict    gate,
                       const struct sockaddr_un * __restrict peer_addr,
                       socklen_t                             peer_size,
                       const struct ucred * __restrict       peer_cred)
{
	galv_unix_assert_api(gate);
	galv_unix_assert_api(gate->track);
	galv_unix_assert_api(gate->untrack);
	galv_unix_assert_api(peer_addr);
	galv_unix_assert_api(peer_size >= sizeof(sa_family_t));
	galv_unix_assert_api(peer_cred);

	gate->untrack(gate, peer_addr, peer_size, peer_cred);
}

/******************************************************************************
 * Default unix connection gate implementation
 ******************************************************************************/

struct galv_unix_conn_gate {
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
galv_unix_conn_gate_track(
	struct galv_unix_gate * __restrict    gate,
	const struct sockaddr_un * __restrict peer_addr __unused,
	socklen_t                             peer_size __unused,
	const struct ucred * __restrict       peer_cred);

extern void
galv_unix_conn_gate_untrack(
	struct galv_unix_gate * __restrict    gate,
	const struct sockaddr_un * __restrict peer_addr __unused,
	socklen_t                             peer_size __unused,
	const struct ucred * __restrict       peer_cred);

extern int
galv_unix_conn_gate_init(struct galv_unix_conn_gate * __restrict gate,
                         unsigned int                            max_conn,
                         unsigned int                            max_per_pid,
                         unsigned int                            max_per_uid);

extern void
galv_unix_conn_gate_fini(struct galv_unix_conn_gate * __restrict gate);

/******************************************************************************
 * Unix connection handling
 ******************************************************************************/

struct galv_unix_conn {
	struct galv_conn   base;
	socklen_t          peer_size;
	struct sockaddr_un peer_addr;
	struct ucred       peer_cred;
};

extern int
galv_unix_conn_accept(struct galv_unix_conn * __restrict conn,
                      int                                listen,
                      int                                flags);

static inline
int
galv_unix_conn_poll(const struct galv_unix_conn * __restrict conn,
                    struct upoll_worker * __restrict         worker,
                    const struct upoll * __restrict          poller,
                    int                                      flags)
{
	galv_unix_assert_api(conn);
	galv_unix_assert_api(conn->base.fd >= 0);
	galv_unix_assert_api(conn->base.state == GALV_CONN_CONNECTING_STATE);
	galv_unix_assert_api(conn->peer_size >= sizeof(sa_family_t));
	galv_unix_assert_api(conn->peer_cred.pid > 0);
	galv_unix_assert_api(worker);
	galv_unix_assert_api(worker->dispatch);
	galv_unix_assert_api(poller);

	return upoll_register(poller, conn->base.fd, flags, worker);
}

static inline
void
galv_unix_conn_unpoll(const struct galv_unix_conn * __restrict conn,
                      const struct upoll * __restrict          poller)
{
	galv_unix_assert_api(conn);
	galv_unix_assert_api(conn->base.fd >= 0);
	galv_unix_assert_api(conn->base.state != GALV_CONN_CLOSED_STATE);
	galv_unix_assert_api(conn->peer_size >= sizeof(sa_family_t));
	galv_unix_assert_api(conn->peer_cred.pid > 0);

	return upoll_unregister(poller, conn->base.fd);
}

/*
 * May return -EINTR or -EIO
 */
static inline
int
galv_unix_conn_close(struct galv_unix_conn * __restrict conn)
{
	galv_unix_assert_api(conn);
	galv_unix_assert_api(conn->base.fd >= 0);
	galv_unix_assert_api(conn->base.state != GALV_CONN_CLOSED_STATE);
	galv_unix_assert_api(conn->peer_size >= sizeof(sa_family_t));
	galv_unix_assert_api(conn->peer_cred.pid > 0);

	int ret;

	ret = unsk_close(conn->base.fd);
	conn->base.state = GALV_CONN_CLOSED_STATE;

	return ret;
}

/******************************************************************************
 * Asynchronous unix connection and acceptor handling
 ******************************************************************************/

struct galv_unix_acceptor;

struct galv_unix_async_conn {
	struct galv_unix_conn       sync;
	struct upoll_worker         work;
	struct galv_unix_acceptor * accept;
};

extern int
galv_unix_async_conn_close(struct galv_unix_async_conn * __restrict conn,
                           const struct upoll * __restrict          poller);

typedef int
        galv_unix_async_conn_on_new_fn(
		const struct galv_unix_acceptor * __restrict,
		struct galv_unix_async_conn * __restrict,
		const struct upoll * __restrict);

struct galv_unix_acceptor_attrs {
	int                              sock_type;
	int                              listen_flags;
	const char *                     bind_path;
	int                              listen_bklog;
	int                              accept_flags;
	galv_unix_async_conn_on_new_fn * on_new;
	int                              poll_flags;
};

struct galv_fabric;

struct galv_unix_acceptor {
	struct upoll_worker              work;
	int                              fd;
	struct galv_fabric *             fabric;
	int                              sock_flags; /* Flags applied at new connection accept() time. */
	struct galv_unix_gate *          gate;
	galv_unix_async_conn_on_new_fn * on_new;
	struct galv_conn_repo *          repo;
	int                              poll_flags; /* Poll flags applied to new connections. */
	socklen_t                        bind_size;
	struct sockaddr_un               bind_addr;
};

extern int
galv_unix_acceptor_open(
	struct galv_unix_acceptor * __restrict             acceptor,
	const struct galv_unix_acceptor_attrs * __restrict attrs,
	struct galv_fabric * __restrict                    fabric,
	struct galv_unix_gate * __restrict                 gate,
	struct galv_conn_repo * __restrict                 repo,
	const struct upoll * __restrict                    poller);

extern void
galv_unix_acceptor_close(const struct galv_unix_acceptor * __restrict acceptor,
                         const struct upoll * __restrict              poller);

/******************************************************************************/
/******************************************************************************/
/******************************************************************************/

struct galv_unix_attrs {
	socklen_t          peer_size;
	struct sockaddr_un peer_addr;
	struct ucred       peer_cred;
};

struct galv_unix_async_conn {
	struct galv_async_conn async;
	struct galv_unix_attrs unix;
};

struct galv_acceptor_ctx {
	struct galv_conn_repo * repo;
};

extern int
galv_unix_async_conn_accept(
	struct galv_unix_async_conn * __restrict        conn,
	const struct galv_unix_acceptor * __restrict    acceptor,
	int                                             flags,
	const struct galv_async_conn_ops * __restrict * ops);

extern int
galv_unix_async_conn_poll(struct galv_unix_async_conn * __restrict conn,
                          const struct upoll * __restrict          poller,
                          int                                      flags);

static inline
void
galv_unix_async_conn_unpoll(const struct galv_async_conn * __restrict conn,
                            const struct upoll * __restrict           poller)
{
	galv_async_conn_poll(&conn->async, poller);
}

static inline
int
galv_unix_async_conn_close(struct galv_unix_async_conn * __restrict conn,
                           const struct upoll * __restrict          poller)
{
	return galv_async_conn_close(&conn->async, poller);
}
