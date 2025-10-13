/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "galv/unix.h"
#include "common.h"
#include "galv/fabric.h"
#include <stroll/hash.h>
#include <stroll/hlist.h>
#include <stroll/pow2.h>
#include <sys/socket.h>

#define galv_unix_assert_intern(_expr) \
	galv_assert_intern("galv:unix", _expr)

/******************************************************************************
 * Default unix gate implementation
 ******************************************************************************/

#define GALV_UNIX_CONN_GATE_HASH_RATIO \
	STROLL_CONCAT(CONFIG_GALV_UNIX_CONN_GATE_HASH_RATIO, U)

#define GALV_UNIX_CONN_GATE_HASH_BITS \
	STROLL_CONCAT(CONFIG_GALV_UNIX_CONN_GATE_HASH_BITS, U)

#define galv_unix_conn_gate_assert_api(_gate) \
	galv_unix_assert_api(_gate); \
	galv_unix_assert_api((_gate)->base.track); \
	galv_unix_assert_api((_gate)->base.untrack); \
	galv_unix_assert_api((_gate)->nr); \
	galv_unix_assert_api((_gate)->cnt <= (_gate)->nr); \
	galv_unix_assert_api((_gate)->nr <= (1U << (_gate)->bits)); \
	galv_unix_assert_api((_gate)->per_pid); \
	galv_unix_assert_api((_gate)->per_pid <= (_gate)->nr); \
	galv_unix_assert_api((_gate)->pids); \
	galv_unix_assert_api((_gate)->per_uid); \
	galv_unix_assert_api((_gate)->per_uid <= (_gate)->nr); \
	galv_unix_assert_api((_gate)->uids)

struct galv_unix_conn_gate_count {
	struct stroll_hlist_node   hlist;
	union {
		pid_t              pid;
		uid_t              uid;
	};
	unsigned int               val;
};

static
void
galv_unix_conn_gate_unregister_count(
	struct galv_unix_conn_gate * __restrict       gate,
	struct galv_unix_conn_gate_count * __restrict count)
{
	galv_unix_assert_intern(stroll_hlist_node_hashed(&count->hlist));
	galv_unix_assert_intern(count->val);

	if (!--count->val) {
		stroll_hlist_del(&count->hlist);
		stroll_palloc_free(&gate->alloc, count);
	}
}

static
unsigned int
galv_unix_conn_gate_hash_pid(const struct galv_unix_conn_gate * __restrict gate,
                             const struct ucred * __restrict               cred)
{
	unsigned int hash = stroll_hash((unsigned int)cred->pid, gate->bits);

	galv_unix_assert_intern(hash < (1U << gate->bits));

	return hash;
}

static
struct galv_unix_conn_gate_count *
galv_unix_conn_gate_find_bypid(
	const struct galv_unix_conn_gate * __restrict gate,
	const struct ucred * __restrict               cred,
	unsigned int                                  hash)
{
	struct stroll_hlist_node * node;

	stroll_hlist_foreach_node(&gate->pids[hash], node) {
		struct galv_unix_conn_gate_count * cnt;

		cnt = stroll_hlist_entry(node,
		                         struct galv_unix_conn_gate_count,
		                         hlist);

		galv_unix_assert_intern(cnt->pid > 0);
		galv_unix_assert_intern(cnt->val);
		galv_unix_assert_intern(cnt->val <= gate->per_pid);
		if (cred->pid == cnt->pid)
			return cnt;
	}

	return NULL;
}

static
void
galv_unix_conn_gate_track_pid(
	struct galv_unix_conn_gate * __restrict       gate,
	struct galv_unix_conn_gate_count * __restrict count,
	const struct ucred * __restrict               cred,
	unsigned int                                  hash)
{
	if (count) {
		galv_unix_assert_intern(
			stroll_hlist_node_hashed(&count->hlist));
		galv_unix_assert_intern(count->val);

		count->val++;
		return;
	}

	count = (struct galv_unix_conn_gate_count *)
	        stroll_palloc_alloc(&gate->alloc);
	galv_unix_assert_intern(count);
	count->pid = cred->pid;
	count->val = 1;

	stroll_hlist_add(&gate->pids[hash], &count->hlist);
}

static
void
galv_unix_conn_gate_untrack_pid(
	struct galv_unix_conn_gate * __restrict gate,
	const struct ucred * __restrict         peer_cred)
{
	struct galv_unix_conn_gate_count * cnt;
	unsigned int                       hash;

	hash = galv_unix_conn_gate_hash_pid(gate, peer_cred);
	cnt = galv_unix_conn_gate_find_bypid(gate, peer_cred, hash);
	galv_unix_assert_intern(cnt);
	galv_unix_assert_intern(cnt->val);

	galv_unix_conn_gate_unregister_count(gate, cnt);
}

static
unsigned int
galv_unix_conn_gate_hash_uid(const struct galv_unix_conn_gate * __restrict gate,
                             const struct ucred * __restrict               cred)
{
	unsigned int hash = stroll_hash((unsigned int)cred->uid, gate->bits);

	galv_unix_assert_intern(hash < (1U << gate->bits));

	return hash;
}

static
struct galv_unix_conn_gate_count *
galv_unix_conn_gate_find_byuid(
	const struct galv_unix_conn_gate * __restrict gate,
	const struct ucred * __restrict               cred,
	unsigned int                                  hash)
{
	struct stroll_hlist_node * node;

	stroll_hlist_foreach_node(&gate->uids[hash], node) {
		struct galv_unix_conn_gate_count * cnt;

		cnt = stroll_hlist_entry(node,
		                         struct galv_unix_conn_gate_count,
		                         hlist);

		galv_unix_assert_intern(cnt->val);
		galv_unix_assert_intern(cnt->val <= gate->per_uid);
		if (cred->uid == cnt->uid)
			return cnt;
	}

	return NULL;
}

static
void
galv_unix_conn_gate_track_uid(
	struct galv_unix_conn_gate * __restrict       gate,
	struct galv_unix_conn_gate_count * __restrict count,
	const struct ucred * __restrict               cred,
	unsigned int                                  hash)
{
	if (count) {
		galv_unix_assert_intern(
			stroll_hlist_node_hashed(&count->hlist));
		galv_unix_assert_intern(count->val);

		count->val++;
		return;
	}

	count = (struct galv_unix_conn_gate_count *)
	        stroll_palloc_alloc(&gate->alloc);
	galv_unix_assert_intern(count);
	count->uid = cred->uid;
	count->val = 1;

	stroll_hlist_add(&gate->uids[hash], &count->hlist);
}

static
void
galv_unix_conn_gate_untrack_uid(
	struct galv_unix_conn_gate * __restrict gate,
	const struct ucred * __restrict         peer_cred)
{
	struct galv_unix_conn_gate_count * cnt;
	unsigned int                       hash;

	hash = galv_unix_conn_gate_hash_uid(gate, peer_cred);
	cnt = galv_unix_conn_gate_find_byuid(gate, peer_cred, hash);
	galv_unix_assert_intern(cnt);
	galv_unix_assert_intern(cnt->val);

	galv_unix_conn_gate_unregister_count(gate, cnt);
}

int
galv_unix_conn_gate_track(
	struct galv_unix_gate * __restrict    gate,
	const struct sockaddr_un * __restrict peer_addr __unused,
	socklen_t                             peer_size __unused,
	const struct ucred * __restrict       peer_cred)
{
	struct galv_unix_conn_gate *       ucgt = (struct galv_unix_conn_gate *)
	                                          gate;
	unsigned int                       pid_hash;
	struct galv_unix_conn_gate_count * pid_cnt;
	unsigned int                       uid_hash;
	struct galv_unix_conn_gate_count * uid_cnt;

	galv_unix_conn_gate_assert_api(ucgt);
	galv_unix_assert_api(peer_addr);
	galv_unix_assert_api(peer_size >= sizeof(sa_family_t));
	galv_unix_assert_api(peer_cred->pid > 0);

	if (ucgt->cnt == ucgt->nr)
		return -EPERM;

	pid_hash = galv_unix_conn_gate_hash_pid(ucgt, peer_cred);
	pid_cnt = galv_unix_conn_gate_find_bypid(ucgt, peer_cred, pid_hash);
	if (pid_cnt) {
		galv_unix_assert_intern(pid_cnt->val <= ucgt->per_pid);
		if (pid_cnt->val == ucgt->per_pid)
			return -EPERM;
	}

	uid_hash = galv_unix_conn_gate_hash_uid(ucgt, peer_cred);
	uid_cnt = galv_unix_conn_gate_find_byuid(ucgt, peer_cred, uid_hash);
	if (uid_cnt) {
		galv_unix_assert_intern(uid_cnt->val <= ucgt->per_uid);
		if (uid_cnt->val == ucgt->per_uid)
			return -EPERM;
	}

	galv_unix_conn_gate_track_pid(ucgt, pid_cnt, peer_cred, pid_hash);
	galv_unix_conn_gate_track_uid(ucgt, uid_cnt, peer_cred, uid_hash);
	ucgt->cnt++;

	return 0;
}

void
galv_unix_conn_gate_untrack(
	struct galv_unix_gate * __restrict    gate,
	const struct sockaddr_un * __restrict peer_addr __unused,
	socklen_t                             peer_size __unused,
	const struct ucred * __restrict       peer_cred)
{
	struct galv_unix_conn_gate *       ucgt = (struct galv_unix_conn_gate *)
	                                          gate;

	galv_unix_conn_gate_assert_api(ucgt);
	galv_unix_assert_api(peer_addr);
	galv_unix_assert_api(peer_size >= sizeof(sa_family_t));
	galv_unix_assert_api(peer_cred->pid > 0);

	galv_unix_conn_gate_untrack_pid(ucgt, peer_cred);
	galv_unix_conn_gate_untrack_uid(ucgt, peer_cred);
	ucgt->cnt--;
}

int
galv_unix_conn_gate_init(struct galv_unix_conn_gate * __restrict gate,
                         unsigned int                            max_conn,
                         unsigned int                            max_per_pid,
                         unsigned int                            max_per_uid)
{
	galv_unix_assert_api(gate);
	galv_unix_assert_api(max_conn);
	galv_unix_assert_api(max_per_pid <= max_conn);
	galv_unix_assert_api(max_per_uid <= max_conn);

	unsigned int          bits;
	struct stroll_hlist * pids;
	struct stroll_hlist * uids;


	bits = stroll_pow2_up((max_conn * 100) /
	                      GALV_UNIX_CONN_GATE_HASH_RATIO);
	bits = stroll_min(bits, GALV_UNIX_CONN_GATE_HASH_BITS);

	pids = stroll_hlist_create_buckets(bits);
	if (!pids)
		return -ENOMEM;
	uids = stroll_hlist_create_buckets(bits);
	if (!uids)
		goto free_pids;
	if (stroll_palloc_init(&gate->alloc,
	                       2 * max_conn,
	                       sizeof(struct galv_unix_conn_gate_count)))
		goto free_uids;

	gate->base.track = galv_unix_conn_gate_track;
	gate->base.untrack = galv_unix_conn_gate_untrack;
	gate->cnt = 0;
	gate->nr = max_conn;
	gate->bits = bits;
	gate->per_pid = max_per_pid;
	gate->pids = pids;
	gate->per_uid = max_per_uid;
	gate->uids = uids;

	return 0;

free_uids:
	free(uids);
free_pids:
	free(pids);

	return -ENOMEM;
}

void
galv_unix_conn_gate_fini(struct galv_unix_conn_gate * __restrict gate)
{
	galv_unix_conn_gate_assert_api(gate);

	stroll_hlist_destroy_buckets(gate->pids);
	stroll_hlist_destroy_buckets(gate->uids);
	stroll_palloc_fini(&gate->alloc);
}

/******************************************************************************
 * Unix connection handling
 ******************************************************************************/

int
galv_unix_conn_accept(struct galv_unix_conn * __restrict conn,
                      int                                listen,
                      int                                flags)
{
	galv_unix_assert_api(conn);
	galv_unix_assert_api(listen >= 0);
	galv_unix_assert_api(!(flags & ~(SOCK_NONBLOCK | SOCK_CLOEXEC)));

	int       fd;
	socklen_t sz = sizeof(conn->peer_cred);

	conn->peer_size = sizeof(conn->peer_addr);
	fd = unsk_accept(listen, &conn->peer_addr, &conn->peer_size, flags);
	if (fd < 0)
		return fd;

	unsk_getsockopt(fd, SO_PEERCRED, &conn->peer_cred, &sz);
	galv_unix_assert_intern(sz == sizeof(conn->peer_cred));

	conn->base.fd = fd;
	conn->base.state = GALV_CONN_CONNECTING_STATE;

	return 0;
}

/******************************************************************************
 * Unix asynchronous connection acceptor handling
 ******************************************************************************/

/*
 * As stated into unix(7), unix sockets don't support the transmission of
 * out-of-band data. Hence we disallow setting the EPOLLPRI flag.
 */
#define GALV_UNIX_CONN_VALID_POLL_FLAGS \
	(EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLHUP)

#define galv_unix_acceptor_assert_attrs(_attrs) \
	galv_unix_assert_api(_attrs); \
	galv_unix_assert_api(((_attrs)->sock_type == SOCK_STREAM) || \
	                     ((_attrs)->sock_type == SOCK_SEQPACKET)); \
	galv_unix_assert_api(!(_attrs)->listen_flags || \
	                     ((_attrs)->listen_flags == SOCK_CLOEXEC)); \
	galv_unix_assert_api(!unsk_is_named_path_ok((_attrs)->bind_path)); \
	galv_unix_assert_api((_attrs)->listen_bklog >= 0); \
	galv_unix_assert_api(!(_attrs)->accept_flags || \
	                     ((_attrs)->accept_flags == SOCK_CLOEXEC)); \
	galv_unix_assert_api((_attrs)->on_new); \
	galv_unix_assert_api((_attrs)->poll_flags && \
	                     !((_attrs)->poll_flags & \
	                       ~(GALV_UNIX_CONN_VALID_POLL_FLAGS)));

#define galv_unix_acceptor_assert_api(_accept) \
	galv_unix_assert_api(_accept); \
	galv_unix_assert_api((_accept)->fd >= 0); \
	galv_unix_assert_api((_accept)->fabric); \
	galv_unix_assert_api(!(_accept)->sock_flags || \
	                     ((_accept)->sock_flags == SOCK_CLOEXEC)); \
	galv_unix_assert_api((_accept)->gate); \
	galv_unix_assert_api((_accept)->on_new); \
	galv_unix_assert_api((_accept)->repo); \
	galv_unix_assert_api((_accept)->poll_flags && \
	                     !((_accept)->poll_flags & \
	                       ~(GALV_UNIX_CONN_VALID_POLL_FLAGS))); \
	galv_unix_assert_api((_accept)->bind_size > \
	                     (sizeof(sa_family_t) + 1)); \
	galv_unix_assert_api( \
		!unsk_is_named_path_ok((_accept)->bind_addr.sun_path))

#define galv_unix_acceptor_assert_intern(_accept) \
	galv_unix_assert_intern(_accept); \
	galv_unix_assert_intern((_accept)->fd >= 0); \
	galv_unix_assert_intern((_accept)->fabric); \
	galv_unix_assert_intern(!(_accept)->sock_flags || \
	                        ((_accept)->sock_flags == SOCK_CLOEXEC)); \
	galv_unix_assert_intern((_accept)->gate); \
	galv_unix_assert_intern((_accept)->on_new); \
	galv_unix_assert_intern((_accept)->repo); \
	galv_unix_assert_intern((_accept)->poll_flags && \
	                        !((_accept)->poll_flags & \
	                          ~(GALV_UNIX_CONN_VALID_POLL_FLAGS))); \
	galv_unix_assert_intern((_accept)->bind_size > \
	                        (sizeof(sa_family_t) + 1)); \
	galv_unix_assert_intern( \
		!unsk_is_named_path_ok((_accept)->bind_addr.sun_path))

int
galv_unix_async_conn_close(struct galv_unix_async_conn * __restrict conn,
                           const struct upoll * __restrict          poller)
{
	galv_unix_assert_api(conn);
	galv_unix_assert_api(conn->sync.base.fd >= 0);
	galv_unix_assert_api(conn->sync.base.state != GALV_CONN_CLOSED_STATE);
	galv_unix_assert_api(conn->sync.peer_size >= sizeof(sa_family_t));
	galv_unix_assert_api(conn->sync.peer_cred.pid > 0);
	galv_unix_acceptor_assert_api(conn->accept);
	galv_unix_assert_api(poller);

	galv_unix_conn_unpoll(&conn->sync, poller);
	galv_unix_gate_untrack(conn->accept->gate,
	                       &conn->sync.peer_addr,
	                       conn->sync.peer_size,
	                       &conn->sync.peer_cred);
	galv_conn_repo_unregister(conn->accept->repo, &conn->sync.base);

	return galv_unix_conn_close(&conn->sync);
}

static
int
galv_unix_async_conn_accept(struct galv_unix_acceptor * __restrict acceptor,
                            const struct upoll * __restrict        poller)
{
	galv_unix_acceptor_assert_api(acceptor);
	galv_unix_assert_api(poller);

	struct galv_unix_async_conn * conn;
	int                           err;

	if (galv_conn_repo_full(acceptor->repo)) {
		err = -EPERM;
		goto reject;
	}

	conn = (struct galv_unix_async_conn *)
	       galv_fabric_alloc(acceptor->fabric);
	if (!conn) {
		err = -errno;
		goto reject;
	}

	err = galv_unix_conn_accept(&conn->sync,
	                            acceptor->fd,
	                            SOCK_NONBLOCK | acceptor->sock_flags);
	if (err) {
		if (err == -ECONNABORTED)
			/*
			 * Connection has been aborted: ignore and tell caller
			 * to keep processing connection requests normally.
			 */
			err = 0;
		goto destruct;
	}

	if (unsk_is_named_addr(&conn->sync.peer_addr, conn->sync.peer_size)) {
		err = -EADDRNOTAVAIL;
		goto close;
	}

	err = galv_unix_conn_gate_track(acceptor->gate,
	                                &conn->sync.peer_addr,
	                                conn->sync.peer_size,
	                                &conn->sync.peer_cred);
	if (err)
		goto close;

	conn->accept = acceptor;
	err = acceptor->on_new(acceptor, conn, poller);
	if (err)
		goto untrack;

	galv_conn_repo_register(acceptor->repo, &conn->sync.base);

	err = galv_unix_conn_poll(&conn->sync,
	                          &conn->work,
	                          poller,
	                          acceptor->poll_flags);
	if (err)
		goto unregister;

	conn->sync.base.state = GALV_CONN_ESTABLISHED_STATE;

	return 0;

unregister:
	galv_conn_repo_unregister(acceptor->repo, &conn->sync.base);
untrack:
	galv_unix_conn_gate_untrack(acceptor->gate,
	                            &conn->sync.peer_addr,
	                            conn->sync.peer_size,
	                            &conn->sync.peer_cred);
close:
	galv_unix_conn_close(&conn->sync);
destruct:
	galv_fabric_free(acceptor->fabric, conn);

	return err;

reject:
	/*
	 * When a connection request cannot be handled, we accept() and close()
	 * it. Otherwise, it would sit in the kernel listen backlog till next
	 * call to accept().
	 */
	unsk_reject(acceptor->fd);

	return err;
}

static
int
galv_unix_acceptor_dispatch(struct upoll_worker * worker,
                            uint32_t              state,
                            const struct upoll *  poller)
{
	galv_unix_assert_intern(worker);
	galv_unix_assert_intern(poller);
	galv_unix_assert_intern(state);
	galv_unix_assert_intern(!(state & ~(EPOLLIN | EPOLLERR)));

	struct galv_unix_acceptor * accept;
	int                         ret;

	accept = containerof(worker, struct galv_unix_acceptor, work);
	galv_unix_acceptor_assert_intern(accept);

	if (state & EPOLLERR) {
		ret = -EIO;
		goto apply;
	}

	do {
		ret = galv_unix_async_conn_accept(accept, poller);
	} while (!ret);

	switch (ret) {
	case -EAGAIN:
		ret = 0;
		break;

	case -EINTR:  /* Interrupted by a signal */
	case -ENFILE: /* System limit on max number of open files reached. */
	case -ENOMEM: /* No more memory available. */
		break;

	default:
		ret = 0;
	}

apply:
	upoll_apply(poller, accept->fd, &accept->work);

	return ret;
}

int
galv_unix_acceptor_open(
	struct galv_unix_acceptor * __restrict             acceptor,
	const struct galv_unix_acceptor_attrs * __restrict attrs,
	struct galv_fabric * __restrict                    fabric,
	struct galv_unix_gate * __restrict                 gate,
	struct galv_conn_repo * __restrict                 repo,
	const struct upoll * __restrict                    poller)
{
	galv_unix_assert_api(acceptor);
	galv_unix_acceptor_assert_attrs(attrs);
	galv_unix_assert_api(fabric);
	galv_unix_assert_api(gate);
	galv_unix_assert_api(repo);
	galv_unix_assert_api(poller);

	int ret;

	ret = unsk_open(attrs->sock_type, SOCK_NONBLOCK | attrs->listen_flags);
	if (ret < 0)
		return ret;

	acceptor->fd = ret;

	/*
	 * Remove local filesystem pathname if existing.
	 *
	 * This is required since binding a named UNIX socket to a filesystem
	 * entry that already exists will fail with EADDRINUSE error code
	 * (AF_UNIX sockets do not support the SO_REUSEADDR socket option).
	 */
	ret = unsk_unlink(attrs->bind_path);
	if (ret)
		goto close;

	/* Build local bind address. */
	acceptor->bind_size = (socklen_t)
	                      offsetof(typeof(acceptor->bind_addr), sun_path) +
	                      (socklen_t)
	                      unsk_make_named_addr(&acceptor->bind_addr,
	                                           attrs->bind_path);

	/*
	 * Bind to the given local filesystem pathname.
	 *
	 * This will effectively create the filesystem entry according to
	 * current process priviledges.
	 * See "Pathname socket ownership and permissions" section of unix(7)
	 * man page.
	 */
	ret = unsk_bind(acceptor->fd,
	                &acceptor->bind_addr,
	                acceptor->bind_size);
	if (ret)
		goto close;

	ret = unsk_listen(acceptor->fd, attrs->listen_bklog);
	if (ret)
		goto close;

	acceptor->work.dispatch = galv_unix_acceptor_dispatch;
	acceptor->fabric = fabric;
	acceptor->sock_flags = attrs->accept_flags;
	acceptor->gate = gate;
	acceptor->repo = repo;
	acceptor->poll_flags = attrs->poll_flags;
	acceptor->on_new = attrs->on_new;

	ret = upoll_register(poller, acceptor->fd, EPOLLIN, &acceptor->work);
	if (ret)
		goto close;

	return 0;

close:
	/* Support named sockets only. */
	galv_unix_assert_intern(attrs->bind_path[0]);
	unlink(attrs->bind_path);
	unsk_close(acceptor->fd);

	return ret;
}

void
galv_unix_acceptor_close(const struct galv_unix_acceptor * __restrict acceptor,
                         const struct upoll * __restrict              poller)
{
	galv_unix_acceptor_assert_api(acceptor);
	galv_unix_assert_api(poller);

	upoll_unregister(poller, acceptor->fd);

	unlink(acceptor->bind_addr.sun_path);
	unsk_close(acceptor->fd);
}

/******************************************************************************/
/******************************************************************************/
/******************************************************************************/

static
int
galv_unix_accept(int                                 listen,
                 struct galv_unix_attrs * __restrict unix,
                 int                                 flags)
{
	int       fd;
	socklen_t sz = sizeof(unix->peer_cred);

	unix->peer_size = sizeof(unix->peer_addr);
	fd = unsk_accept(listen, &unix->peer_addr, &unix->peer_size, flags);
	if (fd < 0)
		return fd;

	unsk_getsockopt(fd, SO_PEERCRED, &unix->peer_cred, &sz);
	galv_unix_assert_intern(sz == sizeof(unix->peer_cred));

	return 0;
}

int
galv_unix_async_conn_accept(
	struct galv_unix_async_conn * __restrict        conn,
	const struct galv_unix_acceptor * __restrict    acceptor,
	int                                             flags,
	const struct galv_async_conn_ops * __restrict * ops)
{
	int fd;

	fd = galv_unix_accept(acceptor->fd, &conn->unix, SOCK_NONBLOCK | flags);
	if (fd >= 0) {
		conn->async.ops = ops;
		conn->async.fd = fd;
		conn->async.accept = acceptor;
		return 0;
	}

	return err;
}

static inline
struct galv_unix_async_conn *
galv_unix_async_conn_from_worker(const struct upoll_worker * __restrict worker)
{
	return containerof(worker, struct galv_unix_async_conn, sync.work);
}

static
int
galv_unix_async_conn_process_connecting(
	struct galv_unix_async_conn * __restrict        conn,
	uint32_t                                        events,
	const struct upoll * __restrict                 poller,
	struct galv_acceptor_ctx __restrict *           context)
{
	galv_unix_assert_intern(conn);
	galv_unix_assert_intern(!(events & ~(EPOLLIN | EPOLLPRI |
	                                     EPOLLOUT |
	                                     EPOLLHUP | EPOLLRDHUP |
	                                     EPOLLERR)));
	galv_unix_assert_intern(poller);

	int ret;

	if (!(events & ~(EPOLLHUP | EPOLLRDHUP | EPOLLERR))) {
		if (events & (EPOLLIN | EPOLLPRI)) {
		}
		if (events & EPOLLOUT) {
		}
	}

	if (events & EPOLLERR) {
	}
	else if (events & EPOLLHUP) {
	}
	else if (events & EPOLLRDHUP) {
	}

	return ret;
}

static
int
galv_unix_async_conn_process_established(
	struct galv_unix_async_conn * __restrict         conn,
	uint32_t                                         events,
	const struct upoll * __restrict                  poller,
	struct galv_acceptor_ctx __restrict * __restrict context)
{
	galv_unix_assert_intern(conn);
	galv_unix_assert_intern(!(events & ~(EPOLLIN | EPOLLPRI |
	                                     EPOLLOUT |
	                                     EPOLLHUP | EPOLLRDHUP |
	                                     EPOLLERR)));
	galv_unix_assert_intern(poller);

	int ret;

	if (!(events & ~(EPOLLHUP | EPOLLRDHUP | EPOLLERR))) {
		if (events & (EPOLLIN | EPOLLPRI)) {
		}
		if (events & EPOLLOUT) {
		}
	}

	if (events & EPOLLERR) {
	}
	else if (events & EPOLLHUP) {
	}
	else if (events & EPOLLRDHUP) {
	}

	return ret;
}

static
int
galv_unix_async_conn_process_recv_shut(
	struct galv_unix_async_conn * __restrict         conn,
	uint32_t                                         events,
	const struct upoll * __restrict                  poller,
	struct galv_acceptor_ctx __restrict * __restrict context)
{
	int ret;

	if (!(events & ~(EPOLLHUP | EPOLLRDHUP | EPOLLERR))) {
		if (events & (EPOLLIN | EPOLLPRI)) {
		}
		if (events & EPOLLOUT) {
		}
	}

	if (events & EPOLLERR) {
	}
	else if (events & EPOLLHUP) {
	}
	else if (events & EPOLLRDHUP) {
	}

	return ret;
}

static
int
galv_unix_async_conn_process_send_shut(
	struct galv_unix_async_conn * __restrict         conn,
	uint32_t                                         events,
	const struct upoll * __restrict                  poller,
	struct galv_acceptor_ctx __restrict * __restrict context)
{
	int ret;

	if (!(events & ~(EPOLLHUP | EPOLLRDHUP | EPOLLERR))) {
		if (events & (EPOLLIN | EPOLLPRI)) {
		}
		if (events & EPOLLOUT) {
		}
	}

	if (events & EPOLLERR) {
	}
	else if (events & EPOLLHUP) {
	}
	else if (events & EPOLLRDHUP) {
	}

	return ret;
}

static
int
galv_unix_async_conn_dispatch(struct upoll_worker * worker,
                              uint32_t              events,
                              const struct upoll *  poller)
{
	galv_unix_assert_intern(worker);
	galv_unix_assert_intern(poller);
	galv_unix_assert_intern(events);
	galv_unix_assert_intern(!(events & ~(EPOLLIN | EPOLLPRI |
	                                     EPOLLOUT |
	                                     EPOLLHUP | EPOLLRDHUP |
	                                     EPOLLERR)));

	struct galv_unix_async_conn * conn;
	struct galv_acceptor_ctx *    ctx;
	int                           ret = 0;

	conn = galv_unix_async_conn_from_worker(worker);
	ctx = conn->accept->ctx;

	switch (conn->async.state) {
	case GALV_CONN_ESTABLISHED_STATE:
		ret = galv_unix_async_conn_process_established(conn,
		                                               events,
		                                               poller,
		                                               ctx);
		break;

	case GALV_CONN_CONNECTING_STATE:
		ret = galv_unix_async_conn_process_connecting(conn,
		                                              events,
		                                              poller,
		                                              ctx);
		break;

	case GALV_CONN_RECVSHUT_STATE:
		ret = galv_unix_async_conn_process_recv_shut(conn,
		                                             events,
		                                             poller,
		                                             ctx);
		break;

	case GALV_CONN_SENDSHUT_STATE:
		ret = galv_unix_async_conn_process_send_shut(conn,
		                                             events,
		                                             poller,
		                                             ctx);
		break;

	case GALV_CONN_CLOSED_STATE:
	default:
		galv_unix_assert_api(0);
	}

	return ret;
}

int
galv_unix_async_conn_poll(struct galv_unix_async_conn * __restrict conn,
                          const struct upoll * __restrict          poller,
                          int                                      flags)
{
	return galv_async_conn_poll(&conn->async,
	                            galv_unix_async_conn_dispatch,
	                            poller,
	                            flags);
}
