/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "galv/unix.h"
#include "conn.h"
#include "acceptor.h"
#include <utils/unsk.h>

/******************************************************************************
 * Asynchronous unix connection handling
 ******************************************************************************/

void
galv_unix_conn_setup(struct galv_unix_conn * __restrict        conn,
                     int                                       fd,
                     struct galv_unix_acceptor * __restrict    acceptor,
                     const struct galv_conn_ops * __restrict   ops,
                     const struct galv_unix_attrs * __restrict attrs)
{
	galv_conn_setup(&conn->base, fd, &acceptor->base, ops);
	conn->attrs = *attrs;
}

/******************************************************************************
 * Asynchronous unix connection acceptor handling
 ******************************************************************************/

#define galv_unix_assert_acceptor_api(_accept) \
	galv_assert_api(_accept); \
	galv_acceptor_assert_iface_api(&(_accept)->base); \
	galv_assert_api((_accept)->bind_size > (sizeof(sa_family_t) + 1)); \
	galv_assert_api(!unsk_is_named_path_ok((_accept)->bind_addr.sun_path))

#define galv_unix_assert_acceptor_intern(_accept) \
	galv_assert_intern(_accept); \
	galv_acceptor_assert_iface_intern(&(_accept)->base); \
	galv_assert_intern((_accept)->bind_size > (sizeof(sa_family_t) + 1)); \
	galv_assert_intern( \
		!unsk_is_named_path_ok((_accept)->bind_addr.sun_path))

int
galv_unix_acceptor_grab(const struct galv_unix_acceptor * __restrict acceptor,
                        struct galv_unix_attrs * __restrict          attrs,
                        int                                          flags)
{
	galv_unix_assert_acceptor_api(acceptor);
	galv_assert_intern(attrs);
	galv_assert_intern(!(flags & ~(SOCK_NONBLOCK | SOCK_CLOEXEC)));

	int       fd;
	socklen_t sz = sizeof(attrs->peer_cred);

	attrs->peer_size = sizeof(attrs->peer_addr);
	fd = unsk_accept(acceptor->base.fd,
	                 &attrs->peer_addr,
	                 &attrs->peer_size,
	                 O_NONBLOCK | flags);
	if (fd < 0)
		return fd;

	unsk_getsockopt(fd, SO_PEERCRED, &attrs->peer_cred, &sz);
	galv_assert_intern(sz == sizeof(attrs->peer_cred));

	return fd;
}

static
int
galv_unix_acceptor_dispatch(struct upoll_worker * worker,
                            uint32_t              events,
                            const struct upoll *  poller)
{
	galv_assert_intern(worker);
	galv_assert_intern(events);
	galv_assert_intern(!(events & ~((uint32_t)(EPOLLIN | EPOLLERR))));
	galv_assert_intern(poller);

	struct galv_unix_acceptor * unacc;

	unacc = containerof(worker, struct galv_unix_acceptor, base.work);
	galv_unix_assert_acceptor_intern(unacc);

	if (events & EPOLLERR) {
		/*
		 * Nothing specific to do as next syscall called with our socket
		 * fd as argument should return the error as errno...
		 */
		galv_notice("unix:acceptor: socket error ignored");

		if (!(events & EPOLLIN))
			return 0;
	}

	/* events & EPOLLIN is true. */
	while (true) {
		int ret;

		ret = galv_acceptor_on_accept_conn(&unacc->base,
		                                   events,
		                                   poller);
		switch (ret) {
		case 0:
			break;

		case -EAGAIN: /* All queued connection requests processed. */
			upoll_enable_watch(&unacc->base.work, EPOLLIN);
			upoll_apply(poller, unacc->base.fd, &unacc->base.work);
			return 0;

		case -EINTR:  /* Interrupted by a signal */
		case -ENOMEM: /* No more memory available. */
			return ret;

		case -EMFILE: /* Too many open files by process. */
		case -ENFILE: /* Too many open files in system. */
			galv_warn("unix:acceptor: "
			          "cannot process connection request: "
			          "%s (%d)",
			          strerror(-ret),
			          -ret);
			return ret;

		default:
			galv_notice("unix:acceptor: "
			            "cannot process connection request: "
			            "%s (%d)",
			            strerror(-ret),
			            -ret);
			break;
		}
	}

	unreachable();
}

int
galv_unix_acceptor_open(struct galv_unix_acceptor * __restrict      acceptor,
                        const char * __restrict                     path,
                        int                                         type,
                        int                                         flags,
                        int                                         backlog,
                        const struct upoll * __restrict             poller,
                        const struct galv_acceptor_ops * __restrict ops,
                        void * __restrict                           context)
{
	galv_assert_api(acceptor);
	galv_assert_api(!unsk_is_named_path_ok(path));
	galv_assert_api((type == SOCK_STREAM) || (type == SOCK_SEQPACKET));
	galv_assert_api(!flags || (flags == SOCK_CLOEXEC));
	galv_assert_api(backlog >= 0);
	galv_assert_api(poller);
	galv_acceptor_assert_ops_api(ops);

	int fd;
	int ret;

	fd = unsk_open(type, SOCK_NONBLOCK | flags);
	if (fd < 0) {
		ret = fd;
		goto err;
	}

	/*
	 * Remove local filesystem pathname if existing.
	 *
	 * This is required since binding a named UNIX socket to a filesystem
	 * entry that already exists will fail with EADDRINUSE error code
	 * (AF_UNIX sockets do not support the SO_REUSEADDR socket option).
	 */
	ret = unsk_unlink(path);
	if (ret)
		goto close;

	/* Build local bind address. */
	acceptor->bind_size =
		(socklen_t)offsetof(typeof(acceptor->bind_addr), sun_path) +
		(socklen_t)unsk_make_named_addr(&acceptor->bind_addr, path);

	/*
	 * Bind to the given local filesystem pathname.
	 *
	 * This will effectively create the filesystem entry according to
	 * current process priviledges.
	 * See "Pathname socket ownership and permissions" section of unix(7)
	 * man page.
	 */
	ret = unsk_bind(fd, &acceptor->bind_addr, acceptor->bind_size);
	if (ret)
		goto close;

	ret = galv_acceptor_turn_on(&acceptor->base,
	                            fd,
	                            backlog,
	                            poller,
	                            galv_unix_acceptor_dispatch,
	                            ops,
	                            context);
	if (ret)
		goto unlink;

	return 0;

unlink:
	/* Support named sockets only. */
	galv_assert_intern(path[0]);
	unlink(path);
close:
	unsk_close(fd);
err:
	galv_err("unix:acceptor: failed to open: %s (%d)",
	         strerror(-ret),
	         -ret);

	return ret;
}

int
galv_unix_acceptor_close(const struct galv_unix_acceptor * __restrict acceptor,
                         const struct upoll * __restrict              poller)
{
	galv_unix_assert_acceptor_api(acceptor);
	galv_assert_api(poller);

	int ret;

	unlink(acceptor->bind_addr.sun_path);

	ret = galv_acceptor_close(&acceptor->base, poller);
	if (ret && (ret != -EINTR))
		galv_notice("unix:acceptor: unexpected close return code: "
		            "%s (%d)",
		            strerror(-ret),
		            -ret);

	return ret;
}

/******************************************************************************
 * Unix connection gate handling
 ******************************************************************************/

#if defined(CONFIG_GALV_UNIX_CONN_GATE)

#include <stroll/hash.h>
#include <stroll/pow2.h>

#define GALV_UNIX_CONN_GATE_HASH_RATIO \
	STROLL_CONCAT(CONFIG_GALV_UNIX_CONN_GATE_HASH_RATIO, U)

#define GALV_UNIX_CONN_GATE_HASH_BITS \
	STROLL_CONCAT(CONFIG_GALV_UNIX_CONN_GATE_HASH_BITS, U)

#define galv_unix_gate_assert_ucred_api(_gate) \
	galv_unix_gate_assert_iface_api(&(_gate)->base); \
	galv_assert_api((_gate)->nr); \
	galv_assert_api((_gate)->cnt <= (_gate)->nr); \
	galv_assert_api((_gate)->nr <= (1U << (_gate)->bits)); \
	galv_assert_api((_gate)->per_pid); \
	galv_assert_api((_gate)->per_pid <= (_gate)->nr); \
	galv_assert_api((_gate)->pids); \
	galv_assert_api((_gate)->per_uid); \
	galv_assert_api((_gate)->per_uid <= (_gate)->nr); \
	galv_assert_api((_gate)->uids)

struct galv_unix_gate_ucred_count {
	struct stroll_hlist_node   hlist;
	union {
		pid_t              pid;
		uid_t              uid;
	};
	unsigned int               val;
};

static
void
galv_unix_gate_ucred_unregister_count(
	struct galv_unix_gate_ucred * __restrict       gate,
	struct galv_unix_gate_ucred_count * __restrict count)
{
	galv_assert_intern(stroll_hlist_node_hashed(&count->hlist));
	galv_assert_intern(count->val);

	if (!--count->val) {
		stroll_hlist_del(&count->hlist);
		stroll_palloc_free(&gate->alloc, count);
	}
}

static
unsigned int
galv_unix_gate_ucred_hash_pid(
	const struct galv_unix_gate_ucred * __restrict gate,
	const struct ucred * __restrict                cred)
{
	unsigned int hash = stroll_hash((unsigned int)cred->pid, gate->bits);

	galv_assert_intern(hash < (1U << gate->bits));

	return hash;
}

static
struct galv_unix_gate_ucred_count *
galv_unix_gate_ucred_find_bypid(
	const struct galv_unix_gate_ucred * __restrict gate,
	const struct ucred * __restrict                cred,
	unsigned int                                   hash)
{
	struct stroll_hlist_node * node;

	stroll_hlist_foreach_node(&gate->pids[hash], node) {
		struct galv_unix_gate_ucred_count * cnt;

		cnt = stroll_hlist_entry(node,
		                         struct galv_unix_gate_ucred_count,
		                         hlist);

		galv_assert_intern(cnt->pid > 0);
		galv_assert_intern(cnt->val);
		galv_assert_intern(cnt->val <= gate->per_pid);
		if (cred->pid == cnt->pid)
			return cnt;
	}

	return NULL;
}

static
void
galv_unix_gate_ucred_track_pid(
	struct galv_unix_gate_ucred * __restrict       gate,
	struct galv_unix_gate_ucred_count * __restrict count,
	const struct ucred * __restrict                cred,
	unsigned int                                   hash)
{
	if (count) {
		galv_assert_intern(stroll_hlist_node_hashed(&count->hlist));
		galv_assert_intern(count->val);

		count->val++;
		return;
	}

	count = (struct galv_unix_gate_ucred_count *)
	        stroll_palloc_alloc(&gate->alloc);
	galv_assert_intern(count);
	count->pid = cred->pid;
	count->val = 1;

	stroll_hlist_add(&gate->pids[hash], &count->hlist);
}

static
void
galv_unix_gate_ucred_untrack_pid(struct galv_unix_gate_ucred * __restrict gate,
                                 const struct ucred * __restrict          cred)
{
	struct galv_unix_gate_ucred_count * cnt;
	unsigned int                        hash;

	hash = galv_unix_gate_ucred_hash_pid(gate, cred);
	cnt = galv_unix_gate_ucred_find_bypid(gate, cred, hash);
	galv_assert_intern(cnt);
	galv_assert_intern(cnt->val);

	galv_unix_gate_ucred_unregister_count(gate, cnt);
}

static
unsigned int
galv_unix_gate_ucred_hash_uid(
	const struct galv_unix_gate_ucred * __restrict gate,
	const struct ucred * __restrict                cred)
{
	unsigned int hash = stroll_hash((unsigned int)cred->uid, gate->bits);

	galv_assert_intern(hash < (1U << gate->bits));

	return hash;
}

static
struct galv_unix_gate_ucred_count *
galv_unix_gate_ucred_find_byuid(
	const struct galv_unix_gate_ucred * __restrict gate,
	const struct ucred * __restrict                cred,
	unsigned int                                   hash)
{
	struct stroll_hlist_node * node;

	stroll_hlist_foreach_node(&gate->uids[hash], node) {
		struct galv_unix_gate_ucred_count * cnt;

		cnt = stroll_hlist_entry(node,
		                         struct galv_unix_gate_ucred_count,
		                         hlist);

		galv_assert_intern(cnt->val);
		galv_assert_intern(cnt->val <= gate->per_uid);
		if (cred->uid == cnt->uid)
			return cnt;
	}

	return NULL;
}

static
void
galv_unix_gate_ucred_track_uid(
	struct galv_unix_gate_ucred * __restrict       gate,
	struct galv_unix_gate_ucred_count * __restrict count,
	const struct ucred * __restrict                cred,
	unsigned int                                   hash)
{
	if (count) {
		galv_assert_intern(stroll_hlist_node_hashed(&count->hlist));
		galv_assert_intern(count->val);

		count->val++;
		return;
	}

	count = (struct galv_unix_gate_ucred_count *)
	        stroll_palloc_alloc(&gate->alloc);
	galv_assert_intern(count);
	count->uid = cred->uid;
	count->val = 1;

	stroll_hlist_add(&gate->uids[hash], &count->hlist);
}

static
void
galv_unix_gate_ucred_untrack_uid(struct galv_unix_gate_ucred * __restrict gate,
                                 const struct ucred * __restrict          cred)
{
	struct galv_unix_gate_ucred_count * cnt;
	unsigned int                        hash;

	hash = galv_unix_gate_ucred_hash_uid(gate, cred);
	cnt = galv_unix_gate_ucred_find_byuid(gate, cred, hash);
	galv_assert_intern(cnt);
	galv_assert_intern(cnt->val);

	galv_unix_gate_ucred_unregister_count(gate, cnt);
}

static
int
galv_unix_gate_ucred_track(struct galv_unix_gate * __restrict        gate,
                           const struct galv_unix_attrs * __restrict attrs)
{
	struct galv_unix_gate_ucred *       ucgt =
		(struct galv_unix_gate_ucred *)gate;
	unsigned int                        pid_hash;
	struct galv_unix_gate_ucred_count * pid_cnt;
	unsigned int                        uid_hash;
	struct galv_unix_gate_ucred_count * uid_cnt;
	const struct ucred *                cred = &attrs->peer_cred;

	galv_unix_gate_assert_ucred_api(ucgt);
	galv_assert_intern(attrs);

	if (ucgt->cnt == ucgt->nr)
		return -EPERM;

	pid_hash = galv_unix_gate_ucred_hash_pid(ucgt, cred);
	pid_cnt = galv_unix_gate_ucred_find_bypid(ucgt, cred, pid_hash);
	if (pid_cnt) {
		galv_assert_intern(pid_cnt->val <= ucgt->per_pid);
		if (pid_cnt->val == ucgt->per_pid)
			return -EPERM;
	}

	uid_hash = galv_unix_gate_ucred_hash_uid(ucgt, cred);
	uid_cnt = galv_unix_gate_ucred_find_byuid(ucgt, cred, uid_hash);
	if (uid_cnt) {
		galv_assert_intern(uid_cnt->val <= ucgt->per_uid);
		if (uid_cnt->val == ucgt->per_uid)
			return -EPERM;
	}

	galv_unix_gate_ucred_track_pid(ucgt, pid_cnt, cred, pid_hash);
	galv_unix_gate_ucred_track_uid(ucgt, uid_cnt, cred, uid_hash);
	ucgt->cnt++;

	return 0;
}

static
void
galv_unix_gate_ucred_untrack(struct galv_unix_gate * __restrict        gate,
                             const struct galv_unix_attrs * __restrict attrs)
{
	struct galv_unix_gate_ucred * ucgt = (struct galv_unix_gate_ucred *)
	                                     gate;
	const struct ucred *          cred = &attrs->peer_cred;

	galv_unix_gate_assert_ucred_api(ucgt);
	galv_assert_intern(attrs);

	galv_unix_gate_ucred_untrack_pid(ucgt, cred);
	galv_unix_gate_ucred_untrack_uid(ucgt, cred);
	ucgt->cnt--;
}

static const struct galv_unix_gate_ops galv_unix_gate_ucred_ops = {
	.track   = galv_unix_gate_ucred_track,
	.untrack = galv_unix_gate_ucred_untrack
};

int
galv_unix_gate_ucred_init(struct galv_unix_gate_ucred * __restrict gate,
                          unsigned int                             max_conn,
                          unsigned int                             max_per_pid,
                          unsigned int                             max_per_uid)
{
	galv_assert_api(gate);
	galv_assert_api(max_conn);
	galv_assert_api(max_per_pid <= max_conn);
	galv_assert_api(max_per_uid <= max_conn);

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
	                       sizeof(struct galv_unix_gate_ucred_count)))
		goto free_uids;

	gate->base.ops = &galv_unix_gate_ucred_ops;
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
galv_unix_gate_ucred_fini(struct galv_unix_gate_ucred * __restrict gate)
{
	galv_unix_gate_assert_ucred_api(gate);

	stroll_hlist_destroy_buckets(gate->pids);
	stroll_hlist_destroy_buckets(gate->uids);
	stroll_palloc_fini(&gate->alloc);
}

#endif /* defined(CONFIG_GALV_UNIX_CONN_GATE) */
