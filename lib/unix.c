/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "unix.h"
#include <utils/sock.h>
#include <stroll/page.h>
#include <stroll/hlist.h>
#include <utils/string.h>

#if defined(CONFIG_GALV_DEBUG)

static
void
galv_unix_conn_debug(const struct galv_unix_endpt * __restrict endpoint,
                     const char * __restrict                   message)
{
	galv_unix_assert_addr_intern(&endpoint->addr);

	char                          str[UNSK_NAMED_PATH_MAX];
	const struct galv_unix_addr * addr = &endpoint->addr;
	const struct ucred *          cred = &endpoint->cred;

	galv_debug("unix: %s [addr:%s pid:%d uid:%d]",
	           message,
	           addr->size ? unsk_make_addr_string(str,
	                                              &addr->data,
	                                              addr->size)
	                      : "??",
	           cred->pid,
	           cred->uid);
}

#else  /* !defined(CONFIG_GALV_DEBUG) */

static
void
galv_unix_conn_debug(
	const struct galv_unix_endpt * __restrict endpoint __unused,
	const char * __restrict                   message __unused)
{
}

#endif /* defined(CONFIG_GALV_DEBUG) */

void
galv_unix_make_named_addr(struct galv_unix_addr * __restrict address,
                          const char * __restrict            path)
{
	galv_assert_api(address);
	galv_assert_api(!unsk_is_named_path_ok(path));

	socklen_t len;

	len = unsk_make_named_addr(&address->data, path);
	galv_assert_intern(len > 0);

	address->size = len;
}

/******************************************************************************
 * Unix (client-side) connection binder handling
 ******************************************************************************/

static
int
_galv_unix_binder_connect_clnt(
	const struct galv_binder * __restrict binder __unused,
	struct galv_unix_conn * __restrict    client)
{
	const struct galv_unix_addr * addr = &client->peer.addr;
	int                           ret;
	char                          str[UNSK_NAMED_PATH_MAX];

	galv_assert_intern(addr->data.sun_family == AF_UNIX);
	galv_assert_intern(unsk_is_named_addr(&addr->data, addr->size));

	ret = unsk_connect(client->base.fd, &addr->data, addr->size);
	galv_assert_intern(ret <= 0);
	if (!ret)
		return 0;

	if (ret == -EAGAIN) {
		/*
		 * Nonblocking UNIX domain sockets return -EAGAIN (instead of
		 * -EINPROGRESS when the connection cannot be completed
		 * immediately.
		 */
		galv_debug("unix: differing client connection establishment to"
		           "[addr:%s]..",
		           unsk_make_addr_string(str, &addr->data, addr->size));
		return -EINPROGRESS;
	}

	galv_ratelim_pinfo(-ret,
	                   "unix: cannot establish client connection",
	                   " to [addr:%s]",
	                   unsk_make_addr_string(str, &addr->data, addr->size));

	/*
	 * When no one is listening, i.e, no (named) socket file is existing,
	 * connect(2) on a UNIX socket returns ENOENT.
	 * Make error code consistent with other socket types by returning
	 * ECONNREFUSED.
	 */
	return (ret == -ENOENT) ? -ECONNREFUSED : ret;
}

static
int
galv_unix_binder_connect_clnt(
	const struct galv_binder * __restrict binder __unused,
	struct galv_conn * __restrict         client,
	const struct sockaddr * __restrict    peer)
{
	struct galv_unix_conn *       clnt = (struct galv_unix_conn *)client;
	const struct galv_unix_addr * addr = (const struct galv_unix_addr *)
	                                     peer;

	galv_assert_api(addr->data.sun_family == AF_UNIX);
	galv_assert_api(unsk_is_named_addr(&addr->data, addr->size));
	clnt->peer.addr = *addr;

	return _galv_unix_binder_connect_clnt(binder, clnt);
}

static
void
galv_unix_binder_on_connected(
	const struct galv_binder * __restrict binder __unused,
	struct galv_conn * __restrict         client)
{
	struct galv_unix_conn *       clnt = (struct galv_unix_conn *)client;
	const struct galv_unix_addr * addr = &clnt->peer.addr;
	struct ucred *                cred = &clnt->peer.cred;
	socklen_t                     sz = sizeof(*cred);
	char                          str[UNSK_NAMED_PATH_MAX];

	galv_assert_intern(addr->data.sun_family == AF_UNIX);
	galv_assert_intern(unsk_is_named_addr(&addr->data, addr->size));

	unsk_getsockopt(client->fd, SO_PEERCRED, cred, &sz);
	galv_assert_intern(sz == sizeof(*cred));

	galv_ratelim_info("unix: client connection established",
	                  " to [addr:%s pid:%d uid:%d]",
	                   unsk_make_addr_string(str, &addr->data, addr->size),
	                   cred->pid,
	                   cred->uid);
}

static
int
galv_unix_binder_reconnect_clnt(
	const struct galv_binder * __restrict binder __unused,
	struct galv_conn * __restrict         client,
	const struct upoll * __restrict       poller)
{
	galv_assert_intern((binder->sock_type == SOCK_STREAM) ||
	                   (binder->sock_type == SOCK_SEQPACKET));

	struct galv_unix_conn * clnt = (struct galv_unix_conn *)client;
	int                     ret;
	const char *            msg;

	/*
	 * As stated into connect(2), we should consider the state of the socket
	 * as unspecified in case of failure: open a new socket, close the old
	 * one and try to perform the connect(2) again.
	 *
	 * Note that we prefer to open the new socket first and close the old
	 * one afterward so that a potential socket(2) failure does not leave
	 * the whole Galv internal state machine with no valid file descriptor
	 * at all upon return from this function (galv_coupler, galv_conn and
	 * galv_unix_conn highly depend on its presence).
	 */

	/*
	 * Open the new socket first using the flags that were passed at initial
	 * opening time...
	 */
	ret = unsk_open(binder->sock_type,
	                SOCK_NONBLOCK | etux_sock_getfd(client->fd));
	if (ret < 0) {
		msg = "failed to reopen";
		goto err;
	}

	/*
	 *  ... then close the old one to keep a valid file descriptor in
	 * `client->fd' in case of failure.
	 *
	 * In addition, we *MUST* also remove the old file descriptor from the
	 * epoll(7) interest list.
	 * See section `Questions and answers' of epoll(7) man page to
	 * understand why.
	 */
	upoll_unregister(poller, client->fd);
	unsk_close(client->fd);
	client->fd = ret;

	/* Connect(2) again using currently stored remote peer address. */
	ret = _galv_unix_binder_connect_clnt(binder, clnt);
	if (ret)
		goto err;

	return 0;

err:
	if (ret != -ENOMEM)
		galv_ratelim_pnotice(ret,
		                     "unix: cannot reconnect client connection",
		                     ": %s",
		                     msg);
	return ret;
}

static
struct galv_conn *
galv_unix_binder_create_clnt(struct galv_binder * __restrict         binder,
                             const struct galv_conn_ops * __restrict operations,
                             int                                     flags,
                             struct galv_coupler * __restrict        coupler)
{
	galv_assert_intern((binder->sock_type == SOCK_STREAM) ||
	                   (binder->sock_type == SOCK_SEQPACKET));

	int                     sk;
	int                     err;
	struct galv_unix_conn * clnt;
	const char *            msg;

	sk = unsk_open(binder->sock_type, SOCK_NONBLOCK | flags);
	if (sk < 0) {
		if (sk == -ENOMEM) {
			errno = ENOMEM;
			return NULL;
		}

		err = -sk;
		msg = "failed to open";
		goto err;
	}

	/* Allocate UNIX connection. */
	clnt = stroll_falloc_alloc(&binder->alloc);
	if (!clnt) {
		err = errno;
		unsk_close(sk);
		if (err == ENOMEM)
			return NULL;

		msg = "failed to allocate";
		goto err;
	}

	galv_conn_setup(&clnt->base,
	                sk,
	                operations,
	                (struct galv_dispatch *)coupler);
	clnt->peer.addr.size = 0;
	clnt->peer.cred.pid = 0;
	clnt->peer.cred.uid = 0;

	galv_debug("unix: client connection created");

	return &clnt->base;

err:
	galv_ratelim_pnotice(err,
	                     "unix: cannot create client connection",
	                     ": %s",
	                     msg);
	errno = err;

	return NULL;
}

static
int
galv_unix_binder_destroy_clnt(struct galv_binder * __restrict binder,
                              struct galv_conn * __restrict   client)
{
	int ret;

	ret = unsk_close(client->fd);
	if (ret && (ret != -EINTR))
		galv_ratelim_pnotice(-ret,
		                     "unix: failed to close client socket",
		                     "");

	stroll_falloc_free(&binder->alloc, client);

	galv_unix_conn_debug(&((const struct galv_unix_conn *)client)->peer,
	                     "client connection destroyed");

	return ret;
}

static const struct galv_binder_ops galv_unix_binder_ops = {
	.create_clnt    = galv_unix_binder_create_clnt,
	.connect_clnt   = galv_unix_binder_connect_clnt,
	.reconnect_clnt = galv_unix_binder_reconnect_clnt,
	.on_connected   = galv_unix_binder_on_connected,
	.destroy_clnt   = galv_unix_binder_destroy_clnt
};

void
galv_unix_binder_open(struct galv_binder * __restrict binder,
                      int                             sock_type,
                      unsigned int                    max_conn)
{
	galv_assert_api((sock_type == SOCK_STREAM) ||
	                (sock_type == SOCK_SEQPACKET));

	galv_binder_open(binder,
	                 &galv_unix_binder_ops,
	                 sock_type,
	                 max_conn,
	                 sizeof(struct galv_conn));

	galv_debug("unix: binder opened");
}

void
galv_unix_binder_close(struct galv_binder * __restrict binder)
{
	galv_binder_close(binder);

	galv_debug("unix: binder closed");
}

/******************************************************************************
 * UNIX (service-side) socket adopter handling
 ******************************************************************************/

static
int
galv_unix_accept(int                                 fd,
                 struct galv_unix_endpt * __restrict peer,
                 int                                 flags)
{
	galv_assert_intern(fd >= 0);
	galv_assert_intern(peer);
	galv_assert_intern(!(flags & ETUX_SOCK_ACCEPT_INVALID_FLAGS));

	int       sk;
	socklen_t sz = sizeof(peer->cred);

	peer->addr.size = sizeof(peer->addr.data);
	sk = unsk_accept(fd, &peer->addr.data, &peer->addr.size, flags);
	if (sk < 0)
		return sk;

	unsk_getsockopt(sk, SO_PEERCRED, &peer->cred, &sz);
	galv_assert_intern(sz == sizeof(peer->cred));

	return sk;
}

static
struct galv_conn *
galv_unix_adopt_create_conn(struct galv_adopt * __restrict          adopter,
                            const struct galv_conn_ops * __restrict operations,
                            int                                     flags,
                            struct galv_accept * __restrict         acceptor)
{
	galv_unix_assert_adopt_api((const struct galv_unix_adopt *)adopter);
	galv_conn_assert_ops_intern(operations);
	galv_assert_intern(!(flags & ETUX_SOCK_ACCEPT_INVALID_FLAGS));
	galv_accept_assert_intern(acceptor);

	struct galv_unix_endpt  peer;
	int                     fd;
	struct galv_unix_conn * unc;
	int                     err;
	const char *            msg;

	/*
	 * As we are called from an asynchronous context, try to accept
	 * connection request first to prevent from useless allocations in cases
	 * where no (kernel-side) connection requests are pending.
	 */
	fd = galv_unix_accept(adopter->fd, &peer, flags);
	if (fd < 0) {
		if ((fd == -EAGAIN) || (fd == -ENOMEM)) {
			errno = -fd;
			return NULL;
		}

		err = -fd;
		msg = "failed to accept";
		goto err;
	}

	/* Allocate UNIX connection. */
	unc = stroll_falloc_alloc(&adopter->alloc);
	if (!unc) {
		err = errno;
		unsk_close(fd);
		if (err == ENOMEM)
			return NULL;

		msg = "failed to allocate";
		goto err;
	}

	/* Setup connection internal state. */
	galv_conn_setup(&unc->base,
	                fd,
	                operations,
	                (struct galv_dispatch *)acceptor);
	unc->peer = peer;

	galv_unix_conn_debug(&unc->peer, "service connection created");

	return &unc->base;

err:
	galv_ratelim_pnotice(err,
	                     "unix: cannot create service connection",
	                     ": %s",
	                     msg);
	errno = err;

	return NULL;
}

static
int
galv_unix_adopt_destroy_conn(struct galv_adopt * __restrict adopter,
                             struct galv_conn * __restrict  connection)
{
	galv_unix_assert_adopt_api((const struct galv_unix_adopt *)adopter);
	galv_conn_assert_intern(connection);

	int ret;

	ret = unsk_close(connection->fd);
	if (ret && (ret != -EINTR))
		galv_ratelim_pnotice(-ret,
		                     "unix: failed to close service socket",
		                     "");
	stroll_falloc_free(&adopter->alloc, connection);

	galv_unix_conn_debug(&((const struct galv_unix_conn *)connection)->peer,
	                     "service connection destroyed");

	return ret;
}

static const struct galv_adopt_ops galv_unix_adopt_ops = {
	.create_conn  = galv_unix_adopt_create_conn,
	.destroy_conn = galv_unix_adopt_destroy_conn
};

int
galv_unix_adopt_config_path(struct galv_unix_adopt_conf * __restrict config,
                            const char * __restrict                  string)
{
	galv_assert_api(config);
	galv_assert_api(string);

	int err;

	err = unsk_is_named_path_ok(string);
	if (!err) {
		config->bind_path = string;
		return 0;
	}

	return err;
}

int
galv_unix_adopt_config_max_conn(struct galv_unix_adopt_conf * __restrict config,
                                const char * __restrict                  string)
{
	galv_assert_api(config);
	galv_assert_api(string);

	return ustr_parse_uint_range(string, &config->max_conn, 1, UINT_MAX);
}

void
galv_unix_adopt_config(struct galv_unix_adopt_conf * __restrict config,
                       int                                      sock_type,
                       int                                      sock_flags,
                       const char * __restrict                  bind_path,
                       unsigned int                             max_conn)
{
	galv_assert_api(config);
	galv_assert_api((sock_type == SOCK_STREAM) ||
	                (sock_type == SOCK_SEQPACKET));
	galv_assert_api(!(sock_flags & ETUX_SOCK_ACCEPT_INVALID_FLAGS));
	galv_assert_api(!unsk_is_named_path_ok(bind_path));
	galv_assert_api(max_conn);

	config->sock_type = sock_type;
	config->sock_flags = sock_flags;
	config->bind_path = bind_path;
	config->max_conn = max_conn;
}

int
galv_unix_adopt_open(struct galv_unix_adopt * __restrict            adopter,
                     struct galv_gate * __restrict                  gate,
                     const struct galv_unix_adopt_conf * __restrict config)
{
	galv_assert_api(adopter);
	galv_gate_assert_api(gate);
	galv_unix_assert_adopt_conf_api(config);

	int          fd;
	int          ret;
	const char * msg __unused;

	fd = unsk_open(config->sock_type, SOCK_NONBLOCK | config->sock_flags);
	if (fd < 0) {
		ret = fd;
		msg = "failed to create socket";
		goto err;
	}

	/*
	 * Remove local filesystem pathname if existing.
	 *
	 * This is required since binding a named UNIX socket to a filesystem
	 * entry that already exists will fail with EADDRINUSE error code
	 * (AF_UNIX sockets do not support the SO_REUSEADDR socket option).
	 */
	ret = unsk_unlink(config->bind_path);
	if (ret) {
		msg = "failed to unlink pathname";
		goto close;
	}

	/* Build local bind address. */
	adopter->bind_addr.size =
		(socklen_t)offsetof(typeof(adopter->bind_addr.data), sun_path) +
		(socklen_t)unsk_make_named_addr(&adopter->bind_addr.data,
		                                config->bind_path);

	/*
	 * Bind to the given local filesystem pathname.
	 *
	 * This will effectively create the filesystem entry according to
	 * current process priviledges.
	 * See "Pathname socket ownership and permissions" section of unix(7)
	 * man page.
	 */
	ret = unsk_bind(fd, &adopter->bind_addr.data, adopter->bind_addr.size);
	if (ret) {
		msg = "failed to bind to local pathname";
		goto close;
	}

	galv_adopt_setup(&adopter->base,
	                 &galv_unix_adopt_ops,
	                 fd,
	                 config->max_conn,
	                 sizeof(struct galv_unix_conn),
	                 gate);

	galv_debug("unix: adopter opened");

	return 0;

close:
	unsk_close(fd);
err:
	galv_perr(-ret, "unix: cannot open adopter: %s", msg);

	return ret;
}

int
galv_unix_adopt_close(struct galv_unix_adopt * __restrict adopter)
{
	galv_unix_assert_adopt_api(adopter);

	int ret;

	unlink(adopter->bind_addr.data.sun_path);

	ret = galv_adopt_close(&adopter->base);
	if (!ret || (ret == -EINTR)) {
		galv_debug("unix: adopter closed");
		return 0;
	}

	galv_pnotice(-ret, "unix: cannot close adopter");

	return ret;
}

/******************************************************************************
 * Unix connection gate handling
 ******************************************************************************/

#if defined(CONFIG_GALV_GATE)

#include <stroll/hash.h>
#include <stroll/pow2.h>

#define GALV_UNIX_GATE_HASH_RATIO \
	STROLL_CONCAT(CONFIG_GALV_UNIX_GATE_HASH_RATIO, U)

#define GALV_UNIX_GATE_HASH_BITS \
	STROLL_CONCAT(CONFIG_GALV_UNIX_GATE_HASH_BITS, U)

#define galv_unix_gate_assert_ucred_api(_gate) \
	galv_gate_assert_api(&(_gate)->base); \
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
		stroll_falloc_free(&gate->alloc, count);
	}
}

static
unsigned int
galv_unix_gate_ucred_hash_pid(
	const struct galv_unix_gate_ucred * __restrict gate,
	const struct ucred * __restrict                credentials)
{
	unsigned int hash = stroll_hash((unsigned int)credentials->pid,
	                                gate->bits);

	galv_assert_intern(hash < (1U << gate->bits));

	return hash;
}

static
struct galv_unix_gate_ucred_count *
galv_unix_gate_ucred_find_bypid(
	const struct galv_unix_gate_ucred * __restrict gate,
	const struct ucred * __restrict                credentials,
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
		if (credentials->pid == cnt->pid)
			return cnt;
	}

	return NULL;
}

static
struct galv_unix_gate_ucred_count *
galv_unix_gate_ucred_create_pid_count(
	struct galv_unix_gate_ucred * __restrict gate,
	const struct ucred * __restrict          credentials,
	unsigned int                             hash)
{
	struct galv_unix_gate_ucred_count * cnt;

	cnt = stroll_falloc_alloc(&gate->alloc);
	if (!cnt)
		return NULL;

	cnt->pid = credentials->pid;
	cnt->val = 0;

	stroll_hlist_add(&gate->pids[hash], &cnt->hlist);

	return cnt;
}

static
void
galv_unix_gate_ucred_untrack_pid(
	struct galv_unix_gate_ucred * __restrict gate,
	const struct ucred * __restrict          credentials)
{
	struct galv_unix_gate_ucred_count * cnt;
	unsigned int                        hash;

	hash = galv_unix_gate_ucred_hash_pid(gate, credentials);
	cnt = galv_unix_gate_ucred_find_bypid(gate, credentials, hash);
	galv_assert_intern(cnt);
	galv_assert_intern(cnt->val);

	galv_unix_gate_ucred_unregister_count(gate, cnt);
}

static
unsigned int
galv_unix_gate_ucred_hash_uid(
	const struct galv_unix_gate_ucred * __restrict gate,
	const struct ucred * __restrict                credentials)
{
	unsigned int hash = stroll_hash((unsigned int)credentials->uid,
	                                gate->bits);

	galv_assert_intern(hash < (1U << gate->bits));

	return hash;
}

static
struct galv_unix_gate_ucred_count *
galv_unix_gate_ucred_find_byuid(
	const struct galv_unix_gate_ucred * __restrict gate,
	const struct ucred * __restrict                credentials,
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
		if (credentials->uid == cnt->uid)
			return cnt;
	}

	return NULL;
}

static
struct galv_unix_gate_ucred_count *
galv_unix_gate_ucred_create_uid_count(
	struct galv_unix_gate_ucred * __restrict gate,
	const struct ucred * __restrict          credentials,
	unsigned int                             hash)
{
	struct galv_unix_gate_ucred_count * cnt;

	cnt = stroll_falloc_alloc(&gate->alloc);
	if (!cnt)
		return NULL;

	cnt->uid = credentials->uid;
	cnt->val = 0;

	stroll_hlist_add(&gate->uids[hash], &cnt->hlist);

	return  cnt;
}

static
void
galv_unix_gate_ucred_untrack_uid(
	struct galv_unix_gate_ucred * __restrict gate,
	const struct ucred * __restrict          credentials)
{
	struct galv_unix_gate_ucred_count * cnt;
	unsigned int                        hash;

	hash = galv_unix_gate_ucred_hash_uid(gate, credentials);
	cnt = galv_unix_gate_ucred_find_byuid(gate, credentials, hash);
	galv_assert_intern(cnt);
	galv_assert_intern(cnt->val);

	galv_unix_gate_ucred_unregister_count(gate, cnt);
}

static
int
galv_unix_gate_ucred_track(struct galv_gate * __restrict       gate,
                           const struct galv_conn * __restrict connection)
{
	galv_unix_gate_assert_ucred_api((struct galv_unix_gate_ucred *)gate);
	galv_unix_assert_conn_api((const struct galv_unix_conn *)connection);

	struct galv_unix_gate_ucred *       ucgt =
		(struct galv_unix_gate_ucred *)gate;
	unsigned int                        pid_hash;
	struct galv_unix_gate_ucred_count * pid_cnt;
	unsigned int                        uid_hash;
	struct galv_unix_gate_ucred_count * uid_cnt;
	const struct ucred *                cred;

	if (ucgt->cnt == ucgt->nr)
		return -EPERM;

	cred = &((const struct galv_unix_conn *)connection)->peer.cred;

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

	if (!pid_cnt) {
		pid_cnt = galv_unix_gate_ucred_create_pid_count(ucgt,
		                                                cred,
		                                                pid_hash);
		if (!pid_cnt)
			return -errno;
	}
	galv_assert_intern(stroll_hlist_node_hashed(&pid_cnt->hlist));
	pid_cnt->val++;

	if (!uid_cnt) {
		uid_cnt = galv_unix_gate_ucred_create_uid_count(ucgt,
		                                                cred,
		                                                uid_hash);
		if (!uid_cnt) {
			int err = -errno;

			galv_unix_gate_ucred_unregister_count(ucgt, pid_cnt);
			return err;
		}
	}
	galv_assert_intern(stroll_hlist_node_hashed(&uid_cnt->hlist));
	uid_cnt->val++;

	ucgt->cnt++;

	return 0;
}

static
void
galv_unix_gate_ucred_untrack(struct galv_gate * __restrict       gate,
                             const struct galv_conn * __restrict connection)
{
	galv_unix_gate_assert_ucred_api((struct galv_unix_gate_ucred *)gate);
	galv_unix_assert_conn_api((const struct galv_unix_conn *)connection);

	struct galv_unix_gate_ucred * ucgt = (struct galv_unix_gate_ucred *)
	                                     gate;
	const struct ucred *          cred = &((const struct galv_unix_conn *)
	                                       connection)->peer.cred;

	galv_unix_gate_ucred_untrack_pid(ucgt, cred);
	galv_unix_gate_ucred_untrack_uid(ucgt, cred);
	ucgt->cnt--;
}

static const struct galv_gate_ops galv_unix_gate_ucred_ops = {
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


	bits = stroll_pow2_up((max_conn * 100) / GALV_UNIX_GATE_HASH_RATIO);
	bits = stroll_min(bits, GALV_UNIX_GATE_HASH_BITS);

	pids = stroll_hlist_create_buckets(bits);
	if (!pids)
		return -ENOMEM;

	uids = stroll_hlist_create_buckets(bits);
	if (!uids)
		goto free_pids;

	stroll_falloc_init_block_size(&gate->alloc,
	                              2 * max_conn,
	                              sizeof(struct galv_unix_gate_ucred_count),
	                              stroll_page_size());

	galv_gate_init(&gate->base, &galv_unix_gate_ucred_ops);
	gate->cnt = 0;
	gate->nr = max_conn;
	gate->bits = bits;
	gate->per_pid = max_per_pid;
	gate->pids = pids;
	gate->per_uid = max_per_uid;
	gate->uids = uids;

	return 0;

free_pids:
	stroll_hlist_destroy_buckets(pids);

	return -ENOMEM;
}

static
void
galv_unix_gate_destroy_counts(struct galv_unix_gate_ucred * __restrict gate,
                              struct stroll_hlist * __restrict         buckets)
{
	unsigned int                        buck;
	struct galv_unix_gate_ucred_count * cnt;
	struct stroll_hlist_node *          tmp;

	stroll_hlist_foreach_buckets_entry_safe(buckets,
	                                        gate->bits,
	                                        buck,
	                                        cnt,
	                                        hlist,
	                                        tmp)
		stroll_falloc_free(&gate->alloc, cnt);

	stroll_hlist_destroy_buckets(buckets);
}

void
galv_unix_gate_ucred_fini(struct galv_unix_gate_ucred * __restrict gate)
{
	galv_unix_gate_assert_ucred_api(gate);

	galv_unix_gate_destroy_counts(gate, gate->pids);
	galv_unix_gate_destroy_counts(gate, gate->uids);
	stroll_falloc_fini(&gate->alloc);
}

#endif /* defined(CONFIG_GALV_GATE) */
