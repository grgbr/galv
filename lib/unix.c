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
	galv_assert_api((_accept)->bind_size > \
	                     (sizeof(sa_family_t) + 1)); \
	galv_assert_api( \
		!unsk_is_named_path_ok((_accept)->bind_addr.sun_path))

#define galv_unix_assert_acceptor_intern(_accept) \
	galv_assert_intern(_accept); \
	galv_acceptor_assert_iface_intern(&(_accept)->base); \
	galv_assert_intern((_accept)->bind_size > \
	                        (sizeof(sa_family_t) + 1)); \
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
	                 flags);
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
