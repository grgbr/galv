/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "common.h"
#include "galv/unix.h"
#include "galv/accept.h"
#include <stroll/alloc.h>

#define GALVSMPL_DISC_PATH           "sock"
#define GALVSMPL_DISC_BACKLOG        16
#define GALVSMPL_DISC_CONN_NR        (32U)
#define GALVSMPL_DISC_PERPID_CONN_NR (2U)
#define GALVSMPL_DISC_PERUID_CONN_NR (16U)
#define GALVSMPL_DISC_BULK_NR        (4U)

static
int
galvsmpl_disc_on_may_xfer(struct galv_conn * __restrict   connection,
                          uint32_t                        events,
                          const struct upoll * __restrict poller)
{
	unsigned int cnt = GALVSMPL_DISC_BULK_NR;
	ssize_t      ret;

	/* Restrict to GALVSMPL_DISC_BULK_NR receive operations in a row. */
	while (cnt--) {
		static char buff[1024];

		ret = galv_conn_recv(connection, buff, sizeof(buff), 0);
		galvsmpl_assert(ret);
		if (ret < 0)
			break;
		galvsmpl_debug("%zd bytes discarded", ret);
	}

	switch (ret) {
	case -EAGAIN:
		galv_conn_watch(connection, EPOLLIN);
		ret = 0;
		break;

	case -ECONNREFUSED:
		ret = galv_conn_on_recv_closed(connection, events, poller);
		break;

	case -EINTR:
	case -ENOMEM:
		break;

	default:
		/* Data left to be consummed or unexpected receive failure. */
		ret = 0;
	}

	return (int)ret;
}

static
int
galvsmpl_disc_on_connecting(struct galv_conn * __restrict   connection,
                            uint32_t                        events,
                            const struct upoll * __restrict poller)
{
	int err;

	err = galv_conn_poll(connection, poller, events, NULL);
	if (!err) {
		galv_conn_switch_state(connection, GALV_CONN_ESTABLISHED_STATE);
		galvsmpl_debug("connection established");

		return 0;
	}

	galvsmpl_perr(-err, "failed to enable connection polling");

	return err;
}

static
int
galvsmpl_disc_on_send_closed(struct galv_conn * __restrict   connection,
                             uint32_t                        events,
                             const struct upoll * __restrict poller)
{
	galvsmpl_debug("connection transmit end shut down: flushing...");

	if (events & EPOLLIN)
		return galvsmpl_disc_on_may_xfer(connection, events, poller);

	return 0;
}

static
int
galvsmpl_disc_on_recv_closed(struct galv_conn * __restrict   connection,
                             uint32_t                        events __unused,
                             const struct upoll * __restrict poller __unused)
{
	galvsmpl_debug("connection receive end shut down: closing...");

	galv_conn_launch_close(connection);

	return 0;
}

static
int
galvsmpl_disc_on_error(struct galv_conn * __restrict   connection __unused,
                       uint32_t                        events __unused,
                       const struct upoll * __restrict poller __unused)
{
	galvsmpl_debug("unexpected connection socket error");

	return 0;
}

static
void
galvsmpl_disc_on_closing(struct galv_conn * __restrict   connection,
                         const struct upoll * __restrict poller)
{
	galv_conn_unpoll(connection, poller);
}

static const struct galv_conn_ops galvsmpl_disc_conn_ops = {
	.on_may_xfer    = galvsmpl_disc_on_may_xfer,
	.on_connecting  = galvsmpl_disc_on_connecting,
	.on_send_closed = galvsmpl_disc_on_send_closed,
	.on_recv_closed = galvsmpl_disc_on_recv_closed,
	.on_closing     = galvsmpl_disc_on_closing,
	.on_error       = galvsmpl_disc_on_error
};

int
main(void)
{
	struct stroll_alloc *   alloc;
	struct galv_unix_adopt  adopt;
	struct upoll            poll;
	struct galv_repo        repo = GALV_REPO_INIT(repo,
	                                              GALVSMPL_DISC_CONN_NR);
	struct galv_accept      accept;
	struct galvsmpl_sigchan sigs;
	int                     ret;

	galvsmpl_init();

	alloc = galv_unix_create_conn_alloc(GALVSMPL_DISC_CONN_NR);
	if (!alloc) {
		ret = -errno;
		galvsmpl_perr(errno, "failed to create UNIX socket allocator");
		goto out;
	}

	ret = galv_unix_adopt_open(&adopt,
	                           GALVSMPL_DISC_PATH,
	                           SOCK_STREAM,
	                           SOCK_CLOEXEC,
	                           alloc,
	                           GALV_GATE_DUMMY);
	if (ret) {
		galvsmpl_perr(errno, "failed to create UNIX socket adopter");
		goto destroy_alloc;
	}

	/* Max number of connections + 1 for acceptor / adopter socket. */
	ret = upoll_open(&poll, GALVSMPL_DISC_CONN_NR + 1);
	if (ret) {
		galvsmpl_perr(-ret, "failed to open poller");
		goto close_adopt;
	}

	ret = galv_accept_open(&accept,
	                       &repo,
	                       (struct galv_adopt *)&adopt,
	                       GALVSMPL_DISC_BACKLOG,
	                       &galvsmpl_disc_conn_ops,
	                       SOCK_CLOEXEC,
	                       &poll);
	if (ret) {
		galvsmpl_perr(-ret, "failed to open socket acceptor");
		goto close_poll;
	}

	ret = galvsmpl_open_sigchan(&sigs, &poll);
	if (ret)
		goto close_accept;

	do {
		ret = upoll_process(&poll, -1);
	} while (!ret || (ret == -EINTR));
	if (ret == -ESHUTDOWN)
		ret = 0;

	galv_accept_halt(&accept, &poll);

	galvsmpl_close_sigchan(&sigs, &poll);

close_accept:
	galv_accept_close(&accept, &poll);
close_poll:
	upoll_close(&poll);
close_adopt:
	if (!ret)
		ret = galv_unix_adopt_close(&adopt);
	else
		galv_unix_adopt_close(&adopt);
destroy_alloc:
	stroll_alloc_destroy(alloc);
out:
	galvsmpl_fini();

	return !ret ? EXIT_SUCCESS : EXIT_FAILURE;
}
