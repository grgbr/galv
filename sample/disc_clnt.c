/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2026 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "common.h"
#include "galv/unix.h"
#include "galv/coupler.h"
#include "galv/client.h"

#define GALVSMPL_DISC_CLNT_PATH    "sock"
#define GALVSMPL_DISC_CLNT_CONN_NR (8U)
#define GALVSMPL_DISC_CLNT_BULK_NR (4U)
#define GALVSMPL_DISC_CLNT_TRIES   (-3)
#define GALVSMPL_DISC_CLNT_MSECS   (500)

static char galvsmpl_disc_clnt_buffer[1024];

static
int
galvsmpl_disc_clnt_send(struct galv_conn * connection)
{
	unsigned int cnt = GALVSMPL_DISC_CLNT_BULK_NR;
	ssize_t      ret;
	size_t       bytes = 0;

	/* Restrict to GALVSMPL_DISC_CLNT_BULK_NR send operations in a row. */
	do {
		ret = galv_conn_send(connection,
		                     galvsmpl_disc_clnt_buffer,
		                     sizeof(galvsmpl_disc_clnt_buffer),
		                     MSG_NOSIGNAL);
		galvsmpl_assert(ret);
		if (ret > 0)
			bytes += (size_t)ret;
	} while ((ret == sizeof(galvsmpl_disc_clnt_buffer)) && --cnt);

	if (bytes) {
		unsigned long sum = (unsigned long)
		                    galv_conn_context(connection);

		galv_conn_set_context(connection,
		                      (void *)(sum + (unsigned long)bytes));
		galvsmpl_debug("%zu bytes sent", bytes);
	}

	if (ret == sizeof(galvsmpl_disc_clnt_buffer))
		return 0;
	else if ((ret > 0) || (ret == -EAGAIN))
		return -EAGAIN;
	else
		return (int)ret;
}

static
int
galvsmpl_disc_process_established_clnt(struct upoll_worker * worker,
                                       uint32_t              events,
                                       const struct upoll *  poller)
{
	galvsmpl_assert(!(events &
	                  ~((uint32_t)
	                    (EPOLLRDHUP | EPOLLOUT | EPOLLHUP | EPOLLERR))));

	struct galv_conn * clnt = galv_conn_from_worker(worker);
	int                ret;

	if (events & EPOLLERR) {
		ret = galv_conn_async_error(clnt);
		galvsmpl_pwarn(ret, "asynchronous socket error");
	}

	if (events & (EPOLLRDHUP | EPOLLHUP)) {
		galvsmpl_info("peer connection shut down");
		goto close;
	}

	if (events & EPOLLOUT)
		galv_conn_unwatch(clnt, EPOLLOUT);

	ret = galvsmpl_disc_clnt_send(clnt);
	switch (ret) {
	case 0:
		break;

STROLL_IGNORE_WARN("-Wimplicit-fallthrough")
	case -ENOBUFS:
		galvsmpl_info("transient outgoing connection congestion");
STROLL_RESTORE_WARN
	case -EAGAIN:
		galv_conn_watch(clnt, EPOLLOUT);
		ret = 0;
		break;

	case -EPIPE:
		galvsmpl_assert(0);
	case -ECONNRESET:
		/* Connection reset by peer. */
		galvsmpl_info("outgoing connection shut down");
		goto close;

	case -EINTR:
	case -ENOMEM:
		return ret;

	default:
		galvsmpl_perr(-(int)ret, "unexpected emit failure");
		ret = 0;
	}

	galv_conn_apply_watch(clnt, poller);

	return ret;

close:
	return galv_conn_close(clnt, poller);
}

static
int
galvsmpl_disc_on_clnt_bound(struct galv_conn *   connection,
                            const struct upoll * poller)
{
	galv_conn_set_context(connection, (void *)0);
	galv_conn_switch_state(connection,
	                       GALV_CONN_ESTABLISHED_STATE,
	                       galvsmpl_disc_process_established_clnt);
	galv_conn_reset_watch(connection, poller, EPOLLOUT | EPOLLRDHUP);
	galvsmpl_info("connection established");

	return 0;
}

static
void
galvsmpl_disc_close_clnt(struct galv_conn *   connection,
                         const struct upoll * poller __unused)
{
	unsigned long sum = (unsigned long)galv_conn_context(connection);

	galvsmpl_info("sent %lu bytes overall", sum);
}

static const struct galv_conn_ops galvsmpl_disc_clnt_ops = {
	.on_bound = galvsmpl_disc_on_clnt_bound,
	.halt     = galv_conn_close,
	.close    = galvsmpl_disc_close_clnt
};

static
int
galvsmpl_disc_clnt_process_round(struct upoll * poller)
{
	int msecs = etux_timer_issue_msec();
	int ret;

	ret = upoll_wait(poller, msecs);
	if (!msecs || (ret == -ETIME))
		etux_timer_run();

	if (ret > 0)
		return upoll_dispatch(poller, (unsigned int)ret);

	return (ret != -ETIME) ? ret : 0;
}

static
int
galvsmpl_disc_clnt_loop(struct upoll * poller, struct galv_repo * repository)
{
	struct galvsmpl_sigchan sigs;
	int                     ret;

	ret = galvsmpl_open_sigchan(&sigs, poller);
	if (ret)
		return ret;

	do {
		ret = galvsmpl_disc_clnt_process_round(poller);
	} while (!ret || (ret == -EINTR));
	switch (ret) {
	case -ESHUTDOWN:
	case -EINTR:
		ret = 0;
		break;
	}

	galv_conn_repo_close(repository, poller);
	galvsmpl_close_sigchan(&sigs, poller);

	if (ret)
		galvsmpl_perr(-ret, "some errors occured");

	return ret;
}

int
main(void)
{
	struct galv_binder    bind;
	struct galv_repo      repo = GALV_REPO_INIT(repo,
	                                            GALVSMPL_DISC_CLNT_CONN_NR);
	struct galv_coupler   cpl;
	struct galv_conn *    clnt;
	struct galv_unix_addr peer = GALV_UNIX_NAMED_ADDR(GALVSMPL_DISC_CLNT_PATH);
	struct upoll          poll;
	int                   ret;

	galvsmpl_init();

	galv_unix_binder_open(&bind, SOCK_STREAM, GALVSMPL_DISC_CLNT_CONN_NR);
	galv_coupler_setup(&cpl,
	                   &bind,
	                   &repo,
	                   &galvsmpl_disc_clnt_ops);

	clnt = galv_coupler_create_clnt(&cpl, SOCK_CLOEXEC);
	if (!clnt) {
		ret = -errno;
		galvsmpl_perr(-ret, "failed to create client connection");
		goto close_bind;
	}

	/* Max number of connections * + 1 for signal channel */
	ret = upoll_open(&poll, GALVSMPL_DISC_CLNT_CONN_NR + 1);
	if (ret) {
		galvsmpl_perr(-ret, "failed to open poller");
		goto destroy_clnt;
	}

	ret = galv_clnt_connect(clnt,
	                        (const struct sockaddr *)&peer,
	                        GALVSMPL_DISC_CLNT_TRIES,
	                        GALVSMPL_DISC_CLNT_MSECS,
	                        &poll);
	if (ret && (ret != -EINPROGRESS)) {
		galvsmpl_perr(-ret, "failed to connect");
		goto close_poll;
	}

	ret = galvsmpl_disc_clnt_loop(&poll, &repo);

close_poll:
	upoll_close(&poll);
destroy_clnt:
	galv_coupler_destroy_clnt(&cpl, clnt);
close_bind:
	galv_unix_binder_close(&bind);
	galv_repo_fini(&repo);
	galvsmpl_fini();

	return !ret ? EXIT_SUCCESS : EXIT_FAILURE;
}
