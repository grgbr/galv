/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "common.h"
#include "galv/unix.h"
#include "galv/coupler.h"

#define GALVSMPL_ECHOC_PATH      "sock"
#define GALVSMPL_ECHOC_CONN_NR   (32U)
#define GALVSMPL_ECHOC_BULK_NR   (4U)

struct galvsmpl_echoc {
	struct galv_conn * conn;
	size_t             busy;
	char               buff[1024];
};

static
struct galvsmpl_echoc *
galvsmpl_echoc_from_conn(const struct galv_conn * connection)
{
	return (struct galvsmpl_echoc *)galv_conn_context(connection);
}

static
int
galvsmpl_echoc_process_established(struct galvsmpl_echoc * echo,
                                   uint32_t                events,
                                   const struct upoll *    poller)
{
	galvsmpl_assert(echo);
	galvsmpl_assert(events);
	galvsmpl_assert(poller);

	return 0;
}

static
int
galvsmpl_echoc_process_closing(struct galvsmpl_echoc * echo,
                               const struct upoll *    poller)
{
	galvsmpl_assert(echo);
	galvsmpl_assert(poller);

	return 0;
}

static
int
galvsmpl_echoc_on_may_xfer(struct galv_conn *   connection,
                           uint32_t             events,
                           const struct upoll * poller)
{
	struct galvsmpl_echoc * echo = galvsmpl_echoc_from_conn(connection);

	switch (galv_conn_state(connection)) {
	case GALV_CONN_ESTABLISHED_STATE:
		return galvsmpl_echoc_process_established(echo, events, poller);

	case GALV_CONN_CLOSING_STATE:
		return galvsmpl_echoc_process_closing(echo, poller);

	default:
		galvsmpl_assert(0);
	}

	unreachable();
}

static
int
galvsmpl_echoc_on_connect(struct galv_conn *   connection,
                          uint32_t             events __unused,
                          const struct upoll * poller)
{
	struct galvsmpl_echoc * echo;
	int                     err;

	echo = malloc(sizeof(*echo));
	if (!echo)
		return -errno;

	err = galv_conn_poll(connection, poller, EPOLLIN | EPOLLOUT, echo);
	if (!err) {
		echo->conn = connection;
		echo->busy = 0;

		galv_conn_switch_state(connection, GALV_CONN_ESTABLISHED_STATE);
		galvsmpl_debug("connection established");

		return 0;
	}

	free(echo);

	galvsmpl_perr(-err, "failed to enable client connection polling");

	return err;
}

static
int
galvsmpl_echoc_on_send_shut(struct galv_conn *   connection,
                            uint32_t             events __unused,
                            const struct upoll * poller)
{
	struct galvsmpl_echoc * echo = galvsmpl_echoc_from_conn(connection);

	galvsmpl_debug("client connection receive end shut down: closing..");

	return galvsmpl_echoc_process_closing(echo, poller);
}

static
int
galvsmpl_echoc_on_recv_shut(struct galv_conn *   connection,
                            uint32_t             events __unused,
                            const struct upoll * poller)
{
	galvsmpl_debug("client connection transmit end shut down: closing..");

	return galv_conn_close(connection, poller);
}

static
int
galvsmpl_echoc_halt(struct galv_conn * connection, const struct upoll * poller)
{
	struct galvsmpl_echoc * echo = galvsmpl_echoc_from_conn(connection);

	galvsmpl_debug("client connection halt requested: closing..");

	return galvsmpl_echoc_process_closing(echo, poller);
}

static
void
galvsmpl_echoc_close(struct galv_conn * connection, const struct upoll * poller)
{
	/*
	 * Unregister from poller since we registered at connect time, see
	 * galvsmpl_echoc_on_connect().
	 */
	galv_conn_unpoll(connection, poller);

	free(galvsmpl_echoc_from_conn(connection));
}

static
int
galvsmpl_echoc_on_error(struct galv_conn *   connection __unused,
                        int                  error,
                        uint32_t             events __unused,
                        const struct upoll * poller __unused)
{
	galvsmpl_pdebug(error, "unexpected connection socket error");

	return galv_conn_close(connection, poller);
}

static const struct galv_conn_ops galvsmpl_echoc_ops = {
	.on_may_xfer  = galvsmpl_echoc_on_may_xfer,
	.on_connect   = galvsmpl_echoc_on_connect,
	.on_send_shut = galvsmpl_echoc_on_send_shut,
	.on_recv_shut = galvsmpl_echoc_on_recv_shut,
	.halt         = galvsmpl_echoc_halt,
	.close        = galvsmpl_echoc_close,
	.on_error     = galvsmpl_echoc_on_error
};

static
int
galvsmpl_clnt_loop(struct upoll * poller)
{
	struct galvsmpl_sigchan sigs;
	int                     ret;

	ret = galvsmpl_open_sigchan(&sigs, poller);
	if (ret)
		return ret;

	do {
		ret = upoll_process(poller, -1);
	} while (!ret || (ret == -EINTR));
	if (ret == -ESHUTDOWN)
		ret = 0;

	/* TODO implement gracefull coupler stop... */

	galvsmpl_close_sigchan(&sigs, poller);

	if (ret)
		galvsmpl_pdebug(-ret, "failed to gracefully halt");

	return ret;
}

int
main(void)
{
	struct galv_binder    bind;
	struct galv_repo      repo = GALV_REPO_INIT(repo,
	                                            GALVSMPL_ECHOC_CONN_NR);
	struct galv_coupler   cpl;
	struct galv_conn *    conn;
	struct galv_unix_addr peer = GALV_UNIX_NAMED_ADDR(GALVSMPL_ECHOC_PATH);
	struct upoll          poll;
	int                   ret;

	galvsmpl_init();

	galv_unix_binder_open(&bind, GALVSMPL_ECHOC_CONN_NR);
	galv_coupler_setup(&cpl,
	                   &bind,
	                   &repo,
	                   &galvsmpl_echoc_ops,
	                   SOCK_STREAM);

	conn = galv_coupler_create_conn(&cpl, SOCK_CLOEXEC);
	if (!conn) {
		galvsmpl_perr(errno, "failed to create client connection");
		ret = -errno;
		goto close_bind;
	}

	/* Max number of connections * + 1 for signal channel */
	ret = upoll_open(&poll, GALVSMPL_ECHOC_CONN_NR + 1);
	if (ret) {
		galvsmpl_perr(-ret, "failed to open poller");
		goto destroy_conn;
	}

	ret = galv_coupler_connect_conn(&cpl,
	                                conn,
	                                (const struct sockaddr *)&peer,
	                                &poll);
	if (ret) {
		galvsmpl_perr(-ret, "failed to open poller");
		goto close_poll;
	}

	ret = galvsmpl_clnt_loop(&poll);

close_poll:
	upoll_close(&poll);
destroy_conn:
	galv_coupler_destroy_conn(&cpl, conn);
close_bind:
	galv_unix_binder_close(&bind);
fini:
	galv_repo_fini(&repo);
	galvsmpl_fini();

	return !ret ? EXIT_SUCCESS : EXIT_FAILURE;
}
