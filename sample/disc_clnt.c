/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "common.h"
#include "galv/unix.h"
#include "galv/coupler.h"
#include <utils/timer.h>

#define GALVSMPL_DISC_PATH      "sock"
#define GALVSMPL_DISC_CONN_NR   (8U)
#define GALVSMPL_DISC_BULK_NR   (4U)

#define GALVSMPL_DISC_MSGLEN    (33U)

struct galvsmpl_disc {
	struct galv_conn * conn;
	unsigned int       count;
	size_t             send_busy;
	char               send_buff[GALVSMPL_DISC_MSGLEN + 1];
	size_t             recv_busy;
	char               recv_buff[GALVSMPL_DISC_MSGLEN + 1];
};

static
struct galvsmpl_disc *
galvsmpl_disc_from_conn(const struct galv_conn * connection)
{
	return (struct galvsmpl_disc *)galv_conn_context(connection);
}

static
int
galvsmpl_disc_send(struct galvsmpl_disc * echo)
{
	ssize_t ret = 0;

	if (echo->send_busy) {
		size_t       busy = echo->send_busy;
		unsigned int off = GALVSMPL_DISC_MSGLEN - (unsigned int)busy;

		ret = galv_conn_send(echo->conn,
		                     &echo->send_buff[off],
		                     busy,
		                     MSG_NOSIGNAL);
		galvsmpl_assert(ret);
		if (ret > 0) {
			echo->send_busy -= (size_t)ret;
			if ((size_t)ret == busy)
				return 0;

			ret = -EAGAIN;
		}
	}

	return (int)ret;
}

static
int
galvsmpl_disc_recv(struct galvsmpl_disc * echo)
{
	ssize_t ret = 0;

	if (echo->recv_busy < GALVSMPL_DISC_MSGLEN) {
		size_t       miss = GALVSMPL_DISC_MSGLEN - echo->recv_busy;
		unsigned int off = (unsigned int)echo->recv_busy;

		ret = galv_conn_recv(echo->conn,
		                     &echo->recv_buff[off],
		                     miss,
		                     0);
		galvsmpl_assert(ret);
		if (ret > 0) {
			echo->recv_busy += (size_t)ret;
			if ((size_t)ret == miss) {
				echo->recv_buff[GALVSMPL_DISC_MSGLEN] = '\0';
				return 0;
			}

			ret = -EAGAIN;
		}
	}

	return (int)ret;
}

static
void
galvsmpl_disc_gen_pload(struct galvsmpl_disc * echo)
{
	int ret;

	ret = snprintf(echo->send_buff,
	               sizeof(echo->send_buff),
	               "This is message number %10u",
	               echo->count);
	galvsmpl_assert(ret == GALVSMPL_DISC_MSGLEN);

	echo->send_busy = GALVSMPL_DISC_MSGLEN;
	echo->recv_busy = 0;
	echo->count++;
}

static
int
galvsmpl_disc_chat(struct galvsmpl_disc * echo)
{
	int ret;

	ret = galvsmpl_disc_recv(echo);
	switch (ret) {
	case 0:
		break;

	case -EAGAIN:
		galv_conn_watch(echo->conn, EPOLLIN);
		ret = 0;
		break;

	case -ECONNREFUSED:
	case -EINTR:
	case -ENOMEM:
		return ret;

	default:
		galvsmpl_perr(-ret, "unexpected receive failure");
	}

	if (echo->recv_busy == GALVSMPL_DISC_MSGLEN) {
		if (memcmp(echo->send_buff,
		           echo->recv_buff,
		           GALVSMPL_DISC_MSGLEN))
			galvsmpl_err("'%*.*s': invalid payload received",
			             (int)GALVSMPL_DISC_MSGLEN,
			             (int)GALVSMPL_DISC_MSGLEN,
			             echo->recv_buff);
		else
			galvsmpl_info("%s", echo->recv_buff);
		galvsmpl_disc_gen_pload(echo);
	}
	
	ret = galvsmpl_disc_send(echo);
	switch (ret) {
	case 0:
		break;

	case -ENOBUFS:
	case -EAGAIN:
		galv_conn_watch(echo->conn, EPOLLOUT);
		break;

	case -EPIPE:
	case -ECONNRESET:
	case -EINTR:
	case -ENOMEM:
		return ret;

	default:
		galvsmpl_perr(-ret, "unexpected emit failure");
		ret = 0;
	}

	return 0;
}

static
int
galvsmpl_disc_process_established(struct galvsmpl_disc * echo,
                                   uint32_t                events,
                                   const struct upoll *    poller)
{
	galvsmpl_assert(echo);
	galvsmpl_assert(events);
	galvsmpl_assert(poller);

	int          ret;
	unsigned int cnt = GALVSMPL_DISC_BULK_NR;

	if (events & EPOLLOUT)
		galv_conn_unwatch(echo->conn, EPOLLOUT);


	/* Restrict to GALVSMPL_DISC_BULK_NR operations in a row. */
	do {
		ret = galvsmpl_disc_chat(echo);
	} while (!ret && --cnt);

	switch (ret) {
	case 0:
		break;

	case -ECONNREFUSED:
		return galv_conn_on_recv_shut(echo->conn, events, poller);

	case -EPIPE:
	case -ECONNRESET:
		return galv_conn_on_send_shut(echo->conn, events, poller);

	case -EINTR:
	case -ENOMEM:
		break;

	case -EAGAIN:
	case -ENOBUFS:
	default:
		ret = 0;
	}

	galv_conn_apply_watch(echo->conn, poller);

	return ret;
}

static
int
galvsmpl_disc_process_closing(struct galvsmpl_disc * echo,
                               const struct upoll *    poller)
{
	return galv_conn_close(echo->conn, poller);
}

static
int
galvsmpl_disc_on_may_xfer(struct galv_conn *   connection,
                           uint32_t             events,
                           const struct upoll * poller)
{
	struct galvsmpl_disc * echo = galvsmpl_disc_from_conn(connection);

	switch (galv_conn_state(connection)) {
	case GALV_CONN_ESTABLISHED_STATE:
		return galvsmpl_disc_process_established(echo, events, poller);

	case GALV_CONN_CLOSING_STATE:
		return galvsmpl_disc_process_closing(echo, poller);

	default:
		galvsmpl_assert(0);
	}

	unreachable();
}

static
int
galvsmpl_disc_on_connect(struct galv_conn *   connection,
                          uint32_t             events __unused,
                          const struct upoll * poller)
{
	struct galvsmpl_disc * echo;
	int                     ret;

	echo = malloc(sizeof(*echo));
	if (!echo)
		return -errno;

	ret = galv_conn_poll(connection, poller, EPOLLIN, echo);
	if (!ret) {
		echo->conn = connection;
		echo->count = 0;
		galvsmpl_disc_gen_pload(echo);

		galv_conn_switch_state(connection, GALV_CONN_ESTABLISHED_STATE);
		galvsmpl_debug("connection established");

		ret = galvsmpl_disc_send(echo);
		switch (ret) {
		case 0:
			return 0;

		case -ENOBUFS:
		case -EAGAIN:
			galv_conn_watch(echo->conn, EPOLLOUT);
			galv_conn_apply_watch(echo->conn, poller);
			return 0;

		case -EPIPE:
		case -ECONNRESET:
			/* REVIEW mE!!! */
			return galv_conn_on_send_shut(echo->conn, 0, poller);

		case -EINTR:
		case -ENOMEM:
			break;

		default:
			galvsmpl_perr(-ret, "unexpected emit failure");
			ret = 0;
		}

		return ret;
	}

	free(echo);

	galvsmpl_perr(-ret, "failed to enable client connection polling");

	return ret;
}

static
int
galvsmpl_disc_on_send_shut(struct galv_conn *   connection,
                            uint32_t             events __unused,
                            const struct upoll * poller)
{
	struct galvsmpl_disc * echo = galvsmpl_disc_from_conn(connection);

	galvsmpl_debug("client connection receive end shut down: closing..");

	return galvsmpl_disc_process_closing(echo, poller);
}

static
int
galvsmpl_disc_on_recv_shut(struct galv_conn *   connection,
                            uint32_t             events __unused,
                            const struct upoll * poller)
{
	galvsmpl_debug("client connection transmit end shut down: closing..");

	return galv_conn_close(connection, poller);
}

static
int
galvsmpl_disc_halt(struct galv_conn * connection, const struct upoll * poller)
{
	struct galvsmpl_disc * echo = galvsmpl_disc_from_conn(connection);

	galvsmpl_debug("client connection halt requested: closing..");

	return galvsmpl_disc_process_closing(echo, poller);
}

static
void
galvsmpl_disc_close(struct galv_conn * connection, const struct upoll * poller)
{
	/*
	 * Unregister from poller since we registered at connect time, see
	 * galvsmpl_disc_on_connect().
	 */
	galv_conn_unpoll(connection, poller);

	free(galvsmpl_disc_from_conn(connection));
}

static
int
galvsmpl_disc_on_error(struct galv_conn *   connection __unused,
                        int                  error,
                        uint32_t             events __unused,
                        const struct upoll * poller __unused)
{
	galvsmpl_pdebug(error, "unexpected connection socket error");

	/* Release this connection. */
	galv_conn_close(connection, poller);

	/*
	 * Return error to caller so that either:
	 * - the polling loop get this error code when returning from
	 *   upoll_process() / upoll_wait()
	 * - the main() caller get this error code when returning from
	 *   galv_coupler_connect();
	 */
	return -error;
}

static const struct galv_conn_ops galvsmpl_disc_ops = {
	.on_may_xfer  = galvsmpl_disc_on_may_xfer,
	.on_connect   = galvsmpl_disc_on_connect,
	.on_send_shut = galvsmpl_disc_on_send_shut,
	.on_recv_shut = galvsmpl_disc_on_recv_shut,
	.halt         = galvsmpl_disc_halt,
	.close        = galvsmpl_disc_close,
	.on_error     = galvsmpl_disc_on_error
};

static
int
galvsmpl_process_round(struct upoll * poller)
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
galvsmpl_clnt_loop(struct upoll * poller)
{
	struct galvsmpl_sigchan sigs;
	int                     ret;

	ret = galvsmpl_open_sigchan(&sigs, poller);
	if (ret)
		return ret;

	do {
		ret = galvsmpl_process_round(poller);
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
	                                            GALVSMPL_DISC_CONN_NR);
	struct galv_coupler   cpl;
	struct galv_unix_addr peer = GALV_UNIX_NAMED_ADDR(GALVSMPL_DISC_PATH);
	struct upoll          poll;
	int                   ret;

	galvsmpl_init();

	galv_unix_binder_open(&bind, GALVSMPL_DISC_CONN_NR);
	galv_coupler_setup(&cpl,
	                   &bind,
	                   &repo,
	                   &galvsmpl_disc_ops,
	                   SOCK_STREAM);

	/* Max number of connections * + 1 for signal channel */
	ret = upoll_open(&poll, GALVSMPL_DISC_CONN_NR + 1);
	if (ret) {
		galvsmpl_perr(-ret, "failed to open poller");
		goto close_bind;
	}

	ret = galv_coupler_connect(&cpl,
	                           (const struct sockaddr *)&peer,
	                           SOCK_CLOEXEC,
	                           &poll);
	if (ret) {
		galvsmpl_perr(-ret, "failed to connect");
		goto close_poll;
	}

	ret = galvsmpl_clnt_loop(&poll);

close_poll:
	upoll_close(&poll);
close_bind:
	galv_unix_binder_close(&bind);
	galv_repo_fini(&repo);
	galvsmpl_fini();

	return !ret ? EXIT_SUCCESS : EXIT_FAILURE;
}
