/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "common.h"
#include "galv/unix.h"
#include "galv/coupler.h"
#include "galv/client.h"

#define GALVSMPL_ECHOC_PATH    "sock"
#define GALVSMPL_ECHOC_CONN_NR (32U)
#define GALVSMPL_ECHOC_BULK_NR (4U)
#define GALVSMPL_ECHOC_TRIES   (-3)
#define GALVSMPL_ECHOC_MSECS   (500)
#define GALVSMPL_ECHOC_MSGLEN  (33U)
#define GALVSMPL_ECHOC_MSG_NR  (10000U)

#if GALVSMPL_ECHOC_BULK_NR > GALVSMPL_ECHOC_MSG_NR
#error Invalid GALVSMPL_ECHOC_BULK_NR / GALVSMPL_ECHOC_MSG_NR values !
#endif /* GALVSMPL_ECHOC_BULK_NR > GALVSMPL_ECHOC_MSG_NR */

struct galvsmpl_echoc {
	struct galv_conn * conn;
	unsigned int       count;
	size_t             send_busy;
	char               send_buff[GALVSMPL_ECHOC_MSGLEN + 1];
	size_t             recv_busy;
	char               recv_buff[GALVSMPL_ECHOC_MSGLEN + 1];
};

static
struct galvsmpl_echoc *
galvsmpl_echoc_from_conn(const struct galv_conn * connection)
{
	return (struct galvsmpl_echoc *)galv_conn_context(connection);
}

static
int
galvsmpl_echoc_send(struct galvsmpl_echoc * echo)
{
	galvsmpl_assert(echo->send_busy);

	ssize_t      ret = 0;
	size_t       busy = echo->send_busy;
	unsigned int off = GALVSMPL_ECHOC_MSGLEN - (unsigned int)busy;

	ret = galv_conn_send(echo->conn,
	                     &echo->send_buff[off],
	                     busy,
	                     MSG_NOSIGNAL);
	galvsmpl_assert(ret);
	if (ret > 0) {
		echo->send_busy -= (size_t)ret;
		if (!echo->send_busy)
			return 0;

		ret = -EAGAIN;
	}

	return (int)ret;
}

static
int
galvsmpl_echoc_recv(struct galvsmpl_echoc * echo)
{
	galvsmpl_assert(echo->recv_busy < GALVSMPL_ECHOC_MSGLEN);

	ssize_t      ret = 0;
	size_t       miss = GALVSMPL_ECHOC_MSGLEN - echo->recv_busy;
	unsigned int off = (unsigned int)echo->recv_busy;

	ret = galv_conn_recv(echo->conn,
	                     &echo->recv_buff[off],
	                     miss,
	                     0);
	galvsmpl_assert(ret);
	if (ret > 0) {
		echo->recv_busy += (size_t)ret;
		if ((size_t)ret == miss) {
			echo->recv_buff[GALVSMPL_ECHOC_MSGLEN] = '\0';
			return 0;
		}

		ret = -EAGAIN;
	}

	return (int)ret;
}

static
void
galvsmpl_echoc_gen_pload(struct galvsmpl_echoc * echo)
{
	int ret;

	ret = snprintf(echo->send_buff,
	               sizeof(echo->send_buff),
	               "This is message number %10u",
	               echo->count);
	galvsmpl_assert(ret == GALVSMPL_ECHOC_MSGLEN);

	echo->send_busy = GALVSMPL_ECHOC_MSGLEN;
	echo->recv_busy = 0;
}

static
int
galvsmpl_echoc_chat(struct galvsmpl_echoc * echo)
{
	int ret = 0;

	if (echo->send_busy) {
		ret = galvsmpl_echoc_send(echo);
		switch (ret) {
		case 0:
			break;

		case -EAGAIN:
			galv_conn_watch(echo->conn, EPOLLOUT);
			break;

		case -EPIPE:
		case -ECONNRESET:
			galvsmpl_err("incomplete payload emitted: "
			             "outgoing connection shut down");
			return -ECONNRESET;

		case -ENOBUFS:
			galvsmpl_info(
				"transient outgoing connection congestion");
			galv_conn_watch(echo->conn, EPOLLOUT);
			ret = -EAGAIN;
			break;

		case -EINTR:
		case -ENOMEM:
			return ret;

		default:
			galvsmpl_perr(-ret,
			              "incomplete payload emitted: "
			              "unexpected failure");
			return ret;
		}
	}

	if (echo->recv_busy < GALVSMPL_ECHOC_MSGLEN) {
		ret = galvsmpl_echoc_recv(echo);
		switch (ret) {
		case 0:
			if (memcmp(echo->send_buff,
			           echo->recv_buff,
			           GALVSMPL_ECHOC_MSGLEN))
				galvsmpl_err("'%*.*s': invalid payload received",
				             (int)GALVSMPL_ECHOC_MSGLEN,
				             (int)GALVSMPL_ECHOC_MSGLEN,
				             echo->recv_buff);
			else
				galvsmpl_info("%s", echo->recv_buff);

			echo->count++;
			break;

		case -EAGAIN:
			galv_conn_watch(echo->conn, EPOLLIN);
			break;

		case -ECONNREFUSED:
			galvsmpl_err("incomplete payload received: "
			             "incoming connection shut down");
			break;

		case -EINTR:
		case -ENOMEM:
			break;

		default:
			galvsmpl_perr(-ret,
			              "incomplete payload received: "
			              "unexpected failure");
		}
	}

	return ret;
}

static
int
galvsmpl_echoc_process_closing(struct upoll_worker * worker,
                               uint32_t              events,
                               const struct upoll *  poller)
{
	struct galv_conn *      clnt = galv_conn_from_worker(worker);
	struct galvsmpl_echoc * echo = galvsmpl_echoc_from_conn(clnt);
	int                     ret;

	if (events & EPOLLERR) {
		ret = galv_conn_async_error(clnt);
		galvsmpl_pwarn(ret, "asynchronous socket error");
	}

	if ((echo->send_busy == GALVSMPL_ECHOC_MSGLEN) && !echo->recv_busy)
		goto close;

	if (events & EPOLLOUT)
		galv_conn_unwatch(clnt, EPOLLOUT);

	ret = galvsmpl_echoc_chat(echo);
	switch (ret) {
	case 0:
		if (echo->count == GALVSMPL_ECHOC_MSG_NR)
			goto close;
		break;

	case -EAGAIN:
		ret = 0;
		break;

	case -EINTR:
	case -ENOMEM:
		break;

	case -ECONNRESET:
	case -ECONNREFUSED:
	default:
		goto close;
	}

	galv_conn_apply_watch(clnt, poller);

	return ret;

close:
	return galv_conn_close(clnt, poller);
}

static
int
galvsmpl_echoc_process_established(struct upoll_worker * worker,
                                   uint32_t              events,
                                   const struct upoll *  poller)
{
	galvsmpl_assert(!(events &
	                  ~((uint32_t)
	                    (EPOLLIN | EPOLLRDHUP |
	                     EPOLLOUT | EPOLLHUP | EPOLLERR))));

	struct galv_conn *      clnt = galv_conn_from_worker(worker);
	struct galvsmpl_echoc * echo = galvsmpl_echoc_from_conn(clnt);
	int                     ret;
	unsigned int            cnt;

	if (events & (EPOLLRDHUP | EPOLLHUP)) {
		galvsmpl_info("shutting down connection..");
		galv_conn_switch_state(clnt,
		                       GALV_CONN_CLOSING_STATE,
		                       galvsmpl_echoc_process_closing);
		return galvsmpl_echoc_process_closing(worker, events, poller);
	}

	if (events & EPOLLERR) {
		ret = galv_conn_async_error(clnt);
		galvsmpl_pwarn(ret, "asynchronous socket error");
	}

	if (events & EPOLLOUT)
		galv_conn_unwatch(clnt, EPOLLOUT);

	/* Restrict to GALVSMPL_ECHOC_BULK_NR operations in a row. */
	cnt = GALVSMPL_ECHOC_BULK_NR;
	do {
		ret = galvsmpl_echoc_chat(echo);
		if (ret)
			break;

		if (echo->count == GALVSMPL_ECHOC_MSG_NR)
			return galv_conn_close(clnt, poller);

		galvsmpl_echoc_gen_pload(echo);
	} while (--cnt);

	switch (ret) {
	case 0:
		if (!cnt)
			galv_conn_watch(echo->conn, EPOLLOUT);
		break;
		
	case -EAGAIN:
		ret = 0;
		break;

	case -EINTR:
	case -ENOMEM:
		break;

	case -ECONNRESET:
	case -ECONNREFUSED:
	default:
		galv_conn_switch_state(clnt,
		                       GALV_CONN_CLOSING_STATE,
		                       galvsmpl_echoc_process_closing);
		ret = 0;
	}

	galv_conn_apply_watch(echo->conn, poller);

	return ret;
}

static
int
galvsmpl_echoc_on_bound(struct galv_conn *   connection,
                        const struct upoll * poller)
{
	struct galvsmpl_echoc * echo = galvsmpl_echoc_from_conn(connection);
	int                     ret;
	uint32_t                watch = EPOLLIN | EPOLLRDHUP;

	if (!echo) {
		echo = malloc(sizeof(*echo));
		if (!echo)
			return -errno;

		echo->conn = connection;
		galv_conn_set_context(connection, echo);

		echo->count = 0;
		galvsmpl_echoc_gen_pload(echo);
	}

	ret = galvsmpl_echoc_send(echo);
	switch (ret) {
	case 0:
		break;

	case -EAGAIN:
		watch |= EPOLLOUT;
		ret = 0;
		break;

	case -EPIPE:
	case -ECONNRESET:
		galvsmpl_err("incomplete payload emitted: "
		             "outgoing connection shut down");
		ret = -ECONNREFUSED;
		goto free;

	case -ENOBUFS:
		galvsmpl_info(
			"transient outgoing connection congestion");
		watch |= EPOLLOUT;
		ret = 0;
		break;

	case -EINTR:
		watch |= EPOLLOUT;
		break;

	case -ENOMEM:
		goto free;

	default:
		galvsmpl_pwarn(-ret, "unexpected emission failure");
		goto free;
	}

	galv_conn_switch_state(connection,
	                       GALV_CONN_ESTABLISHED_STATE,
	                       galvsmpl_echoc_process_established);
	galv_conn_reset_watch(connection, poller, watch);

	return ret;

free:
	galv_conn_set_context(connection, NULL);
	free(echo);

	return ret;
}

static
int
galvsmpl_echoc_halt(struct galv_conn * connection, const struct upoll * poller)
{
	galvsmpl_debug("connection halt requested: closing..");

	const struct galvsmpl_echoc * echo =
		galvsmpl_echoc_from_conn(connection);

	if ((echo->send_busy == GALVSMPL_ECHOC_MSGLEN) && !echo->recv_busy)
		return galv_conn_close(connection, poller);

	galv_conn_switch_state(connection,
	                       GALV_CONN_CLOSING_STATE,
	                       galvsmpl_echoc_process_closing);

	return 0;
}

static
void
galvsmpl_echoc_close(struct galv_conn *   connection,
                     const struct upoll * poller __unused)
{
	free(galvsmpl_echoc_from_conn(connection));
}

static const struct galv_conn_ops galvsmpl_echoc_ops = {
	.on_bound = galvsmpl_echoc_on_bound,
	.halt     = galvsmpl_echoc_halt,
	.close    = galvsmpl_echoc_close
};

static
int
galvsmpl_echoc_process_round(struct upoll * poller)
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
galvsmpl_echoc_loop(struct upoll * poller, struct galv_repo * repository)
{
	struct galvsmpl_sigchan sigs;
	int                     ret;

	ret = galvsmpl_open_sigchan(&sigs, poller);
	if (ret)
		return ret;

	while (!galv_repo_empty(repository)) {
		ret = galvsmpl_echoc_process_round(poller);
		if (ret)
			break;
	}
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
	unsigned int          c;
	struct galv_conn *    clnt[GALVSMPL_ECHOC_CONN_NR];
	struct galv_unix_addr peer = GALV_UNIX_NAMED_ADDR(GALVSMPL_ECHOC_PATH);
	struct upoll          poll;
	int                   ret;

	galvsmpl_init();

	galv_unix_binder_open(&bind, SOCK_STREAM, GALVSMPL_ECHOC_CONN_NR);
	galv_coupler_setup(&cpl,
	                   &bind,
	                   &repo,
	                   &galvsmpl_echoc_ops);

	for (c = 0; c < stroll_array_nr(clnt); c++) {
		clnt[c] = galv_coupler_create_clnt(&cpl, SOCK_CLOEXEC);
		if (!clnt[c]) {
			ret = -errno;
			galvsmpl_perr(-ret,
			              "failed to create client connection");
			goto destroy_clnt;
		}
	}

	/* Max number of connections * + 1 for signal channel */
	ret = upoll_open(&poll, GALVSMPL_ECHOC_CONN_NR + 1);
	if (ret) {
		galvsmpl_perr(-ret, "failed to open poller");
		goto destroy_clnt;
	}

	for (c = 0; c < stroll_array_nr(clnt); c++) {
		ret = galv_clnt_connect(clnt[c],
		                        (const struct sockaddr *)&peer,
		                        GALVSMPL_ECHOC_TRIES,
		                        GALVSMPL_ECHOC_MSECS,
		                        &poll);
		if (ret) {
			galvsmpl_perr(-ret, "failed to connect");
			goto close_clnt;
		}
	}

	ret = galvsmpl_echoc_loop(&poll, &repo);

close_clnt:
	galv_conn_repo_close(&repo, &poll);
	upoll_close(&poll);
	c = GALVSMPL_ECHOC_CONN_NR;

destroy_clnt:
	while (c--)
		galv_coupler_destroy_clnt(&cpl, clnt[c]);
	galv_unix_binder_close(&bind);
	galv_repo_fini(&repo);
	galvsmpl_fini();

	return !ret ? EXIT_SUCCESS : EXIT_FAILURE;
}
