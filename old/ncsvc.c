#warning FIXME
#ifndef NDEBUG
#define NDEBUG
#endif

#include <galv/unix.h>
#include <elog/elog.h>
#include <utils/unsk.h>

#define GALVUT_NCSVC_UNIX_PATH    "./sock"
#define GALVUT_NCSVC_UNIX_BACKLOG (2)
#define GALVUT_NCSVC_UNIX_CONN_NR (5)
#define GALVUT_NCSVC_UNIX_MSG_NR  (5)

#define galvut_assert_intern(...) \
	assert(__VA_ARGS__)

#define galvut_ncsvc_err(_fmt, ...) \
	elog_err(&galvut_ncsvc_log, _fmt, ## __VA_ARGS__)

#define galvut_ncsvc_warn(_fmt, ...) \
	elog_warn(&galvut_ncsvc_log, _fmt, ## __VA_ARGS__)

#define galvut_ncsvc_notice(_fmt, ...) \
	elog_notice(&galvut_ncsvc_log, _fmt, ## __VA_ARGS__)

#define galvut_ncsvc_info(_fmt, ...) \
	elog_info(&galvut_ncsvc_log, _fmt, ## __VA_ARGS__)

#define galvut_ncsvc_debug(_fmt, ...) \
	elog_debug(&galvut_ncsvc_log, _fmt, ## __VA_ARGS__)

const struct galv_conn_ops galv_ncsvc_seqpack_ops = {
	.on_may_xfer    = galv_ncsvc_seqpack_on_may_xfer,
	.on_connecting  = galv_ncsvc_seqpack_on_connecting,
	.on_send_closed = galv_ncsvc_seqpack_on_send_closed,
	.on_recv_closed = galv_ncsvc_seqpack_on_recv_closed,
	.on_error       = galv_ncsvc_seqpack_on_error
};

static
int
galvut_seqpack_ncsvc_on_accept(struct galv_acceptor * __restrict acceptor,
                               uint32_t                          events,
                               const struct upoll * __restrict   poller)
{
	struct galv_unix_conn * conn;
	int                     err;

	conn = malloc(sizeof(*conn));
	if (!conn) {
		/*
		 * When a connection request cannot be handled, we accept() and
		 * close() it. Otherwise, it would sit in the kernel listen
		 * backlog till next call to accept().
		 */
		err = -errno;
		galv_acceptor_reject_conn(acceptor);
		return err;
	}

	err = galv_unix_conn_accept(conn,
	                            acceptor,
	                            SOCK_CLOEXEC,
	                            &galv_ncsvc_seqpack_ops);
	if (err) {
		if (err == -ECONNABORTED)
			/*
			 * Connection has been aborted: ignore and tell caller
			 * to keep processing connection requests normally.
			 */
			err = 0;
		goto free;
	}

	err = galv_conn_on_connecting(&conn->base, 0, poller);
	switch (err) {
	case 0:
		break;

	case -ENOMEM: /* No more memory. */
	case -ENOSPC: /* Cannot register new fd to poll loop. */
		goto close;

	default:
		/* Ensure poll loop keeps processing events. */
		err = 0;
		goto close;
	}

	return 0;

close:
	galv_conn_complete_close(&conn->base);
free:
	free(conn);

	return err;
}

static
int
galvut_seqpack_ncsvc_on_close(
	struct galv_acceptor * __restrict acceptor __unused,
	struct galv_conn * __restrict     conn,
	const struct upoll * __restrict   poller)
{
	galv_conn_unpoll(conn, poller);
	galv_conn_complete_close(conn);
	free(conn);

	galvut_ncsvc_debug("connection closed");

	return 0;
}

static const struct galv_acceptor_ops galvut_seqpack_ncsvc_ops = {
	.on_accept_conn = galvut_seqpack_ncsvc_on_accept,
	.on_close_conn  = galvut_seqpack_ncsvc_on_close
};

static
int
galvut_seqpack_ncsvc_open(struct galv_unix_acceptor * acceptor,
                          const struct upoll *        poller)
{
	return galv_unix_acceptor_open(acceptor,
	                               GALVUT_NCSVC_UNIX_PATH,
	                               SOCK_SEQPACKET,
	                               SOCK_CLOEXEC,
	                               GALVUT_NCSVC_UNIX_BACKLOG,
	                               poller,
	                               &galvut_seqpack_ncsvc_ops,
	                               NULL);
}

static
int
galvut_seqpack_ncsvc_close(struct galv_unix_acceptor * acceptor,
                           const struct upoll *        poller)
{
	return galv_unix_acceptor_close(acceptor, poller);
}

int
main(void)
{
	int                       ret;
	struct upoll              poll;
	struct galv_unix_acceptor accept;

	elog_init_stdio(&galvut_ncsvc_log, &elog_cfg);
	galv_setup((struct elog *)&galvut_ncsvc_log);

	/* Max number of connections + 1 for acceptor socket. */
	ret = upoll_open(&poll, GALVUT_NCSVC_UNIX_CONN_NR + 1);
	if (ret) {
		elog_err(&galvut_ncsvc_log,
		         "cannot initialize poller: %s (%d).\n",
		         strerror(-ret),
		         -ret);
		ret = EXIT_FAILURE;
		goto fini_log;
	}

	ret = galvut_seqpack_ncsvc_open(&accept, &poll);
	if (ret) {
		elog_err(&galvut_ncsvc_log,
		         "cannot open service: %s (%d).\n",
		         strerror(-ret),
		         -ret);
		ret = EXIT_FAILURE;
		goto fini_poll;
	}

	do {
		ret = upoll_process(&poll, -1);
	} while (!ret);

	galvut_seqpack_ncsvc_close(&accept, &poll);

	ret = EXIT_SUCCESS;

fini_poll:
	upoll_close(&poll);
fini_log:
	elog_fini_stdio(&galvut_ncsvc_log);

	return ret;
}
