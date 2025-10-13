#include <galv/unix.h>
#include <galv/fabric.h>
#include <utils/poll.h>

/* FIXME: Remove me!! */
#define galv_unix_assert_intern(...) stroll_assert("srv:unix", __VA_ARGS__)
#define srv_err(_fmt, ...) fprintf(stderr, "srv: error: " _fmt, ## __VA_ARGS__)
#define srv_warn(_fmt, ...) fprintf(stderr, "srv: warn: " _fmt, ## __VA_ARGS__)
#define srv_notice(_fmt, ...) fprintf(stderr, "srv: notice: " _fmt, ## __VA_ARGS__)
#define srv_info(_fmt, ...) fprintf(stderr, "srv: info: " _fmt, ## __VA_ARGS__)
#define srv_dbg(_fmt, ...) fprintf(stderr, "srv: debug: " _fmt, ## __VA_ARGS__)

#if 0
static
ssize_t
galv_unix_async_conn_send(struct galv_unix_async_conn * __restrict conn,
                          const void * __restrict                  buff,
                          size_t                                   size,
                          int                                      flags)
{
	galv_unix_assert_api(fd >= 0);
	galv_unix_assert_api(buff); /* prohibit empty packets ! */
	galv_unix_assert_api(size); /* prohibit empty packets ! */
	galv_unix_assert_api(size <= SSIZE_MAX);
	galv_unix_assert_api(!(flags & ~(MSG_MORE | MSG_NOSIGNAL | MSG_OOB)));

	ssize_t ret;

	ret = unsk_send(conn->sync.base.fd, buff, size, MSG_NOSIGNAL | flags);
	if (ret >= 0) {
		galv_unix_assert_api((size)ret == size);
		return ret;
	}

	switch (ret) {
	case -EAGAIN:
	case -ENOBUFS:
	case -ECONNRESET:
	case -EINTR:
	case -ENOMEM:
		break;

	default:
		galv_unix_assert_api(ret != -EISCONN);
		galv_unix_assert_api(ret != -EALREADY);
		galv_unix_assert_api(ret != -EMSGSIZE);
		galv_unix_assert_api(ret != -EPIPE);
	}

	return ret;
}

static
int
galv_unix_seqpkt_close(struct galv_unix_async_conn * __restrict conn)
{
	conn->sync.base.state = GALV_CONN_CLOSED_STATE;
}

static
int
seqpkt_process_close(struct galv_unix_async_conn * __restrict conn,
                     const struct upoll * __restrict          poller)
{
	int ret;

	srv_dbg("closing...\n");
	
	ret = galv_unix_async_conn_close(conn, poller);
	galv_fabric_free(conn->accept->fabric, conn);

	switch (ret) {
	case 0:
	case -EINTR:
		break;

	case -EIO:
		srv_warn("failed to close socket: %s (%d).\n",
		         strerror(-ret),
		         -ret);
		ret = 0;
		break;

	default:
		/* Should never happen */
		assert(0);
	}

	srv_dbg("closed.\n");

	return ret;
}

static
int
on_seqpkt_error(struct galv_unix_async_conn * __restrict conn,
               const struct upoll * __restrict          poller)
{
	int ret;

	switch (conn->sync.base.state) {
	case GALV_CONN_CONNECTING_STATE:
	case GALV_CONN_ESTABLISHED_STATE:
	case GALV_CONN_RECVSHUT_STATE:
	case GALV_CONN_SENDSHUT_STATE:
		/* TODO: retrieve error from error queue ? When do this really
		 * happen ?
		 */
		srv_notice("socket error: closing.\n");
		ret = galv_unix_seqpkt_close(conn, poller);
		break;

	case GALV_CONN_CLOSED_STATE:
	default:
		assert(0);
	}

	return ret;
}

static
int
on_seqpkt_send_shut(struct galv_unix_async_conn * __restrict conn,
                    const struct upoll * __restrict          poller)
{
	ssize_t ret;

	srv_dbg("sending end shut down...\n");

	switch (conn->sync.base.state) {
	case GALV_CONN_ESTABLISHED_STATE:
		conn->sync.base.state = GALV_CONN_SENDSHUT_STATE;
		break;

	case GALV_CONN_RECVSHUT_STATE:
		return galv_unix_seqpkt_close(conn, poller);

	case GALV_CONN_CONNECTING_STATE:
	case GALV_CONN_SENDSHUT_STATE:
	case GALV_CONN_CLOSED_STATE:
	default:
		assert(0);
	}

	/*
	 * TODO: REPLACE ME
	 * read as long as messages are to be receive,
	 * close otherwise
	 * conn->ops->send_shut();
	 */
	while (true) {
		static char buff[128];

		ret = unsk_recv(conn->sync.base.fd, buff, sizeof(buff), 0);
		if (ret <= 0)
			/* Zero-sized read means end of data stream. */
			break;

		srv_dbg("send shut: received --%s--\n", buff);
	}

	switch (ret) {
	case 0:
		/*
		 * In this case, a recv() returning a zero size may mean either:
		 * - "end of incoming stream" (once all outstanding data has
		 *   been consumed) ;
		 * - or reception of an empty seqpacket.
		 * As we prohibit usage of empty seqpackets (since we cannot
		 * reliably distinguish between peer socket closure event and
		 * zero sized message, always consider this as a peer socket
		 * closure condition and close our local connection.
		 * See EPOLLHUP related comment from seqpkt_dispatch() below.
		 * See also https://stackoverflow.com/questions/51467936/empty-packet-on-sock-seqpacket-unix-socket
		 */

	case -EAGAIN:
		/*
		 * All outstanding incoming data has been consumed: close
		 * connection.
		 */
		srv_dbg("send shut: end of incoming stream\n");
		ret = galv_unix_seqpkt_close(conn, poller);
		break;

	case -EINTR:
	case -ENOMEM:
		break;

	case -ECONNREFUSED:
		/* Can this really happen for connection oriented sockets ?? */
		assert(0);
		ret = galv_unix_seqpkt_close(conn, poller);
		break;

	default:
		/* Should never happen */
		assert(0);
	}

	switch (conn->sync.base.state) {
	case GALV_CONN_SENDSHUT_STATE:
		upoll_disable_watch(&conn->work, EPOLLOUT);
		break;

	case GALV_CONN_CLOSED_STATE:
		break;

	case GALV_CONN_RECVSHUT_STATE:
	case GALV_CONN_ESTABLISHED_STATE:
	case GALV_CONN_CONNECTING_STATE:
	default:
		assert(0);
	}

	return ret;
}

static
int
on_seqpkt_recv_shut(struct galv_unix_async_conn * __restrict conn,
                    const struct upoll * __restrict          poller)
{
	srv_dbg("receiving end shut down...\n");

	int ret;

	switch (conn->sync.base.state) {
	case GALV_CONN_ESTABLISHED_STATE:
		conn->sync.base.state = GALV_CONN_RECVSHUT_STATE;
		break;

	case GALV_CONN_SENDSHUT_STATE:
		return galv_unix_seqpkt_close(conn, poller);

	case GALV_CONN_CONNECTING_STATE:
	case GALV_CONN_RECVSHUT_STATE:
	case GALV_CONN_CLOSED_STATE:
	default:
		assert(0);
	}

	/*
	 * TODO: REPLACE ME
	 * write as much as we can if messages are to be sent,
	 * then close:
	 * conn->ops->recv_shut();
	 */
	ret = galv_unix_seqpkt_close(conn, poller);

	switch (conn->sync.base.state) {
	case GALV_CONN_RECVSHUT_STATE:
		upoll_disable_watch(&conn->work, EPOLLIN | EPOLLRDHUP);
		break;

	case GALV_CONN_CLOSED_STATE:
		break;

	case GALV_CONN_SENDSHUT_STATE:
	case GALV_CONN_ESTABLISHED_STATE:
	case GALV_CONN_CONNECTING_STATE:
	default:
		assert(0);
	}

	return ret;
}

static
int
on_seqpkt_may_write(struct galv_unix_async_conn * __restrict conn,
                     const struct upoll * __restrict          poller __unused)
{
	int ret;

	switch (conn->sync.base.state) {
	case GALV_CONN_ESTABLISHED_STATE:
	case GALV_CONN_RECVSHUT_STATE:
		/* implement me! */
		assert(0);

	case GALV_CONN_CONNECTING_STATE:
	case GALV_CONN_SENDSHUT_STATE:
	case GALV_CONN_CLOSED_STATE:
	default:
		assert(0);
	}

	return ret;
}

static
int
on_seqpkt_may_recv(struct galv_unix_async_conn * __restrict conn,
                   const struct upoll * __restrict          poller)
{
	ssize_t ret;

	switch (conn->sync.base.state) {
	case GALV_CONN_ESTABLISHED_STATE:
	case GALV_CONN_SENDSHUT_STATE:
		break;

	case GALV_CONN_CONNECTING_STATE:
	case GALV_CONN_RECVSHUT_STATE:
	case GALV_CONN_CLOSED_STATE:
	default:
		assert(0);
	}

	/*
	 * TODO: REPLACE ME
	 * conn->ops->may_recv() instead.
	 */
	while (true) {
		static char buff[128];

		ret = unsk_recv(conn->sync.base.fd, buff, sizeof(buff), 0);
		if (ret <= 0)
			break;

		srv_dbg("may recv: received --%s--\n", buff);
	}

	switch (ret) {
	case -EAGAIN:
		upoll_enable_watch(&conn->work, EPOLLIN);
		ret = 0;
		break;

	case -EINTR:
	case -ENOMEM:
		break;

	case -ECONNREFUSED:
		/* Can this really happen for connection oriented sockets ?? */
		assert(0);
		ret = on_seqpkt_recv_shut(conn, poller);
		break;

	case 0:
		/*
		 * Prohibit usage of empty seqpackets since we cannot reliably
		 * distinguish between peer socket closure event and zero sized
		 * message.
		 * Always consider this as a peer socket closure condition and
		 * shutdown our own local connection.
		 * See EPOLLHUP related comment from seqpkt_dispatch() below.
		 * See also https://stackoverflow.com/questions/51467936/empty-packet-on-sock-seqpacket-unix-socket
		 */
		srv_notice("may recv: empty payload\n");
		ret = galv_unix_seqpkt_close(conn, poller);
		break;

	default:
		/* Should never happen */
		assert(0);
	}

	return ret;
}

static
int
seqpkt_process_may_send(struct galv_unix_async_conn * __restrict conn,
                        const struct upoll * __restrict          poller)
{
	ssize_t     ret;
	static char buff = "answer";

	ret = galv_unix_async_conn_send(conn, buff, sizeof(buff), 0);
	if (ret >= 0) {
		assert(ret == sizeof(buff));
		return 0;
	}

	switch (ret) {
	case -EAGAIN:
	case -ENOBUFS:
	case -ECONNRESET:
	case -EINTR:
	case -ENOMEM:
		break;

	default:
		srv_warning("may_send: unknown send return code: %s (%d).\n",
		            strerror(-ret),
		            -ret);
	}

	return ret;
}

static
int
seqpkt_process_may_recv(struct galv_unix_async_conn * __restrict conn,
                        const struct upoll * __restrict          poller)
{
	ssize_t ret;

	while (true) {
		static char buff[128];

		ret = unsk_recv(conn->sync.base.fd, buff, sizeof(buff), 0);
		if (ret <= 0)
			break;

		srv_dbg("may recv: received --%s--\n", buff);
	}

	if (!ret) {
		/*
		 * Prohibit usage of empty seqpackets since we cannot reliably
		 * distinguish between peer socket closure event and zero sized
		 * message.
		 * Always consider this as a peer socket closure condition and
		 * instruct the caller to shut our local receiving end down.
		 * See EPOLLHUP related comment from seqpkt_dispatch() below.
		 * See also https://stackoverflow.com/questions/51467936/empty-packet-on-sock-seqpacket-unix-socket
		 */
		ret = -ECONNREFUSED;
	}

	return ret;
}

static
int
seqpkt_process_established_event(
	struct galv_unix_async_conn * __restrict conn,
	uint32_t                                 events,
	const struct upoll * __restrict          poller)
{
	if (events & EPOLLHUP) {
		/*
		 * Peer closed its connection. No more data can be written to
		 * our local writing end.  After any (possible) readable data is
		 * consumed, reading from our local connection reading end will
		 * return zero-sized payloads, meaning "end of data stream".
		 */
		conn->sync.base.state = GALV_CONN_SENDSHUT_STATE;
		/* TODO: replace seqpkt_process_send_shut() with conn->ops->send_shut() */
#warning replace me!
		ret = seqpkt_process_send_shut(conn, poller);
		switch (ret) {
		case -EAGAIN:
		case -ECONNREFUSED: /* No more incoming data: close. */
			srv_notice("seqpkt_process_established_event: "
			           "end of connection.\n");
			return galv_unix_seqpkt_close(conn, poller);

		case 0:             /* Incoming data left to process. */
		case -EINTR:        /* Interrupted by a signal. */
			upoll_enable_watch(&conn->work, EPOLLIN);
			upoll_disable_watch(&conn->work, EPOLLOUT);
			break;
		}

		return ret;
	}
	else if (events & EPOLLRDHUP) {
		/*
		 * Peer (half-)closed its connection writing end. No more data
		 * can be read from our local reading end.
		 */
		conn->sync.base.state = GALV_CONN_RECVSHUT_STATE;
		/* TODO: replace seqpkt_process_recv_shut() with conn->ops->recv_shut() */
#warning replace me!
		ret = seqpkt_process_recv_shut(conn, poller);
		switch (ret) {
				FINISH ME!
		case 0:
			/* No more outgoing data to transmit. */
			upoll_disable_watch(&conn->work, EPOLLOUT);
			break;

		case -EAGAIN:
			upoll_enable_watch(&conn->work, EPOLLOUT);
			break;

		case -ENOBUFS:
			srv_notice("seqpkt_process_established_event: "
			           "output stream congestion.\n");
			upoll_enable_watch(&conn->work, EPOLLOUT);
			break;

		case -ECONNRESET:
			srv_notice("seqpkt_process_established_event: "
			           "outgoing stream closed because of remote peer.\n");
			conn->sync.base.state = GALV_CONN_SENDSHUT_STATE;
			/*
			 * TODO: REPLACE ME
			 * read as much as we can if messages are to be
			 * received, then close:
			 * conn->ops->send_shut();
			 */
#warning replace me!
			//upoll_disable_watch(&conn->work, EPOLLOUT);
			//upoll_apply(poller, conn->sync.base.fd, &conn->work);
			return galv_unix_seqpkt_close(conn, poller);

		case -EINTR:
			upoll_enable_watch(&conn->work, EPOLLOUT);
			upoll_apply(poller, conn->sync.base.fd, &conn->work);
			return -EINTR;
		}

		return ret;
	}

	if (events & EPOLLOUT) {
		ret = seqpkt_process_may_send(conn, poller);
		switch (ret) {
		case 0:
			/* No more outgoing data to transmit. */
			upoll_disable_watch(&conn->work, EPOLLOUT);
			break;

		case -EAGAIN:
			upoll_enable_watch(&conn->work, EPOLLOUT);
			break;

		case -ENOBUFS:
			srv_notice("seqpkt_process_established_event: "
			           "output stream congestion.\n");
			upoll_enable_watch(&conn->work, EPOLLOUT);
			break;

		case -ECONNRESET:
			srv_notice("seqpkt_process_established_event: "
			           "outgoing stream closed because of remote peer.\n");
			conn->sync.base.state = GALV_CONN_SENDSHUT_STATE;
			/*
			 * TODO: REPLACE ME
			 * read as much as we can if messages are to be
			 * received, then close:
			 * conn->ops->send_shut();
			 */
#warning replace me!
			//upoll_disable_watch(&conn->work, EPOLLOUT);
			//upoll_apply(poller, conn->sync.base.fd, &conn->work);
			return galv_unix_seqpkt_close(conn, poller);

		case -EINTR:
			upoll_enable_watch(&conn->work, EPOLLOUT);
			upoll_apply(poller, conn->sync.base.fd, &conn->work);
			return -EINTR;
		}
	}

	if (events & EPOLLIN) {
		/* TODO: replace seqpkt_process_may_recv() with conn->ops->may_recv() */
#warning replace me!
		ret = seqpkt_process_may_recv(conn, poller);
		switch (ret) {
		case 0:
			break;

		case -EAGAIN:
			upoll_enable_watch(&conn->work, EPOLLIN);
			break;

		case -EINTR:
			upoll_enable_watch(&conn->work, EPOLLIN);
			upoll_apply(poller, conn->sync.base.fd, &conn->work);
			return -EINTR;

		case -ECONNREFUSED:
			srv_notice("seqpkt_process_established_event: "
			           "incoming stream closed because of remote peer.\n");
			conn->sync.base.state = GALV_CONN_RECVSHUT_STATE;
			/*
			 * TODO: REPLACE ME
			 * write as much as we can if messages are to be sent,
			 * then close:
			 * conn->ops->recv_shut();
			 */
#warning replace me!
			//upoll_disable_watch(&conn->work, EPOLLIN | EPOLLRDHUP);
			//upoll_apply(poller, conn->sync.base.fd, &conn->work);
			return galv_unix_seqpkt_close(conn, poller);
		}
	}

	return ret;
}

static
int
seqpkt_dispatch(struct upoll_worker * worker,
                uint32_t              events,
                const struct upoll *  poller)
{
	galv_unix_assert_intern(worker);
	galv_unix_assert_intern(poller);
	galv_unix_assert_intern(events);
	galv_unix_assert_intern(!(events & ~(EPOLLIN |
	                                    EPOLLHUP | EPOLLRDHUP |
	                                    EPOLLERR)));

	struct galv_unix_async_conn * conn;
	int                           ret;

	conn = containerof(worker, struct galv_unix_async_conn, work);
	galv_unix_assert_intern(conn->sync.base.fd >= 0);
	galv_unix_assert_intern(conn->sync.base.state !=
	                        GALV_CONN_CLOSED_STATE);
	galv_unix_assert_intern(conn->sync.peer_size >= sizeof(sa_family_t));
	galv_unix_assert_intern(conn->sync.peer_cred.pid > 0);

	if (events & EPOLLERR) {
		/*
		 * on error queue
		 *  ECONNRESET: on dgram socket disconnected / dgram
		 *              client reconnection
		 *  on close with data still to be read ??
		 * Replace me with conn->ops->on_error() ?
		 */
#warning replace me!
		srv_notice("seqpkt_process_established_event: socket error.\n");
		ret = 0;
		goto close;
	}

	switch (conn->sync.base.state) {
	case GALV_CONN_ESTABLISHED_STATE:
		ret = seqpkt_process_established_event(conn, events, poller);
		break;

	case GALV_CONN_RECVSHUT_STATE:
		ret = seqpkt_process_recvshut_event(conn, events, poller);
		break;
	case GALV_CONN_SENDSHUT_STATE:
		ret = seqpkt_process_sendshut_event(conn, events, poller);
		break;
	case GALV_CONN_CONNECTING_STATE:
		ret = seqpkt_process_connecting_event(conn, events, poller);
		break;

	case GALV_CONN_CLOSED_STATE:
	default:
		assert(0);
	}

	if ((ret == -ENOMEM) ||
	    (conn->sync.base.state == GALV_CONN_CLOSED_STATE)) {
close:
		int err;

		err = seqpkt_process_close(conn, poller);
		if (!ret)
			ret = err;
	}
	else
		upoll_apply(poller, conn->sync.base.fd, &conn->work);

	return ret;
}

static
int
on_new_conn(const struct galv_unix_acceptor * __restrict acceptor __unused,
            struct galv_unix_async_conn * __restrict     conn,
            const struct upoll * __restrict              poller __unused)
{
	assert(acceptor);
	assert(conn);
	assert(poller);

	conn->work.dispatch = seqpkt_dispatch;

	return 0;
}

/******************************************************************************/
/******************************************************************************/
/******************************************************************************/
/******************************************************************************/

#define SRV_CONNS_NR 5
#define SRV_PER_PID_NR 1
#define SRV_PER_UID_NR 2
int
main(int argc, char * const argv[])
{
	int                                   ret;
	struct galv_fabric_palloc             fab;
	struct galv_unix_conn_gate            gate;
	struct galv_conn_repo                 repo;
	struct upoll                          poll;
	struct galv_unix_acceptor             accept;
	const struct galv_unix_acceptor_attrs attrs = {
		.sock_type    = SOCK_SEQPACKET,
		.listen_flags = SOCK_CLOEXEC,
		.bind_path    = "./sock",
		.listen_bklog = 2,
		.accept_flags = SOCK_CLOEXEC,
		.on_new       = on_new_conn,
		.poll_flags   = EPOLLIN | EPOLLRDHUP
	};

	ret = galv_fabric_palloc_init(&fab,
	                              SRV_CONNS_NR,
	                              sizeof(struct galv_unix_async_conn));

	if (ret) {
		srv_err("fabric: cannot initialize: %s (%d).\n",
		        strerror(-ret),
		        -ret);
		return EXIT_FAILURE;
	}

	ret = galv_unix_conn_gate_init(&gate,
	                               SRV_CONNS_NR,
	                               SRV_PER_PID_NR,
	                               SRV_PER_UID_NR);
	if (ret) {
		srv_err("gate: cannot initialize: %s (%d).\n",
		        strerror(-ret),
		        -ret);
		ret = EXIT_FAILURE;
		goto fini_fab;
	}

	galv_conn_repo_init(&repo, SRV_CONNS_NR);

	/* max_conn + 1 for acceptor socket. */
	ret = upoll_open(&poll, SRV_CONNS_NR + 1);
	if (ret) {
		srv_err("poller: cannot initialize: %s (%d).\n",
		        strerror(-ret),
		        -ret);
		ret = EXIT_FAILURE;
		goto fini_repo;
	}

	ret = galv_unix_acceptor_open(&accept,
	                              &attrs,
	                              &fab.base,
	                              &gate.base,
	                              &repo,
	                              &poll);
	if (ret) {
		srv_err("acceptor: cannot open: %s (%d).\n",
		        strerror(-ret),
		        -ret);
		ret = EXIT_FAILURE;
		goto fini_upoll;
	}

	do {
		ret = upoll_process(&poll, -1);
		if (galv_conn_repo_full(&repo))
			break;
	} while (!ret);

	galv_unix_acceptor_close(&accept, &poll);

	while (!stroll_dlist_empty(&repo.conns)) {
		struct galv_unix_async_conn * conn;

		conn = stroll_dlist_entry(stroll_dlist_dqueue_front(&repo.conns),
		                          struct galv_unix_async_conn,
		                          sync.base.repo);
		galv_unix_gate_untrack(&gate.base,
		                       &conn->sync.peer_addr,
		                       conn->sync.peer_size,
		                       &conn->sync.peer_cred);
		galv_unix_conn_unpoll(&conn->sync, &poll);
		galv_unix_conn_close(&conn->sync);
		galv_fabric_free(&fab.base, conn);
	}

	ret = EXIT_SUCCESS;

fini_upoll:
	upoll_close(&poll);

fini_repo:
	galv_conn_repo_fini(&repo);
	galv_unix_conn_gate_fini(&gate);

fini_fab:
	galv_fabric_fini(&fab.base);

	return ret;
}
#endif

/******************************************************************************/
/******************************************************************************/
/******************************************************************************/
/******************************************************************************/

#define galv_unix_echo_svc_err(_fmt, ...) \
	fprintf(stderr, "echo server:err: " _fmt, ## __VA_ARGS__)

#define galv_unix_echo_svc_info(_fmt, ...) \
	fprintf(stderr, "echo server:info: " _fmt, ## __VA_ARGS__)

#define galv_unix_echo_svc_dbg(_fmt, ...) \
	fprintf(stderr, "echo server:debug: " _fmt, ## __VA_ARGS__)

static
int
galv_unix_echo_svc_process(void)
{
	ssize_t recv;
	ssize_t sent;
	char    buff[32];

	/* Get request. */
	recv = galv_async_conn_recv(conn, buff, sizeof(buff), MSG_TRUNC);
	/* Seqpacket sockets perform "atomic" message read... */
	galv_unix_assert_intern(recv);
	if (recv < 0) {
		switch (recv) {
		case -EAGAIN:
			galv_conn_watch(conn, EPOLLIN);
			break;

		case -ECONNREFUSED:
		case -EINTR:
		case -ENOMEM:
			break;

		default:
			galv_unix_assert_intern(0);
		}

		return recv;
	}
	else if (recv > sizeof(buff)) {
		/* Ignore messages which size is > 32. */
		galv_unix_echo_svc_dbg("oversized message ignored.\n");
		return 0;
	}

	/* Send reply. */
	sent = galv_conn_send(conn, buff, recv, MSG_TRUNC);
	if (sent >= 0)
		galv_unix_assert_intern(sent == recv);
		galv_conn_unwatch(conn, EPOLLOUT);
		return 0;
	}

	switch (sent) {
	case -EAGAIN:
	case -ENOBUFS:
		/*
		 * No need to read requests since we have to wait for the socket
		 * to be ready to send our replies back.
		 */
		galv_conn_unwatch(conn, EPOLLIN);
		/* Request poller to wake us up when socket is ready to send. */
		galv_conn_watch(conn, EPOLLOUT);
		break;

	case -EPIPE:
	case -ECONNRESET:
	case -EINTR:
	case -ENOMEM:
		break;

	default:
		/* Seqpacket sockets perform "atomic" sends... */
		galv_unix_assert_intern(sent < 0);
		/*
		 * No variable MTU for unix seqpacket sockets (and our payload
		 * is always < 32 bytes).
		 */
		galv_unix_assert_intern(sent != -EMSGSIZE);
		/* No TCP fast open for unix seqpacket sockets. */
		galv_unix_assert_intern(sent != -EALREADY);
		galv_unix_assert_intern(0);
	}

	return sent;
}

static
int
galv_unix_echo_svc_on_may_xfer(struct galv_async_conn * __restrict   conn,
                               uint32_t                              events,
                               const struct upoll * __restrict       poller
                               struct galv_acceptor_ctx __restrict * context)
{
	int ret = 0;

	if (events & EPOLLOUT)
		galv_conn_unwatch(conn, EPOLLOUT);

	/* Silently ignore out-of-band data / priority signaling (EPOLLPRI). */
	do {
		ret = galv_unix_echo_svc_process();
	} while (!ret);

	switch (ret) {
	case 0:
	case -EINTR: /* signal occured before any I/O could start. */
	case -ENOBUFS: /* local send end congestion. */
		break;

	case -EAGAIN:
		ret = 0;
		break;

	case -ECONNREFUSED: /* local recv end closed by remote peer. */
		ret = galv_unix_echo_svc_on_recv_closed(conn,
		                                        events,
		                                        poller,
		                                        context);
		break;


	case -EPIPE: /* local send end closed. */
	case -ECONNRESET:
		ret = galv_unix_echo_svc_on_send_closed(conn,
		                                        events,
		                                        poller,
		                                        context);
		break;

	case -ENOMEM: /* no more memory. */
		galv_conn_launch_close(conn);
		break;

	default:
		galv_unix_assert_intern(0);
	}

	return ret;
}

static
int
galv_unix_echo_svc_on_connecting(struct galv_async_conn * __restrict   conn,
                                 uint32_t                              events,
                                 const struct upoll * __restrict       poller
                                 struct galv_acceptor_ctx __restrict * context)
{
	galv_unix_assert_intern(conn);
	galv_unix_assert_intern(!events);
	galv_unix_assert_intern(poller);
	galv_unix_assert_intern(context);

	int err;

	galv_unix_echo_svc_dbg("connecting.\n");

	/*
	 *  To be thread safe, register to connection repository before calling
	 *  galv_unix_async_conn_poll() !
	 */
	galv_conn_repo_register(context->repo, &conn->repo);

	err = galv_unix_async_conn_poll((struct galv_unix_async_conn *)conn,
	                                poller,
	                                EPOLLIN);
	if (!err) {
		conn->async.state = GALV_CONN_ESTABLISHED_STATE;
		galv_unix_echo_svc_dbg("established.\n");
		return 0;
	}

	galv_conn_repo_unregister(context->repo, &conn->repo);
	galv_unix_echo_svc_err("failed to connect: "
	                       "failed to enable polling: %s (%d).\n",
	                       strerror(-err),
	                       -err);

	return err;
}

static
int
galv_unix_echo_svc_on_send_closed(struct galv_conn * __restrict         conn,
                                  uint32_t                              events,
                                  const struct upoll * __restrict       poller
                                  struct galv_acceptor_ctx __restrict * context)
{
	galv_unix_assert_intern(conn);
	galv_unix_assert_intern(conn->state == GALV_CONN_CLOSING_STATE);
	galv_unix_assert_intern(conn->state != GALV_CONN_CLOSED_STATE);
	galv_unix_assert_intern(poller);
	galv_unix_assert_intern(context);

	/*
	 * Just simply request closure of the local socket since we need to send
	 * replies back for each incoming message and we can no more send
	 * messages...
	 * If we wanted to process remaining incoming messages, we would likely
	 * call galv_conn_unwatch(conn, EPOLLOUT).
	 */
	galv_conn_launch_close(conn);

	return 0;

}

static
int
galv_unix_echo_svc_on_recv_closed(struct galv_conn * __restrict         conn,
                                  uint32_t                              events,
                                  const struct upoll * __restrict       poller
                                  struct galv_acceptor_ctx __restrict * context)
{
	galv_unix_assert_intern(conn);
	galv_unix_assert_intern(conn->state == GALV_CONN_CLOSING_STATE);
	galv_unix_assert_intern(conn->state != GALV_CONN_CLOSED_STATE);
	galv_unix_assert_intern(poller);
	galv_unix_assert_intern(context);

	/*
	 * FIXME: do we need to make sure that no incoming messages are still
	 *        sitting into the socket ??
	 *
	 * Just simply request closure of the local socket since we do not
	 * buffer outgoing messages, i.e., we don't need to send pending
	 * outgoing messages...
	 * If we wanted to process remaining outgoing messages, we would likely
	 * call galv_conn_unwatch(conn, EPOLLIN | EPOLLRDHUP).
	 */
	galv_conn_launch_close(conn);

	return 0;
}

static
int
galv_unix_echo_svc_on_close(struct galv_conn * __restrict         conn,
                            uint32_t                              events,
                            const struct upoll * __restrict       poller
                            struct galv_acceptor_ctx __restrict * context)
{
	galv_unix_assert_intern(conn);
	galv_unix_assert_intern(conn->state == GALV_CONN_CLOSING_STATE);
	galv_unix_assert_intern(poller);
	galv_unix_assert_intern(context);

	int ret;

	galv_conn_unpoll(conn, poller);
	galv_conn_repo_unregister(context->repo, conn);
	ret = galv_conn_complete_close(conn);
	free(conn);

	galv_unix_echo_svc_dbg("closed: %d\n", ret);

	return (ret != -EINTR) ? 0 : -EINTR;
}

static
int
galv_unix_echo_svc_on_error(struct galv_conn * __restrict         conn,
                            uint32_t                              events,
                            const struct upoll * __restrict       poller
                            struct galv_acceptor_ctx __restrict * context)
{
	galv_unix_assert_intern(conn);
	galv_unix_assert_intern(conn->state != GALV_CONN_CLOSED_STATE);
	galv_unix_assert_intern(poller);
	galv_unix_assert_intern(context);

	galv_unix_echo_svc_notice("socket error.\n");
	galv_conn_launch_close(conn);

	return 0;
}

static const struct galv_async_conn_ops galv_unix_echo_svc_ops = {
	.on_may_xfer    = galv_unix_echo_svc_on_may_xfer,
	.on_connecting  = galv_unix_echo_svc_on_connecting,
	.on_send_closed = galv_unix_echo_svc_on_send_closed,
	.on_recv_closed = galv_unix_echo_svc_on_recv_closed,
	.on_close       = galv_unix_echo_svc_on_close,
	.on_error       = galv_unix_echo_svc_on_error
};

static
int
galv_unix_echo_svc_accept(struct galv_unix_acceptor * __restrict acceptor,
                          const struct upoll * __restrict        poller,
                          struct galv_acceptor_ctx * __restrict  context)
{
	struct galv_unix_async_conn * conn;
	int                           err;

	galv_unix_echo_svc_dbg("connection requested.\n");

	if (galv_conn_repo_full(context->repo)) {
		/* TODO: log a notice/info message */
		err = -EPERM;
		goto reject;
	}

	conn = malloc(sizeof(*conn));
	if (!conn) {
		/*
		 * When a connection request cannot be handled, we accept() and
		 * close() it. Otherwise, it would sit in the kernel listen
		 * backlog till next call to accept().
		 */
		err = -errno;
		goto reject;
	}

	err = galv_unix_async_conn_accept(conn,
	                                  acceptor,
	                                  SOCK_CLOEXEC,
	                                  &galv_unix_echo_svc_ops);
	if (err) {
		if (err == -ECONNABORTED)
			/*
			 * Connection has been aborted: ignore and tell caller
			 * to keep processing connection requests normally.
			 */
			err = 0;
		goto free;
	}

	conn->async.state = GALV_CONN_CONNECTING_STATE;
	err = conn->ops->on_connecting(conn, 0, poller, context);
	if (err)
		goto close;

	return 0;

close:
	galv_unix_async_conn_close(&conn, context);
free:
	free(conn);

	return err;

reject:
	unsk_reject(acceptor->fd);

	return err;
}

int
main(void)
{
	int                       ret;
	struct upoll              poll;
	struct galv_unix_acceptor accept = {
		.accept
	}

	/* max_conn + 1 for acceptor socket. */
	ret = upoll_open(&poll, SRV_CONNS_NR + 1);
	if (ret) {
		srv_err("poller: cannot initialize: %s (%d).\n",
		        strerror(-ret),
		        -ret);
		ret = EXIT_FAILURE;
		goto fini_repo;
	}

	ret = galv_unix_acceptor_open(&accept, &ctx, &poll);
	if (ret) {
		srv_err("acceptor: cannot open: %s (%d).\n",
		        strerror(-ret),
		        -ret);
		ret = EXIT_FAILURE;
		goto fini_upoll;
	}

	do {
		ret = upoll_process(&poll, -1);
	} while (!ret);

	galv_unix_acceptor_close(&accept, &poll);

	while (!stroll_dlist_empty(&repo.conns)) {
		struct galv_unix_async_conn * conn;

		conn = stroll_dlist_entry(stroll_dlist_dqueue_front(&repo.conns),
		                          struct galv_unix_async_conn,
		                          sync.base.repo);
		galv_unix_gate_untrack(&gate.base,
		                       &conn->sync.peer_addr,
		                       conn->sync.peer_size,
		                       &conn->sync.peer_cred);
		galv_unix_conn_unpoll(&conn->sync, &poll);
		galv_unix_conn_close(&conn->sync);
		galv_fabric_free(&fab.base, conn);
	}

	ret = EXIT_SUCCESS;

fini_upoll:
	upoll_close(&poll);

fini_repo:
	galv_conn_repo_fini(&repo);
	galv_unix_conn_gate_fini(&gate);

fini_fab:
	galv_fabric_fini(&fab.base);

	return ret;
}
