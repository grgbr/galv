#undef NDEBUG
#include <utils/unsk.h>
#include <stdio.h>
#include <assert.h>

#define PEER_SUN_PATH "./sock"

static
int
galvut_accept_test_connect(void)
{
	int                      sk;
	int                      ret;
	const struct sockaddr_un peer_addr = {
		.sun_family = AF_UNIX,
		.sun_path   = PEER_SUN_PATH
	};

	sk = unsk_open(SOCK_STREAM, SOCK_CLOEXEC);
	if (sk < 0)
		return sk;

	ret = unsk_connect(sk,
	                   &peer_addr,
	                   (socklen_t)(offsetof(typeof(peer_addr), sun_path) +
	                               sizeof(PEER_SUN_PATH)));
	if (!ret)
		return sk;

	unsk_close(sk);

	return ret;
}

/*
 * Open then close immediatly.
 *
 * On server side, acceptor should:
 * - be waken up by an EPOLLIN|EPOLLHUP|EPOLLRDHUP epoll event mask,
 * - receive a zero-sized message, meaning end of data stream,
 * - then close.
 */
void
galvut_accept_test_open_close()
{
	int sk;

	sk = galvut_accept_test_connect();
	assert(sk >= 0);

	unsk_close(sk);
}

/*
 * Open, send a zero-sized message then close.
 *
 * On server side, acceptor should:
 * - be waken up by an EPOLLIN|EPOLLHUP|EPOLLRDHUP epoll event mask,
 * - receive a zero-sized message, meaning end of data stream,
 * - then close.
 *
 * This is a pathological case where the server cannot distinguish between a
 * zero-sized message and a socket closure condition.
 */
void
galvut_accept_test_open_zero_close()
{
	int     sk;
	ssize_t ret;

	sk = galvut_accept_test_connect();
	assert(sk >= 0);

	ret = unsk_send(sk, NULL, 0, 0);
	assert(!ret);

	unsk_close(sk);
}

/*
 * Open, send a message then close.
 *
 * On server side, acceptor should:
 * - be waken up by an EPOLLIN|EPOLLHUP|EPOLLRDHUP epoll event mask,
 * - receive one message,
 * - receive a zero-sized message, meaning end of data stream,
 * - then close.
 */
void
galvut_accept_test_open_one_close()
{
	int     sk;
	ssize_t ret;

	sk = galvut_accept_test_connect();
	assert(sk >= 0);

	ret = unsk_send(sk, "msg0", sizeof("msg0"), 0);
	assert(ret == sizeof("msg0"));

	unsk_close(sk);
}

void
galvut_conn_test_send(void)
{
	int     sk;
	ssize_t ret;

	sk = galvut_accept_test_connect();
	assert(sk >= 0);

	do {
		ret = unsk_send(sk, "msg0", sizeof("msg0"), MSG_NOSIGNAL);
	} while (ret == sizeof("msg0"));

	printf("send failed: ret=%zd\n", ret);

	unsk_close(sk);
}

void
galvut_conn_test_recv(void)
{
	int                      listen;
	const struct sockaddr_un bind_addr = {
		.sun_family = AF_UNIX,
		.sun_path   = PEER_SUN_PATH
	};
	int                      sk;
	ssize_t                  ret;

	listen = unsk_open(SOCK_STREAM, SOCK_CLOEXEC);
	assert(listen >= 0);

	assert(!unsk_bind(listen,
	                  &bind_addr,
	                  (socklen_t)(offsetof(typeof(bind_addr), sun_path) +
	                              sizeof(PEER_SUN_PATH))));

	assert(!unsk_listen(listen, 0));

	sk = unsk_accept(listen, NULL, NULL, SOCK_CLOEXEC);
	assert(sk >= 0);

	do {
		char data[32];
		ret = unsk_recv(sk, data, sizeof(data), 0);
	} while (ret >= 0);

	printf("recv failed: ret=%zd\n", ret);

	unsk_close(sk);
	unsk_close(listen);
	unlink(PEER_SUN_PATH);
}

int
main(void)
{
#if 0
	galvut_accept_test_open_close();
	/*
	 *  sleep() required since server side may handle multiple accept()
	 * before processing data. This leads to the situation where we try to
	 * run (and open socket of) the next test before the server had the time
	 * to handle socket closure (and server side gate may prevent multiple
	 * connection from the same pid and/or uid...
	 */
	sleep(1);
	galvut_accept_test_open_zero_close();
	sleep(1);
	galvut_accept_test_open_one_close();
	galvut_conn_test_send();
#endif
	galvut_conn_test_recv();
}
