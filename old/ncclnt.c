#warning FIXME
#ifndef NDEBUG
#define NDEBUG
#endif

#include <utils/unsk.h>
#include <stdio.h>
#include <assert.h>

#define GALVUT_NCCLNT_UNIX_PATH "./sock"

#define galvut_assert(...) assert(__VA_ARGS__)

static
int
galvut_ncclnt_seqpack_connect(void)
{
	int                      sk;
	int                      ret;
	const struct sockaddr_un peer_addr = {
		.sun_family = AF_UNIX,
		.sun_path   = GALVUT_NCCLNT_UNIX_PATH
	};

	sk = unsk_open(SOCK_SEQPACKET, SOCK_CLOEXEC);
	if (sk < 0)
		return sk;

	ret = unsk_connect(sk,
	                   &peer_addr,
	                   (socklen_t)(offsetof(typeof(peer_addr), sun_path) +
	                               sizeof(GALVUT_NCCLNT_UNIX_PATH)));
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
static
void
galvut_ncclnt_open_close()
{
	int sk;

	sk = galvut_ncclnt_seqpack_connect();
	galvut_assert(sk >= 0);

	unsk_close(sk);
}

static
void
galvut_ncclnt_open_shutrd()
{
	int sk;

	sk = galvut_ncclnt_seqpack_connect();
	galvut_assert(sk >= 0);

	unsk_shutdown(sk, SHUT_RD);
	unsk_close(sk);
}

static
void
galvut_ncclnt_open_shutwr()
{
	int sk;

	sk = galvut_ncclnt_seqpack_connect();
	galvut_assert(sk >= 0);

	unsk_shutdown(sk, SHUT_WR);
	unsk_close(sk);
}

static
void
galvut_ncclnt_open_send0_close()
{
	int sk;
	int ret;

	sk = galvut_ncclnt_seqpack_connect();
	galvut_assert(sk >= 0);

	ret = unsk_send(sk, "msg0", sizeof("msg0"), MSG_NOSIGNAL);
	galvut_assert(ret == sizeof("msg0"));

	unsk_close(sk);
}

static
void
galvut_ncclnt_send_bulk(int sk, unsigned int nr)
{
	galvut_assert(sk >= 0);
	galvut_assert(nr);
	galvut_assert(nr < 1000);

	int          ret;
	char         buff[] = "msgxxx";
	unsigned int cnt;

	for (cnt = 0; cnt < nr; cnt++) {
		sprintf(buff, "msg%03u", cnt);
		ret = unsk_send(sk, buff, sizeof(buff), MSG_NOSIGNAL);
		galvut_assert(ret == sizeof(buff));
	}
}

static
void
galvut_ncclnt_open_sendn_close(unsigned int nr)
{
	int          sk;
	int          ret;
	char         buff[] = "msgn";
	unsigned int cnt;

	sk = galvut_ncclnt_seqpack_connect();
	galvut_assert(sk >= 0);

	galvut_ncclnt_send_bulk(sk, nr);

	unsk_close(sk);
}

static
void
galvut_ncclnt_open_send0_shutrd()
{
	int sk;
	int ret;

	sk = galvut_ncclnt_seqpack_connect();
	galvut_assert(sk >= 0);

	unsk_shutdown(sk, SHUT_RD);

	ret = unsk_send(sk, "msg0", sizeof("msg0"), MSG_NOSIGNAL);
	galvut_assert(ret == sizeof("msg0"));

	unsk_close(sk);


}

static
void
galvut_ncclnt_open_sendn_shutrd(unsigned int nr)
{
	int          sk;
	int          ret;
	char         buff[] = "msgn";
	unsigned int cnt;

	sk = galvut_ncclnt_seqpack_connect();
	galvut_assert(sk >= 0);

	unsk_shutdown(sk, SHUT_RD);

	galvut_ncclnt_send_bulk(sk, nr);

	unsk_close(sk);
}

static
void
galvut_ncclnt_open_send0_shutwr()
{
	int sk;
	int ret;

	sk = galvut_ncclnt_seqpack_connect();
	galvut_assert(sk >= 0);

	ret = unsk_send(sk, "msg0", sizeof("msg0"), MSG_NOSIGNAL);
	galvut_assert(ret == sizeof("msg0"));

	unsk_shutdown(sk, SHUT_WR);

	unsk_close(sk);


}

static
void
galvut_ncclnt_open_sendn_shutwr(unsigned int nr)
{
	int          sk;
	int          ret;
	char         buff[] = "msgn";
	unsigned int cnt;

	sk = galvut_ncclnt_seqpack_connect();
	galvut_assert(sk >= 0);

	galvut_ncclnt_send_bulk(sk, nr);

	unsk_shutdown(sk, SHUT_WR);

	unsk_close(sk);
}

static
void
galvut_ncclnt_timed_send(int sk, unsigned int nr, unsigned int max)
{
	galvut_assert(sk >= 0);
	galvut_assert(nr);
	galvut_assert(nr < 1000);
	galvut_assert(max < nr);

	int          ret;
	char         buff[] = "msgxxx";
	unsigned int cnt = 0;

	while (cnt < nr) {
		unsigned int end = cnt + stroll_min(nr - cnt, max);

		while (cnt < end) {
			sprintf(buff, "msg%03u", cnt);
			ret = unsk_send(sk, buff, sizeof(buff), MSG_NOSIGNAL);
			galvut_assert(ret == sizeof(buff));
			cnt++;
		}

		if (cnt < nr)
			sleep(1);
	}
}

static
void
galvut_ncclnt_open_timed_sendn_close(unsigned int nr, unsigned int max)
{
	int          sk;
	int          ret;
	char         buff[] = "msgn";
	unsigned int cnt;

	sk = galvut_ncclnt_seqpack_connect();
	galvut_assert(sk >= 0);

	galvut_ncclnt_timed_send(sk, nr, max);

	unsk_close(sk);
}

static
void
galvut_ncclnt_open_timed_sendn_shutrd(unsigned int nr, unsigned int max)
{
	int          sk;
	int          ret;
	char         buff[] = "msgn";
	unsigned int cnt;

	sk = galvut_ncclnt_seqpack_connect();
	galvut_assert(sk >= 0);

	unsk_shutdown(sk, SHUT_RD);

	galvut_ncclnt_timed_send(sk, nr, max);

	unsk_close(sk);
}

static
void
galvut_ncclnt_open_timed_sendn_shutwr(unsigned int nr, unsigned int max)
{
	int          sk;
	int          ret;
	char         buff[] = "msgn";
	unsigned int cnt;

	sk = galvut_ncclnt_seqpack_connect();
	galvut_assert(sk >= 0);

	galvut_ncclnt_timed_send(sk, nr, max);

	unsk_shutdown(sk, SHUT_WR);

	unsk_close(sk);
}

int main(void)
{
#if 0
	galvut_ncclnt_open_close();
	galvut_ncclnt_open_shutrd();
	galvut_ncclnt_open_shutwr();

	galvut_ncclnt_open_send0_close();
	galvut_ncclnt_open_send0_shutrd();
	galvut_ncclnt_open_send0_shutwr();

	galvut_ncclnt_open_sendn_close(5);
	galvut_ncclnt_open_sendn_shutrd(5);
	galvut_ncclnt_open_sendn_shutwr(5);

	galvut_ncclnt_open_sendn_close(15);
	galvut_ncclnt_open_sendn_shutrd(15);
	galvut_ncclnt_open_sendn_shutwr(15);

	galvut_ncclnt_open_timed_sendn_close(5, 1);
	galvut_ncclnt_open_timed_sendn_shutrd(5, 1);
	galvut_ncclnt_open_timed_sendn_shutwr(5, 1);

	galvut_ncclnt_open_timed_sendn_close(15, 5);
	galvut_ncclnt_open_timed_sendn_shutrd(15, 5);
	galvut_ncclnt_open_timed_sendn_shutwr(15, 5);

	galvut_ncclnt_open_timed_sendn_close(15, 6);
	galvut_ncclnt_open_timed_sendn_shutrd(15, 6);
	galvut_ncclnt_open_timed_sendn_shutwr(15, 6);
#endif
}
