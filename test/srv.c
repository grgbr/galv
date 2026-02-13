#include <utils/unsk.h>
#include <stdio.h>

#define GALVUT_SRV_PATH  "sock"
#define GALVUT_SRV_BKLOG 1

#define galvut_srv_log(_format, ...) \
	fprintf(stderr, \
	        "%s: " _format, \
	        program_invocation_short_name, \
	        ## __VA_ARGS__)

int main(void)
{
	int                lsk;
	int                err;
	struct sockaddr_un local = UNSK_NAMED_ADDR(GALVUT_SRV_PATH);
	struct sockaddr_un peer;
	socklen_t          sz = sizeof(peer);
	int                psk;
	char               str[UNSK_NAMED_PATH_MAX];
	const char *       msg;

	lsk = unsk_open(SOCK_STREAM, SOCK_CLOEXEC);
	if (lsk < 0) {
		err = lsk;
		msg = "failed to open socket";
		goto out;
	}

	err = unsk_unlink(GALVUT_SRV_PATH);
	if (err) {
		msg = "failed to cleanup local address";
		goto close_local;
	}

	err = unsk_bind(lsk, &local, UNSK_NAMED_ADDR_LEN(GALVUT_SRV_PATH));
	if (err) {
		msg = "failed to bind socket to local address";
		goto close_local;
	}

	err = unsk_listen(lsk, GALVUT_SRV_BKLOG);
	if (err) {
		msg = "failed to listen for connection requests";
		goto close_local;
	}

	sleep(10);
	psk = unsk_accept(lsk, &peer, &sz, SOCK_CLOEXEC);
	if (psk < 0) {
		err = psk;
		msg = "failed to accept connection";
		goto close_local;
	}

	galvut_srv_log("connection request accepted from '%s'.\n",
	               unsk_make_addr_string(str, &peer, sz));

	err = 0;

/*close_peer:*/
	unsk_close(psk);
close_local:
	unsk_close(lsk);
out:
	if (err)
		galvut_srv_log("%s: %s (%d).\n", msg, strerror(-err), -err);

	return !err ? EXIT_SUCCESS : EXIT_FAILURE;
}
