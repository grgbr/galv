#define GALVUT_SESS_UNIX_PATH "./sock"
#define GALVUT_SESS_BACKLOG   (2)

static
int
galvut_sess_open_unix(struct galv_unix_acceptor * __restrict   acceptor,
                      const struct upoll * __restrict          poller,
                      struct galvut_ncsvc_context * __restrict ctx)
{
	return galv_unix_acceptor_open(acceptor,
	                               GALVUT_SESS_UNIX_PATH,
	                               SOCK_STREAM,
	                               SOCK_CLOEXEC,
	                               GALVUT_SESS_BACKLOG,
	                               poller,
	                               &galvut_sess_unix_acceptor_ops,
	                               ctx);
}

static
int
galvut_sess_close_unix(struct galv_unix_acceptor * __restrict acceptor,
                       const struct upoll * __restrict        poller)
{
	return galv_unix_acceptor_close(acceptor, poller);
}
