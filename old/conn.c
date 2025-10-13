#include "galv/conn.h"

/******************************************************************************
 * Asynchronous connection acceptor handling
 ******************************************************************************/

#define galv_acceptor_assert_api(_expr) \
	galv_assert_api("galv:acceptor:", _expr)

typedef int galv_acceptor_handle_fn(struct galv_acceptor * __restrict,
                                    uint32_t,
                                    const struct upoll * __restrict);

struct galv_acceptor_ops {
	galv_acceptor_handle_fn * on_accept;
	galv_acceptor_handle_fn * on_close;
};

#define galv_acceptor_assert_ops_api(_ops) \
	galv_acceptor_assert_api(_ops); \
	galv_acceptor_assert_api((_ops)->on_accept); \
	galv_acceptor_assert_api((_ops)->on_close)

struct galv_acceptor {
	struct upoll_worker              work;
	int                              fd;
	const struct galv_acceptor_ops * ops;
	void *                           ctx;
};

#define galv_acceptor_assert_acceptor_api(_accept) \
	galv_acceptor_assert_api(_accept); \
	galv_acceptor_assert_api((_accept)->fd >= 0); \
	galv_acceptor_assert_ops_api((_accept)->ops)

static inline
struct galv_acceptor *
galv_acceptor_from_worker(const struct upoll_worker * __restrict worker)
{
	return containerof(worker, struct galv_acceptor, work);
}

static inline
struct galv_acceptor *
galv_acceptor_context(const struct galv_acceptor __restrict * acceptor)
{
	galv_acceptor_assert_acceptor_api(acceptor);

	return acceptor->ctx;
}

int
galv_acceptor_open(struct galv_acceptor * __restrict acceptor,
                   const struct upoll * __restrict   poller)
{
	galv_acceptor_assert_api(acceptor);
	galv_acceptor_assert_api(poller);

	int ret;

	ret = unsk_open(attrs->sock_type, SOCK_NONBLOCK | attrs->listen_flags);
	if (ret < 0)
		return ret;

	acceptor->fd = ret;

	/*
	 * Remove local filesystem pathname if existing.
	 *
	 * This is required since binding a named UNIX socket to a filesystem
	 * entry that already exists will fail with EADDRINUSE error code
	 * (AF_UNIX sockets do not support the SO_REUSEADDR socket option).
	 */
	ret = unsk_unlink(attrs->bind_path);
	if (ret)
		goto close;

	/* Build local bind address. */
	acceptor->bind_size = (socklen_t)
	                      offsetof(typeof(acceptor->bind_addr), sun_path) +
	                      (socklen_t)
	                      unsk_make_named_addr(&acceptor->bind_addr,
	                                           attrs->bind_path);

	/*
	 * Bind to the given local filesystem pathname.
	 *
	 * This will effectively create the filesystem entry according to
	 * current process priviledges.
	 * See "Pathname socket ownership and permissions" section of unix(7)
	 * man page.
	 */
	ret = unsk_bind(acceptor->fd,
	                &acceptor->bind_addr,
	                acceptor->bind_size);
	if (ret)
		goto close;

	ret = unsk_listen(acceptor->fd, attrs->listen_bklog);
	if (ret)
		goto close;

	acceptor->work.dispatch = galv_unix_acceptor_dispatch;
	acceptor->fabric = fabric;
	acceptor->sock_flags = attrs->accept_flags;
	acceptor->gate = gate;
	acceptor->repo = repo;
	acceptor->poll_flags = attrs->poll_flags;
	acceptor->on_new = attrs->on_new;

	ret = upoll_register(poller, acceptor->fd, EPOLLIN, &acceptor->work);
	if (ret)
		goto close;

	return 0;

close:
	/* Support named sockets only. */
	galv_unix_assert_intern(attrs->bind_path[0]);
	unlink(attrs->bind_path);
	unsk_close(acceptor->fd);

	return ret;
}

void
galv_unix_acceptor_close(const struct galv_unix_acceptor * __restrict acceptor,
                         const struct upoll * __restrict              poller)
{
	galv_unix_acceptor_assert_api(acceptor);
	galv_unix_assert_api(poller);

	upoll_unregister(poller, acceptor->fd);

	unlink(acceptor->bind_addr.sun_path);
	unsk_close(acceptor->fd);
}
