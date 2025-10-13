#include "acceptor.h"
#include <utils/sock.h>

int
galv_acceptor_reject_conn(const struct galv_acceptor * __restrict acceptor)
{
	galv_acceptor_assert_iface_api(acceptor);

	int ret;

	ret = etux_sock_accept(acceptor->fd, NULL, NULL, 0);
	if (ret >= 0)
		ret = etux_sock_close(ret);

	switch (ret) {
	case -EAGAIN:  /* No more connection to accept(2). */
	case -EINTR:   /* Give caller a way to react when system / process */
	case -EMFILE:  /* resource limits are reached. */
	case -ENFILE:
	case -ENOBUFS:
	case -ENOMEM:
		return ret;
	default:
		return 0;
	}

	unreachable();
}

int
galv_acceptor_turn_on(struct galv_acceptor * __restrict           acceptor,
                      int                                         fd,
                      int                                         backlog,
                      const struct upoll * __restrict             poller,
                      upoll_dispatch_fn *                         dispatch,
                      const struct galv_acceptor_ops * __restrict ops,
                      void * __restrict                           context)
{
	galv_assert_intern(acceptor);
	galv_assert_intern(fd >= 0);
	galv_assert_intern(backlog >= 0);
	galv_assert_intern(poller);
	galv_assert_intern(dispatch);
	galv_acceptor_assert_ops_intern(ops);

	int err;

	err = etux_sock_listen(fd, backlog);
	if (err)
		return err;

	acceptor->fd = fd;
	acceptor->ops = ops;
	acceptor->work.dispatch = dispatch;
	acceptor->ctx = context;

	return upoll_register(poller, acceptor->fd, EPOLLIN, &acceptor->work);
}

int
galv_acceptor_close(const struct galv_acceptor * __restrict acceptor,
                    const struct upoll * __restrict         poller)
{
	galv_acceptor_assert_iface_api(acceptor);
	galv_assert_api(poller);

	upoll_unregister(poller, acceptor->fd);

	return etux_sock_close(acceptor->fd);
}
