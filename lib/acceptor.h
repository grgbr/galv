#ifndef _GALV_LIB_ACCEPTOR_H
#define _GALV_LIB_ACCEPTOR_H

#include "common.h"
#include "galv/acceptor.h"

#define galv_acceptor_assert_ops_intern(_ops) \
	galv_assert_intern(_ops); \
	galv_assert_intern((_ops)->on_accept_conn); \
	galv_assert_intern((_ops)->on_close_conn)

#define galv_acceptor_assert_iface_intern(_accept) \
	galv_assert_intern(_accept); \
	galv_assert_intern((_accept)->fd >= 0); \
	galv_acceptor_assert_ops_intern((_accept)->ops); \
	galv_assert_intern((_accept)->work.dispatch)

static inline
int
galv_acceptor_on_accept_conn(struct galv_acceptor * __restrict acceptor,
                             uint32_t                          events,
                             const struct upoll * __restrict   poller)
{
	galv_acceptor_assert_iface_intern(acceptor);

	return acceptor->ops->on_accept_conn(acceptor, events, poller);
}

static inline
int
galv_acceptor_on_close_conn(struct galv_acceptor * __restrict acceptor,
                            struct galv_conn * __restrict     conn,
                            const struct upoll * __restrict   poller)
{
	galv_acceptor_assert_iface_intern(acceptor);

	return acceptor->ops->on_close_conn(acceptor, conn, poller);
}

extern int
galv_acceptor_turn_on(struct galv_acceptor * __restrict           acceptor,
                      int                                         fd,
                      int                                         backlog,
                      const struct upoll * __restrict             poller,
                      upoll_dispatch_fn *                         dispatch,
                      const struct galv_acceptor_ops * __restrict ops,
                      void * __restrict                           context);

#endif /* _GALV_LIB_ACCEPTOR_H */
