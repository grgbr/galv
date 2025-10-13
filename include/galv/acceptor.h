/******************************************************************************
 * Asynchronous connection acceptor handling
 ******************************************************************************/

#ifndef _GALV_ACCEPTOR_H
#define _GALV_ACCEPTOR_H

#include <galv/cdefs.h>
#include <utils/poll.h>

struct galv_acceptor;
struct galv_conn;

typedef int galv_acceptor_on_accept_fn(struct galv_acceptor * __restrict,
                                       uint32_t,
                                       const struct upoll * __restrict);

typedef int galv_acceptor_on_close_fn(struct galv_acceptor * __restrict,
                                      struct galv_conn * __restrict,
                                      const struct upoll * __restrict);

struct galv_acceptor_ops {
	galv_acceptor_on_accept_fn * on_accept_conn;
	galv_acceptor_on_close_fn *  on_close_conn;
};

#define galv_acceptor_assert_ops_api(_ops) \
	galv_assert_api(_ops); \
	galv_assert_api((_ops)->on_accept_conn); \
	galv_assert_api((_ops)->on_close_conn)

struct galv_acceptor {
	struct upoll_worker              work;
	int                              fd;
	const struct galv_acceptor_ops * ops;
	void *                           ctx;
};

#define galv_acceptor_assert_iface_api(_accept) \
	galv_assert_api(_accept); \
	galv_assert_api((_accept)->fd >= 0); \
	galv_acceptor_assert_ops_api((_accept)->ops)

static inline
struct galv_acceptor *
galv_acceptor_from_worker(const struct upoll_worker * __restrict worker)
{
	galv_assert_api(worker);

	return containerof(worker, struct galv_acceptor, work);
}

static inline
void *
galv_acceptor_context(const struct galv_acceptor * __restrict acceptor)
{
	galv_acceptor_assert_iface_api(acceptor);

	return acceptor->ctx;
}

extern int
galv_acceptor_reject_conn(const struct galv_acceptor * __restrict acceptor)
	__export_public;

extern int
galv_acceptor_close(const struct galv_acceptor * __restrict acceptor,
                    const struct upoll * __restrict         poller);

#endif /* _GALV_ACCEPTOR_H */
