/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _GALV_SERVICE_H
#define _GALV_SERVICE_H

#include <galv/acceptor.h>

struct upoll;
struct galv_conn;

typedef int galv_service_on_accept_fn(struct galv_service * __restrict,
                                      uint32_t,
                                      const struct upoll * __restrict);

typedef int galv_service_on_close_fn(struct galv_service * __restrict,
                                     struct galv_conn * __restrict,
                                     const struct upoll * __restrict);

struct galv_service_ops {
	galv_service_on_accept_fn * on_accept_conn;
	galv_service_on_close_fn *  on_close_conn;
};

#define galv_service_assert_ops_api(_ops) \
	galv_assert_api(_ops); \
	galv_assert_api((_ops)->on_accept_conn); \
	galv_assert_api((_ops)->on_close_conn)

struct galv_service_ctx {
	struct galv_repo *   repo;
	struct galv_fabric * fabric;
	struct galv_gate *   gate;
};

#define galv_acceptor_assert_ctx_api(_ctx) \
	galv_assert_api(_ctx); \
	galv_repo_assert_api((_ctx)->repo); \
	galv_fabric_assert_api((_ctx)->fabric); \
	galv_gate_assert_api((_ctx)->gate)

#define GALV_ACCEPTOR_INIT_CTX(_fabric, _gate) \
	{ .repo = repo, .fabric = _fabric, .gate = _gate }

struct galv_service {
	struct upoll_worker             work;
	const struct galv_service_ops * ops;
	struct galv_service_ctx *       ctx;
};

#define galv_service_assert_api(_service) \
	galv_assert_api(_service); \
	galv_service_assert_ops_api((_service)->ops); \
	galv_service_assert_ctx_api((_service)->ctx)

static inline
struct galv_service *
galv_service_from_worker(const struct upoll_worker * __restrict worker)
{
	galv_assert_api(worker);

	return containerof(worker, struct galv_service, work);
}

static inline
struct galv_service_ctx *
galv_service_context(const struct galv_service * __restrict service)
{
	galv_service_assert_api(service);

	return service->ctx;
}

#endif /* _GALV_SERVICE_H */
