/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _GALV_LIB_ACCEPT_H
#define _GALV_LIB_ACCEPT_H

#include "galv/accept.h"
#include "repo.h"
#include "adopt.h"
#include "conn.h"

typedef struct galv_conn *
        galv_accept_on_conn_request_fn(struct galv_accept * __restrict,
                                       uint32_t,
                                       const struct upoll * __restrict);

typedef int
        galv_accept_on_conn_term_fn(struct galv_accept * __restrict,
                                    struct galv_conn * __restrict,
                                    const struct upoll * __restrict);

struct galv_accept_ops {
	galv_accept_on_conn_request_fn * on_conn_request;
	galv_accept_on_conn_term_fn *    on_conn_term;
};

#define galv_accept_assert_ops_api(_ops) \
	galv_assert_api(_ops); \
	galv_assert_api((_ops)->on_conn_request); \
	galv_assert_api((_ops)->on_conn_term)

#define galv_accept_assert_ops_intern(_ops) \
	galv_assert_intern(_ops); \
	galv_assert_intern((_ops)->on_conn_request); \
	galv_assert_intern((_ops)->on_conn_term)

#define galv_accept_assert_api(_accept) \
	galv_assert_api(_accept); \
	galv_assert_api((_accept)->work.dispatch); \
	galv_accept_assert_ops_api((_accept)->ops); \
	galv_repo_assert_api((_accept)->repo); \
	galv_adopt_assert_api((_accept)->adopt); \
	galv_conn_assert_ops_api((_accept)->conn_ops); \
	galv_assert_api(!((_accept)->conn_flags & \
	                  ~(SOCK_NONBLOCK | SOCK_CLOEXEC))); \
	galv_assert_api((_accept)->conn_flags & SOCK_NONBLOCK); \
	galv_assert_api((_accept)->state >= 0); \
	galv_assert_api((_accept)->state < GALV_ACCEPT_STATE_NR)

#define galv_accept_assert_intern(_accept) \
	galv_assert_intern(_accept); \
	galv_assert_intern((_accept)->work.dispatch); \
	galv_accept_assert_ops_intern((_accept)->ops); \
	galv_repo_assert_intern((_accept)->repo); \
	galv_adopt_assert_intern((_accept)->adopt); \
	galv_conn_assert_ops_intern((_accept)->conn_ops); \
	galv_assert_intern(!((_accept)->conn_flags & \
	                     ~(SOCK_NONBLOCK | SOCK_CLOEXEC))); \
	galv_assert_intern((_accept)->conn_flags & SOCK_NONBLOCK); \
	galv_assert_intern((_accept)->state >= 0); \
	galv_assert_intern((_accept)->state < GALV_ACCEPT_STATE_NR)

static inline
struct galv_adopt *
galv_accept_adopter(const struct galv_accept * __restrict acceptor)
{
	galv_accept_assert_api(acceptor);

	return acceptor->adopt;
}

extern int
galv_accept_on_conn_term(struct galv_accept * __restrict acceptor,
                         struct galv_conn * __restrict   connection,
                         const struct upoll * __restrict poller);

#endif /* _GALV_LIB_ACCEPT_H */
