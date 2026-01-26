/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _GALV_LIB_ACCEPT_H
#define _GALV_LIB_ACCEPT_H

#include "galv/accept.h"
#include "dispatch.h"
#include "repo.h"
#include "adopt.h"
#include "conn.h"

#define galv_accept_assert_api(_accept) \
	galv_assert_api(_accept); \
	galv_dispatch_assert_api(&(_accept)->base); \
	galv_assert_api((_accept)->work.dispatch); \
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
	galv_dispatch_assert_intern(&(_accept)->base); \
	galv_assert_intern((_accept)->work.dispatch); \
	galv_repo_assert_intern((_accept)->repo); \
	galv_adopt_assert_intern((_accept)->adopt); \
	galv_conn_assert_ops_intern((_accept)->conn_ops); \
	galv_assert_intern(!((_accept)->conn_flags & \
	                     ~(SOCK_NONBLOCK | SOCK_CLOEXEC))); \
	galv_assert_intern((_accept)->conn_flags & SOCK_NONBLOCK); \
	galv_assert_intern((_accept)->state >= 0); \
	galv_assert_intern((_accept)->state < GALV_ACCEPT_STATE_NR)

static inline
unsigned int
galv_accept_conn_nr(const struct galv_accept * __restrict acceptor)
{
	galv_accept_assert_api(acceptor);

	return galv_adopt_conn_nr(acceptor->adopt);
}

#endif /* _GALV_LIB_ACCEPT_H */
