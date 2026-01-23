/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _GALV_LIB_COUPLER_H
#define _GALV_LIB_COUPLER_H

#include "galv/coupler.h"
#include "common.h"

#define galv_coupler_assert_ops_api(_ops) \
	galv_assert_api(_ops); \
	galv_assert_api((_ops)->create_conn); \
	galv_assert_api((_ops)->destroy_conn)

#define galv_coupler_assert_ops_intern(_ops) \
	galv_assert_intern(_ops); \
	galv_assert_intern((_ops)->create_conn); \
	galv_assert_intern((_ops)->destroy_conn)

#define galv_coupler_assert_api(_lnk) \
	galv_assert_api(_lnk); \
	galv_coupler_assert_ops_api((_lnk)->ops); \
	galv_repo_assert_api((_lnk)->repo); \
	galv_conn_assert_ops_api((_lnk)->conn_ops); \
	galv_assert_api(((_lnk)->sock_type == SOCK_STREAM) || \
	                ((_lnk)->sock_type == SOCK_SEQPACKET)); \
	galv_assert_api(!((_lnk)->sock_flags & \
	                  ETUX_SOCK_OPEN_INVALID_FLAGS))

#define galv_coupler_assert_intern(_lnk) \
	galv_assert_intern(_lnk); \
	galv_coupler_assert_ops_intern((_lnk)->ops); \
	galv_repo_assert_intern((_lnk)->repo); \
	galv_conn_assert_ops_intern((_lnk)->conn_ops); \
	galv_assert_intern(((_lnk)->sock_type == SOCK_STREAM) || \
	                   ((_lnk)->sock_type == SOCK_SEQPACKET)); \
	galv_assert_intern(!((_lnk)->sock_flags & ETUX_SOCK_OPEN_INVALID_FLAGS))

static inline
struct stroll_falloc *
galv_coupler_allocator(const struct galv_coupler * __restrict coupler)
{
	galv_coupler_assert_api(coupler);

STROLL_IGNORE_WARN("-Wcast-qual")
	return (struct stroll_falloc *)&coupler->alloc;
STROLL_RESTORE_WARN
}

#endif /* _GALV_LIB_COUPLER_H */
