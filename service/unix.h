/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2026 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _GALV_SERVICE_UNIX_H
#define _GALV_SERVICE_UNIX_H

#include "common/unix.h"
#include "adopt.h"
#include "accept.h"

#define galv_unix_assert_adopt_api(_adopt) \
	galv_assert_api(_adopt); \
	galv_adopt_assert_api(&(_adopt)->base); \
	galv_assert_api((_adopt)->bind_addr.size > (sizeof(sa_family_t) + 1))

#define galv_unix_assert_adopt_intern(_adopt) \
	galv_assert_intern(_adopt); \
	galv_adopt_assert_intern(&(_adopt)->base); \
	galv_assert_intern((_adopt)->bind_addr.size > (sizeof(sa_family_t) + 1))

#define galv_unix_assert_adopt_conf_api(_conf) \
	galv_assert_api(_conf); \
	galv_assert_api(((_conf)->sock_type == SOCK_STREAM) || \
			((_conf)->sock_type == SOCK_SEQPACKET)); \
	galv_assert_api(!((_conf)->sock_flags & \
	                  ETUX_SOCK_ACCEPT_INVALID_FLAGS)); \
	galv_assert_api(!unsk_is_named_path_ok((_conf)->bind_path)); \
	galv_assert_api((_conf)->max_conn)

#endif /* _GALV_SERVICE_UNIX_H */
