/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _GALV_LIB_UNIX_H
#define _GALV_LIB_UNIX_H

#include "galv/unix.h"
#include "conn.h"
#include "binder.h"
#include "adopt.h"
#include "accept.h"

#define galv_unix_assert_addr_api(_addr) \
	galv_assert_api(_addr); \
	galv_assert_api(!(_addr)->size || \
	                (((_addr)->data.sun_family == AF_UNIX) && \
	                 ((_addr)->size >= sizeof(sa_family_t))))

#define galv_unix_assert_addr_intern(_addr) \
	galv_assert_intern(_addr); \
	galv_assert_intern(!(_addr)->size || \
	                   (((_addr)->data.sun_family == AF_UNIX) && \
	                    ((_addr)->size >= sizeof(sa_family_t))))

struct galv_unix_endpt {
	struct galv_unix_addr addr;
	struct ucred          cred;
};

#define galv_unix_assert_endpt_api(_endpt) \
	galv_assert_api(_endpt); \
	galv_unix_assert_addr_api(&(_endpt)->addr); \
	galv_assert_api((_endpt)->cred.pid > 0)

#define galv_unix_assert_endpt_intern(_endpt) \
	galv_assert_intern(_endpt); \
	galv_unix_assert_addr_intern(&(_endpt)->addr); \
	galv_assert_intern((_endpt)->cred.pid > 0)

struct galv_unix_conn {
	struct galv_conn       base;
	struct galv_unix_endpt peer;
};

#define galv_unix_assert_conn_api(_conn) \
	galv_assert_api(_conn); \
	galv_conn_assert_api(&(_conn)->base); \
	galv_unix_assert_endpt_api(&(_conn)->peer)

#define galv_unix_assert_conn_intern(_conn) \
	galv_assert_intern(_conn); \
	galv_conn_assert_intern(&(_conn)->base); \
	galv_unix_assert_endpt_intern(&(_conn)->peer)

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

#endif /* _GALV_LIB_UNIX_H */
