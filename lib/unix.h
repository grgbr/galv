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
#include "acceptor.h"

#define galv_unix_assert_addr_intern(_addr) \
	galv_assert_intern(_addr); \
	galv_assert_intern((_addr)->size >= sizeof(sa_family_t))

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
	galv_unix_assert_endpt_api(&(_conn)->_endpt)

#define galv_unix_assert_conn_intern(_conn) \
	galv_assert_intern(_conn); \
	galv_conn_assert_intern(&(_conn)->base); \
	galv_unix_assert_endpt_intern(&(_conn)->_endpt)

struct galv_unix_acceptor {
	struct galv_acceptor  base;
	struct galv_unix_addr bind_addr;
};

#define galv_unix_assert_acceptor_api(_acceptor) \
	galv_assert_api(_acceptor); \
	galv_acceptor_assert_api(&(_acceptor)->base); \
	galv_assert_api(&(_acceptor)->bind_addr.size > \
	                (sizeof(sa_family_t) + 1))

#define galv_unix_assert_acceptor_intern(_acceptor) \
	galv_assert_intern(_acceptor); \
	galv_acceptor_assert_intern(&(_acceptor)->base); \
	galv_assert_intern(&(_acceptor)->bind_addr.size > \
	                   (sizeof(sa_family_t) + 1))

#endif /* _GALV_LIB_UNIX_H */
