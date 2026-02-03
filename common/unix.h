/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _GALV_COMMON_UNIX_H
#define _GALV_COMMON_UNIX_H

#include "common/conn.h"
#include "galv/unix.h"

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

#if defined(CONFIG_GALV_DEBUG)

struct galv_unix_endpt;

extern void
galv_unix_conn_debug(const struct galv_unix_endpt * __restrict endpoint,
                     const char * __restrict                   message)
	__export_public;

#else /* !defined(CONFIG_GALV_DEBUG) */

static inline
void
galv_unix_conn_debug(
	const struct galv_unix_endpt * __restrict endpoint __unused,
	const char * __restrict                   message __unused)
{
}

#endif /* defined(CONFIG_GALV_DEBUG) */

#endif /* _GALV_COMMON_UNIX_H */
