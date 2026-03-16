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
	galv_assert_api((_endpt)->cred.pid >= 0)

#define galv_unix_assert_endpt_intern(_endpt) \
	galv_assert_intern(_endpt); \
	galv_unix_assert_addr_intern(&(_endpt)->addr); \
	galv_assert_intern((_endpt)->cred.pid >= 0)

struct galv_unix_conn {
	struct galv_conn       base;
	struct galv_unix_endpt peer;
	struct galv_unix_endpt local;
};

#define galv_unix_assert_conn_api(_conn) \
	galv_assert_api(_conn); \
	galv_conn_assert_api(&(_conn)->base); \
	galv_unix_assert_endpt_api(&(_conn)->peer); \
	galv_unix_assert_endpt_api(&(_conn)->local)

#define galv_unix_assert_conn_intern(_conn) \
	galv_assert_intern(_conn); \
	galv_conn_assert_intern(&(_conn)->base); \
	galv_unix_assert_endpt_intern(&(_conn)->peer); \
	galv_unix_assert_endpt_intern(&(_conn)->local)

#if defined(CONFIG_GALV_LOG)

extern void
galv_unix_make_endpt_string(char * __restrict                         string,
                            const struct galv_unix_endpt * __restrict endpoint)
	__export_public;

#else  /* !defined(CONFIG_GALV_LOG) */

static inline
void
galv_unix_make_endpt_string(
	char * __restrict                         string __unused,
	const struct galv_unix_endpt * __restrict endpoint __unused)
{
	galv_assert_intern(string);
	galv_unix_assert_endpt_intern(endpoint);
}

#endif /* defined(CONFIG_GALV_LOG) */

static inline
void
galv_unix_load_peer_cred(int fd, struct ucred * __restrict credential)
{
	galv_assert_intern(fd >= 0);
	galv_assert_intern(credential);

	socklen_t sz = sizeof(*credential);

	unsk_getopt(fd, SO_PEERCRED, credential, &sz);
	galv_assert_intern(sz == sizeof(*credential));
}

extern void
galv_unix_setup_cred(struct ucred * __restrict credential)
	__export_public;

extern struct galv_unix_conn *
galv_unix_create_conn(struct stroll_falloc *                  allocator,
                      int                                     fd,
                      const struct galv_conn_ops * __restrict operations,
                      struct galv_dispatch * __restrict       dispatcher)
	__export_public;

extern int
galv_unix_destroy_conn(struct stroll_falloc * __restrict  allocator,
                       struct galv_unix_conn * __restrict connection)
	__export_public;

#endif /* _GALV_COMMON_UNIX_H */
