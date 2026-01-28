/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _GALV_LIB_BINDER_H
#define _GALV_LIB_BINDER_H

#include "galv/priv/binder.h"
#include <stroll/page.h>
#include "common.h"
#include "conn.h"

struct galv_coupler;

typedef int
        galv_binder_connect_clnt_fn(const struct galv_binder * __restrict,
                                    struct galv_conn * __restrict,
                                    const struct sockaddr * __restrict);

typedef void
        galv_binder_on_connected_fn(const struct galv_binder * __restrict,
                                    struct galv_conn * __restrict);

typedef int
        galv_binder_reconnect_clnt_fn(const struct galv_binder * __restrict,
                                      struct galv_conn * __restrict);

typedef struct galv_conn *
        galv_binder_create_clnt_fn(struct galv_binder * __restrict,
                                   const struct galv_conn_ops * __restrict,
                                   int,
                                   struct galv_coupler * __restrict);

typedef int
        galv_binder_destroy_clnt_fn(struct galv_binder * __restrict,
                                    struct galv_conn * __restrict);

struct galv_binder_ops {
	galv_binder_connect_clnt_fn *   connect_clnt;
	galv_binder_on_connected_fn *   on_connected;
	galv_binder_reconnect_clnt_fn * reconnect_clnt;
	galv_binder_create_clnt_fn *    create_clnt;
	galv_binder_destroy_clnt_fn *   destroy_clnt;
};

#define galv_binder_assert_ops_api(_ops) \
	galv_assert_api(_ops); \
	galv_assert_api((_ops)->connect_clnt); \
	galv_assert_api((_ops)->on_connected); \
	galv_assert_api((_ops)->reconnect_clnt); \
	galv_assert_api((_ops)->create_clnt); \
	galv_assert_api((_ops)->destroy_clnt)

#define galv_binder_assert_ops_intern(_ops) \
	galv_assert_intern(_ops); \
	galv_assert_intern((_ops)->connect_clnt); \
	galv_assert_intern((_ops)->on_connected); \
	galv_assert_intern((_ops)->reconnect_clnt); \
	galv_assert_intern((_ops)->create_clnt); \
	galv_assert_intern((_ops)->destroy_clnt)

#define galv_binder_assert_api(_binder) \
	galv_assert_api(_binder); \
	galv_binder_assert_ops_api((_binder)->ops); \
	galv_assert_api((_binder)->sock_type)

#define galv_binder_assert_intern(_binder) \
	galv_assert_intern(_binder); \
	galv_binder_assert_ops_intern((_binder)->ops); \
	galv_assert_intern((_binder)->sock_type)

static inline
unsigned int
galv_binder_clnt_nr(const struct galv_binder * __restrict binder)
{
	galv_binder_assert_intern(binder);

	return stroll_falloc_chunk_nr(&binder->alloc);
}

static inline
int
galv_binder_connect_clnt(const struct galv_binder * __restrict binder,
                         struct galv_conn * __restrict         client,
                         const struct sockaddr * __restrict    peer)
{
	galv_binder_assert_intern(binder);
	galv_conn_assert_intern(client);
	galv_assert_intern(peer);

	int ret;

	ret = binder->ops->connect_clnt(binder, client, peer);
	galv_assert_intern(ret <= 0);

	return ret;
}

static inline
void
galv_binder_on_connected(const struct galv_binder * __restrict binder,
                         struct galv_conn * __restrict         client)
{
	galv_binder_assert_intern(binder);
	galv_conn_assert_intern(client);

	return binder->ops->on_connected(binder, client);
}

static inline
int
galv_binder_reconnect_clnt(const struct galv_binder * __restrict binder,
                           struct galv_conn * __restrict         client)
{
	galv_binder_assert_intern(binder);
	galv_conn_assert_intern(client);

	int ret;

	ret = binder->ops->reconnect_clnt(binder, client);
	galv_assert_intern(ret <= 0);

	return ret;
}

static inline
struct galv_conn *
galv_binder_create_clnt(struct galv_binder * __restrict         binder,
                        const struct galv_conn_ops * __restrict operations,
                        int                                     flags,
                        struct galv_coupler * __restrict        coupler)
{
	galv_binder_assert_intern(binder);
	galv_conn_assert_ops_intern(operations);
	galv_assert_intern(!(flags & ETUX_SOCK_OPEN_INVALID_FLAGS));
	galv_assert_intern(coupler);

	return binder->ops->create_clnt(binder,
	                                operations,
	                                flags,
	                                coupler);
}

static inline
int
galv_binder_destroy_clnt(struct galv_binder * __restrict binder,
                         struct galv_conn * __restrict   client)
{
	galv_binder_assert_intern(binder);
	galv_conn_assert_intern(client);

	int ret;

	ret = binder->ops->destroy_clnt(binder, client);
	galv_assert_intern(ret <= 0);

	return ret;
}

static inline
void
galv_binder_open(struct galv_binder * __restrict           binder,
                 const struct galv_binder_ops * __restrict operations,
                 int                                       sock_type,
                 unsigned int                              max_conn,
                 size_t                                    conn_size)
{
	galv_assert_api(binder);
	galv_binder_assert_ops_api(operations);
	galv_assert_api(sock_type);
	galv_assert_api(max_conn);
	galv_assert_api(conn_size >= sizeof(struct galv_conn));

	binder->ops = operations;
	binder->sock_type = sock_type;
	stroll_falloc_init_block_size(&binder->alloc,
	                              max_conn,
	                              conn_size,
	                              stroll_page_size());
}

static inline
void
galv_binder_close(struct galv_binder * __restrict binder)
{
	galv_binder_assert_api(binder);

	stroll_falloc_fini(&binder->alloc);
}

#endif /* _GALV_LIB_BINDER_H */
