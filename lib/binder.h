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

typedef struct galv_conn *
        galv_binder_create_conn_fn(struct galv_binder * __restrict,
                                   const struct galv_conn_ops * __restrict,
                                   int,
                                   int,
                                   struct galv_coupler * __restrict);

typedef int
        galv_binder_connect_conn_fn(const struct galv_binder * __restrict,
                                    struct galv_conn * __restrict,
                                    const struct sockaddr * __restrict);

typedef void
        galv_binder_on_connected_fn(const struct galv_binder * __restrict,
                                    struct galv_conn * __restrict);

typedef int
        galv_binder_destroy_conn_fn(struct galv_binder * __restrict,
                                    struct galv_conn * __restrict);

struct galv_binder_ops {
	galv_binder_create_conn_fn *  create_conn;
	galv_binder_connect_conn_fn * connect_conn;
	galv_binder_on_connected_fn * on_connected;
	galv_binder_destroy_conn_fn * destroy_conn;
};

#define galv_binder_assert_ops_api(_ops) \
	galv_assert_api(_ops); \
	galv_assert_api((_ops)->create_conn); \
	galv_assert_api((_ops)->connect_conn); \
	galv_assert_api((_ops)->on_connected); \
	galv_assert_api((_ops)->destroy_conn)

#define galv_binder_assert_ops_intern(_ops) \
	galv_assert_intern(_ops); \
	galv_assert_intern((_ops)->create_conn); \
	galv_assert_intern((_ops)->connect_conn); \
	galv_assert_intern((_ops)->on_connected); \
	galv_assert_intern((_ops)->destroy_conn)

#define galv_binder_assert_api(_binder) \
	galv_assert_api(_binder); \
	galv_binder_assert_ops_api((_binder)->ops)

#define galv_binder_assert_intern(_binder) \
	galv_assert_intern(_binder); \
	galv_binder_assert_ops_intern((_binder)->ops)

static inline
unsigned int
galv_binder_conn_nr(const struct galv_binder * __restrict binder)
{
	galv_binder_assert_intern(binder);

	return stroll_falloc_chunk_nr(&binder->alloc);
}

static inline
struct galv_conn *
galv_binder_create_conn(struct galv_binder * __restrict         binder,
                        const struct galv_conn_ops * __restrict operations,
                        int                                     type,
                        int                                     flags,
                        struct galv_coupler * __restrict        coupler)
{
	galv_binder_assert_intern(binder);
	galv_conn_assert_ops_intern(operations);
	galv_assert_intern(!(flags & ETUX_SOCK_OPEN_INVALID_FLAGS));
	galv_assert_intern(coupler);

	return binder->ops->create_conn(binder,
	                                operations,
	                                type,
	                                flags,
	                                coupler);
}

static inline
int
galv_binder_connect_conn(const struct galv_binder * __restrict binder,
                         struct galv_conn * __restrict         connection,
                         const struct sockaddr * __restrict    peer)
{
	galv_binder_assert_intern(binder);
	galv_conn_assert_intern(connection);
	galv_assert_intern(peer);

	return binder->ops->connect_conn(binder, connection, peer);
}

static inline
void
galv_binder_on_connected(const struct galv_binder * __restrict binder,
                         struct galv_conn * __restrict         connection)
{
	galv_binder_assert_intern(binder);
	galv_conn_assert_intern(connection);

	return binder->ops->on_connected(binder, connection);
}

static inline
int
galv_binder_destroy_conn(struct galv_binder * __restrict binder,
                         struct galv_conn * __restrict   connection)
{
	galv_binder_assert_intern(binder);
	galv_conn_assert_intern(connection);

	return binder->ops->destroy_conn(binder, connection);
}

static inline
void
galv_binder_open(struct galv_binder * __restrict           binder,
                 const struct galv_binder_ops * __restrict operations,
                 unsigned int                              max_conn,
                 size_t                                    conn_size)
{
	galv_assert_api(binder);
	galv_binder_assert_ops_api(operations);
	galv_assert_api(conn_size >= sizeof(struct galv_conn));
	galv_assert_api(max_conn);

	binder->ops = operations;
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
