/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _GALV_LIB_ADOPT_H
#define _GALV_LIB_ADOPT_H

#include "galv/priv/adopt.h"
#include "common.h"
#include "conn.h"
#include "gate.h"
#include <utils/sock.h>

typedef struct galv_conn *
        galv_adopt_create_conn_fn(const struct galv_adopt * __restrict,
                                  const struct galv_conn_ops * __restrict,
                                  int,
                                  struct galv_accept * __restrict);

typedef int
        galv_adopt_destroy_conn_fn(const struct galv_adopt * __restrict,
                                   struct galv_conn * __restrict);

struct galv_adopt_ops {
	galv_adopt_create_conn_fn *  create_conn;
	galv_adopt_destroy_conn_fn * destroy_conn;
};

#define galv_adopt_assert_ops_api(_ops) \
	galv_assert_api(_ops); \
	galv_assert_api((_ops)->create_conn); \
	galv_assert_api((_ops)->destroy_conn)

#define galv_adopt_assert_ops_intern(_ops) \
	galv_assert_intern(_ops); \
	galv_assert_intern((_ops)->create_conn); \
	galv_assert_intern((_ops)->destroy_conn)

#define galv_adopt_assert_api(_adopt) \
	galv_assert_api(_adopt); \
	galv_adopt_assert_ops_api((_adopt)->ops); \
	galv_assert_api((_adopt)->fd >= 0); \
	galv_assert_api((_adopt)->alloc); \
	galv_assert_api((_adopt)->gate)

#define galv_adopt_assert_intern(_adopt) \
	galv_assert_intern(_adopt); \
	galv_adopt_assert_ops_intern((_adopt)->ops); \
	galv_assert_intern((_adopt)->fd >= 0); \
	galv_assert_intern((_adopt)->alloc); \
	galv_assert_intern((_adopt)->gate)

static inline
struct stroll_alloc *
galv_adopt_allocator(const struct galv_adopt * __restrict adopter)
{
	galv_adopt_assert_api(adopter);

	return adopter->alloc;
}

static inline
int
galv_adopt_fd(const struct galv_adopt * __restrict adopter)
{
	galv_adopt_assert_api(adopter);

	return adopter->fd;
}

extern struct galv_conn *
galv_adopt_create_conn(const struct galv_adopt * __restrict    adopter,
                       const struct galv_conn_ops * __restrict operations,
                       int                                     flags,
                       struct galv_accept * __restrict         acceptor);

extern int
galv_adopt_destroy_conn(const struct galv_adopt * __restrict adopter,
                        struct galv_conn * __restrict        connection);

static inline
void
galv_adopt_setup(struct galv_adopt * __restrict           adopter,
                 const struct galv_adopt_ops * __restrict operations,
                 int                                      fd,
                 struct stroll_alloc * __restrict         allocator,
                 struct galv_gate * __restrict            gate)
{
	galv_assert_intern(adopter);
	galv_adopt_assert_ops_intern(operations);
	galv_assert_intern(fd >= 0);
	galv_assert_intern(allocator);
	galv_gate_assert_intern(gate);

	adopter->ops = operations;
	adopter->fd = fd;
	adopter->alloc = allocator;
	adopter->gate = gate;
}

static inline
int
galv_adopt_close(const struct galv_adopt * __restrict adopter)
{
	galv_adopt_assert_api(adopter);

	return etux_sock_close(adopter->fd);
}

#endif /* _GALV_LIB_ADOPT_H */
