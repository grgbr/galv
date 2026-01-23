/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _GALV_COUPLER_H
#define _GALV_COUPLER_H

#include <galv/cdefs.h>
#include <utils/poll.h>

struct galv_coupler_conf {
	int          sock_type;
	int          sock_flags;
	unsigned int max_conn;
};

extern int
galv_coupler_config_max_conn(struct galv_coupler_conf * __restrict config,
                             const char * __restrict               string)
	__export_public;

extern void
galv_unix_coupler_config(struct galv_coupler_conf * __restrict config,
                         int                                   sock_type,
                         int                                   sock_flags,
                         unsigned int                          max_conn)
	__export_public;

struct galv_repo;
struct galv_conn;

typedef struct galv_conn *
        galv_coupler_create_conn_fn(const struct galv_coupler * __restrict,
                                    const struct galv_conn_ops * __restrict,
                                    int);

typedef int
        galv_coupler_destroy_conn_fn(const struct galv_coupler * __restrict,
                                     struct galv_conn * __restrict);

struct galv_coupler_ops {
	galv_coupler_connect_fn *      connect_conn;
	galv_coupler_create_conn_fn *  create_conn;
	galv_coupler_destroy_conn_fn * destroy_conn;
};

struct galv_coupler {
	const struct galv_coupler_ops * ops;
	struct galv_repo *              repo;
	struct stroll_falloc            alloc;
	const struct galv_conn_ops *    conn_ops;
	int                             conn_type;
	int                             conn_flags;
};

extern struct galv_conn *
galv_coupler_connect(struct galv_coupler * __restrict        coupler,
                     const struct galv_conn_ops * __restrict operations,
                     const struct sockaddr * __restrict      peer,
                     int                                     flags);

extern int
galv_coupler_open(struct galv_coupler * __restrict            coupler,
                  struct galv_repo * __restrict              repository,
                  const struct galv_conn_ops * __restrict    operations,
                  const struct galv_coupler_conf * __restrict config)
	__export_public;

extern void
galv_coupler_close(const struct galv_coupler * __restrict coupler)
	__export_public;

#endif /* _GALV_COUPLER_H */
