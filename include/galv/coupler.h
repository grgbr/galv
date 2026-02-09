/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _GALV_COUPLER_H
#define _GALV_COUPLER_H

#include <galv/priv/coupler.h>
#include <galv/conn.h>

extern struct galv_conn *
galv_coupler_create_clnt(struct galv_coupler * __restrict coupler,
                         int                              flags)
	__export_public;

extern int
galv_coupler_destroy_clnt(const struct galv_coupler * __restrict coupler,
                          struct galv_conn * __restrict          client)
	__export_public;

extern void
galv_coupler_setup(struct galv_coupler * __restrict        coupler,
	           struct galv_binder * __restrict         binder,
	           struct galv_repo * __restrict           repo,
	           const struct galv_conn_ops * __restrict operations)
	__export_public;

#endif /* _GALV_COUPLER_H */
