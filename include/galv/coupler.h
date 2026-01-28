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

struct sockaddr;

extern int
galv_coupler_connect(struct galv_coupler * __restrict   coupler,
                     const struct sockaddr * __restrict peer,
                     int                                flags,
                     const struct upoll * __restrict    poller)
	__export_public;

extern void
galv_coupler_setup(struct galv_coupler * __restrict        coupler,
	           struct galv_binder * __restrict         binder,
	           struct galv_repo * __restrict           repo,
	           const struct galv_conn_ops * __restrict operations)
	__export_public;

#endif /* _GALV_COUPLER_H */
