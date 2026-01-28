/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _GALV_PRIV_COUPLER_H
#define _GALV_PRIV_COUPLER_H

#include <galv/priv/dispatch.h>

struct galv_binder;
struct galv_repo;
struct galv_conn_ops;

struct galv_coupler {
	struct galv_dispatch         base;
	struct galv_binder *         bind;
	struct galv_repo *           repo;
	const struct galv_conn_ops * conn_ops;
};

#endif /* _GALV_PRIV_COUPLER_H */
