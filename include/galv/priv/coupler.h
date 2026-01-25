/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _GALV_PRIV_COUPLER_H
#define _GALV_PRIV_COUPLER_H

#include <galv/cdefs.h>

struct galv_binder;
struct galv_repo;
struct galv_conn_ops;

struct galv_coupler {
	struct galv_binder *         bind;
	struct galv_repo *           repo;
	const struct galv_conn_ops * conn_ops;
	int                          conn_type;
};

#define galv_coupler_assert_api(_coupler) \
	galv_assert_api(_coupler); \
	galv_binder_assert_api((_coupler)->bind); \
	galv_repo_assert_api((_coupler)->repo); \
	galv_conn_assert_ops_api((_coupler)->conn_ops); \
	galv_assert_api((_coupler)->conn_type)

#endif /* _GALV_PRIV_COUPLER_H */
