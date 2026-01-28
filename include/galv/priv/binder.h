/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _GALV_PRIV_BINDER_H
#define _GALV_PRIV_BINDER_H

#include <galv/cdefs.h>
#include <stroll/falloc.h>

struct galv_binder_ops;

struct galv_binder {
	const struct galv_binder_ops * ops;
	int                            sock_type;
	struct stroll_falloc           alloc;
};

#endif /* _GALV_PRIV_BINDER_H */
