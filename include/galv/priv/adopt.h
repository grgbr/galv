/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _GALV_PRIV_ADOPT_H
#define _GALV_PRIV_ADOPT_H

#include <galv/cdefs.h>

struct galv_adopt_ops;
struct stroll_alloc;

struct galv_adopt {
	const struct galv_adopt_ops * ops;
	int                           fd;
	struct stroll_alloc *         alloc;
	struct galv_gate *            gate;
};

#endif /* _GALV_PRIV_ADOPT_H */
