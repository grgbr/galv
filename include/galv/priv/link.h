/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _GALV_PRIV_LINK_H
#define _GALV_PRIV_LINK_H

#include <galv/cdefs.h>
#include <stroll/falloc.h>

struct galv_link_ops;

struct galv_link {
	const struct galv_link_ops * ops;
	int                          fd;
	struct stroll_falloc         alloc;
};

#endif /* _GALV_PRIV_LINK_H */
