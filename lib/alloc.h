/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Stroll.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _GALV_LIB_ALLOC_H
#define _GALV_LIB_ALLOC_H

#include <stroll/alloc.h>

extern struct stroll_alloc *
galv_alloc_create(unsigned int nr, size_t size);

#endif /*  _GALV_LIB_ALLOC_H */
