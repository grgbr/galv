/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _GALV_UTEST_H
#define _GALV_UTEST_H

#include <sys/types.h>

extern void free(void * ptr);
extern void galvut_expect_free(const void * parm, size_t size);

#endif /* _GALV_UTEST_H */
