/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _GALV_PRIV_DISPATCH_H
#define _GALV_PRIV_DISPATCH_H

#include <galv/cdefs.h>

struct galv_dispatch;
struct galv_conn;
struct upoll;

typedef int
        galv_dispatch_on_conn_term_fn(struct galv_dispatch * __restrict,
                                      struct galv_conn * __restrict,
                                      const struct upoll * __restrict);

struct galv_dispatch {
	galv_dispatch_on_conn_term_fn * on_conn_term;
};

#endif /* _GALV_PRIV_DISPATCH_H */
