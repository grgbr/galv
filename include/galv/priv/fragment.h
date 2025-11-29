/****************************************************************************** 
* SPDX-License-Identifier: LGPL-3.0-only
*
* This file is part of Galv.
* Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
*******************************************************************************/

#ifndef _GALV_PRIV_FRAGMENT_H
#define _GALV_PRIV_FRAGMENT_H

#include <stroll/slist.h>

/**
 * @internal
 *
 * Core network fragment list.
 */
struct galv_frag_list {
	struct stroll_slist base;
};

#endif /* _GALV_PRIV_FRAGMENT_H */
