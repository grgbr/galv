/****************************************************************************** 
* SPDX-License-Identifier: LGPL-3.0-only
*
* This file is part of Galv.
* Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
*******************************************************************************/

#ifndef _GALV_PRIV_SESSION_H
#define _GALV_PRIV_SESSION_H

#include <galv/accept.h>

struct stroll_alloc;

struct galv_sess_accept {
	struct galv_accept    base;
	struct stroll_alloc * alloc;
};

#endif /* _GALV_PRIV_SESSION_H */
