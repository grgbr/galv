/****************************************************************************** 
* SPDX-License-Identifier: LGPL-3.0-only
*
* This file is part of Galv.
* Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
*******************************************************************************/

#ifndef _GALV_LIB_REPO_H
#define _GALV_LIB_REPO_H

#include "galv/repo.h"

#define galv_repo_assert_intern(_repo) \
	galv_assert_intern(_repo); \
	galv_assert_intern((_repo)->nr); \
	galv_assert_intern((_repo)->cnt <= (_repo)->nr)

#endif /* _GALV_LIB_REPO_H */
