/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Stroll.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _GALV_LIB_SESSION_H
#define _GALV_LIB_SESSION_H

#include "common.h"
#include "galv/session.h"

#define galv_sess_assert_conf_api(_conf) \
	galv_assert_api(_conf); \
	galv_assert_api((_conf)->backlog <= (unsigned int)INT_MAX); \
	galv_assert_api(!((_conf)->conn_flags & \
	                  ETUX_SOCK_ACCEPT_INVALID_FLAGS)), \
	galv_assert_api((_conf)->max_pload); \
	galv_assert_api((_conf)->max_pload <= GALV_SESS_PLOAD_SIZE_MAX), \
	galv_assert_api((_conf)->buff_capa >= GALV_SESS_BUFF_CAPA_MIN); \
	galv_assert_api((_conf)->buff_capa <= GALV_SESS_BUFF_CAPA_MAX)

#endif /*  _GALV_LIB_SESSION_H */
