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
	                  ETUX_SOCK_ACCEPT_INVALID_FLAGS)); \
	galv_assert_api((_conf)->max_pload); \
	galv_assert_api((_conf)->max_pload <= GALV_SESS_PLOAD_SIZE_MAX); \
	galv_assert_api(stroll_aligned((_conf)->max_pload, \
	                               __WORDSIZE / CHAR_BIT)); \
	galv_assert_api((_conf)->msg_size >= sizeof(struct galv_sess_msg)); \
	galv_assert_api((_conf)->buff_capa >= GALV_SESS_BUFF_CAPA_MIN); \
	galv_assert_api((_conf)->buff_capa <= GALV_SESS_BUFF_CAPA_MAX); \
	galv_assert_api((_conf)->conn_size >= sizeof(struct galv_sess_conn))

#define galv_sess_assert_ops_api(_ops) \
	galv_assert_api(_ops); \
	galv_assert_api((_ops)->connect); \
	galv_assert_api((_ops)->xfer); \
	galv_assert_api((_ops)->close)

#define galv_sess_assert_ops_intern(_ops) \
	galv_assert_intern(_ops); \
	galv_assert_intern((_ops)->connect); \
	galv_assert_intern((_ops)->xfer); \
	galv_assert_intern((_ops)->close)

#endif /*  _GALV_LIB_SESSION_H */
