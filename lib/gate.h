/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _GALV_LIB_GATE_H
#define _GALV_LIB_GATE_H

#include "galv/gate.h"

#define galv_gate_assert_ops_intern(_ops) \
	galv_assert_intern(_ops); \
	galv_assert_intern((_ops)->track); \
	galv_assert_intern((_ops)->untrack)

#define galv_gate_assert_intern(_gate) \
	galv_assert_intern(_gate); \
	galv_gate_assert_ops_intern((_gate)->ops)

#endif /* _GALV_LIB_GATE_H */
