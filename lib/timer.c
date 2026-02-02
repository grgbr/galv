/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2026 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "galv/priv/timer.h"

void
galv_timer_setup(struct galv_timer * __restrict timer,
                 etux_timer_expire_fn *         expire,
                 int                            tries,
                 int                            msecs)
{
	galv_assert_api(timer);
	galv_assert_api(expire);
	galv_assert_api(tries);
	galv_assert_api(msecs > 0);

	etux_timer_init(&timer->base, expire);
	timer->tries = tries;
	timer->msecs = msecs;
}
