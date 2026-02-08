/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2026 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "timer.h"

void
galv_timer_setup_retry(struct galv_timer * __restrict timer,
                       etux_timer_expire_fn *         expire,
                       int                            tries,
                       int                            msecs)
{
	galv_assert_intern(timer);
	galv_assert_intern(expire);
	galv_assert_intern(tries);
	galv_assert_intern(msecs > 0);

	etux_timer_init(&timer->base, expire);
	timer->retry.tries = tries;
	timer->retry.msecs = msecs;
}
