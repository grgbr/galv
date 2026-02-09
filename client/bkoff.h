/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2026 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _GALV_CLNT_BKOFF_H
#define _GALV_CLNT_BKOFF_H

#include "common/timer.h"

#define galv_timer_assert_bkoff_intern(_tmr) \
	galv_assert_intern(_tmr); \
	galv_assert_intern(timer->bkoff.high_msecs); \
	galv_assert_intern((_tmr)->bkoff.low_msecs > 0); \
	galv_assert_intern(timer->bkoff.low_msecs <= \
	                   stroll_abs(timer->bkoff.high_msecs))

static inline
bool
galv_timer_bkoff_armed(const struct galv_timer * __restrict timer)
{
	galv_timer_assert_bkoff_intern(timer);

	return etux_timer_is_armed(&timer->base);
}

static inline
bool
galv_timer_bkoff_defunct(const struct galv_timer * __restrict timer)
{
	galv_timer_assert_bkoff_intern(timer);

	return (timer->bkoff.high_msecs > 0) &&
	       (timer->bkoff.low_msecs == timer->bkoff.high_msecs);
}

extern void
galv_timer_arm_bkoff(struct galv_timer * __restrict timer);

static inline
void
galv_timer_cancel_bkoff(struct galv_timer * __restrict timer)
{
	galv_timer_assert_bkoff_intern(timer);

	etux_timer_cancel(&timer->base);
}

extern void
galv_timer_setup_bkoff_tries(struct galv_timer * __restrict timer,
                             etux_timer_expire_fn *         expire,
                             int                            tries,
                             int                            msecs);

extern void
galv_timer_setup_bkoff_range(struct galv_timer * __restrict timer,
                             etux_timer_expire_fn *         expire,
                             bool                           endless,
                             int                            low_msecs,
                             int                            high_msecs);

#endif /* _GALV_CLNT_BKOFF_H */
