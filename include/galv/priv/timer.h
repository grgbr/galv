/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2026 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _GALV_PRIV_TIMER_H
#define _GALV_PRIV_TIMER_H

#include <galv/cdefs.h>
#include <utils/timer.h>

struct galv_timer {
	struct etux_timer base;
	int               tries;
	int               msecs;
};

#define galv_timer_assert_api(_tmr) \
	galv_assert_api(_tmr); \
	galv_assert_api(!(_tmr)->tries || ((_tmr)->msecs > 0)); \
	galv_assert_api(!!(_tmr)->tries || !etux_timer_is_armed(&(_tmr)->base))

static inline
bool
galv_timer_armed(const struct galv_timer * __restrict timer)
{
	galv_timer_assert_api(timer);

	return etux_timer_is_armed(&timer->base);
}

static inline
bool
galv_timer_defunct(const struct galv_timer * __restrict timer)
{
	galv_timer_assert_api(timer);

	return !timer->tries;
}

static inline
void
galv_timer_arm(struct galv_timer * __restrict timer)
{
	galv_timer_assert_api(timer);
	galv_assert_api(timer->tries);
	galv_assert_api(timer->msecs > 0);

	etux_timer_arm_msec(&timer->base, timer->msecs);
	if (timer->tries > 0)
		timer->tries--;
}

static inline
void
galv_timer_cancel(struct galv_timer * __restrict timer)
{
	galv_timer_assert_api(timer);

	etux_timer_cancel(&timer->base);
}

extern void
galv_timer_setup(struct galv_timer * __restrict timer,
                 etux_timer_expire_fn *         expire,
                 int                            tries,
                 int                            msecs);

#endif /* _GALV_PRIV_TIMER_H */
