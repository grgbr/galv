/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2026 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _GALV_COMMON_TIMER_H
#define _GALV_COMMON_TIMER_H

#include "common/common.h"
#include "galv/priv/timer.h"

#define galv_timer_assert_retry_intern(_tmr) \
	galv_assert_intern(_tmr); \
	galv_assert_intern(!(_tmr)->retry.tries || ((_tmr)->retry.msecs > 0)); \
	galv_assert_intern(!!(_tmr)->retry.tries || \
	                   !etux_timer_is_armed(&(_tmr)->base))

static inline
struct galv_timer *
galv_timer_from_etux(const struct etux_timer * __restrict timer)
{
	galv_assert_intern(timer);

	return containerof(timer, struct galv_timer, base);
}

static inline
bool
galv_timer_retry_armed(const struct galv_timer * __restrict timer)
{
	galv_timer_assert_retry_intern(timer);

	return etux_timer_is_armed(&timer->base);
}

static inline
bool
galv_timer_retry_defunct(const struct galv_timer * __restrict timer)
{
	galv_timer_assert_retry_intern(timer);

	return !timer->retry.tries;
}

static inline
void
galv_timer_arm_retry(struct galv_timer * __restrict timer)
{
	galv_timer_assert_retry_intern(timer);
	galv_assert_intern(timer->retry.tries);
	galv_assert_intern(timer->retry.msecs > 0);

	etux_timer_arm_msec(&timer->base, timer->retry.msecs);
	if (timer->retry.tries > 0)
		timer->retry.tries--;
}

static inline
void
galv_timer_cancel_retry(struct galv_timer * __restrict timer)
{
	galv_timer_assert_retry_intern(timer);

	etux_timer_cancel(&timer->base);
}

extern void
galv_timer_setup_retry(struct galv_timer * __restrict timer,
                       etux_timer_expire_fn *         expire,
                       int                            tries,
                       int                            msecs);

#endif /* _GALV_COMMON_TIMER_H */
