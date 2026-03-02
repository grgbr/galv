/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2026 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "bkoff.h"
#include <stroll/pow2.h>

void
galv_timer_arm_bkoff(struct galv_timer * __restrict timer)
{
	galv_timer_assert_bkoff_intern(timer);

	int msecs = timer->bkoff.low_msecs;

#if defined(CONFIG_GALV_TIMER_BKOFF_RAND)
	etux_timer_arm_msec(&timer->base,
	                    (msecs >> 1) + galv_prng_max(msecs));
#else  /* !defined(GALV_TIMER_BKOFF_RAND) */
	etux_timer_arm_msec(&timer->base, msecs);
#endif /* defined(GALV_TIMER_BKOFF_RAND) */

	timer->bkoff.low_msecs =
		stroll_min(msecs << 1, stroll_abs(timer->bkoff.high_msecs));
}

void
galv_timer_setup_bkoff_tries(struct galv_timer * __restrict timer,
                             etux_timer_expire_fn *         expire,
                             int                            tries,
                             int                            msecs)
{
	galv_assert_intern(timer);
	galv_assert_intern(expire);
	galv_assert_intern(stroll_abs(tries));
	galv_assert_intern(msecs > 0);

	etux_timer_init(&timer->base, expire);

	timer->bkoff.low_msecs = msecs;
	if (tries > 0)
		timer->bkoff.high_msecs = msecs << tries;
	else
		timer->bkoff.high_msecs = -(msecs << (-tries - 1));
}

void
galv_timer_setup_bkoff_range(struct galv_timer * __restrict timer,
                             etux_timer_expire_fn *         expire,
                             bool                           endless,
                             int                            low_msecs,
                             int                            high_msecs)
{
	galv_timer_assert_bkoff_intern(timer);
	galv_assert_intern(expire);
	galv_assert_intern(low_msecs > 0);
	galv_assert_intern(high_msecs >= low_msecs);

	int tries;

	tries = (int)
	        stroll_pow2_low((unsigned int)(high_msecs / low_msecs) + 1);
	galv_assert_intern(tries >= 1);

	galv_timer_setup_bkoff_tries(timer,
	                             expire,
	                             (!endless) ? tries : -tries,
	                             low_msecs);
}
