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

struct etux_timer_retry {
	int tries;
	int msecs;
};

struct etux_timer_bkoff {
	int high_msecs;
	int low_msecs;
};

struct galv_timer {
	struct etux_timer base;
	union {
		struct etux_timer_retry retry;
		struct etux_timer_bkoff bkoff;
	};
};

#endif /* _GALV_PRIV_TIMER_H */
