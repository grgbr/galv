/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2026 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "common.h"
#include <utils/prng.h>

#if defined(CONFIG_GALV_PRNG)

/*
 * Thread-safe internal pseudo-random integers generator internal state.
 * Use an 8 integers long table to select the Glibc's simple linear congruential
 * generator (LCG), referred to as TYPE_0 in the Glibc source.
 *
 * This LCG does not generate a fully pseudorandom number on each separate
 * random_r() call. Basically, it traverses the whole 2^31 numbers range in a
 * pseudorandom order so that once some number is obtained, it will not be
 * obtained again in the current 2^31 period. That number will be obtained
 * exactly in the next 2^31 random_r() call, no sooner, no later.
 *
 * This should be enough for most of Galv usages, mainly, introducing jitter
 * while computing the reconnection timer expiration delay.
 *
 * THIS IS NOT CRYPTOGRAPHICALLY SECURE !!
 */
static __thread ETUX_PRNG_DECLARE(galv_the_prng, ETUX_PRNG0_TYPE);

int
galv_prng_max(int high)
{
	galv_assert_intern(high);
	galv_assert_intern(high <= RAND_MAX);

	return etux_prng_draw_max(&galv_the_prng, high);
}

static
void
galv_prng_init(void)
{
	etux_prng_init(&galv_the_prng);
}

#else  /* !defined(CONFIG_GALV_PRNG) */

static void galv_prng_init(void) { }

#endif /* defined(CONFIG_GALV_PRNG) */

/* Per-thread logger instance. */
__thread struct elog * galv_logger = NULL;

void
galv_setup(struct elog * __restrict logger)
{
	galv_logger = logger;
	galv_prng_init();
}
