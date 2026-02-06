#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <sys/utsname.h>
#include <limits.h>
#include <stdlib.h>
#include <stroll/cdefs.h>
#include <stdbool.h>

#define galv_timer_assert_api(...) assert(__VA_ARGS__)
#define galv_assert_api(...) assert(__VA_ARGS__)
#define galv_assert_intern(...) assert(__VA_ARGS__)

/* Return a pseudo random integer between [0, 2^bits[ */
static
int
galv_rand_max(int * state, unsigned int bits)
{
	galv_assert_intern(state);
	galv_assert_intern(bits);
	galv_assert_intern(bits <= 32);

	return rand_r(state) & (UINT_MAX >> (32 - bits));
}

struct etux_timer {
};

struct galv_timer {
	struct etux_timer base;
	bool              endless;
	unsigned int      msec_bits;
	unsigned int      max_bits;
};

static
void
etux_timer_arm_msec(struct etux_timer * timer, int msecs)
{
	static int no = 0;

	printf("%d: %d\n", no++, msecs);
}

static inline
void
galv_timer_arm(struct galv_timer * __restrict timer, int * rand_state)
{
	galv_timer_assert_api(timer);
	galv_assert_api(timer->msec_bits);
	galv_assert_api(timer->msec_bits <= timer->max_bits);
	galv_assert_api(timer->endless || (timer->msec_bits < timer->max_bits));

	unsigned int bits = timer->msec_bits;
	int          rnd = galv_rand_max(rand_state, bits);

	etux_timer_arm_msec(&timer->base, (1 << (bits - 1)) + rnd);

	timer->msec_bits = stroll_min(timer->msec_bits + 1, timer->max_bits);
}

struct galv_coupler {
	int rnd_stat;
};

void
galv_coupler_init_rand(struct galv_coupler * coupler)
{
	struct timespec tspec;
	unsigned int    seed = 0;

#if 1
	clock_gettime(CLOCK_REALTIME, &tspec);
	seed ^= (unsigned int)(tspec.tv_sec >> 32) ^
	        (unsigned int)(tspec.tv_sec & UINT_MAX);
	seed ^= (unsigned int)tspec.tv_nsec;

	seed ^= (unsigned int)(gethostid() & UINT_MAX);
#endif

	clock_gettime(CLOCK_BOOTTIME, &tspec);
	seed ^= (unsigned int)(tspec.tv_sec >> 32) ^
	        (unsigned int)(tspec.tv_sec & UINT_MAX);
	seed ^= (unsigned int)tspec.tv_nsec;

	seed ^= (unsigned int)getuid();
	seed ^= (unsigned int)getpid();

	coupler->rnd_stat = seed;
}

#if 0
int
galv_coupler_bind_msecs(struct galv_coupler * coupler, int try)
{
	galv_assert_intern(coupler->min_bits);
	galv_assert_intern(coupler->max_bits <= 32);
	galv_assert_intern(coupler->max_bits > coupler->min_bits);

	int bits = stroll_min(coupler->min_bits + try, coupler->max_bits);

	return galv_rand_range(&coupler->rnd_stat, bits - 1, bits);
}
#endif

int main(void)
{
	struct galv_coupler cpl;
	struct galv_timer   tmr = { .endless = true, .msec_bits = 8, .max_bits = 12 };
	unsigned int        a;

	galv_coupler_init_rand(&cpl);

	for (a = 0; a < 32; a++)
		galv_timer_arm(&tmr, &cpl.rnd_stat);
}
