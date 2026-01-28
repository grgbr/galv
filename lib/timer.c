INTEGRATE ME
struct galv_timer {
	struct etux_timer    base;
	int                  tries;
	int                  msecs;
};

#define galv_timer_assert_api(_tmr) \
	galv_assert_api(_tmr); \
	galv_assert_api((_tmr)->msecs); \
	galv_timer_assert_api(!!timer->tries || \
	                      !etux_timer_is_armed(&(_tmr)->base))

static inline
void
galv_timer_is_armed(const struct galv_timer * __restrict timer)
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

void
galv_timer_setup(struct galv_timer * __restrict timer,
                 etux_timer_expire_fn *         expire,
                 unsigned int                   tries,
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
