struct galv_timer {
	struct etux_timer    base;
	int                  tries;
	int                  msecs;
	const struct upoll * poll;
};

static inline
int
galv_timer_arm(struct galv_timer * __restrict timer)
{
	galv_timer_assert_api(timer);

	if (!timer->tries)
		return -ETIMEDOUT;

	etux_timer_arm_msec(&timer->base, timer->msecs);

	return 0;
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
	timer->poll = poller;
	timer->tries = tries;
	timer->msecs = msecs;
}
