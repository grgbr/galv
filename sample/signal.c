#include "common.h"
#include <galv/cdefs.h>
#include <utils/signal.h>

static const struct elog_stdio_conf galvsmpl_log_cfg = {
	.super.severity = ELOG_DEBUG_SEVERITY,
	.format         = ELOG_TAG_FMT
};

struct elog_stdio galvsmpl_log;

void
galvsmpl_init(void)
{
	elog_init_stdio(&galvsmpl_log, &galvsmpl_log_cfg);
	galv_setup((struct elog *)&galvsmpl_log);
}

void
galvsmpl_fini(void)
{
	elog_fini_stdio(&galvsmpl_log);
}

static
int
galvsmpl_dispatch_sigchan(struct upoll_worker * work,
                          uint32_t              state __unused,
                          const struct upoll *  poll __unused)
{
	galvsmpl_assert(work);
	galvsmpl_assert(state);
	galvsmpl_assert(!(state & EPOLLOUT));
	galvsmpl_assert(!(state & EPOLLRDHUP));
	galvsmpl_assert(!(state & EPOLLPRI));
	galvsmpl_assert(!(state & EPOLLHUP));
	galvsmpl_assert(!(state & EPOLLERR));
	galvsmpl_assert(state & EPOLLIN);
	galvsmpl_assert(poll);

	const struct galvsmpl_sigchan * chan;
	struct signalfd_siginfo         info;
	int                             ret;

	chan = containerof(work, struct galvsmpl_sigchan, work);
	galvsmpl_assert(chan);

	ret = usig_read_fd(chan->fd, &info, 1);
	galvsmpl_assert(ret);
	if (ret < 0)
		return (ret == -EAGAIN) ? 0 : ret;

	switch (info.ssi_signo) {
	case SIGHUP:
	case SIGINT:
	case SIGQUIT:
	case SIGTERM:
		/* Tell caller we were requested to terminate. */
		galvsmpl_debug("interrupted by signal '%s'",
		               strsignal((int)info.ssi_signo));
		return -ESHUTDOWN;

	case SIGUSR1:
	case SIGUSR2:
		/* Silently ignore these... */
		return 0;

	default:
		galvsmpl_assert(0);
	}

	return ret;
}

int
galvsmpl_open_sigchan(struct galvsmpl_sigchan * __restrict channel,
                      const struct upoll * __restrict      poller)
{
	galvsmpl_assert(channel);
	galvsmpl_assert(poller);

	sigset_t     msk = *usig_empty_msk;
	int          err;
	const char * msg;

	usig_addset(&msk, SIGHUP);
	usig_addset(&msk, SIGINT);
	usig_addset(&msk, SIGQUIT);
	usig_addset(&msk, SIGTERM);
	usig_addset(&msk, SIGUSR1);
	usig_addset(&msk, SIGUSR2);

	channel->fd = usig_open_fd(&msk, SFD_NONBLOCK | SFD_CLOEXEC);
	if (channel->fd < 0) {
		err = channel->fd;
		msg = "open failed";
		goto err;
	}

	channel->work.dispatch = galvsmpl_dispatch_sigchan;
	err = upoll_register(poller, channel->fd, EPOLLIN, &channel->work);
	if (err) {
		msg = "cannot register poll worker";
		goto close;
	}

	usig_procmask(SIG_SETMASK, usig_full_msk, NULL);

	galvsmpl_debug("signal handlers registered.");

	return 0;

close:
	usig_close_fd(channel->fd);
err:
	galvsmpl_perr(-err, "cannot setup signal handlers: %s", msg);

	return err;
}

void
galvsmpl_close_sigchan(const struct galvsmpl_sigchan * __restrict channel,
                       const struct upoll * __restrict            poller)
{
	galvsmpl_assert(channel);
	galvsmpl_assert(poller);

	upoll_unregister(poller, channel->fd);
	usig_close_fd(channel->fd);

	galvsmpl_debug("signal handlers unregistered");
}
