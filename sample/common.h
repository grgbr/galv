#ifndef _GALV_SMPL_COMMON_H
#define _GALV_SMPL_COMMON_H

#include <stroll/assert.h>
#include <elog/elog.h>
#include <utils/poll.h>

extern struct elog_stdio galvsmpl_log;

#define galvsmpl_assert(_expr) \
	stroll_assert("sample:discard", _expr)

#define galvsmpl_perr(_err, _format, ...) \
	elog_err(&galvsmpl_log, \
	         _format ": %s (%d).", \
	         ## __VA_ARGS__, \
	         strerror(_err), \
	         _err)

#define galvsmpl_debug(_format, ...) \
	elog_debug(&galvsmpl_log, _format ".", ## __VA_ARGS__)

extern void
galvsmpl_init(void);

extern void
galvsmpl_fini(void);

struct galvsmpl_sigchan {
	struct upoll_worker work;
	int                 fd;
};

extern int
galvsmpl_open_sigchan(struct galvsmpl_sigchan * __restrict channel,
                      const struct upoll * __restrict      poller);

extern void
galvsmpl_close_sigchan(const struct galvsmpl_sigchan * __restrict channel,
                       const struct upoll * __restrict            poller);

#endif /* _GALV_SMPL_COMMON_H */
