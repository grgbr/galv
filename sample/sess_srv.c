/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "galv/repo.h"
#include "galv/fabric.h"
#include "galv/unix.h"
#include <elog/elog.h>

#define GALVSMPL_SESS_PATH           "sock"
#define GALVSMPL_SESS_BACKLOG        16
#define GALVSMPL_SESS_CONN_NR        (32U)
#define GALVSMPL_SESS_PERPID_CONN_NR (2U)
#define GALVSMPL_SESS_PERUID_CONN_NR (2U)

static const struct elog_stdio_conf galvsmpl_sess_log_cfg = {
	.super.severity = ELOG_DEBUG_SEVERITY,
	.format         = ELOG_TAG_FMT
};

static struct elog_stdio             galvsmpl_sess_log;

#define galvsmpl_perr(_err, _format, ...) \
	elog_err(&galvsmpl_sess_log, \
	         _format ": %s (%d).\n", \
	         ## __VA_ARGS__, \
	         strerror(_err), \
	         _err)

static const struct galv_conn_ops    galvsmpl_sess_ops = {
};

int
main(void)
{
	struct galv_fabric_palloc    fab;
	struct galv_unix_gate_ucred  gate;
	struct galv_conn_repo        repo;
	struct galv_unix_svc_context ctx = {
		.repo = &repo,
		.fab  = (struct galv_fabric *)&fab,
		.gate = (struct galv_gate *)&gate
	};
	struct upoll                 poll;
	struct galv_unix_svc         svc;
	int                          ret;

	elog_init_stdio(&galvsmpl_sess_log, &galvsmpl_sess_log_cfg);
	galv_setup((struct elog *)&galvsmpl_sess_log);

	ret = galv_fabric_palloc_init(&fab,
	                              GALVSMPL_SESS_CONN_NR,
	                              sizeof(struct galv_unix_conn));
	if (ret) {
		galvsmpl_perr(-ret,
		              "failed to initialize UNIX connection fabric");
		goto out;
	}

	ret = galv_unix_gate_ucred_init(&gate,
	                                GALVSMPL_SESS_CONN_NR,
	                                GALVSMPL_SESS_PERPID_CONN_NR,
	                                GALVSMPL_SESS_PERUID_CONN_NR);
	if (ret) {
		galvsmpl_perr(-ret,
		              "failed to initialize UNIX connection gate");
		goto fini_fab;
	}

	/* Max number of connections + 1 for acceptor socket. */
	ret = upoll_open(&poll, GALVSMPL_SESS_CONN_NR + 1);
	if (ret) {
		galvsmpl_perr(-ret, "failed to open poller");
		goto fini_gate;
	}

	galv_conn_repo_init(&repo, GALVSMPL_SESS_CONN_NR);

	ret = galv_unix_svc_open(&svc,
	                         GALVSMPL_SESS_PATH,
	                         SOCK_STREAM,
	                         SOCK_CLOEXEC,
	                         GALVSMPL_SESS_BACKLOG,
	                         &poll,
	                         &galvsmpl_sess_ops,
	                         &ctx);
	if (ret) {
		galvsmpl_perr(-ret, "failed to open service");
		goto close_poll;
	}

	ret = galv_unix_svc_close(&svc, &poll);
	if (ret)
		galvsmpl_perr(-ret, "failed to close service");

close_poll:
	upoll_close(&poll);
	galv_conn_repo_fini(&repo);
fini_gate:
	galv_unix_gate_ucred_fini(&gate);
fini_fab:
	galv_fabric_fini((struct galv_fabric *)&fab);
out:
	elog_fini_stdio(&galvsmpl_sess_log);

	return !ret ? EXIT_SUCCESS : EXIT_FAILURE;
}
