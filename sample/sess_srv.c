/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "common.h"
#include "galv/unix.h"
#include "galv/session.h"

#define GALVSMPL_SESS_PATH           "sock"
#define GALVSMPL_SESS_BACKLOG        16
#define GALVSMPL_SESS_CONN_NR        (32U)
#define GALVSMPL_SESS_PERPID_CONN_NR (2U)
#define GALVSMPL_SESS_PERUID_CONN_NR (16U)
#define GALVSMPL_SESS_PLOAD_MAX      (32U * 1024U)
#define GALVSMPL_SESS_BUFF_CAPA_MAX  (4U * 1024U)

static
int
galvsmpl_sess_xfer(struct galv_sess_conn * __restrict session)
{
	galvsmpl_debug("received message");

	return 0;
}

static const struct galv_sess_ops galvsmpl_sess_ops = {
	.xfer = galvsmpl_sess_xfer
};

static
int
galvsmpl_loop(struct galv_repo *        repository,
              struct galv_sess_accept * acceptor,
              struct upoll *            poller)
{
	struct galvsmpl_sigchan sigs;
	int                     ret;
	int                     err;

	ret = galvsmpl_open_sigchan(&sigs, poller);
	if (ret)
		return ret;

	do {
		ret = upoll_process(poller, -1);
	} while (!ret || (ret == -EINTR));
	switch (ret) {
	case -ESHUTDOWN:
	case -EINTR:
		ret = 0;
		break;
	}

	galv_accept_suspend((struct galv_accept *)acceptor, poller);
	galv_conn_repo_halt(repository, poller);
	err = 0;
	while (!galv_repo_empty(repository)) {
		/*
		 * To be safe, a timer should be armed here to prevent from
		 * blocking into epoll_wait() forever...
		 */
		err = upoll_process(poller, -1);
		if (err)
			break;
	}
	if (err == -ESHUTDOWN)
		err = -EINTR;
	if (!ret)
		ret = err;

	galv_conn_repo_close(repository, poller);
	galvsmpl_close_sigchan(&sigs, poller);

	if (ret)
		galvsmpl_pdebug(-ret, "failed to gracefully halt");

	return ret;
}

static const struct galv_unix_adopt_conf
galvsmpl_sess_unix_conf = GALV_UNIX_ADOPT_CONF(SOCK_STREAM,
	                                       SOCK_CLOEXEC,
	                                       GALVSMPL_SESS_PATH,
	                                       GALVSMPL_SESS_CONN_NR);

static const struct galv_sess_accept_conf
galvsmpl_sess_conf = GALV_SESS_ACCEPT_CONF(GALVSMPL_SESS_BACKLOG,
	                                   SOCK_CLOEXEC,
	                                   GALVSMPL_SESS_PLOAD_MAX,
	                                   GALVSMPL_SESS_BUFF_CAPA_MAX);

int
main(void)
{
	struct galv_unix_adopt  adopt;
	struct upoll            poll;
	struct galv_repo        repo = GALV_REPO_INIT(repo,
	                                              GALVSMPL_SESS_CONN_NR);
	struct galv_sess_accept accept;
	int                     ret;

	galvsmpl_init();

	ret = galv_unix_adopt_open(&adopt,
	                           GALV_GATE_DUMMY,
	                           &galvsmpl_sess_unix_conf);
	if (ret) {
		galvsmpl_perr(errno, "failed to create UNIX socket adopter");
		goto fini;
	}

	/* Max number of connections + 1 for acceptor / adopter socket. */
	ret = upoll_open(&poll, GALVSMPL_SESS_CONN_NR + 1);
	if (ret) {
		galvsmpl_perr(-ret, "failed to open poller");
		goto close_adopt;
	}

	ret = galv_sess_open_accept(&accept,
	                            &galvsmpl_sess_ops,
	                            &repo,
	                            (struct galv_adopt *)&adopt,
	                            &poll,
	                            &galvsmpl_sess_conf);
	if (ret) {
		galvsmpl_perr(-ret, "failed to open session acceptor");
		goto close_poll;
	}

	ret = galvsmpl_loop(&repo, &accept, &poll);

	galv_sess_close_accept(&accept, &poll);

close_poll:
	upoll_close(&poll);
close_adopt:
	if (!ret)
		ret = galv_unix_adopt_close(&adopt);
	else
		galv_unix_adopt_close(&adopt);
fini:
	galv_repo_fini(&repo);
	galvsmpl_fini();

	return !ret ? EXIT_SUCCESS : EXIT_FAILURE;
}
