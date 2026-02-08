/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _GALV_PRIV_COUPLER_H
#define _GALV_PRIV_COUPLER_H

#include <galv/priv/dispatch.h>

#if !defined(CONFIG_GALV_CLNT)
#error Cannot include coupler headers with client build configuration disabled !
#endif /* !defined(CONFIG_GALV_CLNT) */

struct galv_binder;
struct galv_repo;
struct galv_conn_ops;
struct sockaddr;

struct galv_coupler {
	struct galv_dispatch         base;
	struct galv_binder *         bind;
	struct galv_repo *           repo;
	const struct galv_conn_ops * conn_ops;
};

extern int
galv_coupler_connect(struct galv_coupler * __restrict   coupler,
                     struct galv_conn * __restrict      client,
                     const struct sockaddr * __restrict peer,
                     const struct upoll * __restrict    poller,
                     int                                tries,
                     int                                msecs)
	__export_public;

#endif /* _GALV_PRIV_COUPLER_H */
