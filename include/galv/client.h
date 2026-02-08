/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2026 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _GALV_CLIENT_H
#define _GALV_CLIENT_H

/******************************************************************************
 * Asynchronous client connection handling
 ******************************************************************************/

#include <galv/conn.h>

struct sockaddr;

extern int
galv_clnt_connect(struct galv_conn * __restrict   connection,
                  struct sockaddr * __restrict    peer,
                  int                             tries,
                  int                             msecs,
                  const struct upoll * __restrict poller)
	__export_public;

#endif /* _GALV_CLIENT_H */
