/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _GALV_PRIV_UNIX_H
#define _GALV_PRIV_UNIX_H

#include <galv/priv/adopt.h>
#include <sys/un.h>
#include <sys/socket.h>

struct galv_unix_addr {
	socklen_t          size;
	struct sockaddr_un data;
};

struct galv_unix_adopt {
	struct galv_adopt     base;
	struct galv_unix_addr bind_addr;
};

#endif /* _GALV_PRIV_UNIX_H */
