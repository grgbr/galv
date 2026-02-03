/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "unix.h"
#include <utils/sock.h>
#include <stroll/page.h>
#include <stroll/hlist.h>
#include <utils/string.h>

#if defined(CONFIG_GALV_DEBUG)

void
galv_unix_conn_debug(const struct galv_unix_endpt * __restrict endpoint,
                     const char * __restrict                   message)
{
	galv_unix_assert_addr_intern(&endpoint->addr);

	char                          str[UNSK_NAMED_PATH_MAX];
	const struct galv_unix_addr * addr = &endpoint->addr;
	const struct ucred *          cred = &endpoint->cred;

	galv_debug("unix: %s [addr:%s pid:%d uid:%d]",
	           message,
	           addr->size ? unsk_make_addr_string(str,
	                                              &addr->data,
	                                              addr->size)
	                      : "??",
	           cred->pid,
	           cred->uid);
}

#endif /* defined(CONFIG_GALV_DEBUG) */

void
galv_unix_make_named_addr(struct galv_unix_addr * __restrict address,
                          const char * __restrict            path)
{
	galv_assert_api(address);
	galv_assert_api(!unsk_is_named_path_ok(path));

	socklen_t len;

	len = unsk_make_named_addr(&address->data, path);
	galv_assert_intern(len > 0);

	address->size = len;
}
