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

#if defined(CONFIG_GALV_LOG)

#define GALV_UNIX_ENDPT_STRSZ_MAX \
	((UNSK_NAMED_PATH_MAX - 1) + \
	 sizeof('[') + \
	 10U + \
	 sizeof(']') + \
	 1U)

int
galv_unix_make_endpt_string(
	const struct galv_unix_endpt * __restrict endpoint,
	char ** __restrict                        string)
{
	galv_unix_assert_endpt_intern(endpoint);
	galv_assert_intern(string);

	char * str = *string;

	if (!str) {
		str = malloc(GALV_UNIX_ENDPT_STRSZ_MAX);
		if (!str)
			return -errno;

		*string = str;
	}

	if (endpoint->addr.size)
		str += unsk_make_addr_string(str,
		                             &endpoint->addr.data,
		                             endpoint->addr.size);
	else
		*str++ = '?';

	*str++ = '[';

	if (endpoint->cred.pid)
		str += sprintf(str, "%d", endpoint->cred.pid);
	else
		*str++ = '?';

	*str++ = ']';
	*str = '\0';

	galv_assert_intern(str < &(*string)[GALV_UNIX_ENDPT_STRSZ_MAX]);

	return 0;
}

#endif /* defined(CONFIG_GALV_LOG) */

void
galv_unix_setup_cred(struct ucred * __restrict credential)
{
	galv_assert_intern(credential);

	credential->pid = gettid();
	credential->uid = geteuid();
	credential->gid = getegid();
}
