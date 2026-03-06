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

static
const char *
galv_unix_addr_string(
	const struct galv_unix_addr * __restrict address,
	char                                     string[__restrict_arr UNSK_NAMED_PATH_MAX])
{
	galv_unix_assert_addr_intern(address);
	galv_assert_intern(string);

	return address->size ? unsk_make_addr_string(string,
	                                             &address->data,
	                                             address->size)
	                     : "??";
}

#define GALV_PID_STRSZ_MAX (11)

static
const char *
galv_unix_pid_str(pid_t pid, char string[__restrict_arr GALV_PID_STRSZ_MAX])
{
	galv_assert_intern(pid >= 0);
	galv_assert_intern(string);

	if (pid) {
		int len __unused;

		len = snprintf(string, GALV_PID_STRSZ_MAX, "%d", pid);
		galv_assert_intern(len);
		galv_assert_intern(len < GALV_PID_STRSZ_MAX);

		return string;
	}

	return "?";
}

void
galv_unix_conn_debug(const struct galv_unix_conn * __restrict connection,
                     const char * __restrict                  message)
{
	galv_unix_assert_addr_intern(&connection->peer.addr);
	galv_unix_assert_addr_intern(&connection->local.addr);
	galv_assert_intern(message);
	galv_assert_intern(message[0]);

	char paddr[UNSK_NAMED_PATH_MAX];
	char ppid[GALV_PID_STRSZ_MAX];
	char laddr[UNSK_NAMED_PATH_MAX];
	char lpid[GALV_PID_STRSZ_MAX];

	galv_debug("unix: %s[%s] -> %s[%s]: %s",
	           galv_unix_addr_string(&connection->local.addr, laddr),
	           galv_unix_pid_str(connection->local.cred.pid, lpid),
	           galv_unix_addr_string(&connection->peer.addr, paddr),
	           galv_unix_pid_str(connection->peer.cred.pid, ppid),
	           message);
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

void
galv_unix_setup_cred(struct ucred * __restrict credential)
{
	galv_assert_intern(credential);

	credential->pid = gettid();
	credential->uid = geteuid();
	credential->gid = getegid();
}
