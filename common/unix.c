/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "unix.h"
#include "dispatch.h"
#include <utils/sock.h>
#include <stroll/page.h>
#include <stroll/hlist.h>
#include <utils/string.h>

void
galv_unix_setup_cred(struct ucred * __restrict credential)
{
	galv_assert_intern(credential);

	credential->pid = gettid();
	credential->uid = geteuid();
	credential->gid = getegid();
}

#if defined(CONFIG_GALV_LOG)

#define GALV_UNIX_ENDPT_STRSZ_MAX \
	((UNSK_NAMED_PATH_MAX - 1) + \
	 sizeof('[') + \
	 10U + \
	 sizeof(']') + \
	 1U)

void
galv_unix_make_endpt_string(char * __restrict                         string,
                            const struct galv_unix_endpt * __restrict endpoint)
{
	galv_assert_intern(string);
	galv_unix_assert_endpt_intern(endpoint);

	char * str = string;

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

	galv_assert_intern(str < &string[GALV_UNIX_ENDPT_STRSZ_MAX]);
}

#endif /* defined(CONFIG_GALV_LOG) */

struct galv_unix_conn *
galv_unix_create_conn(struct stroll_falloc *                  allocator,
                      int                                     fd,
                      const struct galv_conn_ops * __restrict operations,
                      struct galv_dispatch * __restrict       dispatcher)
{
	galv_assert_intern(allocator);
	galv_assert_intern(fd >= 0);
	galv_conn_assert_ops_intern(operations);
	galv_dispatch_assert_intern(dispatcher);

	struct galv_unix_conn * unc;

	/* Allocate UNIX connection. */
	unc = stroll_falloc_alloc(allocator);
	if (!unc)
		return NULL;

#if defined(CONFIG_GALV_LOG)
	unc->base.peer = malloc(GALV_UNIX_ENDPT_STRSZ_MAX);
	if (!unc->base.peer)
		goto free_conn;

	unc->base.local = malloc(GALV_UNIX_ENDPT_STRSZ_MAX);
	if (!unc->base.local)
		goto free_peer;
#endif /* defined(CONFIG_GALV_LOG) */

	galv_conn_setup(&unc->base, fd, operations, dispatcher);

	return unc;

free_peer:
	free(unc->base.peer);
free_conn:
	stroll_falloc_free(allocator, unc);

	errno = ENOMEM;
	return NULL;
}

int
galv_unix_destroy_conn(struct stroll_falloc * __restrict  allocator,
                       struct galv_unix_conn * __restrict connection)
{
	galv_assert_intern(allocator);
	galv_unix_assert_conn_intern(connection);

	int ret;

	ret = unsk_close(connection->base.fd);
	if (ret && (ret != -EINTR))
		galv_conn_pnotice(&connection->base,
		                  -ret,
		                  "unix",
		                  "cannot close socket");

#if defined(CONFIG_GALV_LOG)
	free(connection->base.peer);
	free(connection->base.local);
#endif /* defined(CONFIG_GALV_LOG) */

	stroll_falloc_free(allocator, connection);

	return ret;
}
