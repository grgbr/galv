/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2026 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "galv/client.h"

int
galv_clnt_connect(struct galv_conn * __restrict   connection,
                  struct sockaddr * __restrict    peer,
                  int                             retries,
                  int                             msecs,
                  const struct upoll * __restrict poller)
{
	galv_conn_assert_api(connection);
	galv_assert_api(connection->fd >= 0);
	galv_assert_api(connection->state == GALV_CONN_CLOSED_STATE);
	galv_assert_api(peer);
	galv_assert_api(retries);
	galv_assert_api(!retries || (msecs > 0));
	galv_assert_api(poller);

	return galv_coupler_connect((struct galv_coupler *)connection->dispatch,
	                            connection,
	                            peer,
	                            poller,
	                            retries,
	                            msecs);
}
