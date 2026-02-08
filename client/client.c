/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2026 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "common/common.h"
#include "galv/client.h"
#include "galv/coupler.h"

int
galv_clnt_connect(struct galv_conn * __restrict   connection,
                  struct sockaddr * __restrict    peer,
                  int                             tries,
                  int                             msecs,
                  const struct upoll * __restrict poller)
{
	galv_conn_assert_api(connection);
	galv_assert_api(connection->fd >= 0);
	galv_assert_api(connection->state == GALV_CONN_OPENED_STATE);
	galv_assert_api(peer);
	galv_assert_api(tries);
	galv_assert_api(!tries || (msecs > 0));
	galv_assert_api(poller);

	return galv_coupler_connect((struct galv_coupler *)connection->dispatch,
	                            connection,
	                            peer,
	                            poller,
	                            tries,
	                            msecs);
}
