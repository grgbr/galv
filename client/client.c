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
galv_clnt_connect(struct galv_conn * __restrict      client,
                  const struct sockaddr * __restrict peer,
                  int                                retries,
                  int                                msecs,
                  const struct upoll * __restrict    poller)
{
	galv_conn_assert_api(client);
	galv_assert_api(client->fd >= 0);
	galv_assert_api(client->state == GALV_CONN_OPENED_STATE);
	galv_assert_api(peer);
	galv_assert_api(!retries || (msecs > 0));
	galv_assert_api(poller);

	return galv_coupler_connect((struct galv_coupler *)client->dispatch,
	                            client,
	                            peer,
	                            poller,
	                            retries,
	                            msecs);
}
