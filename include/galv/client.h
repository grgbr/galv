/******************************************************************************
 * Asynchronous client connection handling
 ******************************************************************************/

#ifndef _GALV_CLIENT_H
#define _GALV_CLIENT_H

#include <galv/conn.h>

struct sockaddr;

extern int
galv_conn_connect(struct galv_conn * __restrict   connection,
                  struct sockaddr * __restrict    peer,
                  int                             retries,
                  int                             msecs,
                  const struct upoll * __restrict poller)
	__export_public;

#define /* _GALV_CLIENT_H */
