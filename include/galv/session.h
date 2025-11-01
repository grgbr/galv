/****************************************************************************** 
* SPDX-License-Identifier: LGPL-3.0-only
*
* This file is part of Galv.
* Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
*******************************************************************************/

/**
 * @file
 * Session connection interface
 *
 * @author    Grégor Boirie <gregor.boirie@free.fr>
 * @date      26 Oct 2025
 * @copyright Copyright (C) 2024 Grégor Boirie.
 * @license   [GNU Lesser General Public License (LGPL) v3]
 *            (https://www.gnu.org/licenses/lgpl+gpl-3.0.txt)
 */

#ifndef _GALV_SESSION_H
#define _GALV_SESSION_H

#include <galv/buffer.h>
#include <galv/priv/session.h>
#include <stroll/palloc.h>

struct upoll;

extern int
galv_sess_recv(struct galv_sess * __restrict   session,
               uint32_t                        events,
               const struct upoll * __restrict poller)
	__export_public;

extern int
galv_sess_open(struct galv_sess * __restrict session,
               struct galv_conn * __restrict conn,
               size_t                        max_pload_size,
               size_t                        buff_capa)
	__export_public;

extern void
galv_sess_close(struct galv_sess * __restrict session)
	__export_public;

#endif /* _GALV_SESSION_H */
