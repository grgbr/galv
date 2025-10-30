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
#include <galv/priv/fragment.h>

struct galv_conn;

struct galv_sess {
	struct galv_conn *      conn;
	struct galv_buff_queue  recv_buffq;
	struct galv_buff_fabric buff_fab;
	struct galv_frag_fabric frag_fab;
	struct stroll_slist     recv_msgq;
	unsigned long           recv_bmap[GALV_SESS_RECV_BMAP_WORD_NR];
	struct stroll_palloc    msg_fab;
};

#define galv_sess_assert_api(_sess) \
	galv_assert_api(_sess); \
	galv_assert_api((_sess)->conn)

extern int
galv_sess_init(struct galv_sess * __restrict session,
               struct galv_conn * __restrict conn,
               unsigned int                  buff_nr,
               size_t                        buff_capa,
               unsigned int                  frag_nr,
               unsigned int                  msg_nr)
	__export_public;

extern void
galv_sess_fini(struct galv_sess * __restrict session)
	__export_public;

#endif /* _GALV_SESSION_H */
