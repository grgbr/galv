/****************************************************************************** 
* SPDX-License-Identifier: LGPL-3.0-only
*
* This file is part of Galv.
* Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
*******************************************************************************/

#ifndef _GALV_PRIV_SESSION_H
#define _GALV_PRIV_SESSION_H

#include <galv/priv/config.h>
#include <stroll/fbmap.h>
#include <stdint.h>

/**
 * @internal
 *
 * Session protocol header.
 */
struct galv_sess_head {
	uint8_t  flags;   /* Message flags */
	uint8_t  xchg;    /* eXCHGange identification number */
	uint16_t size;    /* Size of network data segment */
	char     data[0];
} __packed;

#define GALV_SESS_HEAD_XCHG_BITS \
	(sizeof_member(struct galv_sess_head, xchg) * CHAR_BIT)

#define GALV_SESS_HEAD_SIZE_BITS \
	(sizeof_member(struct galv_sess_head, size) * CHAR_BIT)

#define GALV_SESS_MSG_XCHG_NR \
	(1U << GALV_SESS_HEAD_XCHG_BITS)

#define GALV_SESS_RECV_BMAP_WORD_NR \
	STROLL_FBMAP_WORD_NR(GALV_SESS_MSG_XCHG_NR)

#endif /* _GALV_PRIV_SESSION_H */
