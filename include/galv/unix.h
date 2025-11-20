/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

/**
 * @file
 * Unix connection
 *
 * @author    Grégor Boirie <gregor.boirie@free.fr>
 * @date      13 Oct 2025
 * @copyright Copyright (C) 2024 Grégor Boirie.
 * @license   [GNU Lesser General Public License (LGPL) v3]
 *            (https://www.gnu.org/licenses/lgpl+gpl-3.0.txt)
 */

#ifndef _GALV_UNIX_H
#define _GALV_UNIX_H

#include <galv/priv/unix.h>

struct stroll_alloc;

/******************************************************************************
 * Unix connection allocator
 ******************************************************************************/

extern struct stroll_alloc *
galv_unix_create_conn_alloc(unsigned int nr)
	__export_public;

/******************************************************************************
 * UNIX socket adopter
 ******************************************************************************/

extern int
galv_unix_adopt_open(struct galv_unix_adopt * __restrict adopter,
                     const char * __restrict             path,
                     int                                 type,
                     int                                 flags,
                     struct stroll_alloc * __restrict    allocator,
                     struct galv_gate * __restrict       gate)
	__export_public;

extern int
galv_unix_adopt_close(const struct galv_unix_adopt * __restrict adopter)
	__export_public;

/******************************************************************************
 * Credential based UNIX connection gate handling
 ******************************************************************************/

#if defined(CONFIG_GALV_GATE)

#include <galv/gate.h>

struct stroll_hlist;

struct galv_unix_gate_ucred {
	struct galv_gate      base;
	unsigned int          cnt;
	unsigned int          nr;
	unsigned int          bits;
	unsigned int          per_pid;
	struct stroll_hlist * pids;
	unsigned int          per_uid;
	struct stroll_hlist * uids;
	struct stroll_alloc * alloc;
};

extern int
galv_unix_gate_ucred_init(struct galv_unix_gate_ucred * __restrict gate,
                          unsigned int                             max_conn,
                          unsigned int                             max_per_pid,
                          unsigned int                             max_per_uid)
	__export_public;

extern void
galv_unix_gate_ucred_fini(struct galv_unix_gate_ucred * __restrict gate)
	__export_public;

#endif /* defined(CONFIG_GALV_GATE) */

#endif /* _GALV_UNIX_H */
