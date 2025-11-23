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
#include <utils/unsk.h>

/******************************************************************************
 * UNIX socket adopter
 ******************************************************************************/

struct galv_unix_adopt_conf {
	const char * bind_path;
	unsigned int max_conn;
};

#define GALV_UNIX_ADOPT_CONF(_bind_path, _max_conn) \
	{ \
		.bind_path = _bind_path, \
		.max_conn  = _max_conn \
	}

static inline
int
galv_unix_adopt_setup_conf(struct galv_unix_adopt_conf * __restrict config,
                           const char * __restrict                  bind_path,
                           unsigned int                             max_conn)
{
	galv_assert_api(config);
	galv_assert_api(!unsk_is_named_path_ok(bind_path));
	galv_assert_api(max_conn);

	config->bind_path = bind_path;
	config->max_conn = max_conn;
}

extern int
galv_unix_adopt_open(struct galv_unix_adopt * __restrict            adopter,
                     int                                            type,
                     int                                            flags,
                     struct galv_gate * __restrict                  gate,
                     const struct galv_unix_adopt_conf * __restrict config)
	__export_public;

extern int
galv_unix_adopt_close(struct galv_unix_adopt * __restrict adopter)
	__export_public;

/******************************************************************************
 * Credential based UNIX connection gate handling
 ******************************************************************************/

#if defined(CONFIG_GALV_GATE)

#include <galv/gate.h>
#include <stroll/falloc.h>

struct stroll_hlist;

struct galv_unix_gate_ucred {
	struct galv_gate       base;
	unsigned int           cnt;
	unsigned int           nr;
	unsigned int           bits;
	unsigned int           per_pid;
	struct stroll_hlist *  pids;
	unsigned int           per_uid;
	struct stroll_hlist *  uids;
	struct stroll_falloc   alloc;
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
