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

/* TODO: make sure _path is constant ! */
#define GALV_UNIX_NAMED_ADDR(_path) \
	{ \
		.data = UNSK_NAMED_ADDR(_path), \
		.size = UNSK_NAMED_ADDR_LEN(_path) \
	}

extern void
galv_unix_make_named_addr(struct galv_unix_addr * __restrict address,
                          const char * __restrict            path)
	__export_public;

/******************************************************************************
 * UNIX (client-side) connection binder handling
 ******************************************************************************/

extern void
galv_unix_binder_open(struct galv_binder * __restrict binder,
                      unsigned int                    max_conn)
	__export_public;

extern void
galv_unix_binder_close(struct galv_binder * __restrict binder)
	__export_public;

/******************************************************************************
 * UNIX (service-side) socket adopter handling
 ******************************************************************************/

struct galv_unix_adopt_conf {
	int          sock_type;
	int          sock_flags;
	const char * bind_path;
	unsigned int max_conn;
};

#define GALV_UNIX_ADOPT_CONF(_sock_type, _sock_flags, _bind_path, _max_conn) \
	{ \
		.sock_type      = compile_eval( \
			((_sock_type) == SOCK_STREAM) || \
			((_sock_type) == SOCK_SEQPACKET), \
			_sock_type, \
			"invalid UNIX adopter socket type"), \
		.sock_flags     = compile_eval( \
			!((_sock_flags) & ETUX_SOCK_ACCEPT_INVALID_FLAGS), \
			_sock_flags, \
			"invalid UNIX adopter socket flags"), \
		.bind_path = compile_eval(_bind_path != NULL, \
		                          _bind_path, \
		                          "invalid adopter bind path"), \
		.max_conn  = compile_eval( \
			_max_conn, \
			_max_conn, \
			"invalid adopter maximum number of connections") \
	}

extern int
galv_unix_adopt_config_path(struct galv_unix_adopt_conf * __restrict config,
                            const char * __restrict                  string)
	__export_public;

extern int
galv_unix_adopt_config_max_conn(struct galv_unix_adopt_conf * __restrict config,
                                const char * __restrict                  string)
	__export_public;

extern void
galv_unix_adopt_config(struct galv_unix_adopt_conf * __restrict config,
                       int                                      sock_type,
                       int                                      sock_flags,
                       const char * __restrict                  bind_path,
                       unsigned int                             max_conn)
	__export_public;

extern int
galv_unix_adopt_open(struct galv_unix_adopt * __restrict            adopter,
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
