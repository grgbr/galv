/****************************************************************************** 
* SPDX-License-Identifier: LGPL-3.0-only
*
* This file is part of Galv.
* Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
*******************************************************************************/

/**
 * @file
 * RPC interface
 *
 * @author    Loic Jourdheuil Sellin <46419549+Geneo-5@users.noreply.github.com>
 * @date      13 Jan 2026
 * @copyright Copyright (C) 2024 Grégor Boirie.
 * @license   [GNU Lesser General Public License (LGPL) v3]
 *            (https://www.gnu.org/licenses/lgpl+gpl-3.0.txt)
 */

#ifndef _GALV_RPC_H
#define _GALV_RPC_H

#include <dpack/codec.h>
#include <galv/session.h>

/******************************************************************************
 * RPC message handling
 ******************************************************************************/

struct galv_rpc_msg {
	struct galv_sess_msg base;
	struct dpack_encoder enc;
	struct dpack_decoder dec;
	uint32_t             id;
	void *               ctx;
};

#define galv_rpc_assert_msg_api(_msg) \
	galv_assert_api(_msg); \
	galv_sess_assert_msg_api(&(_msg)->base)

static inline
struct dpack_encoder *
galv_rpc_msg_encoder(const struct galv_rpc_msg * __restrict message)
{
	galv_rpc_assert_msg_api(message);

STROLL_IGNORE_WARN("-Wcast-qual")
	return (struct dpack_encoder *)&message->enc;
STROLL_RESTORE_WARN
}

static inline
struct dpack_decoder *
galv_rpc_msg_decoder(const struct galv_rpc_msg * __restrict message)
{
	galv_rpc_assert_msg_api(message);

STROLL_IGNORE_WARN("-Wcast-qual")
	return (struct dpack_decoder *)&message->dec;
STROLL_RESTORE_WARN
}

static inline
void *
galv_rpc_msg_context(const struct galv_rpc_msg * __restrict message)
{
	galv_rpc_assert_msg_api(message);

	return message->ctx;
}

static inline
size_t
galv_rpc_msg_size(const struct galv_rpc_msg * __restrict message)
{
	galv_rpc_assert_msg_api(message);

	return galv_sess_msg_size(&message->base);
}

static inline
enum galv_sess_head_type
galv_rpc_msg_type(const struct galv_rpc_msg * __restrict message)
{
	galv_rpc_assert_msg_api(message);

	return galv_sess_msg_type(&message->base);
}

extern void
galv_rpc_msg_drop(struct galv_rpc_msg * __restrict message)
	__export_public;

/******************************************************************************
 * RPC connection handling
 ******************************************************************************/

typedef int galv_rpc_fn(struct galv_rpc_msg *);

struct galv_rpc_conn {
	struct galv_sess_conn base;
	size_t                meth_nr;
	galv_rpc_fn * const * meth;
};

extern struct galv_rpc_msg *
galv_rpc_create_request(struct galv_rpc_conn * __restrict rpc,
                        uint32_t                          id,
                        void *                            context)
	__export_public;

extern struct galv_rpc_msg *
galv_rpc_create_notif(struct galv_rpc_conn * __restrict rpc, uint32_t id)
	__export_public;

extern int
galv_rpc_make_reply(struct galv_rpc_msg * __restrict message)
	__export_public;

extern int
galv_rpc_push_msg(struct galv_rpc_msg * __restrict message)
	__export_public;

/******************************************************************************
 * RPC acceptor handling
 ******************************************************************************/

#define galv_rpc_assert_factory_api(_ops) \
	galv_assert_api(_ops); \
	galv_assert_api((_ops)->create); \
	galv_assert_api((_ops)->destroy)

#define galv_rpc_assert_factory_intern(_ops) \
	galv_assert_intern(_ops); \
	galv_assert_intern((_ops)->create); \
	galv_assert_intern((_ops)->destroy)

#define galv_rpc_assert_accept_intern(_accept) \
	galv_assert_intern(_accept); \
	galv_rpc_assert_factory_intern((_accept)->factory)

struct galv_rpc_factory;

typedef ssize_t galv_rpc_create_fn(struct galv_rpc_factory * factory,
                                   struct galv_rpc_conn *    rpc,
                                   galv_rpc_fn * * * meth);

typedef void galv_rpc_destroy_fn(struct galv_rpc_factory * factory,
                                 struct galv_rpc_conn * rpc,
                                 galv_rpc_fn * * meth);

struct galv_rpc_factory {
	galv_rpc_create_fn * create;
	galv_rpc_destroy_fn * destroy;
};

struct galv_rpc_accept {
	struct galv_sess_accept base;
	struct galv_rpc_factory * factory;
};

struct galv_rpc_accept_conf {
	struct galv_sess_accept_conf base;
	struct galv_rpc_factory * factory;
};

#define GALV_RPC_ACCEPT_CONF(_backlog, _conn_flags, _max_pload, _buff_capa, \
                            _factory) \
	{ \
		.base = GALV_SESS_ACCEPT_CONF(_backlog, _conn_flags, \
		                              _max_pload, \
		                              sizeof(struct galv_rpc_msg), \
		                              _buff_capa, \
		                              sizeof(struct galv_rpc_conn)), \
		.factory = _factory \
	}

extern int
galv_rpc_open_accept(struct galv_rpc_accept            * acceptor,
                     struct galv_repo                  * repository,
                     struct galv_adopt                 * adopter,
                     const struct upoll                * poller,
                     const struct galv_rpc_accept_conf * conf)
	__export_public;

static inline
void
galv_rpc_close_accept(struct galv_rpc_accept * acceptor,
                      const struct upoll    * poller)
{
	galv_assert_api(acceptor);
	galv_assert_api(poller);

	galv_sess_close_accept(&acceptor->base, poller);
}

#endif /* _GALV_RPC_H */
