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
 * @author    Grégor Boirie <gregor.boirie@free.fr>
 * @date      26 Oct 2026
 * @copyright Copyright (C) 2024 Grégor Boirie.
 * @license   [GNU Lesser General Public License (LGPL) v3]
 *            (https://www.gnu.org/licenses/lgpl+gpl-3.0.txt)
 */

#ifndef _GALV_RPC_H
#define _GALV_RPC_H

#include <dpack/codec.h>
#include <galv/session.h>

struct galv_rpc_msg {
	struct galv_sess_msg base;
	struct dpack_encoder enc;
	struct dpack_decoder dec;
	uint32_t             id;
	void               * ctx;
};

typedef int galv_rpc_fn(struct galv_rpc_msg * msg);

struct galv_rpc_conn {
	struct galv_sess_conn base;
	size_t rpc_nb;
	galv_rpc_fn * * rpc;
};

extern int
galv_rpc_xfer(struct galv_sess_conn * ctx)
	__export_public;

extern struct galv_rpc_msg *
galv_rpc_create_request(struct galv_rpc_conn * conn, uint32_t id, void * ctx)
	__export_public;

extern struct galv_rpc_msg *
galv_rpc_create_notif(struct galv_rpc_conn * conn, uint32_t id)
	__export_public;

extern int
galv_rpc_make_reply(struct galv_rpc_msg * msg)
	__export_public;

static inline
void *
glav_rpc_get_ctx(struct galv_rpc_msg * msg)
{
	galv_assert_api(msg);

	return msg->ctx;
}

static inline
struct dpack_encoder *
galv_rpc_get_encoder(struct galv_rpc_msg * msg)
{
	galv_assert_api(msg);

	return &msg->enc;
}

static inline
struct dpack_decoder *
galv_rpc_get_decoder(struct galv_rpc_msg * msg)
{
	galv_assert_api(msg);

	return &msg->dec;
}

extern int
galv_rpc_push_msg(struct galv_rpc_msg * msg)
	__export_public;

extern void
galv_rpc_drop_msg(struct galv_rpc_msg * msg)
	__export_public;

static inline
size_t
galv_rpc_msg_size(const struct galv_rpc_msg * msg)
{
	galv_assert_api(msg);

	return galv_sess_msg_type(&msg->base);
}

static inline
enum galv_sess_head_type
galv_rpc_msg_type(const struct galv_rpc_msg * msg)
{
	galv_assert_api(msg);

	return galv_sess_msg_type(&msg->base);
}

#endif /* _GALV_RPC_H */
