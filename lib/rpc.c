/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "common.h"
#include "galv/rpc.h"
#include <dpack/codec.h>
#include <dpack/scalar.h>

#define dpack_decoder_to_rpc_msg(_dec) containerof(_dec, struct galv_rpc_msg, dec)
#define dpack_encoder_to_rpc_msg(_enc) containerof(_enc, struct galv_rpc_msg, enc)

static
size_t
galv_rpc_decoder_left(const struct dpack_decoder * __restrict decoder)
{
	galv_assert_intern(decoder);

	const struct galv_rpc_msg * msg = dpack_decoder_to_rpc_msg(decoder);

	return galv_rpc_msg_size(msg);
}

static
int
galv_rpc_decoder_read(struct dpack_decoder * __restrict decoder,
                      uint8_t * __restrict              data,
                      size_t                            size)
{
	galv_assert_intern(decoder);
	galv_assert_intern(data);
	galv_assert_intern(size);

	ssize_t ret;
	struct galv_rpc_msg * msg = dpack_decoder_to_rpc_msg(decoder);

	ret = galv_sess_msg_read(&msg->base, data, size);
	if (ret < 0)
		return (int)ret;

	galv_assert_intern((size_t)ret == size);
	return 0;
}

static
int
galv_rpc_decoder_discard(struct dpack_decoder * __restrict decoder,
                         size_t                            size)
{
	galv_assert_intern(decoder);
	galv_assert_intern(size);

	struct galv_rpc_msg * msg = dpack_decoder_to_rpc_msg(decoder);

	do {
		ssize_t         sz;
		const uint8_t * data;

		sz = galv_sess_msg_pull_head(&msg->base, &data, size);
		if (sz < 0)
			return sz;

		size -= (size_t)sz;
	} while (size);

	return 0;
}

static
void
galv_rpc_decoder_fini(struct dpack_decoder * __restrict decoder __unused)
{
	galv_assert_intern(decoder);
}

const struct dpack_decoder_ops galv_rpc_decoder_ops = {
	.left = galv_rpc_decoder_left,
	.read = galv_rpc_decoder_read,
	.disc = galv_rpc_decoder_discard,
	.fini = galv_rpc_decoder_fini
};

static
size_t
galv_rpc_encoder_left(const struct dpack_encoder * __restrict encoder)
{
	galv_assert_intern(encoder);

	struct galv_rpc_msg     * msg;
	struct galv_sess_accept * acceptor;

	msg  = dpack_encoder_to_rpc_msg(encoder);
	acceptor = galv_sess_conn_acceptor(msg->base.sess);

	return acceptor->max_pload - galv_rpc_msg_size(msg);
}

static
size_t
galv_rpc_encoder_used(const struct dpack_encoder * __restrict encoder)
{
	galv_assert_intern(encoder);

	struct galv_rpc_msg * msg = dpack_encoder_to_rpc_msg(encoder);

	return galv_rpc_msg_size(msg);
}

static
int
galv_rpc_encoder_write(struct dpack_encoder * __restrict encoder,
                       const uint8_t * __restrict        data,
                       size_t                            size)
{
	galv_assert_intern(encoder);
	galv_assert_intern(data);
	galv_assert_intern(size);

	struct galv_rpc_msg * msg = dpack_encoder_to_rpc_msg(encoder);

	return galv_sess_msg_write(&msg->base, data, size);
}

static
void
galv_rpc_encoder_fini(struct dpack_encoder * __restrict encoder __unused)
{
	galv_assert_intern(encoder);
}

const struct dpack_encoder_ops galv_rpc_encoder_ops = {
	.left  = galv_rpc_encoder_left,
	.used  = galv_rpc_encoder_used,
	.write = galv_rpc_encoder_write,
	.fini  = galv_rpc_encoder_fini
};

static
void
galv_rpc_msg_init_codec(struct galv_rpc_msg * msg)
{
	galv_assert_intern(msg);

	dpack_encoder_init(&msg->enc, &galv_rpc_encoder_ops);
	dpack_decoder_init(&msg->dec, &galv_rpc_decoder_ops);
}

extern __export_public
int
galv_rpc_push_msg(struct galv_rpc_msg * msg)
{
	galv_assert_api(msg);

	dpack_encoder_fini(&msg->enc);
	dpack_decoder_fini(&msg->dec);
	return galv_sess_push_msg(&msg->base);
}

extern __export_public
void
galv_rpc_drop_msg(struct galv_rpc_msg * msg)
{
	galv_assert_api(msg);

	dpack_encoder_fini(&msg->enc);
	dpack_decoder_fini(&msg->dec);
	galv_sess_drop_msg(&msg->base);
}


extern __export_public
int
galv_rpc_xfer(struct galv_sess_conn * ctx)
{
	galv_assert_api(ctx);

	struct galv_rpc_conn  *conn = (struct galv_rpc_conn *)ctx;
	struct galv_rpc_msg   *msg;
	uint32_t               id;
	int                    ret = 0;

	while(galv_sess_may_pull_msg(ctx)) {
		msg = (struct galv_rpc_msg *)galv_sess_pull_msg(ctx);
		galv_assert_intern(msg);
		galv_rpc_msg_init_codec(msg);

		ret = dpack_decode_uint32(&msg->dec, &id);
		if (ret)
			goto drop;

		if (galv_rpc_msg_type(msg) == GALV_SESS_HEAD_REPLY_TYPE) {
			if (msg->id != id) {
				ret = -EINVAL;
				goto drop;
			}
		} else {
			msg->id = id;
		}

		if ((id >= conn->rpc_nb) || (!conn->rpc[id])) {
			ret = -EPERM;
			goto drop;
		}

		ret = conn->rpc[id](msg);
		if (ret)
			goto end;
	}
	return 0;

drop:
	galv_rpc_drop_msg(msg);
end:
	switch(ret) {
	case -EINTR:  /* Interrupted by a signal */
	case -ENOMEM: /* No more memory available. */
		return ret;

	default:
		galv_sess_ignore(ctx);
		return 0;
	}
}

extern __export_public
struct galv_rpc_msg *
galv_rpc_create_request(struct galv_rpc_conn * conn, uint32_t id, void * ctx)
{
	galv_assert_api(conn);

	struct galv_rpc_msg * msg;

	msg = (struct galv_rpc_msg *)galv_sess_create_request(&conn->base);
	if (!msg)
		return NULL;

	galv_rpc_msg_init_codec(msg);
	msg->ctx = ctx;
	msg->id  = id;
	if (dpack_encode_uint32(&msg->enc, id)) {
		galv_rpc_drop_msg(msg);
		return NULL;
	}

	return msg;
}

extern __export_public
struct galv_rpc_msg *
galv_rpc_create_notif(struct galv_rpc_conn * conn, uint32_t id)
{
	galv_assert_api(conn);

	struct galv_rpc_msg * msg;

	msg = (struct galv_rpc_msg *)galv_sess_create_notif(&conn->base);
	if (!msg)
		return NULL;

	galv_rpc_msg_init_codec(msg);
	msg->id  = id;
	if (dpack_encode_uint32(&msg->enc, id)) {
		galv_rpc_drop_msg(msg);
		return NULL;
	}

	return msg;
}

extern __export_public
int
galv_rpc_make_reply(struct galv_rpc_msg * msg)
{
	galv_assert_api(msg);

	int ret;

	ret = galv_sess_make_reply(&msg->base);
	if (ret)
		return ret;

	return dpack_encode_uint32(&msg->enc, msg->id);
}

