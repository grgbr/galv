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

/******************************************************************************
 * RPC message handling
 ******************************************************************************/

#define galv_rpc_assert_msg_intern(_msg) \
	galv_assert_intern(_msg); \
	galv_sess_assert_msg_api(&(_msg)->base)

#define galv_rpc_assert_recv_msg_api(_msg) \
	galv_assert_api(_msg); \
	galv_sess_assert_recv_msg_api(&(_msg)->base)

#define galv_rpc_assert_recv_msg_intern(_msg) \
	galv_assert_intern(_msg); \
	galv_sess_assert_recv_msg_api(&(_msg)->base)

#define galv_rpc_assert_send_msg_intern(_msg) \
	galv_assert_intern(_msg); \
	galv_sess_assert_send_msg_api(&(_msg)->base)

#define galv_rpc_assert_send_msg_api(_msg) \
	galv_assert_api(_msg); \
	galv_sess_assert_send_msg_api(&(_msg)->base)

static inline
struct galv_rpc_msg *
galv_rpc_msg_from_dec(const struct dpack_decoder * __restrict decoder)
{
	return containerof(decoder, struct galv_rpc_msg, dec);

}

static inline
struct galv_rpc_msg *
galv_rpc_msg_from_enc(const struct dpack_encoder * __restrict encoder)
{
	return containerof(encoder, struct galv_rpc_msg, enc);
}

static
size_t
galv_rpc_decoder_left(const struct dpack_decoder * __restrict decoder)
{
	galv_assert_intern(decoder);

	const struct galv_rpc_msg * msg = galv_rpc_msg_from_dec(decoder);

	galv_rpc_assert_recv_msg_intern(msg);

	return galv_rpc_msg_size(galv_rpc_msg_from_dec(decoder));
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

	struct galv_rpc_msg * msg = galv_rpc_msg_from_dec(decoder);
	ssize_t               ret;

	galv_rpc_assert_recv_msg_intern(msg);

	ret = galv_sess_msg_read(&msg->base, data, size);
	galv_assert_intern(ret);
	if ((size_t)ret == size)
		return 0;
	else if (ret > 0)
		return -ENODATA;

	return (int)ret;
}

static
int
galv_rpc_decoder_skip(struct dpack_decoder * __restrict decoder,
                      size_t                            size)
{
	galv_assert_intern(decoder);
	galv_assert_intern(size);

	struct galv_rpc_msg * msg = galv_rpc_msg_from_dec(decoder);

	galv_rpc_assert_recv_msg_intern(msg);

	do {
		ssize_t         sz;
		const uint8_t * data;

		sz = galv_sess_msg_pull_head(&msg->base, &data, size);
		if (sz < 0)
			return (int)sz;

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

static const struct dpack_decoder_ops galv_rpc_decoder_ops = {
	.left = galv_rpc_decoder_left,
	.read = galv_rpc_decoder_read,
	.skip = galv_rpc_decoder_skip,
	.fini = galv_rpc_decoder_fini
};

static
size_t
galv_rpc_encoder_left(const struct dpack_encoder * __restrict encoder)
{
	galv_assert_intern(encoder);

	const struct galv_rpc_msg * msg = galv_rpc_msg_from_enc(encoder);

	galv_rpc_assert_send_msg_intern(msg);

	return galv_sess_msg_capacity(&msg->base) - galv_rpc_msg_size(msg);
}

static
size_t
galv_rpc_encoder_used(const struct dpack_encoder * __restrict encoder)
{
	galv_assert_intern(encoder);

	const struct galv_rpc_msg * msg = galv_rpc_msg_from_enc(encoder);

	galv_rpc_assert_send_msg_intern(msg);

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

	struct galv_rpc_msg * msg = galv_rpc_msg_from_enc(encoder);

	galv_rpc_assert_send_msg_intern(msg);

	return galv_sess_msg_write(&msg->base, data, size);
}

static
int
galv_rpc_encoder_fini(struct dpack_encoder * __restrict encoder __unused)
{
	galv_assert_intern(encoder);

	return 0;
}

const struct dpack_encoder_ops galv_rpc_encoder_ops = {
	.left  = galv_rpc_encoder_left,
	.used  = galv_rpc_encoder_used,
	.write = galv_rpc_encoder_write,
	.fini  = galv_rpc_encoder_fini
};

static
void
galv_rpc_msg_init_codec(struct galv_rpc_msg * __restrict message)
{
	galv_assert_intern(message);

	dpack_encoder_init(&message->enc, &galv_rpc_encoder_ops);
	dpack_decoder_init(&message->dec,
	                   &galv_rpc_decoder_ops,
	                   DPACK_DECODER_NODISC);
}

void
galv_rpc_msg_drop(struct galv_rpc_msg * __restrict message)
{
	galv_rpc_assert_msg_api(message);

	dpack_encoder_fini(&message->enc);
	dpack_decoder_fini(&message->dec);

	galv_sess_msg_drop(&message->base);
}

/******************************************************************************
 * RPC connection handling
 ******************************************************************************/

#define galv_rpc_assert_api(_rpc) \
	galv_assert_api(_rpc); \
	galv_sess_assert_conn_api(&(_rpc)->base); \
	galv_assert_api((_rpc)->meth_nr); \
	galv_assert_api((_rpc)->meth)

static
int
galv_rpc_srv_xfer(struct galv_sess_conn * __restrict session)
{
	galv_assert_intern(session);

	struct galv_rpc_conn * conn = (struct galv_rpc_conn *)session;
	struct galv_rpc_msg  * msg;
	int                    ret = 0;

	while (galv_sess_may_pull_msg(session)) {
		uint32_t id;

		msg = (struct galv_rpc_msg *)galv_sess_pull_msg(session);
		galv_sess_assert_recv_msg_api(&msg->base);
		galv_rpc_msg_init_codec(msg);

		ret = dpack_decode_uint32(&msg->dec, &id);
		if (ret)
			goto drop;

		ret = -EPROTO;

		switch (galv_rpc_msg_type(msg)) {
		case GALV_SESS_HEAD_REQUEST_TYPE:
		case GALV_SESS_HEAD_NOTIF_TYPE:
			msg->id = id;
			break;

		case GALV_SESS_HEAD_REPLY_TYPE:
		default:
			galv_assert_intern(0);
			goto drop;
		}

		if ((id >= conn->meth_nr) || (!conn->meth[id])) {
			ret = -ENOTSUP;
			goto drop;
		}

		ret = conn->meth[id](msg);
		if (ret)
			goto end;
	}

	return 0;

drop:
	galv_rpc_msg_drop(msg);

end:
	switch(ret) {
	case -EINTR:  /* Interrupted by a signal */
	case -ENOMEM: /* No more memory available. */
		return ret;

	default:
		galv_sess_ignore(session);
	}

	return 0;
}

#if 0
static
int
galv_rpc_clt_xfer(struct galv_sess_conn * __restrict session)
{
	galv_assert_intern(session);

	struct galv_rpc_conn * conn = (struct galv_rpc_conn *)session;
	struct galv_rpc_msg  * msg;
	int                    ret = 0;

	while (galv_sess_may_pull_msg(session)) {
		uint32_t id;

		msg = (struct galv_rpc_msg *)galv_sess_pull_msg(session);
		galv_sess_assert_recv_msg_api(&msg->base);
		galv_rpc_msg_init_codec(msg);

		ret = dpack_decode_uint32(&msg->dec, &id);
		if (ret)
			goto drop;

		ret = -EPROTO;

		switch (galv_rpc_msg_type(msg)) {
		case GALV_SESS_HEAD_NOTIF_TYPE:
			msg->id = id;
			break;

		case GALV_SESS_HEAD_REPLY_TYPE:
			if (msg->id == id)
				break;
			goto drop;

		case GALV_SESS_HEAD_REQUEST_TYPE:
		default:
			galv_assert_intern(0);
			goto drop;
		}

		if ((id >= conn->meth_nr) || (!conn->meth[id])) {
			ret = -ENOTSUP;
			goto drop;
		}

		ret = conn->meth[id](msg);
		if (ret)
			goto end;
	}

	return 0;

drop:
	galv_rpc_msg_drop(msg);

end:
	switch(ret) {
	case -EINTR:  /* Interrupted by a signal */
	case -ENOMEM: /* No more memory available. */
		return ret;

	default:
		galv_sess_ignore(session);
	}

	return 0;
}
#endif

struct galv_rpc_msg *
galv_rpc_create_request(struct galv_rpc_conn * __restrict rpc,
                        uint32_t                          id,
                        void *                            context)
{
	galv_rpc_assert_api(rpc);

	struct galv_rpc_msg * msg;

	msg = (struct galv_rpc_msg *)galv_sess_create_request(&rpc->base);
	if (msg) {
		int err;

		galv_rpc_msg_init_codec(msg);
		msg->id  = id;
		msg->ctx = context;

		err = dpack_encode_uint32(&msg->enc, id);
		if (!err)
			return msg;

		galv_rpc_msg_drop(msg);

		errno = -err;
	}

	return NULL;
}

struct galv_rpc_msg *
galv_rpc_create_notif(struct galv_rpc_conn * __restrict rpc, uint32_t id)
{
	galv_rpc_assert_api(rpc);

	struct galv_rpc_msg * msg;

	msg = (struct galv_rpc_msg *)galv_sess_create_notif(&rpc->base);
	if (msg) {
		int err;

		galv_rpc_msg_init_codec(msg);
		msg->id  = id;
		msg->ctx = NULL;

		err = dpack_encode_uint32(&msg->enc, id);
		if (!err)
			return msg;

		galv_rpc_msg_drop(msg);

		errno = -err;
	}

	return NULL;
}

int
galv_rpc_make_reply(struct galv_rpc_msg * __restrict message)
{
	galv_assert_api(message);

	int err;

	err = galv_sess_make_reply(&message->base);
	if (!err)
		return dpack_encode_uint32(&message->enc, message->id);

	return err;
}

int
galv_rpc_push_msg(struct galv_rpc_msg * __restrict message)
{
	galv_rpc_assert_send_msg_api(message);

	dpack_encoder_fini(&message->enc);
	dpack_decoder_fini(&message->dec);

	return galv_sess_push_msg(&message->base);
}

/******************************************************************************
 * RPC acceptor handling
 ******************************************************************************/

static
int
galv_rpc_srv_connect(struct galv_sess_conn * __restrict session)
{
	galv_assert_intern(session);

	struct galv_rpc_conn * conn = (struct galv_rpc_conn *)session;
	struct galv_rpc_accept * acceptor =
		(struct galv_rpc_accept *)galv_sess_conn_acceptor(session);

	galv_rpc_assert_accept_intern(acceptor);

	ssize_t ret;

STROLL_IGNORE_WARN("-Wcast-qual")
	ret = acceptor->factory->create(acceptor->factory, conn,
					(galv_rpc_fn * * *)&conn->meth);
STROLL_RESTORE_WARN
	if (ret > 0) {
		conn->meth_nr = (size_t)ret;
		galv_sess_establish(session);
		return 0;
	}

	galv_assert_api(ret);
	return ret;
}

static
void
galv_rpc_srv_close(struct galv_sess_conn * __restrict session)
{
	galv_assert_intern(session);

	struct galv_rpc_conn * conn = (struct galv_rpc_conn *)session;
	struct galv_rpc_accept * acceptor =
		(struct galv_rpc_accept *)galv_sess_conn_acceptor(session);

	galv_rpc_assert_accept_intern(acceptor);

STROLL_IGNORE_WARN("-Wcast-qual")
	acceptor->factory->destroy(acceptor->factory, conn,
	                           (galv_rpc_fn * *)conn->meth);
STROLL_RESTORE_WARN
	conn->meth    = NULL;
	conn->meth_nr = 0;
}

static const struct galv_sess_ops galv_rpc_ops = {
	.connect = galv_rpc_srv_connect,
	.xfer    = galv_rpc_srv_xfer,
	.close   = galv_rpc_srv_close,
};

int
galv_rpc_open_accept(struct galv_rpc_accept            * acceptor,
                     struct galv_repo                  * repository,
                     struct galv_adopt                 * adopter,
                     const struct upoll                * poller,
                     const struct galv_rpc_accept_conf * conf)
{
	galv_assert_api(acceptor);
	galv_assert_api(repository);
	galv_assert_api(adopter);
	galv_assert_api(poller);
	galv_assert_api(conf);

	int ret;

	ret = galv_sess_open_accept(&acceptor->base,
	                            &galv_rpc_ops,
	                            repository,
	                            adopter,
	                            poller,
	                            &conf->base);
	if (ret)
		return ret;

STROLL_IGNORE_WARN("-Wcast-qual")
	*(struct galv_rpc_factory **)&acceptor->factory = conf->factory;
STROLL_RESTORE_WARN
	return 0;
}
