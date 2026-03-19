#include "../lib/common.h"
#include <galv/rpc_clnt.h>
#include <utils/unsk.h>
#include <dpack/codec.h>
#include <dpack/scalar.h>

static inline
struct galv_rpc_clnt_msg *
galv_rpc_clnt_msg_from_dec(const struct dpack_decoder * __restrict decoder)
{
	return containerof(decoder, struct galv_rpc_clnt_msg, dec);

}

static
size_t
galv_rpc_clnt_decoder_left(const struct dpack_decoder * __restrict decoder)
{
	const struct galv_rpc_clnt_msg * msg =
		galv_rpc_clnt_msg_from_dec(decoder);

	return msg->busy;
}

static
int
galv_rpc_clnt_decoder_read(struct dpack_decoder * __restrict decoder,
                           uint8_t * __restrict              data,
                           size_t                            size)
{
	struct galv_rpc_clnt_msg * msg = galv_rpc_clnt_msg_from_dec(decoder);

	if (size > msg->busy)
		return -ENODATA;

	memcpy(data, &msg->buff[msg->off], size);
	msg->off += size;
	msg->busy -= size;

	return 0;
}

static
int
galv_rpc_clnt_decoder_skip(struct dpack_decoder * __restrict decoder,
                           size_t                            size)
{
	struct galv_rpc_clnt_msg * msg = galv_rpc_clnt_msg_from_dec(decoder);

	if (size > msg->busy)
		return -ENODATA;

	msg->off += size;
	msg->busy -= size;

	return 0;
}

static
int
galv_rpc_clnt_decoder_fini(struct dpack_decoder * __restrict decoder __unused)
{
	return 0;
}

static const struct dpack_decoder_ops galv_rpc_clnt_decoder_ops = {
	.left = galv_rpc_clnt_decoder_left,
	.read = galv_rpc_clnt_decoder_read,
	.skip = galv_rpc_clnt_decoder_skip,
	.fini = galv_rpc_clnt_decoder_fini
};

static inline
struct galv_rpc_clnt_msg *
galv_rpc_clnt_msg_from_enc(const struct dpack_encoder * __restrict encoder)
{
	return containerof(encoder, struct galv_rpc_clnt_msg, enc);
}

static
size_t
galv_rpc_clnt_encoder_left(const struct dpack_encoder * __restrict encoder)
{
	const struct galv_rpc_clnt_msg * msg =
		galv_rpc_clnt_msg_from_enc(encoder);

	return sizeof(msg->buff) - (msg->off + msg->busy);
}

static
size_t
galv_rpc_clnt_encoder_used(const struct dpack_encoder * __restrict encoder)
{
	const struct galv_rpc_clnt_msg * msg =
		galv_rpc_clnt_msg_from_enc(encoder);

	return msg->busy;
}

static
int
galv_rpc_clnt_encoder_write(struct dpack_encoder * __restrict encoder,
                            const uint8_t * __restrict        data,
                            size_t                            size)
{
	struct galv_rpc_clnt_msg * msg = galv_rpc_clnt_msg_from_enc(encoder);

	if ((msg->off + msg->busy + size) > sizeof(msg->buff))
		return -ENOBUFS;

	memcpy(&msg->buff[msg->off + msg->busy], data, size);
	msg->busy += size;

	return 0;
}

static
int
galv_rpc_clnt_encoder_fini(struct dpack_encoder * __restrict encoder __unused)
{
	return 0;
}

const struct dpack_encoder_ops galv_rpc_clnt_encoder_ops = {
	.left  = galv_rpc_clnt_encoder_left,
	.used  = galv_rpc_clnt_encoder_used,
	.write = galv_rpc_clnt_encoder_write,
	.fini  = galv_rpc_clnt_encoder_fini
};

static
void
galv_rpc_clnt_prep_reply(struct galv_rpc_clnt_msg * message)
{
	message->type = GALV_SESS_HEAD_REPLY_TYPE;
	message->off = 0;
	message->busy = 0;

}

struct galv_rpc_clnt_msg *
galv_rpc_clnt_create_request(struct galv_rpc_clnt * __restrict rpc,
                             uint32_t                          id,
                             galv_rpc_clnt_fn *                handler)
{
	if (!rpc->msg) {
		struct galv_rpc_clnt_msg * req;
		struct galv_sess_head *    head;
		int                        err;

		req = malloc(rpc->msg_size);
		if (!req)
			return NULL;

		req->clnt = rpc;
		dpack_encoder_init(&req->enc, &galv_rpc_clnt_encoder_ops);
		dpack_decoder_init(&req->dec,
		                   &galv_rpc_clnt_decoder_ops,
		                   DPACK_DECODER_NODISC);
		req->type = GALV_SESS_HEAD_REQUEST_TYPE;
		req->id = id;
		req->hndl = handler;
		req->off = sizeof(*head);
		req->busy = 0;

		err = dpack_encode_uint32(&req->enc, id);
		if (err) {
			free(req);
			errno = -err;
			return NULL;
		}

		rpc->msg = req;

		return req;
	}
	else {
		errno = EBUSY;

		return NULL;
	}
}

static
int
galv_rpc_clnt_recv_msg(struct galv_rpc_clnt_msg * __restrict message)
{
	galv_assert_api(message);
	galv_assert_api(message == message->clnt->msg);

	struct galv_rpc_clnt * clnt = message->clnt;
	struct galv_sess_head  head;
	size_t                 off = 0;
	size_t                 left = sizeof(head);
	ssize_t                ret;

	do {
		ret = etux_sock_recv(clnt->fd,
		                     &((uint8_t *)&head)[off],
		                     left,
		                     0);
		if (ret > 0) {
			off += (size_t)ret;
			left -= (size_t)ret;
		}
		else if (!ret) {
			ret = -ECONNREFUSED;
			break;
		}
		else if (ret != -EINTR)
			break;
	} while (left);
	if (ret < 0)
		return (int)ret;

	if (head.flags !=
	    ((GALV_SESS_HEAD_LAST_MULTI << GALV_SESS_HEAD_MULTI_FLAG_BIT) |
	     (GALV_SESS_HEAD_REPLY_TYPE << GALV_SESS_HEAD_TYPE_FLAG_BIT)))
		return -EPROTO;

	if (head.xchg != 0)
		return -EPROTO;

	left = (size_t)head.size + 1;
	if ((sizeof(head) + left) > sizeof(message->buff))
		return -EMSGSIZE;

	message->off = 0;
	message->busy = left;

	off = 0;
	do {
		ret = etux_sock_recv(clnt->fd, &message->buff[off], left, 0);
		if (ret > 0) {
			off += (size_t)ret;
			left -= (size_t)ret;
		}
		else if (!ret) {
			ret = -ECONNREFUSED;
			break;
		}
		else if (ret != -EINTR)
			break;
	} while (left);

	return (ret < 0) ? (int)ret : 0;
}

static
int
galv_rpc_clnt_send_msg(struct galv_rpc_clnt_msg * __restrict message)
{
	galv_assert_api(message == message->clnt->msg);

	struct galv_rpc_clnt *  clnt = message->clnt;
	struct galv_sess_head * head = (struct galv_sess_head *)message->buff;
	size_t                  off = 0;
	size_t                  left;
	ssize_t                 ret;

	left = galv_rpc_clnt_encoder_used(&message->enc);

	head->flags = (uint8_t)
	              ((GALV_SESS_HEAD_LAST_MULTI <<
	                GALV_SESS_HEAD_MULTI_FLAG_BIT) |
	               (message->type << GALV_SESS_HEAD_TYPE_FLAG_BIT));
	head->xchg = 0;
	head->size = (uint16_t)(left - 1);

	left += sizeof(*head);

	do {
		ret = etux_sock_send(clnt->fd,
		                     &message->buff[off],
		                     left,
		                     MSG_NOSIGNAL);
		galv_assert_intern(ret);
		if (ret > 0) {
			off += (size_t)ret;
			left -= (size_t)ret;
		}
		else if (ret != -EINTR)
			break;
	} while (left);

	return (ret < 0) ? (int)ret : 0;
}

int
galv_rpc_clnt_push_msg(struct galv_rpc_clnt_msg * __restrict message)
{
	galv_assert_api(message->type == GALV_SESS_HEAD_REQUEST_TYPE);

	int      ret;
	uint32_t id;

	ret = galv_rpc_clnt_send_msg(message);
	if (ret)
		goto out;

	galv_rpc_clnt_prep_reply(message);
	ret = galv_rpc_clnt_recv_msg(message);
	if (ret)
		goto out;

	ret = dpack_decode_uint32(&message->dec, &id);
	if (ret)
		goto out;

	if (id != message->id) {
		ret = -EPROTO;
		goto out;
	}

	ret = 0;

out:
	ret = message->hndl(message, ret);
	switch (ret) {
	case 0:
	case -EINTR:
	case -ENOMEM:
	case -ENFILE:
	case -EMFILE:
	case -ENOSPC:
		break;

	default:
		galv_assert_api(0);
		ret = 0;
	}

	return ret;
}

void
galv_rpc_clnt_msg_drop(struct galv_rpc_clnt_msg * __restrict message)
{
	struct galv_rpc_clnt * clnt = message->clnt;
	
	galv_assert_api(message == clnt->msg);

	dpack_encoder_fini(&message->enc);
	dpack_decoder_fini(&message->dec);
	free(message);

	clnt->msg = NULL;
}

int
galv_rpc_clnt_connect(struct galv_rpc_clnt *     client,
                      const struct sockaddr_un * peer,
                      socklen_t                  size)
{
	return unsk_connect(client->fd, peer, size);
}

int
galv_rpc_clnt_open(struct galv_rpc_clnt * client, int flags, size_t msg_size)
{
	galv_assert_api(msg_size >= sizeof(struct galv_rpc_clnt_msg));

	int sk;

	sk = unsk_open(SOCK_STREAM, flags);
	if (sk < 0)
		return sk;

	client->fd = sk;
	client->msg = NULL;
	client->msg_size = msg_size;

	return 0;
}

void
galv_rpc_clnt_close(struct galv_rpc_clnt * client)
{
	unsk_close(client->fd);
}
