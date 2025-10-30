/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "common.h"
#include "galv/session.h"
#include "galv/conn.h"
#include <string.h>

#define galv_sess_assert_intern(_sess) \
	galv_assert_intern(_sess); \
	galv_assert_intern((_sess)->conn)

static
void
galv_sess_drain_buff(struct galv_buff_queue * __restrict buffq,
                     struct galv_buff * __restrict       buff,
                     size_t                              size)
{
	galv_assert_intern(buffq);
	galv_assert_intern(!galv_buff_queue_empty(buffq));
	galv_assert_intern(buff);
	galv_assert_intern(buff == galv_buff_queue_first(buffq));
	galv_assert_intern(galv_buff_busy(buff));
	galv_assert_intern(size <= galv_buff_busy(buff));

	galv_buff_grow_head(buff, size);
	galv_buff_shrink_queue(buffq, size);
	if (galv_buff_busy(buff)) {
		/* No more data stored into current buffer `buff'. */
		if (!galv_buff_avail_tail(buff) || galv_buff_next(buff)) {
			/*
			 * Either:
			 * - `buff' has no more room to store additional data at
			 *   its tail end ;
			 * - or, galv_sess_recv_buff() has already started to
			 *   fill in a subsequent buffer in the receive queue.
			 * In both cases, we cannot use current buffer `buff'
			 * any more: release it.
			 */
			galv_buff_dqueue(buffq);
			galv_buff_release(buff);
		}
	}
}

static
void
galv_sess_copyn_drain_buff(struct galv_buff_queue * __restrict buffq,
                           struct galv_buff * __restrict       buff,
                           uint8_t * __restrict                data,
                           size_t                              size)
{
	galv_assert_intern(buffq);
	galv_assert_intern(!galv_buff_queue_empty(buffq));
	galv_assert_intern(buff);
	galv_assert_intern(buff == galv_buff_queue_first(buffq));
	galv_assert_intern(data);
	galv_assert_intern(size);
	galv_assert_intern(size <= galv_buff_busy(buff));

	memcpy(data, galv_buff_data(buff), size);

	galv_sess_drain_buff(buffq, buff, size);
}

static
void
galv_sess_copyn_drain_buffq(struct galv_buff_queue * __restrict buffq,
                            uint8_t * __restrict                data,
                            size_t                              size)
{
	galv_assert_intern(buffq);
	galv_assert_intern(!galv_buff_queue_empty(buffq));
	galv_assert_intern(data);
	galv_assert_intern(size);
	galv_assert_intern(size <= galv_buff_queue_busy(buffq));

	struct galv_buff * buff = galv_buff_queue_first(buffq);
	size_t             busy = galv_buff_busy(buff);

	while (size > busy) {
		galv_assert_intern(size < galv_buff_queue_busy(buffq));
		galv_assert_intern(busy);

		memcpy(data, galv_buff_data(buff), busy);
		data += busy;
		size -= busy;

		galv_buff_dqueue(buffq);
		galv_buff_release(buff);

		buff = galv_buff_queue_first(buffq);
		galv_assert_intern(buff);
		busy = galv_buff_busy(buff);
	}

	galv_sess_copyn_drain_buff(buffq, buff, data, size);
}

/******************************************************************************
 * Session protocol header
 ******************************************************************************/

enum galv_sess_head_type {
	GALV_SESS_HEAD_REQUEST_TYPE = 0,
	GALV_SESS_HEAD_REPLY_TYPE   = 1,
	GALV_SESS_HEAD_NOTIF_TYPE   = 2,
	GALV_SESS_HEAD_TYPE_NR
};

enum galv_sess_head_multi {
	GALV_SESS_HEAD_CONT_MULTI = 0,
	GALV_SESS_HEAD_LAST_MULTI = 1,
	GALV_SESS_HEAD_MULTI_NR
};

#define GALV_SESS_HEAD_MULTI_FLAG_BIT  (0U)
#define GALV_SESS_HEAD_MULTI_FLAG_MASK (0x1U)
#define GALV_SESS_HEAD_TYPE_FLAG_BIT   (1U)
#define GALV_SESS_HEAD_TYPE_FLAG_MASK  (0x3U)
#define GALV_SESS_HEAD_VALID_FLAG_MASK \
	((uint8_t) \
	 (GALV_SESS_HEAD_TYPE_FLAG_MASK << GALV_SESS_HEAD_TYPE_FLAG_BIT) || \
	 (GALV_SESS_HEAD_MULTI_FLAG_MASK << GALV_SESS_HEAD_MULTI_FLAG_BIT))

static
enum galv_sess_head_multi
galv_sess_head_multi(const struct galv_sess_head * __restrict header)
{
	galv_assert_intern(header);

	return (header->flags >> GALV_SESS_HEAD_MULTI_FLAG_BIT) &
	       GALV_SESS_HEAD_MULTI_FLAG_MASK;
}

static
enum galv_sess_head_type
galv_sess_head_type(const struct galv_sess_head * __restrict header)
{
	galv_assert_intern(header);

	return (header->flags >> GALV_SESS_HEAD_TYPE_FLAG_BIT) &
	       GALV_SESS_HEAD_TYPE_FLAG_MASK;
}

static
uint8_t
galv_sess_head_xchg(const struct galv_sess_head * __restrict header)
{
	galv_assert_intern(header);

	return header->xchg;
}
static inline
uint16_t
galv_sess_msg_head_size(const struct galv_sess_head * __restrict header)
{
	galv_assert_intern(header);
	galv_assert_intern(stroll_aligned((size_t)&header->size,
	                                  sizeof(header->size)));

#warning FIXME: do not convert from network byte order if unix socket !
	return be16toh(header->size);
}

/******************************************************************************
 * Session protocol segment
 ******************************************************************************/

struct galv_sess_sgmt {
	size_t size;
	size_t busy;
};

#define GALV_SESS_SGMT_SIZE_MAX \
	((1U << GALV_SESS_HEAD_SIZE_BITS) - 1)

#define galv_sess_assert_sgmt(_sgmt) \
	galv_assert_intern(_sgmt); \
	galv_assert_intern((_sgmt)->size <= GALV_SESS_SGMT_SIZE_MAX); \
	galv_assert_intern((_sgmt)->busy <= (_sgmt)->size)

static
size_t
galv_sess_sgmt_size(const struct galv_sess_sgmt * __restrict segment)
{
	galv_sess_assert_sgmt(segment);

	return segment->size;
}

static
bool
galv_sess_sgmt_loading(const struct galv_sess_sgmt * __restrict segment)
{
	galv_sess_assert_sgmt(segment);

	return !!galv_sess_sgmt_size(segment);
}

static
bool
galv_sess_sgmt_full(const struct galv_sess_sgmt * __restrict segment)
{
	galv_sess_assert_sgmt(segment);

	return segment->busy == galv_sess_sgmt_size(segment);
}

static
void
galv_sess_start_sgmt(struct galv_sess_sgmt * __restrict segment,
                     size_t                             size)
{
	galv_sess_assert_sgmt(segment);
	galv_assert_intern(!segment->busy);
	galv_assert_intern(size <= GALV_SESS_SGMT_SIZE_MAX);

	segment->size = size;
}

static
void
galv_sess_stop_sgmt(struct galv_sess_sgmt * __restrict segment)
{
	galv_assert_intern(segment);

	segment->size = 0;
	segment->busy = 0;
}

/******************************************************************************
 * Session protocol message
 ******************************************************************************/

struct galv_sess_msg {
	size_t                    busy;
	enum galv_sess_head_multi multi;
	enum galv_sess_head_type  type;
	unsigned int              xchg;
	struct galv_sess_sgmt     sgmt;
	struct galv_frag_list     frags;
	struct stroll_slist_node  queue;
};

#define galv_sess_assert_msg_intern(_msg) \
	galv_assert_intern(_msg); \
	galv_assert_intern((_msg)->multi >= 0); \
	galv_assert_intern((_msg)->multi <= GALV_SESS_HEAD_MULTI_NR); \
	galv_assert_intern((_msg)->type >= 0); \
	galv_assert_intern((_msg)->type <= GALV_SESS_HEAD_TYPE_NR); \
	galv_assert_intern((_msg)->xchg < GALV_SESS_MSG_XCHG_NR); \
	galv_sess_assert_sgmt(&(_msg)->sgmt)

static
bool
galv_sess_msg_loading(const struct galv_sess_msg * __restrict message)
{
	galv_sess_assert_msg_intern(message);

	return message->multi != GALV_SESS_HEAD_MULTI_NR;
}

static
bool
galv_sess_msg_full(const struct galv_sess_msg * __restrict message)
{
	galv_sess_assert_msg_intern(message);

	bool full = (message->multi == GALV_SESS_HEAD_LAST_MULTI) &&
	            galv_sess_sgmt_full(&message->sgmt);

	galv_assert_intern(!full || message->busy);

	return full;
}

static
int
galv_sess_recv_sgmt_head(struct galv_sess_msg * __restrict   message,
                         struct galv_buff_queue * __restrict recvq)
{
	galv_sess_assert_msg_intern(message);
	galv_assert_intern(message->multi == GALV_SESS_HEAD_CONT_MULTI);
	galv_assert_intern(message->type < GALV_SESS_HEAD_TYPE_NR);
	galv_assert_intern(recvq);
	galv_assert_intern(galv_buff_queue_busy(recvq));
	galv_assert_intern(!galv_buff_queue_empty(recvq));

	if (galv_buff_queue_busy(recvq) >= sizeof(struct galv_sess_head)) {
		struct galv_sess_head    head;
		enum galv_sess_head_type type;
		uint16_t                 sz;

		galv_sess_copyn_drain_buffq(recvq,
		                            (uint8_t *)&head,
		                            sizeof(head));

		if (head.flags & ~GALV_SESS_HEAD_VALID_FLAG_MASK)
			return -EPROTO;

		type = galv_sess_head_type(&head);
		if (type != message->type)
			return -EPROTO;

		if ((unsigned int)galv_sess_head_xchg(&head) != message->xchg)
			return -EPROTO;

		sz = galv_sess_msg_head_size(&head);
		if (!sz)
			return -ENODATA;

		message->multi = galv_sess_head_multi(&head);
		galv_sess_start_sgmt(&message->sgmt, (size_t)sz);

		return 0;
	}
	else
		return -EAGAIN;
}

static
int
galv_sess_recv_sgmt_frag(struct galv_sess_msg * __restrict    message,
                         struct galv_buff_queue * __restrict  recvq,
                         struct galv_frag_fabric * __restrict fabric)
{
	galv_sess_assert_msg_intern(message);
	galv_assert_intern(galv_sess_msg_loading(message));
	galv_assert_intern(message->multi != GALV_SESS_HEAD_MULTI_NR);
	galv_assert_intern(message->type != GALV_SESS_HEAD_TYPE_NR);
	galv_assert_intern(galv_sess_sgmt_loading(&message->sgmt));
	galv_assert_intern(!galv_sess_sgmt_full(&message->sgmt));
	galv_assert_intern(recvq);
	galv_assert_intern(galv_buff_queue_busy(recvq));
	galv_assert_intern(!galv_buff_queue_empty(recvq));
	galv_assert_intern(fabric);

	struct galv_frag_list * frags = &message->frags;
	struct galv_frag *      frag = (!galv_frag_list_empty(frags))
	                               ? galv_frag_list_last(frags)
	                               : NULL;
	struct galv_sess_sgmt * sgmt;
	struct galv_buff *      buff = galv_buff_queue_first(recvq);
	size_t                  bytes;


	if (!frag || galv_frag_full(frag)) {
		frag = galv_frag_create(fabric, sgmt->size - sgmt->busy, buff);
		if (!frag)
			return -errno;

		galv_frag_nlist(frags, frag);
	}

	bytes = galv_frag_load(frag, buff);
	galv_assert_intern(bytes);

	galv_sess_drain_buff(recvq, buff, bytes);

	sgmt->busy += bytes;

	return 0;
}

static
int
galv_sess_recv_sgmt(struct galv_sess_msg * __restrict    message,
                    struct galv_buff_queue * __restrict  recvq,
                    struct galv_frag_fabric * __restrict fabric)
{
	galv_sess_assert_msg_intern(message);
	galv_assert_intern(galv_sess_msg_loading(message));
	galv_assert_intern(message->multi != GALV_SESS_HEAD_MULTI_NR);
	galv_assert_intern(message->type != GALV_SESS_HEAD_TYPE_NR);
	galv_assert_intern(recvq);
	galv_assert_intern(galv_buff_queue_busy(recvq));
	galv_assert_intern(!galv_buff_queue_empty(recvq));
	galv_assert_intern(fabric);

	struct galv_sess_sgmt * sgmt = &message->sgmt;
	int                     ret;

	if (!galv_sess_sgmt_loading(sgmt)) {
		ret = galv_sess_recv_sgmt_head(message, recvq);
		if (ret)
			return ret;
	}

	galv_assert_intern(!galv_sess_sgmt_full(sgmt));
	do {
		ret = galv_sess_recv_sgmt_frag(message, recvq, fabric);
	} while (!ret &&
	         !galv_sess_sgmt_full(sgmt) &&
	         galv_buff_queue_busy(recvq));

	if (ret)
		return ret;
	
	if (galv_sess_sgmt_full(sgmt)) {
		message->busy += galv_sess_sgmt_size(sgmt);
		galv_sess_stop_sgmt(sgmt);
	}

	return 0;
}

static
int
galv_sess_recv_msg_head(struct galv_sess_msg * __restrict   message,
                        struct galv_buff_queue * __restrict recvq)
{
	galv_sess_assert_msg_intern(message);
	galv_assert_intern(!galv_sess_msg_loading(message));
	galv_assert_intern(!message->busy);
	galv_assert_intern(message->multi == GALV_SESS_HEAD_MULTI_NR);
	galv_assert_intern(message->type == GALV_SESS_HEAD_TYPE_NR);
	galv_assert_intern(galv_frag_list_empty(&message->frags));
	galv_assert_intern(recvq);
	galv_assert_intern(galv_buff_queue_busy(recvq));
	galv_assert_intern(!galv_buff_queue_empty(recvq));

	if (galv_buff_queue_busy(recvq) >= sizeof(struct galv_sess_head)) {
		struct galv_sess_head    head;
		enum galv_sess_head_type type;
		unsigned int             xchg;
		uint16_t                 sz;

		galv_sess_copyn_drain_buffq(recvq,
		                            (uint8_t *)&head,
		                            sizeof(head));

		if (head.flags & ~GALV_SESS_HEAD_VALID_FLAG_MASK)
			return -EPROTO;

		type = galv_sess_head_type(&head);
		if (type >= GALV_SESS_HEAD_TYPE_NR)
			return -EPROTO;

#warning Check that xchg / message ID slot is free
		xchg = (unsigned int)galv_sess_head_xchg(&head);

		sz = galv_sess_msg_head_size(&head);
		if (!sz)
			return -ENODATA;

		message->multi = galv_sess_head_multi(&head);
		message->type = type;
		message->xchg = xchg;
		galv_sess_start_sgmt(&message->sgmt, (size_t)sz);

		return 0;
	}
	else
		return -EAGAIN;
}

static
int
galv_sess_recv_msg(struct galv_sess_msg * __restrict    message,
                   struct galv_buff_queue * __restrict  recvq,
                   struct galv_frag_fabric * __restrict fabric)
{
	galv_sess_assert_msg_intern(message);
	galv_assert_intern(!galv_sess_msg_full(message));
	galv_assert_intern(recvq);
	galv_assert_intern(galv_buff_queue_busy(recvq));
	galv_assert_intern(!galv_buff_queue_empty(recvq));
	galv_assert_intern(fabric);

	int ret;

	if (!galv_sess_msg_loading(message)) {
		ret = galv_sess_recv_msg_head(message, recvq);
		if (ret)
			return ret;
	}

	galv_assert_intern(!galv_sess_msg_full(message));
	do {
		ret = galv_sess_recv_sgmt(message, recvq, fabric);
	} while (!ret && !galv_sess_msg_full(message));

	return ret;
}

static
void
galv_sess_init_msg(struct galv_sess_msg * __restrict message)
{
	galv_assert_intern(message);

	message->busy = 0;
	message->multi = GALV_SESS_HEAD_MULTI_NR;
	message->type = GALV_SESS_HEAD_TYPE_NR;
	galv_sess_stop_sgmt(&message->sgmt);
	galv_frag_init_list(&message->frags);
}

static
void
galv_sess_fini_msg(struct galv_sess_msg * __restrict message)
{
	galv_sess_assert_msg_intern(message);

	while (!galv_frag_list_empty(&message->frags)) {
		struct galv_frag * frag = galv_frag_dlist(&message->frags);
		galv_assert_intern(frag);

		galv_frag_destroy(frag);
	}
}

/******************************************************************************
 * Session connection
 ******************************************************************************/

#define galv_sess_assert_intern(_sess) \
	galv_assert_intern(_sess); \
	galv_assert_intern((_sess)->conn)

static
int
galv_sess_recv_tail_buff(struct galv_sess * __restrict session,
                         struct galv_buff * __restrict tail_buff,
                         size_t                        tail_size)
{
	galv_sess_assert_intern(session);
	galv_assert_intern(tail_buff);
	galv_assert_intern(tail_buff->fabric == &session->buff_fab);
	galv_assert_intern(tail_size);
	galv_assert_intern(tail_size == galv_buff_avail_tail(tail_buff));

	struct galv_buff * nevv;
	struct iovec       vecs[2];
	struct msghdr      mhdr = {
		.msg_name    = NULL,
		.msg_iov     = vecs,
		.msg_iovlen  = stroll_array_nr(vecs),
		.msg_control = NULL,
		.msg_flags   = 0
	};
	ssize_t            ret;

	nevv = galv_buff_summon(&session->buff_fab);
	if (!nevv)
		return -errno;

	galv_assert_intern((tail_size + galv_buff_capacity(nevv)) <=
	                   (size_t)SSIZE_MAX);
	vecs[0].iov_base = galv_buff_tail(tail_buff);
	vecs[0].iov_len = tail_size;
	vecs[1].iov_base = galv_buff_mem(nevv);
	vecs[1].iov_len = galv_buff_capacity(nevv);

	ret = galv_conn_recvmsg(session->conn, &mhdr, 0);
	galv_assert_intern(ret);
	if (ret > (ssize_t)tail_size) {
		size_t size = tail_size + galv_buff_capacity(nevv);

		galv_buff_grow_tail(tail_buff, tail_size);
		galv_buff_grow_queue(&session->recv_buffq, tail_size);

		galv_buff_grow_tail(nevv, (size_t)ret - tail_size);
		galv_buff_nqueue(&session->recv_buffq, nevv);

		ret = ((size_t)ret != size) ? -EAGAIN : 0;
	}
	else if (ret > 0) {
		galv_buff_grow_tail(tail_buff, (size_t)ret);
		galv_buff_grow_queue(&session->recv_buffq, (size_t)ret);

		ret = -EAGAIN;
	}

	galv_buff_release(nevv);

	return (int)ret;
}

static
int
galv_sess_recv_new_buff(struct galv_sess * __restrict session)
{
	galv_sess_assert_intern(session);

	struct galv_buff * buff;
	size_t             size;
	ssize_t            ret;

	buff = galv_buff_summon(&session->buff_fab);
	if (!buff)
		return -errno;

	size = galv_buff_capacity(buff);
	ret = galv_conn_recv(session->conn, galv_buff_mem(buff), size, 0);
	galv_assert_intern(ret);
	if (ret > 0) {
		galv_buff_grow_tail(buff, (size_t)ret);
		galv_buff_nqueue(&session->recv_buffq, buff);

		ret = ((size_t)ret != size) ? -EAGAIN : 0;
	}

	return (int)ret;
}

static
int
galv_sess_recv_buff(struct galv_sess * __restrict session)
{
	galv_sess_assert_intern(session);

	if (!galv_buff_queue_empty(&session->recv_buffq)) {
		struct galv_buff * buff;
		size_t             size;

		buff = galv_buff_queue_last(&session->recv_buffq);
		size = galv_buff_avail_tail(buff);
		if (size)
			return galv_sess_recv_tail_buff(session, buff, size);
	}

	return galv_sess_recv_new_buff(session);
}

#if 0
FINISH ME!!!!!!!!
make sure to update session->recv_bmap, session->recv_msgq...
static
struct galv_sess_msg *
galv_sess_create_msg(struct galv_sess * __restrict session)
{
	galv_sess_assert_intern(session);

	struct galv_sess_msg * msg;

	msg = stroll_palloc_alloc(&session->msg_fab);
	if (!msg)
		return NULL;

	galv_sess_init_msg(msg);

	return msg;
}

static
void
galv_sess_msg_destroy(struct galv_sess * __restrict     session,
                      struct galv_sess_msg * __restrict message)
{
	galv_sess_assert_intern(session);
	galv_sess_assert_msg_intern(message);

	galv_sess_fini_msg(message);
	stroll_palloc_free(&session->msg_fab, message);
}
FINISH ME!!!!!!!!
#endif

int
galv_sess_init(struct galv_sess * __restrict session,
               struct galv_conn * __restrict conn,
               unsigned int                  buff_nr,
               size_t                        buff_capa,
               unsigned int                  frag_nr,
               unsigned int                  msg_nr)
{
#define GALV_SESS_BUFF_NR_MIN (2U)
#define GALV_SESS_BUFF_NR_MAX (1024U)
#define GALV_SESS_FRAG_NR_MIN \
	(2 * GALV_SESS_MSG_XCHG_NR * GALV_SESS_BUFF_NR_MIN)
#define GALV_SESS_FRAG_NR_MAX \
	(2 * GALV_SESS_MSG_XCHG_NR * GALV_SESS_BUFF_NR_MAX)
	galv_assert_api(session);
	galv_assert_api(conn);
	galv_assert_api(buff_nr >= GALV_SESS_BUFF_NR_MIN);
	galv_assert_api(buff_nr <= GALV_SESS_BUFF_NR_MAX);
	galv_assert_api(frag_nr >= GALV_SESS_FRAG_NR_MIN);
	galv_assert_api(frag_nr <= GALV_SESS_FRAG_NR_MAX);
	galv_assert_api(msg_nr >= frag_nr);

	int err;

	err = galv_buff_init_fabric(&session->buff_fab, buff_nr, buff_capa);
	if (err)
		return err;

	err = galv_frag_init_fabric(&session->frag_fab, frag_nr);
	if (err)
		goto fini_buff_fab;

	err = stroll_palloc_init(&session->msg_fab,
	                         msg_nr,
	                         sizeof(struct galv_sess_msg));
	if (err)
		goto fini_frag_fab;

	session->conn = conn;
	galv_buff_init_queue(&session->recv_buffq);
	stroll_slist_init(&session->recv_msgq);
	memset(session->recv_bmap, 0, sizeof(session->recv_bmap));

	return 0;

fini_frag_fab:
	stroll_palloc_fini(&session->msg_fab);
fini_buff_fab:
	galv_buff_fini_fabric(&session->buff_fab);

	return err;
}

void
galv_sess_fini(struct galv_sess * __restrict session)
{
	galv_sess_assert_api(session);

	galv_frag_fini_fabric(&session->frag_fab);

	while (!galv_buff_queue_empty(&session->recv_buffq))
		galv_buff_release(galv_buff_dqueue(&session->recv_buffq));
	galv_buff_fini_queue(&session->recv_buffq);
	galv_buff_fini_fabric(&session->buff_fab);
}
