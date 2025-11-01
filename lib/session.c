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
struct galv_buff *
galv_sess_summon_buff(struct galv_buff_fabric * __restrict fabric)
{
	struct galv_buff * buff;

	buff = galv_buff_summon(fabric);
	if (!buff) {
		int err = errno;

		galv_ratelim_info("session: cannot allocate buffer...",
		                  "session: cannot allocate buffer: "
		                  "%s (%d)",
		                  strerror(err),
		                  err);
		errno = err;
		return NULL;
	}

	galv_debug("session: buffer allocated [addr:%p]", buff);

	return buff;
}

static
void
galv_sess_release_buff(struct galv_buff * __restrict buff)
{
	galv_buff_release(buff);

	galv_debug("session: buffer released [addr:%p]", buff);
}

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
			 * - or, galv_sess_recv_buffs() has already started to
			 *   fill in a subsequent buffer in the receive queue.
			 * In both cases, we cannot use current buffer `buff'
			 * any more: release it.
			 */
			galv_buff_dqueue(buffq);
			galv_sess_release_buff(buff);
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
		galv_sess_release_buff(buff);

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

#if defined(CONFIG_GALV_DEBUG)

static
const char *
galv_sess_msg_multi_str(enum galv_sess_head_multi multi)
{
	switch (multi) {
	case GALV_SESS_HEAD_CONT_MULTI:
		return "true";
	case GALV_SESS_HEAD_LAST_MULTI:
		return "false";
	default:
		return "?";
	}

	unreachable();
}

#endif /* defined(CONFIG_GALV_DEBUG) */

static
enum galv_sess_head_type
galv_sess_head_type(const struct galv_sess_head * __restrict header)
{
	galv_assert_intern(header);

	return (header->flags >> GALV_SESS_HEAD_TYPE_FLAG_BIT) &
	       GALV_SESS_HEAD_TYPE_FLAG_MASK;
}

#if defined(CONFIG_GALV_DEBUG)

static
const char *
galv_sess_msg_type_str(enum galv_sess_head_type type)
{
	switch (type) {
	case GALV_SESS_HEAD_REQUEST_TYPE:
		return "request";
	case GALV_SESS_HEAD_REPLY_TYPE:
		return "reply";
	case GALV_SESS_HEAD_NOTIF_TYPE:
		return "notif";
	default:
		return "?";
	}

	unreachable();
}

#endif /* defined(CONFIG_GALV_DEBUG) */

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
	size_t                    size;
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

	galv_assert_intern(!full || message->size);

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
	galv_assert_intern(!galv_buff_queue_empty(recvq));
	galv_assert_intern(fabric);

	struct galv_frag_list * frags = &message->frags;
	struct galv_frag *      frag = (!galv_frag_list_empty(frags))
	                               ? galv_frag_list_last(frags)
	                               : NULL;
	struct galv_sess_sgmt * sgmt = &message->sgmt;
	struct galv_buff *      buff = galv_buff_queue_first(recvq);
	size_t                  bytes;

	if (!frag || galv_frag_full(frag)) {
		frag = galv_frag_create(fabric, sgmt->size - sgmt->busy, buff);
		if (!frag) {
			int err = errno;

			galv_ratelim_info(
				"session: cannot allocate receive fragment...",
				"session: cannot allocate receive fragment: "
				"%s (%d)",
				strerror(err),
				err);
			return -err;
		}

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
	galv_assert_intern(!galv_buff_queue_empty(recvq));
	galv_assert_intern(fabric);

	struct galv_sess_sgmt * sgmt = &message->sgmt;
	int                     ret;

	if (!galv_sess_sgmt_loading(sgmt)) {
		ret = galv_sess_recv_sgmt_head(message, recvq);
		if (ret) {
			if (ret != -EAGAIN)
				galv_ratelim_info(
					"session: receive segment rejected...",
					"session: receive segment rejected "
					"[id:%u]: %s (%d)",
					message->xchg,
					strerror(-ret),
					-ret);
			return ret;
		}

		galv_debug("session: receive segment started "
		           "[id:%u type:%s multi:%s size:%zu]",
		           message->xchg,
		           galv_sess_msg_type_str(message->type),
		           galv_sess_msg_multi_str(message->multi),
		           message->sgmt.size);
	}

	galv_assert_intern(!galv_sess_sgmt_full(sgmt));
	do {
		ret = galv_sess_recv_sgmt_frag(message, recvq, fabric);
	} while (!ret &&
	         !galv_sess_sgmt_full(sgmt) &&
	         !galv_buff_queue_empty(recvq));

	if (ret) {
		if (ret != -EAGAIN)
			galv_ratelim_info(
				"session: segment receival failed...",
				"session: segment receival failed "
				"[id:%u]: %s (%d)",
				message->xchg,
				strerror(-ret),
				-ret);
		return ret;
	}
	
	if (galv_sess_sgmt_full(sgmt)) {
		message->size += galv_sess_sgmt_size(sgmt);
		galv_sess_stop_sgmt(sgmt);
		galv_debug("session: receive segment complete "
		           "[id:%u type:%s multi:%s size:%zu]",
		           message->xchg,
		           galv_sess_msg_type_str(message->type),
		           galv_sess_msg_multi_str(message->multi),
		           message->sgmt.size);
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
	galv_assert_intern(!message->size);
	galv_assert_intern(message->multi == GALV_SESS_HEAD_MULTI_NR);
	galv_assert_intern(message->type == GALV_SESS_HEAD_TYPE_NR);
	galv_assert_intern(galv_frag_list_empty(&message->frags));
	galv_assert_intern(recvq);
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
		if (type >= GALV_SESS_HEAD_TYPE_NR)
			return -EPROTO;

		sz = galv_sess_msg_head_size(&head);
		if (!sz)
			return -ENODATA;

		message->multi = galv_sess_head_multi(&head);
		message->type = type;
		message->xchg = (unsigned int)galv_sess_head_xchg(&head);
		galv_sess_start_sgmt(&message->sgmt, (size_t)sz);

		return 0;
	}
	else
		return -EAGAIN;
}

static
void
galv_sess_init_msg(struct galv_sess_msg * __restrict message)
{
	galv_assert_intern(message);

	message->size = 0;
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
 * Session message queue
 ******************************************************************************/

static
bool
galv_sess_msg_queue_empty(const struct galv_sess_msg_queue * __restrict queue)
{
	galv_assert_intern(queue);
	galv_assert_intern(stroll_slist_empty(&queue->base) ^
	                   _stroll_fbmap_test_all(queue->bmap,
	                                          GALV_SESS_MSG_XCHG_NR));

	return stroll_slist_empty(&queue->base);
}

static
bool
galv_sess_may_queue_msg(const struct galv_sess_msg_queue * __restrict queue,
                        const struct galv_sess_msg * __restrict       message)
{
	galv_assert_intern(queue);
	galv_assert_intern(stroll_slist_empty(&queue->base) ^
	                   _stroll_fbmap_test_all(queue->bmap,
	                                          GALV_SESS_MSG_XCHG_NR));
	galv_sess_assert_msg_intern(message);

	return !_stroll_fbmap_test(queue->bmap, message->xchg);
}

static
struct galv_sess_msg *
galv_sess_msg_queue_tail(const struct galv_sess_msg_queue * __restrict queue)
{
	struct galv_sess_msg * msg;

	msg = stroll_slist_last_entry(&queue->base,
	                              struct galv_sess_msg,
	                              queue);
	galv_assert_intern(_stroll_fbmap_test(queue->bmap, msg->xchg));
	galv_sess_assert_msg_intern(msg);

	return msg;
}

static
void
galv_sess_nqueue_msg(struct galv_sess_msg_queue * __restrict queue,
                     struct galv_sess_msg * __restrict       message)
{
	galv_sess_assert_msg_intern(message);
	galv_assert_intern(galv_sess_may_queue_msg(queue, message));

	stroll_slist_nqueue_back(&queue->base, &message->queue);
	_stroll_fbmap_set(queue->bmap, message->xchg);
}

static
struct galv_sess_msg *
galv_sess_dqueue_msg(struct galv_sess_msg_queue * __restrict queue)
{
	galv_assert_intern(!galv_sess_msg_queue_empty(queue));

	struct galv_sess_msg * msg;

	msg = stroll_slist_entry(stroll_slist_dqueue_front(&queue->base),
	                         struct galv_sess_msg,
	                         queue);
	galv_sess_assert_msg_intern(msg);
	galv_assert_intern(_stroll_fbmap_test(queue->bmap, msg->xchg));
	_stroll_fbmap_clear(queue->bmap, msg->xchg);

	return msg;
}

static
void
galv_sess_init_msg_queue(struct galv_sess_msg_queue * __restrict queue)
{
	galv_assert_intern(queue);

	stroll_slist_init(&queue->base);
	_stroll_fbmap_clear_all(queue->bmap, GALV_SESS_MSG_XCHG_NR);
}

static
void
galv_sess_fini_msg_queue(struct galv_sess_msg_queue * __restrict queue)
{
	galv_assert_intern(queue);
	galv_assert_intern(galv_sess_msg_queue_empty(queue));
	galv_assert_intern(!_stroll_fbmap_test_all(queue->bmap,
	                                           GALV_SESS_MSG_XCHG_NR));
}

/******************************************************************************
 * Session connection
 ******************************************************************************/

#define galv_sess_assert_intern(_sess) \
	galv_assert_intern(_sess); \
	galv_assert_intern((_sess)->conn)

static
int
galv_sess_recv_tail_buff(struct galv_sess * __restrict session)
{
	galv_sess_assert_intern(session);

	struct galv_buff * buff;
	size_t             size;
	ssize_t            ret = 0;

	buff = galv_buff_queue_last(&session->recv_buffq);
	galv_assert_intern(buff->fabric == &session->buff_fab);
	size = galv_buff_avail_tail(buff);
	if (size) {
		ret = galv_conn_recv(session->conn,
		                     galv_buff_tail(buff),
		                     size,
		                     0);
		galv_assert_intern(ret);
		if (ret > 0) {
			galv_buff_grow_tail(buff, (size_t)ret);
			galv_buff_grow_queue(&session->recv_buffq, (size_t)ret);

			ret = ((size_t)ret == size) ? 0 : -EAGAIN;
		}
	}

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

	buff = galv_sess_summon_buff(&session->buff_fab);
	if (!buff)
		return -errno;

	size = galv_buff_capacity(buff);
	ret = galv_conn_recv(session->conn, galv_buff_mem(buff), size, 0);
	galv_assert_intern(ret);
	if (ret > 0) {
		galv_buff_grow_tail(buff, (size_t)ret);
		galv_buff_nqueue(&session->recv_buffq, buff);

		return ((size_t)ret == size) ? 0 : -EAGAIN;
	}

	galv_sess_release_buff(buff);

	return (int)ret;
}

static
int
galv_sess_recv_buffs(struct galv_sess * __restrict session)
{
	galv_sess_assert_intern(session);

	int ret;

	if (!galv_buff_queue_empty(&session->recv_buffq)) {
		ret = galv_sess_recv_tail_buff(session);
		if (ret)
			goto out;
	}

	do {
		ret = galv_sess_recv_new_buff(session);
	} while (!ret);

out:
	if (ret == -EAGAIN) {
		/* Underlying socket incoming buffer empty, try again later */
		galv_conn_watch(session->conn, EPOLLIN);
		return 0;
	}

	galv_assert_intern(ret < 0);

	return ret;
}

static
struct galv_sess_msg *
galv_sess_create_msg(struct galv_sess * __restrict session)
{
	galv_sess_assert_intern(session);

	struct galv_sess_msg * msg;

	msg = stroll_palloc_alloc(&session->msg_fab);
	if (!msg) {
		int err = errno;

		galv_ratelim_info("session: cannot allocate message...",
		                  "session: cannot allocate message: "
		                  "%s (%d)",
		                  strerror(err),
		                  err);
		errno = err;
		return NULL;
	}

	galv_sess_init_msg(msg);

	galv_debug("session: message created");

	return msg;
}

static
void
galv_sess_destroy_msg(struct galv_sess * __restrict     session,
                      struct galv_sess_msg * __restrict message)
{
	galv_sess_assert_intern(session);
	galv_sess_assert_msg_intern(message);

	unsigned int xchg __unused = message->xchg;

	galv_sess_fini_msg(message);
	stroll_palloc_free(&session->msg_fab, message);

	galv_debug("session: message destroyed [id:%u]", xchg);
}

static
int
galv_sess_recv_msg(struct galv_sess * __restrict     session,
                   struct galv_sess_msg * __restrict message)
{
	galv_sess_assert_intern(session);
	galv_sess_assert_msg_intern(message);
	galv_assert_intern(!galv_sess_msg_full(message));
	galv_assert_intern(&session->recv_buffq);
	galv_assert_intern(!galv_buff_queue_empty(&session->recv_buffq));

	int ret;

	if (!galv_sess_msg_loading(message)) {
		ret = galv_sess_recv_msg_head(message, &session->recv_buffq);
		if (ret) {
			if (ret != -EAGAIN)
				galv_ratelim_info(
					"session: receive message rejected...",
					"session: receive message rejected: "
					"%s (%d)",
					strerror(-ret),
					-ret);
			return ret;
		}

#warning Implement dropping current message ?
		if (!galv_sess_may_queue_msg(&session->recv_msgq, message)) {
			galv_ratelim_info(
				"session: duplicate exchange rejected...",
				"session: duplicate exchange rejected [id:%u]",
				message->xchg);
			return -EPROTO;
		}

		galv_debug("session: receive message started "
		           "[id:%u type:%s multi:%s]",
		           message->xchg,
		           galv_sess_msg_type_str(message->type),
		           galv_sess_msg_multi_str(message->multi));
	}

	galv_assert_intern(!galv_sess_msg_full(message));
	do {
		ret = galv_sess_recv_sgmt(message,
		                          &session->recv_buffq,
		                          &session->frag_fab);
	} while (!ret && !galv_sess_msg_full(message));

	if (ret) {
		if (ret != -EAGAIN)
			galv_ratelim_info(
				"session: receive message failed...",
				"session: receive message failed [id:%u]: "
				"%s (%d)",
				message->xchg,
				strerror(-ret),
				-ret);
		return ret;
	}

	if (galv_sess_msg_full(message))
		galv_debug("session: receive message complete "
		           "[id:%u type:%s multi:%s size:%zu]",
		           message->xchg,
		           galv_sess_msg_type_str(message->type),
		           galv_sess_msg_multi_str(message->multi),
		           message->size);

	return 0;
}

static
int
galv_sess_recv_tail_msg(struct galv_sess * __restrict session)
{
	struct galv_sess_msg * msg;

	msg = galv_sess_msg_queue_tail(&session->recv_msgq);
	if (!galv_sess_msg_full(msg)) {
		int ret;

		ret = galv_sess_recv_msg(session, msg);
		if (ret)
			return ret;
	}

	return 0;
}

static
int
galv_sess_recv_new_msg(struct galv_sess * __restrict session)
{
	struct galv_sess_msg * msg;
	int                    ret;

	msg = galv_sess_create_msg(session);
	if (!msg)
		return -errno;

	ret = galv_sess_recv_msg(session, msg);
	switch (ret) {
	case 0:
	case -EAGAIN:
	case -ENOBUFS:
		galv_sess_nqueue_msg(&session->recv_msgq, msg);
		return ret;

	default:
		break;
	}

	galv_sess_destroy_msg(session, msg);

	return ret;
}

static
int
galv_sess_recv_msgs(struct galv_sess * __restrict session)
{
	galv_sess_assert_intern(session);

	int ret;

	if (!galv_sess_msg_queue_empty(&session->recv_msgq)) {
		ret = galv_sess_recv_tail_msg(session);
		if (ret)
			goto out;
	}

	do {
		ret = galv_sess_recv_new_msg(session);
	} while (!ret);

out:
	if (ret == -EAGAIN) {
		/* No more data to fill in additional messages. */
		galv_conn_watch(session->conn, EPOLLIN);
		return 0;
	}

	galv_assert_intern(ret < 0);

	return ret;
}

int
galv_sess_recv(struct galv_sess * __restrict   session,
               uint32_t                        events,
               const struct upoll * __restrict poller)
{
	int ret;

	ret = galv_sess_recv_buffs(session);
	switch (ret) {
	case 0:
		break;

	case -ENOBUFS:      /* No more receive buffer available. */
#warning Make sure client is given a change to release messages / fragments / buffers
#warning Do we need to galv_conn_watch() galv_conn_unwatch() EPOLLIN or flush output queues ?
		break;

	case -ECONNREFUSED: /* Remote peer closed its connection */
		return galv_conn_on_recv_closed(session->conn, events, poller);

	case -EINTR:        /* Interrupted by a signal before any data was received */
	case -ENOMEM:       /* No more memory available */
		return ret;

	default:
		galv_assert_intern(0);
		return ret;
	}

	if (galv_buff_queue_empty(&session->recv_buffq))
		return ret;

	ret = galv_sess_recv_msgs(session);
	switch (ret) {
	case 0:
		break;

	case -ENOBUFS:
#warning Do we need to galv_conn_watch() galv_conn_unwatch() EPOLLIN or flush output queues ?
		break;

	case -EPROTO:
	case -ENODATA:
#warning log a message
		break;

	case -ENOMEM:
		break;

	default:
		galv_assert_intern(0);
	}

	return ret;
}

#define GALV_SESS_PLOAD_SIZE_MAX (1U*1024*1024)
#define GALV_SESS_BUFF_CAPA_MIN  (128U)
#define GALV_SESS_BUFF_CAPA_MAX  (128U*1024)

/*
 * Compute the expected number of buffers required to store an entire session
 * message which user payload size and buffer size are given as argument.
 *
 * Let M be the number of bytes required to store the entire session message
 * (and its user payload) including protocol headers.
 * We search for B, the number of buffers required to store an entire session
 * message of size M.
 *
 * Let P be the size of user payload, i.e., the `pload_size' argument.
 * Let S be the size of buffer data area, i.e., the `buff_capa' argument.
 * Let H be the size of a single session protocol header, i.e.,
 * sizeof(struct galv_sess_head).
 *
 * The total message size M is:
 *     (1), M = P + H.B
 *
 * Also note that:
 *     B = M / S
 * Round up because of integer division:
 *     B = (M + S - 1) / S
 * And add 1 to cope with misalignment cases, i.e., when first session message
 * byte starts in the middle of a buffer:
 *              B = 1 + ((M + S - 1) / S)
 *     (2), <=> B = (M + 2.S - 1) / S
 *
 * Because of (1) and (2):
 *              B = (P + H.B + 2.S - 1) / S
 *     (3), <=> B = (P + 2.S - 1) / (S - 1)
 */
static
unsigned int
galv_sess_calc_buff_nr(size_t pload_size, size_t buff_capa)
{
	galv_assert_intern(pload_size);
	galv_assert_intern(pload_size <= GALV_SESS_PLOAD_SIZE_MAX);
	galv_assert_intern(buff_capa >= GALV_SESS_BUFF_CAPA_MIN);
	galv_assert_intern(buff_capa <= GALV_SESS_BUFF_CAPA_MAX);

	size_t sz = (pload_size + (2 * buff_capa) - 1);

	galv_assert_intern(sz > pload_size);
	galv_assert_intern(sz > buff_capa);

	return (unsigned int)(sz / (buff_capa - sizeof(struct galv_sess_head)));
}

int
galv_sess_open(struct galv_sess * __restrict session,
               struct galv_conn * __restrict conn,
               size_t                        max_pload_size,
               size_t                        buff_capa)
{
	galv_assert_api(session);
	galv_assert_api(conn);
	galv_assert_api(max_pload_size);
	galv_assert_api(max_pload_size <= GALV_SESS_PLOAD_SIZE_MAX);
	galv_assert_intern(buff_capa >= GALV_SESS_BUFF_CAPA_MIN);
	galv_assert_intern(buff_capa <= GALV_SESS_BUFF_CAPA_MAX);

	unsigned int buff_nr;
	int          err;
	unsigned int frag_nr;

	buff_nr = galv_sess_calc_buff_nr(max_pload_size, buff_capa);
	err = galv_buff_init_fabric(&session->buff_fab, buff_nr, buff_capa);
	if (err)
		return err;

	err = stroll_palloc_init(&session->msg_fab,
	                         GALV_SESS_MSG_XCHG_NR,
	                         sizeof(struct galv_sess_msg));
	if (err)
		goto fini_buff_fab;

	session->conn = conn;
	galv_buff_init_queue(&session->recv_buffq);

	/*
	 * We need at least as many fragments as the maximum number of
	 * simultaneous messages possible.
	 * In addition, as only complete messages may be passed to upper
	 * layers, we also need at least as many fragments as required to
	 * store the longest session message we have to process (with one
	 * fragment per network buffer).
	 */
	frag_nr = stroll_max(buff_nr, GALV_SESS_MSG_XCHG_NR);
	galv_frag_init_fabric(&session->frag_fab, frag_nr);

	galv_sess_init_msg_queue(&session->recv_msgq);

	galv_debug("session: "
	           "opened with %u buffers of %zu bytes and %u fragments",
	           buff_nr,
	           buff_capa,
	           frag_nr);

	return 0;

fini_buff_fab:
	galv_buff_fini_fabric(&session->buff_fab);

	galv_ratelim_notice("session: cannot initialize...",
	                    "session: cannot initialize: %s (%d)",
	                    strerror(-err),
	                    -err);

	return err;
}

void
galv_sess_close(struct galv_sess * __restrict session)
{
	galv_sess_assert_api(session);

	while (!galv_sess_msg_queue_empty(&session->recv_msgq))
		galv_sess_destroy_msg(session,
		                      galv_sess_dqueue_msg(&session->recv_msgq));
	galv_sess_fini_msg_queue(&session->recv_msgq);
	stroll_palloc_fini(&session->msg_fab);

	galv_frag_fini_fabric(&session->frag_fab);

	while (!galv_buff_queue_empty(&session->recv_buffq))
		galv_sess_release_buff(galv_buff_dqueue(&session->recv_buffq));
	galv_buff_fini_queue(&session->recv_buffq);
	galv_buff_fini_fabric(&session->buff_fab);

	galv_debug("session: closed");
}
