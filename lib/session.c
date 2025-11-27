/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "session.h"
#include "conn.h"
#include "fragment.h"
#include "accept.h"
#include <stroll/fbmap.h>
#include <stroll/page.h>
#include <utils/string.h>

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

struct galv_sess_head {
	uint8_t  flags;   /* Message flags */
	uint8_t  xchg;    /* eXCHGange identification number */
	uint16_t size;    /* Size of network data segment */
	char     data[0];
} __packed;

#define GALV_SESS_HEAD_MULTI_FLAG_BIT  (0U)
#define GALV_SESS_HEAD_MULTI_FLAG_MASK (0x1U)
#define GALV_SESS_HEAD_TYPE_FLAG_BIT   (1U)
#define GALV_SESS_HEAD_TYPE_FLAG_MASK  (0x3U)
#define GALV_SESS_HEAD_VALID_FLAG_MASK \
	((uint8_t) \
	 (GALV_SESS_HEAD_TYPE_FLAG_MASK << GALV_SESS_HEAD_TYPE_FLAG_BIT) || \
	 (GALV_SESS_HEAD_MULTI_FLAG_MASK << GALV_SESS_HEAD_MULTI_FLAG_BIT))

#define GALV_SESS_HEAD_XCHG_BITS \
	(sizeof_member(struct galv_sess_head, xchg) * CHAR_BIT)

#define GALV_SESS_HEAD_SIZE_BITS \
	(sizeof_member(struct galv_sess_head, size) * CHAR_BIT)

#define GALV_SESS_MSG_XCHG_NR \
	(1U << GALV_SESS_HEAD_XCHG_BITS)

struct galv_sess_sgmt {
	size_t size;
	size_t busy;
};

struct galv_sess_msg {
	size_t                    size;
	enum galv_sess_head_multi multi;
	enum galv_sess_head_type  type;
	unsigned int              xchg;
	struct galv_sess_sgmt     sgmt;
	struct galv_frag_list     frags;
	struct stroll_slist_node  queue;
};

struct galv_sess_msg_queue {
	struct stroll_slist base;
	unsigned long       bmap[STROLL_FBMAP_WORD_NR(GALV_SESS_MSG_XCHG_NR)];
};

struct galv_sess_conn {
	struct galv_conn *         conn;
	unsigned int               msg_cnt;
	unsigned int               frag_cnt;
	unsigned int               buff_cnt;
	struct galv_sess_msg_queue recv_msgq;
	struct galv_buff_queue     recv_buffq;
};

/******************************************************************************
 * Various session helpers
 ******************************************************************************/

#define galv_sess_assert_accept_api(_accept) \
	galv_assert_api(_accept); \
	galv_accept_assert_api(&(_accept)->base); \
	galv_sess_assert_ops_api((_accept)->ops); \
	galv_assert_api((_accept)->frag_per_sess == \
	                stroll_max((_accept)->buff_per_sess, \
	                           GALV_SESS_MSG_XCHG_NR)); \
	galv_assert_api((_accept)->buff_per_sess)

#define galv_sess_assert_accept_intern(_accept) \
	galv_assert_intern(_accept); \
	galv_accept_assert_intern(&(_accept)->base); \
	galv_sess_assert_ops_api((_accept)->ops); \
	galv_sess_assert_ops_intern((_accept)->ops); \
	galv_assert_intern((_accept)->frag_per_sess == \
	                   stroll_max((_accept)->buff_per_sess, \
	                              GALV_SESS_MSG_XCHG_NR)); \
	galv_assert_intern((_accept)->buff_per_sess)

#define galv_sess_assert_conn_api(_sess) \
	galv_assert_api(_sess); \
	galv_assert_api((_sess)->conn); \
	galv_assert_api((_sess)->msg_cnt <= GALV_SESS_MSG_XCHG_NR); \
	galv_assert_api((_sess)->frag_cnt <= \
	                galv_sess_conn_acceptor(_sess)->frag_per_sess); \
	galv_assert_api((_sess)->buff_cnt <= \
	                galv_sess_conn_acceptor(_sess)->buff_per_sess)

#define galv_sess_assert_conn_intern(_sess) \
	galv_assert_intern(_sess); \
	galv_assert_intern((_sess)->conn); \
	galv_assert_intern((_sess)->msg_cnt <= GALV_SESS_MSG_XCHG_NR); \
	galv_assert_intern((_sess)->frag_cnt <= \
	                   galv_sess_conn_acceptor(_sess)->frag_per_sess); \
	galv_assert_intern((_sess)->buff_cnt <= \
	                   galv_sess_conn_acceptor(_sess)->buff_per_sess)

static
struct galv_sess_conn *
galv_sess_from_conn(const struct galv_conn * __restrict connection)
{
	galv_assert_intern(connection);

	return (struct galv_sess_conn *)galv_conn_context(connection);
}

static
struct galv_sess_accept *
galv_sess_from_accept(const struct galv_accept * __restrict acceptor)
{
	galv_assert_intern(acceptor);

	return containerof(acceptor, struct galv_sess_accept, base);
}

static
struct galv_sess_accept *
galv_sess_conn_acceptor(const struct galv_sess_conn * __restrict session)
{
	galv_assert_intern(session);

	return galv_sess_from_accept(galv_conn_acceptor(session->conn));
}

static
struct galv_frag *
galv_sess_create_frag(struct galv_sess_conn * __restrict   session,
                      struct galv_sess_accept * __restrict acceptor,
                      size_t                               capacity,
                      struct galv_buff * __restrict        buffer)
{
	galv_sess_assert_conn_intern(session);
	galv_sess_assert_accept_intern(acceptor);
	galv_assert_intern(capacity);
	galv_assert_intern(buffer);
	galv_assert_intern(capacity <= galv_buff_capacity(buffer));

	struct galv_frag * frag;
	int                err;

	if (session->frag_cnt < acceptor->frag_per_sess) {
		frag = stroll_falloc_alloc(&acceptor->frag_alloc);
		if (frag) {
			galv_frag_init(frag, capacity, buffer);
			session->frag_cnt++;
			galv_debug("session: fragment created [addr:%p]",
			           frag);
			return frag;
		}

		err = errno;
	}
	else
		err = ENOBUFS;

	galv_ratelim_pinfo(err,
	                   "session: cannot allocate fragment", "");

	errno = err;
	return NULL;
}

static
void
galv_sess_destroy_frag(struct galv_sess_conn * __restrict   session,
                       struct galv_sess_accept * __restrict acceptor,
                       struct galv_frag * __restrict        fragment)
{
	galv_sess_assert_conn_intern(session);
	galv_assert_intern(session->frag_cnt);
	galv_sess_assert_accept_intern(acceptor);
	galv_frag_assert_intern(fragment);

	if (!galv_frag_fini(fragment))
		/* Underlying buffer has just been released. */
		session->buff_cnt--;

	stroll_falloc_free(&acceptor->frag_alloc, fragment);
	session->frag_cnt--;

	galv_debug("session: fragment destroyed [addr:%p]", fragment);
}

static
struct galv_buff *
galv_sess_summon_buff(struct galv_sess_conn * __restrict   session,
                      struct galv_sess_accept * __restrict acceptor)
{
	galv_sess_assert_conn_intern(session);
	galv_sess_assert_accept_intern(acceptor);

	struct galv_buff * buff;
	int                err;

	if (session->buff_cnt < acceptor->buff_per_sess) {
		/*
		 * FIXME:
		 * Should we allocate smaller capacities according to current
		 * maximum segment size or MTU ?
		 * See description of TCP_MAXSEG in tcp(7).
		 */
		buff = galv_buff_summon(&acceptor->buff_alloc,
		                        GALV_BUFF_DFLT_CAPA);
		if (buff) {
			session->buff_cnt++;
			galv_debug("session: buffer allocated [addr:%p]", buff);
			return buff;
		}

		err = errno;
	}
	else
		err = ENOBUFS;

	galv_ratelim_pinfo(err, "session: cannot allocate buffer", "");

	errno = err;
	return NULL;
}

static
void
galv_sess_release_buff(struct galv_sess_conn * __restrict session,
                       struct galv_buff * __restrict      buffer)
{
	galv_sess_assert_conn_intern(session);
	galv_assert_intern(session->buff_cnt);
	galv_buff_assert_intern(buffer);

	if (!galv_buff_release(buffer)) {
		/*
		 * A buffer has been freed and is now available for reception
		 * purposes. As galv_sess_recv() (-ENOBUFS switch case) disables
		 * EPOLLIN event upon free buffer exhaustion, make sure that we
		 * will get notified upon available connection input data in the
		 * future.
		 */
		switch (galv_conn_state(session->conn)) {
		case GALV_CONN_CONNECTING_STATE:
		case GALV_CONN_ESTABLISHED_STATE:
			galv_conn_watch(session->conn, EPOLLIN);
			break;
		default:
		}

		session->buff_cnt--;

		galv_debug("session: buffer released [addr:%p]", buffer);
	}
}

static
struct galv_sess_conn *
galv_sess_alloc_conn(struct galv_sess_accept * __restrict acceptor)
{
	galv_sess_assert_accept_intern(acceptor);

	struct galv_sess_conn * sess;

	sess = stroll_falloc_alloc(&acceptor->sess_alloc);
	if (!sess) {
		int err = errno;

		if (err != ENOMEM) {
			galv_ratelim_pinfo(
				err,
				"session: cannot allocate connection",
				"");
			errno = err;
		}

		return NULL;
	}

	galv_debug("session: connection allocated [addr:%p]", sess);

	return sess;
}

static
void
galv_sess_free_conn(struct galv_sess_accept * __restrict acceptor,
                    struct galv_sess_conn * __restrict   session)
{
	galv_sess_assert_accept_intern(acceptor);
	galv_sess_assert_conn_intern(session);

	stroll_falloc_free(&acceptor->sess_alloc, session);

	galv_debug("session: connection freed [addr:%p]", session);
}

/******************************************************************************
 * Session protocol header
 ******************************************************************************/

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
		return "cont";
	case GALV_SESS_HEAD_LAST_MULTI:
		return "last";
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

#warning Should init with busy = 0 and cleanup galv_sess_stop_sgmt() in addition to assertions
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
void
galv_sess_init_msg(struct galv_sess_msg * __restrict message)
{
	galv_assert_intern(message);

	message->size = 0;
	message->multi = GALV_SESS_HEAD_MULTI_NR;
	message->type = GALV_SESS_HEAD_TYPE_NR;
	message->xchg = 0;
	galv_sess_stop_sgmt(&message->sgmt);
	galv_frag_init_list(&message->frags);
}

static
void
galv_sess_fini_msg(struct galv_sess_msg * __restrict    message,
                   struct galv_sess_conn * __restrict   session,
                   struct galv_sess_accept * __restrict acceptor)
{
	galv_sess_assert_msg_intern(message);
	galv_sess_assert_conn_intern(session);
	galv_sess_assert_accept_intern(acceptor);

	while (!galv_frag_list_empty(&message->frags)) {
		struct galv_frag * frag = galv_frag_dlist(&message->frags);
		galv_assert_intern(frag);

		galv_sess_destroy_frag(session, acceptor, frag);
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
	galv_assert_intern(galv_sess_msg_loading(message));
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

static
struct galv_sess_msg *
galv_sess_create_msg(struct galv_sess_conn * __restrict   session,
                     struct galv_sess_accept * __restrict acceptor)
{
	galv_sess_assert_conn_intern(session);
	galv_sess_assert_accept_intern(acceptor);

	struct galv_sess_msg * msg;
	int                    err;

	if (session->msg_cnt < GALV_SESS_MSG_XCHG_NR) {
		msg = stroll_falloc_alloc(&acceptor->msg_alloc);
		if (msg) {
			galv_sess_init_msg(msg);
			session->msg_cnt++;
			galv_debug("session: message created [addr:%p]", msg);
			return msg;
		}

		err = errno;
	}
	else
		err = ENOBUFS;

	galv_ratelim_pinfo(err, "session: cannot allocate message", "");

	errno = err;
	return NULL;
}

static
void
galv_sess_destroy_msg(struct galv_sess_conn * __restrict   session,
                      struct galv_sess_accept * __restrict acceptor,
                      struct galv_sess_msg * __restrict    message)
{
	galv_sess_assert_conn_intern(session);
	galv_assert_intern(session->msg_cnt);
	galv_sess_assert_accept_intern(acceptor);
	galv_sess_assert_msg_intern(message);

	unsigned int xchg __unused = message->xchg;

	galv_sess_fini_msg(message, session, acceptor);
	stroll_falloc_free(&acceptor->msg_alloc, message);
	session->msg_cnt--;

	galv_debug("session: message destroyed [id:%u msg:%p]", xchg, message);
}

static
void
galv_sess_drain_buff(struct galv_sess_conn * __restrict  session,
                     struct galv_buff_queue * __restrict buffq,
                     struct galv_buff * __restrict       buff,
                     size_t                              size)
{
	galv_sess_assert_conn_intern(session);
	galv_assert_intern(buffq);
	galv_assert_intern(!galv_buff_queue_empty(buffq));
	galv_assert_intern(buff);
	galv_assert_intern(buff == galv_buff_queue_first(buffq));
	galv_assert_intern(galv_buff_busy(buff));
	galv_assert_intern(size <= galv_buff_busy(buff));

	galv_buff_grow_head(buff, size);
	if (!galv_buff_busy(buff)) {
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
			galv_sess_release_buff(session, buff);
		}
	}
}

static
void
galv_sess_copyn_drain_buff(struct galv_sess_conn * __restrict  session,
                           struct galv_buff_queue * __restrict buffq,
                           struct galv_buff * __restrict       buff,
                           uint8_t * __restrict                data,
                           size_t                              size)
{
	galv_sess_assert_conn_intern(session);
	galv_assert_intern(buffq);
	galv_assert_intern(!galv_buff_queue_empty(buffq));
	galv_assert_intern(buff);
	galv_assert_intern(buff == galv_buff_queue_first(buffq));
	galv_assert_intern(data);
	galv_assert_intern(size);
	galv_assert_intern(size <= galv_buff_busy(buff));

	memcpy(data, galv_buff_data(buff), size);

	galv_sess_drain_buff(session, buffq, buff, size);
}

static
void
galv_sess_copyn_drain_buffq(struct galv_sess_conn * __restrict  session,
                            struct galv_buff_queue * __restrict buffq,
                            uint8_t * __restrict                data,
                            size_t                              size)
{
	galv_sess_assert_conn_intern(session);
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
		galv_sess_release_buff(session, buff);

		buff = galv_buff_queue_first(buffq);
		galv_assert_intern(buff);
		busy = galv_buff_busy(buff);
	}

	galv_sess_copyn_drain_buff(session, buffq, buff, data, size);
}

static
void
galv_sess_open_conn(struct galv_sess_conn * __restrict session,
                    struct galv_conn * __restrict      connection)
{
	galv_assert_api(session);
	galv_assert_api(connection);

	session->conn = connection;
	session->msg_cnt = 0;
	session->frag_cnt = 0;
	session->buff_cnt = 0;
	galv_buff_init_queue(&session->recv_buffq);
	galv_sess_init_msg_queue(&session->recv_msgq);

	galv_debug("session: connection opened [addr:%p]", session);
}

static
void
galv_sess_close_conn(struct galv_sess_conn * __restrict session)
{
	galv_sess_assert_conn_api(session);

	struct galv_sess_accept * accept = galv_sess_conn_acceptor(session);

	/*
	 * Dequeue and release all buffers so that they may be freed safely at
	 * galv_sess_destroy_msg() calling time (a buffer cannot be freed as
	 * long as it is enqueued...)
	 */
	while (galv_buff_queue_count(&session->recv_buffq))
		galv_sess_release_buff(session,
		                       galv_buff_dqueue(&session->recv_buffq));
	galv_buff_fini_queue(&session->recv_buffq);

	while (!galv_sess_msg_queue_empty(&session->recv_msgq))
		galv_sess_destroy_msg(
			session,
			accept,
			galv_sess_dqueue_msg(&session->recv_msgq));
	galv_sess_fini_msg_queue(&session->recv_msgq);

	galv_assert_intern(!session->msg_cnt);
	galv_assert_intern(!session->frag_cnt);
	galv_assert_intern(!session->buff_cnt);

	galv_debug("session: connection closed");
}

/******************************************************************************
 * Session protocol message
 ******************************************************************************/

static
int
galv_sess_recv_sgmt_head(struct galv_sess_conn * __restrict  session,
                         struct galv_sess_msg * __restrict   message,
                         struct galv_buff_queue * __restrict recvq)
{
	galv_sess_assert_conn_intern(session);
	galv_sess_assert_msg_intern(message);
	galv_assert_intern(message->multi == GALV_SESS_HEAD_CONT_MULTI);
	galv_assert_intern(message->type < GALV_SESS_HEAD_TYPE_NR);
	galv_assert_intern(recvq);
	galv_assert_intern(!galv_buff_queue_empty(recvq));

	if (galv_buff_queue_busy(recvq) >= sizeof(struct galv_sess_head)) {
		struct galv_sess_head    head;
		enum galv_sess_head_type type;
		uint16_t                 sz;

		galv_sess_copyn_drain_buffq(session,
		                            recvq,
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
galv_sess_recv_sgmt_frag(struct galv_sess_conn * __restrict  session,
                         struct galv_sess_msg * __restrict   message,
                         struct galv_buff_queue * __restrict recvq)
{
	galv_sess_assert_conn_intern(session);
	galv_sess_assert_msg_intern(message);
	galv_assert_intern(galv_sess_msg_loading(message));
	galv_assert_intern(message->multi != GALV_SESS_HEAD_MULTI_NR);
	galv_assert_intern(message->type != GALV_SESS_HEAD_TYPE_NR);
	galv_assert_intern(galv_sess_sgmt_loading(&message->sgmt));
	galv_assert_intern(!galv_sess_sgmt_full(&message->sgmt));
	galv_assert_intern(recvq);

	if (!galv_buff_queue_empty(recvq)) {
		struct galv_frag_list * frags = &message->frags;
		struct galv_frag *      frag = (!galv_frag_list_empty(frags))
		                               ? galv_frag_list_last(frags)
		                               : NULL;
		struct galv_sess_sgmt * sgmt = &message->sgmt;
		struct galv_buff *      buff = galv_buff_queue_first(recvq);
		size_t                  bytes;

		if (!frag || galv_frag_full(frag)) {
			frag = galv_sess_create_frag(
				session,
				galv_sess_conn_acceptor(session),
				sgmt->size - sgmt->busy,
				buff);
			if (!frag)
				return -errno;

			galv_frag_nlist(frags, frag);
		}

		bytes = galv_frag_load(frag, buff);
		galv_assert_intern(bytes);

		galv_sess_drain_buff(session, recvq, buff, bytes);

		sgmt->busy += bytes;

		return 0;
	}
	else
		return -EAGAIN;
}

static
int
galv_sess_recv_sgmt(struct galv_sess_conn * __restrict session,
                    struct galv_sess_msg * __restrict  message)
{
	galv_sess_assert_conn_intern(session);
	//galv_assert_intern(!galv_buff_queue_empty(&session->recv_buffq));
	galv_sess_assert_msg_intern(message);
	galv_assert_intern(galv_sess_msg_loading(message));
	galv_assert_intern(message->multi != GALV_SESS_HEAD_MULTI_NR);
	galv_assert_intern(message->type != GALV_SESS_HEAD_TYPE_NR);

	struct galv_sess_sgmt *  sgmt = &message->sgmt;
	struct galv_buff_queue * recvq = &session->recv_buffq;
	int                      ret;

	if (!galv_sess_sgmt_loading(sgmt)) {
		ret = galv_sess_recv_sgmt_head(session, message, recvq);
		if (ret) {
			if (ret != -EAGAIN)
				galv_ratelim_pinfo(
					-ret,
					"session: receive segment rejected",
					" [id:%u]",
					message->xchg);
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
		ret = galv_sess_recv_sgmt_frag(session, message, recvq);
	} while (!ret && !galv_sess_sgmt_full(sgmt));

	if (ret) {
		if (ret != -EAGAIN)
			galv_ratelim_pinfo(-ret,
			                   "session: segment receival failed",
			                   " [id:%u]",
			                   message->xchg);
		return ret;
	}
	
	if (galv_sess_sgmt_full(sgmt)) {
		galv_debug("session: receive segment complete "
		           "[id:%u type:%s multi:%s size:%zu]",
		           message->xchg,
		           galv_sess_msg_type_str(message->type),
		           galv_sess_msg_multi_str(message->multi),
		           galv_sess_sgmt_size(sgmt));

		message->size += galv_sess_sgmt_size(sgmt);
		galv_sess_stop_sgmt(sgmt);
	}

	return 0;
}

static
int
galv_sess_recv_msg_head(struct galv_sess_conn * __restrict  session,
                        struct galv_sess_msg * __restrict   message,
                        struct galv_buff_queue * __restrict recvq)
{
	galv_sess_assert_conn_intern(session);
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

		galv_sess_copyn_drain_buffq(session,
		                            recvq,
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

/******************************************************************************
 * Session connection
 ******************************************************************************/

static
int
galv_sess_recv_tail_buff(struct galv_sess_conn * __restrict   session,
                         struct galv_sess_accept * __restrict acceptor)
{
	galv_sess_assert_conn_intern(session);
	galv_sess_assert_accept_intern(acceptor);

	struct galv_buff * buff;
	size_t             size;
	ssize_t            ret = 0;

	buff = galv_buff_queue_last(&session->recv_buffq);
	galv_assert_intern(buff->alloc == &acceptor->buff_alloc);
	size = galv_buff_avail_tail(buff);
	if (size) {
		ret = galv_conn_recv(session->conn,
		                     galv_buff_tail(buff),
		                     size,
		                     0);
		galv_assert_intern(ret);
		if (ret > 0) {
			galv_buff_grow_tail(buff, (size_t)ret);

			ret = ((size_t)ret == size) ? 0 : -EAGAIN;
		}
	}

	return (int)ret;
}

static
int
galv_sess_recv_new_buff(struct galv_sess_conn * __restrict   session,
                        struct galv_sess_accept * __restrict acceptor)
{
	galv_sess_assert_conn_intern(session);
	galv_sess_assert_accept_intern(acceptor);

	struct galv_buff * buff;
	size_t             size;
	ssize_t            ret;

	buff = galv_sess_summon_buff(session, acceptor);
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

	galv_sess_release_buff(session, buff);

	return (int)ret;
}

static
int
galv_sess_recv_buffs(struct galv_sess_conn * __restrict session)
{
	galv_sess_assert_conn_intern(session);

	int                       ret;
	struct galv_sess_accept * accept = galv_sess_conn_acceptor(session);

	if (galv_buff_queue_count(&session->recv_buffq)) {
		ret = galv_sess_recv_tail_buff(session, accept);
		if (ret)
			return ret;
	}

	do {
		ret = galv_sess_recv_new_buff(session, accept);
	} while (!ret);

	galv_assert_intern(ret < 0);

	return ret;
}

static
int
galv_sess_recv_msg(struct galv_sess_conn * __restrict session,
                   struct galv_sess_msg * __restrict  message)
{
	galv_sess_assert_conn_intern(session);
	galv_sess_assert_msg_intern(message);
	galv_assert_intern(!galv_sess_msg_full(message));
	galv_assert_intern(&session->recv_buffq);
	galv_assert_intern(!galv_buff_queue_empty(&session->recv_buffq));

	int ret;

	if (!galv_sess_msg_loading(message)) {
		ret = galv_sess_recv_msg_head(session,
		                              message,
		                              &session->recv_buffq);
		if (ret) {
			if (ret != -EAGAIN)
				galv_ratelim_pinfo(
					-ret,
					"session: receive message rejected",
					"");
			return ret;
		}

#warning Implement dropping current message ?
		if (!galv_sess_may_queue_msg(&session->recv_msgq, message)) {
			galv_ratelim_info(
				"session: duplicate exchange rejected",
				" [id:%u]",
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
		ret = galv_sess_recv_sgmt(session, message);
	} while (!ret && !galv_sess_msg_full(message));

	if (ret) {
		if (ret != -EAGAIN)
			galv_ratelim_pinfo(-ret,
			                   "session: receive message failed",
			                   " [id:%u]: ",
			                   message->xchg);
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
galv_sess_recv_tail_msg(struct galv_sess_conn * __restrict session)
{
	if (!galv_buff_queue_empty(&session->recv_buffq)) {
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
	else
		return -EAGAIN;
}

static
int
galv_sess_recv_new_msg(struct galv_sess_conn * __restrict   session,
                       struct galv_sess_accept * __restrict acceptor)
{
	galv_sess_assert_conn_intern(session);
	galv_sess_assert_accept_intern(acceptor);

	if (!galv_buff_queue_empty(&session->recv_buffq)) {
		struct galv_sess_msg * msg;
		int                    ret;

		msg = galv_sess_create_msg(session, acceptor);
		if (!msg)
			return -errno;

		ret = galv_sess_recv_msg(session, msg);
		switch (ret) {
		case 0:
			galv_sess_nqueue_msg(&session->recv_msgq, msg);
			return 0;

		case -EAGAIN:
		case -ENOBUFS:
			if (!galv_sess_msg_loading(msg))
				/*
				 * Could not even fetch message header: give up
				 * so that we may retry next time we are called
				 * since data are still sitting in the
				 * underlying buffer...
				 */
				break;

			galv_sess_nqueue_msg(&session->recv_msgq, msg);
			return ret;

		default:
			break;
		}

		galv_sess_destroy_msg(session, acceptor, msg);

		return ret;
	}
	else
		return -EAGAIN;
}

static
int
galv_sess_recv_msgs(struct galv_sess_conn * __restrict session)
{
	galv_sess_assert_conn_intern(session);

	int                       ret;
	struct galv_sess_accept * accept = galv_sess_conn_acceptor(session);

	if (!galv_sess_msg_queue_empty(&session->recv_msgq)) {
		ret = galv_sess_recv_tail_msg(session);
		if (ret)
			return ret;
	}

	do {
		ret = galv_sess_recv_new_msg(session, accept);
	} while (!ret);

	galv_assert_intern(ret < 0);

	return ret;
}

static
int
galv_sess_recv(struct galv_sess_conn * __restrict session)
{
	int ret;

	ret = galv_sess_recv_buffs(session);
	switch (ret) {
	case -EAGAIN:
		/* Underlying socket incoming buffer empty, try again later */
		galv_conn_watch(session->conn, EPOLLIN);
		ret = 0;
		break;

	case -ENOBUFS:
		/*
		 * No more receive buffer available. Disable connection input
		 * data available event (i.e., EPOLLIN) to prevent from being
		 * called from polling context while there is no more free
		 * buffer to receive data into.
		 * At galv_sess_release_buff() calling time, i.e., once a buffer
		 * has been freed, EPOLLIN event notification is enabled again.
		 */
		galv_conn_unwatch(session->conn, EPOLLIN);
		ret = 0;
		break;

	case -ECONNREFUSED:
		/* Remote peer closed its connection */
	case -EINTR:
		/* Interrupted by a signal before any data was received */
	case -ENOMEM:
		/* No more memory available */
		return ret;

	default:
		galv_assert_intern(0);
		return ret;
	}

	ret = galv_sess_recv_msgs(session);
	switch (ret) {
	case -EAGAIN:
		/* No more data to fill in additional messages. */
	case -ENOBUFS:
		/*
		 * No more free fragments / messages available to process
		 * messages.
		 */
		ret = 0;
		break;

	case -EPROTO:
		/* Unexpected segment / message header received. */
	case -ENODATA:
		/* Invalid empty segment / message header received. */
	case -ENOMEM:
		/* No more memory available */
		break;

	default:
		galv_assert_intern(0);
	}

	return ret;
}

static
int
galv_sess_process_closing_conn(struct galv_sess_conn * session,
                               const struct upoll *    poller)
{
#warning Implement output buffer flushing.
	return galv_conn_close(session->conn, poller);
}

static
int
galv_sess_process_established_conn(struct galv_sess_conn * session,
                                   uint32_t                events,
                                   const struct upoll *    poller)
{
	int ret;

	if (events & EPOLLOUT)
		galv_conn_unwatch(session->conn, EPOLLOUT);

	if (events & EPOLLIN) {
		ret = galv_sess_recv(session);
		switch (ret) {
		case 0:
			break;

		case -ECONNREFUSED:
		case -EPROTO:
		case -ENODATA:
			return galv_conn_on_recv_shut(session->conn,
			                              events,
			                              poller);

		case -EINTR:
		case -ENOMEM:
			goto apply;

		default:
			galv_ratelim_pnotice(-ret,
			                     "session: unexpected transfer failure",
			                     "");
		}
	}

	ret = galv_sess_conn_acceptor(session)->ops->xfer(session);

#warning Implement output buffer flushing

apply:
	galv_conn_apply_watch(session->conn, poller);

	return ret;
}

static
int
galv_sess_on_may_xfer(struct galv_conn *   connection,
                      uint32_t             events,
                      const struct upoll * poller)
{
	struct galv_sess_conn * sess = galv_sess_from_conn(connection);

	switch (galv_conn_state(connection)) {
	case GALV_CONN_ESTABLISHED_STATE:
		return galv_sess_process_established_conn(sess, events, poller);

	case GALV_CONN_CLOSING_STATE:
		return galv_sess_process_closing_conn(sess, poller);

	default:
		galv_assert_intern(0);
	}

	unreachable();
}

static
int
galv_sess_on_connect(struct galv_conn *   connection,
                     uint32_t             events __unused,
                     const struct upoll * poller)
{
	struct galv_sess_accept * accept;
	struct galv_sess_conn *   sess;
	int                       err;

	accept = galv_sess_from_accept(galv_conn_acceptor(connection));
	sess = galv_sess_alloc_conn(accept);
	if (!sess)
		return -errno;

	galv_sess_open_conn(sess, connection);

	err = galv_conn_poll(connection, poller, EPOLLIN, sess);
	if (err) {
		galv_ratelim_pnotice(-err,
		                     "session: cannot poll connection",
		                     "");
		goto close;
	}

	galv_conn_switch_state(connection, GALV_CONN_ESTABLISHED_STATE);

	galv_debug("session: connection established [addr:%p]", sess);

	return 0;

close:
	galv_sess_close_conn(sess);
	galv_sess_free_conn(accept, sess);

	return err;
}

static
int
galv_sess_on_send_shut(struct galv_conn *   connection,
                       uint32_t             events __unused,
                       const struct upoll * poller)
{
	galv_debug("session: connection emit end shut down: closing..");

	return galv_conn_close(connection, poller);
}

static
int
galv_sess_on_recv_shut(struct galv_conn *   connection,
                       uint32_t             events __unused,
                       const struct upoll * poller)
{
	struct galv_sess_conn * sess = galv_sess_from_conn(connection);

	galv_debug("session: connection receive end shut down: flushing..");

	return galv_sess_process_closing_conn(sess, poller);
}

static
int
galv_sess_halt(struct galv_conn * __restrict   connection,
               const struct upoll * __restrict poller)
{
	struct galv_sess_conn * sess = galv_sess_from_conn(connection);

	galv_debug("session: connection halt requested: flushing..");

	return galv_sess_process_closing_conn(sess, poller);
}

static
void
galv_sess_close(struct galv_conn * __restrict   connection,
                const struct upoll * __restrict poller)
{
	struct galv_sess_conn *   sess = galv_sess_from_conn(connection);
	struct galv_sess_accept * accept =
		galv_sess_from_accept(galv_conn_acceptor(connection));

	galv_conn_unpoll(connection, poller);
	galv_sess_close_conn(sess);
	galv_sess_free_conn(accept, sess);
}

static
int
galv_sess_on_error(struct galv_conn *   connection __unused,
                   uint32_t             events __unused,
                   const struct upoll * poller __unused)
{
	galv_notice("session: unexpected connection socket error");

	return 0;
}

static const struct galv_conn_ops galv_sess_conn_ops = {
	.on_may_xfer  = galv_sess_on_may_xfer,
	.on_connect   = galv_sess_on_connect,
	.on_send_shut = galv_sess_on_send_shut,
	.on_recv_shut = galv_sess_on_recv_shut,
	.halt         = galv_sess_halt,
	.close        = galv_sess_close,
	.on_error     = galv_sess_on_error
};

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
galv_sess_config_accept_backlog(
	struct galv_sess_accept_conf * __restrict config,
	const char * __restrict                   string)
{
	galv_assert_api(config);
	galv_assert_api(string);

	return ustr_parse_uint_range(string, &config->backlog, 0, INT_MAX);
}

void
galv_sess_config_accept(
	struct galv_sess_accept_conf * __restrict config,
	unsigned int                              backlog,
	int                                       conn_flags,
	size_t                                    max_pload,
	size_t                                    buff_capa)
{
	galv_assert_api(config);
	galv_assert_api(backlog <= INT_MAX);
	galv_assert_api(!(conn_flags & ETUX_SOCK_ACCEPT_INVALID_FLAGS));
	galv_assert_api(max_pload);
	galv_assert_api(max_pload <= GALV_SESS_PLOAD_SIZE_MAX);
	galv_assert_api(buff_capa >= GALV_SESS_BUFF_CAPA_MIN);
	galv_assert_api(buff_capa <= GALV_SESS_BUFF_CAPA_MAX);

	config->backlog = backlog;
	config->conn_flags = conn_flags;
	config->max_pload = stroll_align_upper(max_pload, __WORDSIZE);
	config->buff_capa = stroll_align_upper(buff_capa, __WORDSIZE);
}

int
galv_sess_open_accept(
	struct galv_sess_accept * __restrict            acceptor,
	const struct galv_sess_ops * __restrict         operations,
	struct galv_repo * __restrict                   repository,
	struct galv_adopt * __restrict                  adopter,
	const struct upoll * __restrict                 poller,
	const struct galv_sess_accept_conf * __restrict config)
{
	galv_assert_api(acceptor);
	galv_sess_assert_ops_api(operations);
	galv_repo_assert_api(repository);
	galv_adopt_assert_api(adopter);
	galv_sess_assert_conf_api(config);
	galv_assert_api(poller);

	uint64_t     max_msg;
	uint64_t     max_frag;
	uint64_t     max_buff;
	unsigned int conn_nr;
	int          ret;

	ret = galv_accept_open(&acceptor->base,
	                       repository,
	                       adopter,
	                       config->backlog,
	                       &galv_sess_conn_ops,
	                       config->conn_flags,
	                       poller);
	if (ret)
		return ret;

	acceptor->ops = operations;
	acceptor->buff_per_sess = galv_sess_calc_buff_nr(config->max_pload,
	                                                 config->buff_capa);
	acceptor->frag_per_sess = stroll_max(acceptor->buff_per_sess,
	                                     GALV_SESS_MSG_XCHG_NR);

	conn_nr = galv_accept_conn_nr(&acceptor->base);
	galv_assert_intern(conn_nr);
	if (conn_nr != STROLL_FALLOC_UNBOUND_CHUNK_NR) {
		max_msg = stroll_max((uint64_t)GALV_SESS_MSG_XCHG_NR *
		                     (uint64_t)conn_nr,
		                     (uint64_t)UINT_MAX);
		max_frag = stroll_max((uint64_t)acceptor->frag_per_sess *
		                      (uint64_t)conn_nr,
		                      (uint64_t)UINT_MAX);
		max_buff = stroll_max((uint64_t)acceptor->buff_per_sess *
		                      (uint64_t)conn_nr,
		                      (uint64_t)UINT_MAX);
	}
	else {
		max_msg = (uint64_t)STROLL_FALLOC_UNBOUND_CHUNK_NR;
		max_frag = (uint64_t)STROLL_FALLOC_UNBOUND_CHUNK_NR;
		max_buff = (uint64_t)STROLL_FALLOC_UNBOUND_CHUNK_NR;
	}

	stroll_falloc_init_block_size(&acceptor->msg_alloc,
	                             (unsigned int)max_msg,
	                             sizeof(struct galv_sess_msg),
	                             stroll_page_size());
	stroll_falloc_init_block_size(&acceptor->frag_alloc,
	                             (unsigned int)max_frag,
	                             sizeof(struct galv_frag),
	                             stroll_page_size());
	stroll_falloc_init_per_block(&acceptor->buff_alloc,
	                             (unsigned int)max_buff,
	                             config->buff_capa,
	                             acceptor->buff_per_sess);
	stroll_falloc_init_block_size(&acceptor->sess_alloc,
	                              (unsigned int)conn_nr,
	                              sizeof(struct galv_sess_conn),
	                              stroll_page_size());

	return 0;
}

void
galv_sess_close_accept(struct galv_sess_accept * __restrict acceptor,
                       const struct upoll * __restrict      poller)
{
	galv_sess_assert_accept_api(acceptor);
	galv_assert_api(poller);

	stroll_falloc_fini(&acceptor->msg_alloc);
	stroll_falloc_fini(&acceptor->frag_alloc);
	stroll_falloc_fini(&acceptor->buff_alloc);
	stroll_falloc_fini(&acceptor->sess_alloc);
	galv_accept_close(&acceptor->base, poller);
}
