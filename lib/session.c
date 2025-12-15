/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "session.h"
#include "fragment.h"
#include "accept.h"
#include <stroll/page.h>
#include <utils/string.h>

#warning implement session message timeout

/******************************************************************************
 * Various internal session definitions and helpers
 ******************************************************************************/

#define galv_sess_assert_accept_api(_accept) \
	galv_assert_api(_accept); \
	galv_accept_assert_api(&(_accept)->base); \
	galv_sess_assert_ops_api((_accept)->ops); \
	galv_assert_api((_accept)->max_pload); \
	galv_assert_api(stroll_aligned((_accept)->max_pload, \
	                               __WORDSIZE / CHAR_BIT)); \
	galv_assert_api((_accept)->max_pload <= GALV_SESS_PLOAD_SIZE_MAX); \
	galv_assert_api((_accept)->frag_per_sess == \
	                stroll_max((_accept)->buff_per_sess, \
	                           GALV_SESS_MSG_XCHG_NR)); \
	galv_assert_api((_accept)->buff_per_sess)

#define galv_sess_assert_accept_intern(_accept) \
	galv_assert_intern(_accept); \
	galv_accept_assert_intern(&(_accept)->base); \
	galv_sess_assert_ops_intern((_accept)->ops); \
	galv_assert_intern((_accept)->max_pload); \
	galv_assert_intern(stroll_aligned((_accept)->max_pload, \
	                                  __WORDSIZE / CHAR_BIT)); \
	galv_assert_intern((_accept)->max_pload <= GALV_SESS_PLOAD_SIZE_MAX); \
	galv_assert_intern((_accept)->frag_per_sess == \
	                   stroll_max((_accept)->buff_per_sess, \
	                              GALV_SESS_MSG_XCHG_NR)); \
	galv_assert_intern((_accept)->buff_per_sess)

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

		switch (errno) {
		case ENOBUFS:
		case ENOMEM:
			return NULL;

		default:
			err = errno;
			galv_ratelim_pinfo(err,
			                   "session: cannot allocate buffer",
			                   "");
			errno = err;
		}
	}
	else
		errno = ENOBUFS;

	return NULL;
}

static
void
galv_sess_on_buff_released(struct galv_sess_conn * __restrict  session,
                           const struct galv_buff * __restrict buffer __unused)
{
	/*
	 * A buffer has been freed and is now available for reception
	 * purposes.
	 * As galv_sess_recv() (-ENOBUFS switch case) disables EPOLLIN event
	 * upon free buffer exhaustion, make sure that we will get notified upon
	 * available connection input data in the future.
	 */
	switch (galv_conn_state(session->conn)) {
	case GALV_CONN_CONNECTING_STATE:
	case GALV_CONN_ESTABLISHED_STATE:
		galv_conn_watch(session->conn, EPOLLIN);
		break;

	default:
		break;
	}

	session->buff_cnt--;

	galv_debug("session: buffer released [addr:%p]", buffer);
}

static
void
galv_sess_release_buff(struct galv_sess_conn * __restrict session,
                       struct galv_buff * __restrict      buffer)
{
	galv_sess_assert_conn_intern(session);
	galv_assert_intern(session->buff_cnt);
	galv_buff_assert_intern(buffer);

	if (!galv_buff_release(buffer))
		galv_sess_on_buff_released(session, buffer);
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
	galv_assert_intern(capacity <= STROLL_BUFF_CAPACITY_MAX);

	struct galv_frag * frag;
	int                err;

	if (session->frag_cnt < acceptor->frag_per_sess) {
		frag = stroll_falloc_alloc(&acceptor->frag_alloc);
		if (frag) {
			galv_frag_init(frag, capacity, buffer);
			session->frag_cnt++;
			galv_debug("session: fragment created "
			           "[addr:%p capa:%zu]",
			           frag,
			           stroll_min(capacity,
			                      galv_buff_capacity(buffer) -
			                      galv_buff_avail_head(buffer)));
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

	const struct galv_buff * buff __unused = fragment->buff;

	if (!galv_frag_fini(fragment))
		/* Underlying buffer has just been released. */
		galv_sess_on_buff_released(session, buff);

	stroll_falloc_free(&acceptor->frag_alloc, fragment);
	session->frag_cnt--;

	galv_debug("session: fragment destroyed [addr:%p]", fragment);
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

	return ((unsigned int)header->flags >> GALV_SESS_HEAD_MULTI_FLAG_BIT) &
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
static
size_t
galv_sess_msg_head_size(const struct galv_sess_head * __restrict header)
{
	galv_assert_intern(header);
	galv_assert_intern(stroll_aligned((size_t)&header->size,
	                                  sizeof(header->size)));

#warning FIXME: convert from network byte order if not unix socket !
	//return (size_t)be16toh(header->size) + 1;
	return (size_t)header->size + 1;
}

/******************************************************************************
 * Generic Session protocol message
 ******************************************************************************/

#define galv_sess_assert_msg_intern(_msg) \
	galv_assert_intern(_msg); \
	galv_assert_intern((_msg)->type >= 0); \
	galv_assert_intern((_msg)->type <= GALV_SESS_HEAD_TYPE_NR); \
	galv_assert_intern((_msg)->state >= 0); \
	galv_assert_intern((_msg)->state <= GALV_SESS_SGMT_STAT_NR); \
	galv_assert_intern(((_msg)->state == GALV_SESS_SGMT_STAT_NR) || \
	                   ((_msg)->xchg < GALV_SESS_MSG_XCHG_NR)); \
	galv_assert_intern((_msg)->sess); \
	galv_assert_intern((_msg)->fini)

#define galv_sess_assert_recv_msg_intern(_msg) \
	galv_sess_assert_msg_intern(_msg); \
	galv_assert_intern(((_msg)->state == GALV_SESS_SGMT_STAT_NR) || \
	                   ((_msg)->size && \
	                    ((_msg)->recv.multi >= 0) && \
	                    ((_msg)->recv.multi < GALV_SESS_HEAD_MULTI_NR)))

static
size_t
galv_sess_sgmt_size(const struct galv_sess_msg * __restrict message)
{
	galv_sess_assert_msg_intern(message);

	return message->size & ((size_t)GALV_SESS_SGMT_SIZE_MAX - 1);
}

static
bool
galv_sess_recv_sgmt_full(const struct galv_sess_msg * __restrict message)
{
	galv_sess_assert_recv_msg_intern(message);
	galv_assert_intern(message->size);
	galv_assert_intern(message->state != GALV_SESS_SGMT_STAT_NR);
	galv_assert_intern(message->recv.busy <= galv_sess_sgmt_size(message));

	return message->recv.busy == galv_sess_sgmt_size(message);
}

static
void
galv_sess_start_recv_sgmt(struct galv_sess_msg * __restrict  message,
                          size_t                             size,
                          enum galv_sess_head_multi          multi)
{
	galv_sess_assert_recv_msg_intern(message);
	galv_assert_intern(message->type != GALV_SESS_HEAD_TYPE_NR);
	galv_assert_intern(message->state != GALV_SESS_SGMT_PARTIAL_STAT);
	galv_assert_intern(size);
	galv_assert_intern(size <= GALV_SESS_SGMT_SIZE_MAX);
	galv_assert_intern(multi >= 0);
	galv_assert_intern(multi < GALV_SESS_HEAD_MULTI_NR);

	message->size += size;
	message->state = GALV_SESS_SGMT_PARTIAL_STAT;
	message->recv.busy = 0;
	message->recv.multi = multi;
}

static
void
galv_sess_stop_recv_sgmt(struct galv_sess_msg * __restrict  message)
{
	galv_sess_assert_recv_msg_intern(message);
	galv_assert_intern(message->type != GALV_SESS_HEAD_TYPE_NR);
	galv_assert_intern(message->state == GALV_SESS_SGMT_PARTIAL_STAT);
	galv_assert_intern(message->recv.busy == galv_sess_sgmt_size(message));
	galv_assert_intern(message->recv.multi != GALV_SESS_HEAD_MULTI_NR);

	message->state = GALV_SESS_SGMT_COMPLETE_STAT;
}

static
bool
galv_sess_recv_msg_complete(const struct galv_sess_msg * __restrict message)
{
	galv_sess_assert_recv_msg_intern(message);

	bool full = (message->state == GALV_SESS_SGMT_COMPLETE_STAT) &&
	            (message->recv.multi == GALV_SESS_HEAD_LAST_MULTI);

	galv_assert_intern(!full ||
	                   (message->size &&
	                    (message->type != GALV_SESS_HEAD_TYPE_NR)));

	return full;
}

static
void
galv_sess_fini_recv_msg(struct galv_sess_msg * __restrict    message,
                        struct galv_sess_conn * __restrict   session,
                        struct galv_sess_accept * __restrict acceptor)
{
	galv_sess_assert_msg_intern(message);
	galv_sess_assert_conn_intern(session);
	galv_assert_api(!_stroll_fbmap_test(session->xchg_map, message->xchg));
	galv_sess_assert_accept_intern(acceptor);

	while (!galv_frag_list_empty(&message->recv.frags)) {
		struct galv_frag * frag = galv_frag_dlist(&message->recv.frags);
		galv_assert_intern(frag);

		galv_sess_destroy_frag(session, acceptor, frag);
	}
}

static
void
galv_sess_init_recv_msg(struct galv_sess_msg * __restrict  message,
                        struct galv_sess_conn * __restrict session)
{
	galv_assert_intern(message);
	galv_sess_assert_conn_intern(session);

	message->size = 0;
	message->type = GALV_SESS_HEAD_TYPE_NR;
	message->state = GALV_SESS_SGMT_STAT_NR;
	galv_frag_init_list(&message->recv.frags);
	message->sess = session;
	message->fini = galv_sess_fini_recv_msg;
}

static
struct galv_sess_msg *
galv_sess_alloc_msg(struct galv_sess_conn * __restrict   session,
                    struct galv_sess_accept * __restrict acceptor)
{
	galv_sess_assert_conn_intern(session);
	galv_sess_assert_accept_intern(acceptor);

	if (session->msg_cnt < GALV_SESS_MSG_XCHG_NR) {
		struct galv_sess_msg * msg;

		msg = stroll_falloc_alloc(&acceptor->msg_alloc);
		if (msg) {
			session->msg_cnt++;
			return msg;
		}
	}
	else
		errno = ENOBUFS;

	return NULL;
}

static
void
galv_sess_free_msg(struct galv_sess_conn * __restrict   session,
                   struct galv_sess_accept * __restrict acceptor,
                   struct galv_sess_msg * __restrict    message,
                   unsigned int                         xchange __unused)
{
	galv_sess_assert_conn_intern(session);
	galv_assert_intern(session->msg_cnt);
	galv_sess_assert_accept_intern(acceptor);
	galv_assert_intern(xchange < GALV_SESS_MSG_XCHG_NR);

	stroll_falloc_free(&acceptor->msg_alloc, message);
	session->msg_cnt--;

	galv_debug("session: message destroyed [addr:%p id:%u]",
	           message,
	           xchange);
}

/******************************************************************************
 * Session connection receive handling
 ******************************************************************************/

static
bool
galv_sess_may_nqueue_recv_msg(const struct galv_sess_conn * __restrict session,
                              const struct galv_sess_msg * __restrict  message)
{
	galv_sess_assert_conn_intern(session);
	galv_sess_assert_recv_msg_intern(message);

	return !_stroll_fbmap_test(session->xchg_map, message->xchg);
}

static
void
galv_sess_nqueue_recv_msg(struct galv_sess_conn * __restrict session,
                          struct galv_sess_msg * __restrict  message)
{
	galv_sess_assert_conn_intern(session);
	galv_sess_assert_recv_msg_intern(message);
	galv_assert_intern(galv_sess_may_nqueue_recv_msg(session, message));

	stroll_slist_nqueue_back(&session->recv_msgq, &message->recv.queue);
	_stroll_fbmap_set(session->xchg_map, message->xchg);
}

static
struct galv_sess_msg *
galv_sess_dqueue_recv_msg(struct galv_sess_conn * __restrict session)
{
	galv_sess_assert_conn_intern(session);
	galv_assert_intern(galv_sess_may_pull_msg(session));

	struct galv_sess_msg * msg;

	msg = stroll_slist_entry(stroll_slist_dqueue_front(&session->recv_msgq),
	                         struct galv_sess_msg,
	                         recv.queue);
	galv_sess_assert_recv_msg_intern(msg);
	galv_assert_intern(_stroll_fbmap_test(session->xchg_map, msg->xchg));

	return msg;
}

struct galv_sess_msg *
galv_sess_pull_msg(struct galv_sess_conn * __restrict session)
{
	galv_sess_assert_conn_api(session);
	galv_assert_api(galv_sess_may_pull_msg(session));

	return galv_sess_dqueue_recv_msg(session);
}

static
struct galv_sess_msg *
galv_sess_create_recv_msg(struct galv_sess_conn * __restrict   session,
                          struct galv_sess_accept * __restrict acceptor)
{
	galv_sess_assert_conn_intern(session);
	galv_sess_assert_accept_intern(acceptor);

	struct galv_sess_msg * msg;
	int                    err;

	msg = galv_sess_alloc_msg(session, acceptor);
	if (msg) {
		galv_sess_init_recv_msg(msg, session);
		galv_debug("session: receive message created [addr:%p]", msg);
		return msg;
	}

	err = errno;
	galv_ratelim_pinfo(err, "session: cannot allocate receive message", "");
	errno = err;

	return NULL;
}

static
void
galv_sess_destroy_recv_msg(struct galv_sess_conn * __restrict   session,
                           struct galv_sess_accept * __restrict acceptor,
                           struct galv_sess_msg * __restrict    message)
{
	galv_sess_assert_conn_intern(session);
	galv_assert_intern(session->msg_cnt);
	galv_sess_assert_accept_intern(acceptor);
	galv_sess_assert_msg_intern(message);

	unsigned int xchg = message->xchg;

	galv_sess_fini_recv_msg(message, session, acceptor);
	_stroll_fbmap_clear(session->xchg_map, message->xchg);
	galv_sess_free_msg(session, acceptor, message, xchg);
}

void
galv_sess_drop_msg(struct galv_sess_msg * __restrict message)
{
	galv_sess_assert_msg_api(message);

	struct galv_sess_conn *   sess = message->sess;
	struct galv_sess_accept * accept = galv_sess_conn_acceptor(sess);
	unsigned int              xchg = message->xchg;

	galv_sess_assert_conn_api(sess);
	galv_sess_assert_accept_api(accept);

	message->fini(message, sess, accept);
	_stroll_fbmap_clear(sess->xchg_map, xchg);
	galv_sess_free_msg(sess, accept, message, xchg);
}

static
void
galv_sess_drain_buff(struct galv_sess_conn * __restrict  session,
                     struct galv_buff_queue *            buffq,
                     struct galv_buff *                  buff,
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
                           struct galv_buff_queue *            buffq,
                           struct galv_buff *                  buff,
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
		galv_assert_intern(size <= galv_buff_queue_busy(buffq));
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
	_stroll_fbmap_clear_all(session->xchg_map, GALV_SESS_MSG_XCHG_NR);
	session->recv_msg = NULL;
	stroll_slist_init(&session->recv_msgq);
	galv_buff_init_queue(&session->recv_buffq);
	galv_buff_init_queue(&session->send_buffq);

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
	 * galv_sess_destroy_recv_msg() calling time (a buffer cannot be freed
	 * as long as it is enqueued since enqueueing does not increment
	 * internal buffer reference count...)
	 */
	while (galv_buff_queue_count(&session->recv_buffq))
		galv_sess_release_buff(session,
		                       galv_buff_dqueue(&session->recv_buffq));
	galv_buff_fini_queue(&session->recv_buffq);

	if (session->recv_msg)
		galv_sess_destroy_recv_msg( session, accept, session->recv_msg);
	while (galv_sess_may_pull_msg(session))
		galv_sess_destroy_recv_msg(session,
		                           accept,
		                           galv_sess_dqueue_recv_msg(session));

	while (galv_buff_queue_count(&session->send_buffq))
		galv_sess_release_buff(session,
		                       galv_buff_dqueue(&session->send_buffq));
	galv_buff_fini_queue(&session->send_buffq);

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
galv_sess_recv_sgmt_head(struct galv_sess_conn * __restrict         session,
                         const struct galv_sess_accept * __restrict acceptor,
                         struct galv_sess_msg * __restrict          message,
                         struct galv_buff_queue * __restrict        recvq)
{
	galv_sess_assert_conn_intern(session);
	galv_sess_assert_accept_intern(acceptor);
	galv_sess_assert_recv_msg_intern(message);
	galv_assert_intern(message->size);
	galv_assert_intern(message->type != GALV_SESS_HEAD_TYPE_NR);
	galv_assert_intern(message->state == GALV_SESS_SGMT_COMPLETE_STAT);
	galv_assert_intern(message->recv.multi == GALV_SESS_HEAD_CONT_MULTI);
	galv_assert_intern(recvq);

	if (galv_buff_queue_busy(recvq) >= sizeof(struct galv_sess_head)) {
		struct galv_sess_head     head;
		enum galv_sess_head_type  type;
		enum galv_sess_head_multi multi;
		size_t                    sz;
		const char *              estr;
		int                       err;

		galv_sess_copyn_drain_buffq(session,
		                            recvq,
		                            (uint8_t *)&head,
		                            sizeof(head));

		if (head.flags & ~GALV_SESS_HEAD_VALID_FLAG_MASK) {
			estr = "invalid flags";
			err = EPROTO;
			goto err;
		}

		multi = galv_sess_head_multi(&head);

		type = galv_sess_head_type(&head);
		if (type != message->type) {
			estr = "unexpected type";
			err = EPROTO;
			goto err;
		}

		if ((unsigned int)galv_sess_head_xchg(&head) != message->xchg) {
			estr = "unexpected exchange";
			err = EPROTO;
			goto err;
		}

		sz = galv_sess_msg_head_size(&head);
		galv_assert_intern(sz <= (size_t)(USHRT_MAX + 1));
		if ((message->size + sz) > acceptor->max_pload) {
			/*
			 * Thanks to CONFIG_GALV_SESS_PLOAD_SIZE_MAX
			 * restrictions, the above addition cannot overflow.
			 */
			estr = "size too large";
			err = EMSGSIZE;
			goto err;
		}

		if ((multi == GALV_SESS_HEAD_CONT_MULTI) &&
		    (sz != GALV_SESS_SGMT_SIZE_MAX)) {
			estr = "size too small";
			err = EMSGSIZE;
			goto err;
		}

		galv_sess_start_recv_sgmt(message, (size_t)sz, multi);
		galv_debug("session: receive segment started "
		           "[id:%u type:%s multi:%s size:%zu]",
		           message->xchg,
		           galv_sess_msg_type_str(message->type),
		           galv_sess_msg_multi_str(message->recv.multi),
		           sz);

		return 0;

err:
#warning Implement dropping current message ?
		galv_ratelim_pinfo(err,
		                   "session: receive segment header rejected",
		                   " [id:%u]: %s",
		                   message->xchg,
		                   estr);

		return -err;
	}
	else
		return -EAGAIN;
}

static
int
galv_sess_recv_msg_head(struct galv_sess_conn * __restrict         session,
                        const struct galv_sess_accept * __restrict acceptor,
                        struct galv_sess_msg * __restrict          message,
                        struct galv_buff_queue * __restrict        recvq)
{
	galv_sess_assert_conn_intern(session);
	galv_sess_assert_accept_intern(acceptor);
	galv_sess_assert_recv_msg_intern(message);
	galv_assert_intern(message->state == GALV_SESS_SGMT_STAT_NR);
	galv_assert_intern(galv_frag_list_empty(&message->recv.frags));
	galv_assert_intern(recvq);
	galv_assert_intern(!galv_buff_queue_empty(recvq));

	if (galv_buff_queue_busy(recvq) >= sizeof(struct galv_sess_head)) {
		struct galv_sess_head     head;
		enum galv_sess_head_multi multi;
		enum galv_sess_head_type  type;
		size_t                    sz;
		const char *              estr;
		int                       err;

		galv_sess_copyn_drain_buffq(session,
		                            recvq,
		                            (uint8_t *)&head,
		                            sizeof(head));

		if (head.flags & ~GALV_SESS_HEAD_VALID_FLAG_MASK) {
			estr = "invalid flags";
			err = EPROTO;
			goto err;
		}

		multi = galv_sess_head_multi(&head);

		type = galv_sess_head_type(&head);
		if (type >= GALV_SESS_HEAD_TYPE_NR) {
			estr = "invalid type";
			err = EPROTO;
			goto err;
		}

		sz = galv_sess_msg_head_size(&head);
		galv_assert_intern(sz <= (size_t)(USHRT_MAX + 1));
		if (sz > acceptor->max_pload) {
			estr = "size too large";
			err = EMSGSIZE;
			goto err;
		}

		if ((multi == GALV_SESS_HEAD_CONT_MULTI) &&
		    (sz != GALV_SESS_SGMT_SIZE_MAX)) {
			estr = "size too small";
			err = EMSGSIZE;
			goto err;
		}

		message->xchg = (unsigned int)galv_sess_head_xchg(&head);
		if (!galv_sess_may_nqueue_recv_msg(session, message)) {
			estr = "duplicate exchange";
			err = EPROTO;
			goto err;
		}

		message->type = type;

		galv_sess_start_recv_sgmt(message, (size_t)sz, multi);
		galv_debug("session: receive message started "
		           "[id:%u type:%s multi:%s size:%zu]",
		           message->xchg,
		           galv_sess_msg_type_str(message->type),
		           galv_sess_msg_multi_str(message->recv.multi),
		           sz);

		return 0;

err:
#warning Implement dropping current message ?
		galv_ratelim_pinfo(err,
		                   "session: receive message header rejected",
		                   " [id:%u]: %s",
		                   message->xchg,
		                   estr);

		return -err;
	}
	else
		return -EAGAIN;
}

static
int
galv_sess_recv_sgmt_frag(struct galv_sess_conn * __restrict   session,
                         struct galv_sess_accept * __restrict acceptor,
                         struct galv_sess_msg * __restrict    message,
                         struct galv_buff_queue * __restrict  recvq)
{
	galv_sess_assert_conn_intern(session);
	galv_assert_intern(message->state == GALV_SESS_SGMT_PARTIAL_STAT);
	galv_assert_intern(!galv_sess_recv_sgmt_full(message));
	galv_sess_assert_accept_intern(acceptor);
	galv_sess_assert_recv_msg_intern(message);
	galv_assert_intern(message->state != GALV_SESS_SGMT_STAT_NR);
	galv_assert_intern(message->type != GALV_SESS_HEAD_TYPE_NR);
	galv_assert_intern(recvq);

	if (!galv_buff_queue_empty(recvq)) {
		struct galv_frag_list * frags = &message->recv.frags;
		struct galv_frag *      frag = !galv_frag_list_empty(frags)
		                               ? galv_frag_list_last(frags)
		                               : NULL;
		struct galv_buff *      buff = galv_buff_queue_first(recvq);
		size_t                  bytes;

		galv_assert_intern(galv_buff_busy(buff));

		if (!frag || galv_frag_full(frag)) {
			frag = galv_sess_create_frag(
				session,
				acceptor,
				galv_sess_sgmt_size(message) -
				message->recv.busy,
				buff);
			if (!frag)
				return -errno;

			galv_frag_nlist(frags, frag);
		}

		bytes = galv_frag_load(frag, buff);
		galv_assert_intern(bytes);

		galv_sess_drain_buff(session, recvq, buff, bytes);

		message->recv.busy += bytes;

		return 0;
	}
	else
		return -EAGAIN;
}

static
int
galv_sess_recv_sgmt(struct galv_sess_conn * __restrict   session,
                    struct galv_sess_accept * __restrict acceptor,
                    struct galv_sess_msg * __restrict    message)
{
	galv_sess_assert_conn_intern(session);
	galv_sess_assert_accept_intern(acceptor);
	galv_sess_assert_recv_msg_intern(message);
	galv_assert_intern(message->state != GALV_SESS_SGMT_STAT_NR);
	galv_assert_intern(message->type != GALV_SESS_HEAD_TYPE_NR);

	struct galv_buff_queue * recvq = &session->recv_buffq;
	int                      ret;

	if (message->state != GALV_SESS_SGMT_PARTIAL_STAT) {
		ret = galv_sess_recv_sgmt_head(session,
		                               acceptor,
		                               message,
		                               recvq);
		if (ret)
			return ret;
	}

	galv_assert_intern(!galv_sess_recv_sgmt_full(message));
	do {
		ret = galv_sess_recv_sgmt_frag(session,
		                               acceptor,
		                               message,
		                               recvq);
	} while (!ret && !galv_sess_recv_sgmt_full(message));

	if (ret) {
		if (ret != -EAGAIN)
			galv_pdebug(-ret,
			            "session: receive segment failed [id:%u]",
			            message->xchg);
		return ret;
	}
	
	galv_assert_intern(galv_sess_recv_sgmt_full(message));
	galv_debug("session: receive segment complete "
	           "[id:%u type:%s multi:%s size:%zu]",
	           message->xchg,
	           galv_sess_msg_type_str(message->type),
	           galv_sess_msg_multi_str(message->recv.multi),
	           galv_sess_sgmt_size(message));
	galv_sess_stop_recv_sgmt(message);

	return 0;
}

ssize_t
galv_sess_msg_pull_head(struct galv_sess_msg * __restrict message,
                        const uint8_t ** __restrict       data,
                        size_t                            size)
{
	galv_sess_assert_msg_api(message);
	galv_assert_api(data);
	galv_assert_api(size);
	galv_assert_api(size <= STROLL_BUFF_CAPACITY_MAX);

	if (message->size) {
		galv_assert_intern(!galv_frag_list_empty(&message->recv.frags));

		struct galv_frag * frag;
		size_t             bytes;

		frag = galv_frag_list_first(&message->recv.frags);
		galv_assert_intern(galv_frag_busy(frag));

		bytes = galv_frag_pull_head(frag, data, size);
		galv_assert_intern(bytes);
		galv_assert_intern(bytes <= message->size);

		if (!galv_frag_busy(frag)) {
			/*
			 * No more user data within buffer: requeue at tail end.
			 */
			galv_frag_dlist(&message->recv.frags);
			galv_frag_nlist(&message->recv.frags, frag);
		}

		message->size -= bytes;

		return (ssize_t)bytes;
	}

	return -ENODATA;
}

/******************************************************************************
 * Session connection
 ******************************************************************************/

static
int
galv_sess_recv_tail_buff(struct galv_sess_conn * __restrict         session,
                         const struct galv_sess_accept * __restrict acceptor)
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
galv_sess_recv_msg(struct galv_sess_conn * __restrict   session,
                   struct galv_sess_accept * __restrict acceptor,
                   struct galv_sess_msg * __restrict    message)
{
	galv_sess_assert_conn_intern(session);
	galv_sess_assert_accept_intern(acceptor);
	galv_sess_assert_recv_msg_intern(message);
	galv_assert_intern(!galv_buff_queue_empty(&session->recv_buffq));

	int ret;

	galv_assert_intern(!galv_sess_recv_msg_complete(message));
	do {
		ret = galv_sess_recv_sgmt(session, acceptor, message);
	} while (!ret && !galv_sess_recv_msg_complete(message));

	if (ret) {
		if (ret != -EAGAIN)
			galv_ratelim_pinfo(-ret,
			                   "session: receive message failed",
			                   " [id:%u]",
			                   message->xchg);
		return ret;
	}

	galv_assert_intern(galv_sess_recv_msg_complete(message));
	galv_debug("session: receive message complete "
	           "[id:%u type:%s multi:%s size:%zu]",
	           message->xchg,
	           galv_sess_msg_type_str(message->type),
	           galv_sess_msg_multi_str(message->recv.multi),
	           message->size);

	return 0;
}

static
int
galv_sess_recv_tail_msg(struct galv_sess_conn * __restrict   session,
                        struct galv_sess_accept * __restrict acceptor,
                        struct galv_sess_msg * __restrict    message)
{
	galv_sess_assert_conn_intern(session);
	galv_sess_assert_accept_intern(acceptor);
	galv_sess_assert_recv_msg_intern(message);
	galv_assert_intern(message->state != GALV_SESS_SGMT_STAT_NR);
	galv_assert_intern(session->recv_msg == message);

	if (!galv_buff_queue_empty(&session->recv_buffq)) {
		int ret;

		ret = galv_sess_recv_msg(session, acceptor, message);
		if (ret)
			return ret;

		galv_assert_intern(galv_sess_recv_msg_complete(message));
		galv_sess_nqueue_recv_msg(session, message);
		session->recv_msg = NULL;

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
	galv_assert_intern(!session->recv_msg);
	galv_sess_assert_accept_intern(acceptor);

	if (!galv_buff_queue_empty(&session->recv_buffq)) {
		struct galv_sess_msg * msg;
		int                    ret;

		msg = galv_sess_create_recv_msg(session, acceptor);
		if (!msg)
			return -errno;

		ret = galv_sess_recv_msg_head(session,
		                              acceptor,
		                              msg,
		                              &session->recv_buffq);
		if (ret) {
			galv_sess_destroy_recv_msg(session, acceptor, msg);
			return ret;
		}

		session->recv_msg = msg;

		return galv_sess_recv_tail_msg(session, acceptor, msg);
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

	if (session->recv_msg) {
		/* A (uncomplete) message is being received... */
		ret = galv_sess_recv_tail_msg(session,
		                              accept,
		                              session->recv_msg);
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
	galv_sess_assert_conn_intern(session);

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

#warning restrict to request/notify message type for server side ?? what about client side ?? (see msg/sgmt head parser)
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
	case -EMSGSIZE:
		/* Message segment size too large. */
	case -ENOMEM:
		/* No more memory available */
		break;

	default:
		galv_assert_intern(0);
	}

	return ret;
}

/******************************************************************************
 * Session connection emission
 ******************************************************************************/

#define galv_sess_assert_send_msg_intern(_msg) \
	galv_sess_assert_msg_intern(_msg); \
	galv_assert_intern(((_msg)->state == GALV_SESS_SGMT_STAT_NR) || \
	                   ((_msg)->send.head && (_msg)->send.buff))

static
int
galv_sess_send(struct galv_sess_conn * __restrict session)
{
	galv_sess_assert_conn_intern(session);

	unsigned int cnt = galv_buff_queue_count(&session->send_buffq);
	ssize_t      ret = 0;

	while (cnt--) {
		struct galv_buff * buff;
		size_t             size;

		buff = galv_buff_queue_first(&session->send_buffq);
		size = galv_buff_busy(buff);
		galv_assert_intern(size);

		ret = galv_conn_recv(session->conn,
		                     galv_buff_data(buff),
		                     size,
		                     MSG_NOSIGNAL | ((cnt > 0) ? MSG_MORE : 0));
		galv_assert_intern(ret);
		if (ret < 0)
			break;

		galv_buff_grow_head(buff, (size_t)ret);
		if ((size_t)ret != size) {
			ret = -EAGAIN;
			break;
		}

		galv_buff_dqueue(&session->send_buffq);
		galv_sess_release_buff(session, buff);
	}

	galv_assert_intern(ret <= 0);
	switch (ret) {
	case 0:
		/* All buffers have benn sent out. */
		break;

	case -ENOBUFS:
		/*
		 * Underlying network interface output queue full, i.e,
		 * transient congestion happende or interface has been
		 * (administratively ?) stopped.
		 */
	case -EAGAIN:
		/* Underlying socket buffer full, try again later. */
		galv_conn_watch(session->conn, EPOLLOUT);
		ret = 0;
		break;

	case -EPIPE:
		/* Remote peer consumed all of its data and closed */
	case -ECONNRESET:
		/*
		 * Remote peer (unexpectedly) closed while there were still
		 * unhandled data in its socket buffer.
		 */
	case -EINTR:
		/* Interrupted by a signal before any data was received */
	case -ENOMEM:
		/* No more memory available */
		break;

	default:
		galv_assert_intern(0);
	}

	return (int)ret;
}

static
void
galv_sess_fill_send_sgmt_head(struct galv_sess_msg * __restrict message,
                              enum galv_sess_head_multi         multi)
{
	const struct galv_sess_head head = {
		.flags = (uint8_t)((message->type <<
		                    GALV_SESS_HEAD_TYPE_FLAG_BIT) |
		                   (multi << GALV_SESS_HEAD_MULTI_FLAG_BIT)),
		.xchg  = (uint8_t)message->xchg,
		.size  = (uint16_t)(galv_sess_sgmt_size(message) - 1),
	};

	memcpy(message->send.head, &head, sizeof(head));
}

static
struct galv_buff *
galv_sess_grab_send_sgmt_buff(struct galv_sess_conn * __restrict   session,
                              struct galv_sess_accept * __restrict acceptor,
                              struct galv_sess_msg * __restrict    message)
{
	if (galv_buff_avail_tail(message->send.buff) >
	    sizeof(*message->send.head))
		return message->send.buff;

	stroll_slist_nqueue_back(&message->send.buffq,
	                         &message->send.buff->node);
	message->send.buff = galv_sess_summon_buff(session, acceptor);

	return message->send.buff;
}

/*
 * bytes: number of bytes to reserve into current segment for later filling
 *        operation
 * left: number of free bytes available to fill current segment up to its
 *       maximum allowed size.
 */
static
size_t
galv_sess_fill_send_sgmt(struct galv_sess_msg * __restrict message,
                         struct galv_buff * __restrict     buffer,
                         uint8_t ** __restrict             data,
                         size_t                            bytes,
                         size_t                            left)
{
	galv_assert_intern(galv_buff_avail_tail(buffer));

	size_t avail = galv_buff_avail_tail(buffer);

	bytes = stroll_min(bytes, stroll_min(avail, left));
	galv_assert_intern(bytes);
	galv_assert_intern(bytes <= left);

	*data = galv_buff_tail(buffer);
	galv_buff_grow_tail(buffer, bytes);

	message->size += bytes;
	if (bytes == left)
		/* Current segment is full: close it. */
		message->state = GALV_SESS_SGMT_COMPLETE_STAT;

	return bytes;
}

static
ssize_t
galv_sess_process_send_sgmt_init(struct galv_sess_conn * __restrict   session,
                                 struct galv_sess_accept * __restrict acceptor,
                                 struct galv_sess_msg * __restrict    message,
                                 uint8_t ** __restrict                data,
                                 size_t                               size)
{
	galv_assert_intern(message->state == GALV_SESS_SGMT_STAT_NR);

	struct galv_buff * buff;

	buff = galv_sess_summon_buff(session, acceptor);
	if (buff) {
		message->send.buff = buff;

		message->state = GALV_SESS_SGMT_PARTIAL_STAT;
		message->send.head = galv_buff_tail(buff);
		galv_buff_grow_tail(buff, sizeof(*message->send.head));

		return (ssize_t)
		       galv_sess_fill_send_sgmt(message,
		                                buff,
		                                data,
		                                size,
		                                GALV_SESS_SGMT_SIZE_MAX);
	}

	return -errno;
}

static
ssize_t
galv_sess_process_send_sgmt_start(struct galv_sess_conn * __restrict   session,
                                  struct galv_sess_accept * __restrict acceptor,
                                  struct galv_sess_msg * __restrict    message,
                                  uint8_t ** __restrict                data,
                                  size_t                               size)
{
	galv_assert_intern(message->state == GALV_SESS_SGMT_COMPLETE_STAT);

	struct galv_buff * buff;

	/* Fill in previous segment header. */
	galv_sess_fill_send_sgmt_head(message, GALV_SESS_HEAD_CONT_MULTI);

	buff = galv_sess_grab_send_sgmt_buff(session, acceptor, message);
	if (buff) {
		message->state = GALV_SESS_SGMT_PARTIAL_STAT;
		message->send.head = galv_buff_tail(buff);
		galv_buff_grow_tail(buff, sizeof(*message->send.head));

		return (ssize_t)
		       galv_sess_fill_send_sgmt(message,
		                                buff,
		                                data,
		                                size,
		                                GALV_SESS_SGMT_SIZE_MAX);
	}

	return -errno;

}

static
ssize_t
galv_sess_process_send_sgmt_fill(struct galv_sess_conn * __restrict   session,
                                 struct galv_sess_accept * __restrict acceptor,
                                 struct galv_sess_msg * __restrict    message,
                                 uint8_t ** __restrict                data,
                                 size_t                               size)
{
	galv_assert_intern(message->state == GALV_SESS_SGMT_PARTIAL_STAT);
	galv_assert_intern(galv_sess_sgmt_size(message) <
	                   GALV_SESS_SGMT_SIZE_MAX);

	struct galv_buff * buff;

	buff = galv_sess_grab_send_sgmt_buff(session, acceptor, message);
	if (buff)
		return (ssize_t)
		       galv_sess_fill_send_sgmt(message,
		                                buff,
		                                data,
		                                size,
		                                GALV_SESS_SGMT_SIZE_MAX -
		                                galv_sess_sgmt_size(message));

	return -errno;
}

ssize_t
galv_sess_msg_push_tail(struct galv_sess_msg * __restrict message,
                        uint8_t ** __restrict             data,
                        size_t                            size)
{
	struct galv_sess_conn *   sess = message->sess;
	struct galv_sess_accept * accept = galv_sess_conn_acceptor(sess);

	switch (message->state) {
	case GALV_SESS_SGMT_PARTIAL_STAT:
		return galv_sess_process_send_sgmt_fill(sess,
		                                        accept,
		                                        message,
		                                        data,
		                                        size);
	case GALV_SESS_SGMT_COMPLETE_STAT:
		return galv_sess_process_send_sgmt_start(sess,
		                                         accept,
		                                         message,
		                                         data,
		                                         size);
	case GALV_SESS_SGMT_STAT_NR:
		return galv_sess_process_send_sgmt_init(sess,
		                                        accept,
		                                        message,
		                                        data,
		                                        size);
	default:
		galv_assert_intern(0);
	}

	unreachable();
}

static
void
galv_sess_complete_send_msg(struct galv_sess_msg * __restrict message)
{
	galv_assert_api(message->size);
	galv_assert_api(message->send.buff);
	galv_assert_api(message->send.head);

	/* Current segment is full: close it. */
	galv_sess_fill_send_sgmt_head(message, GALV_SESS_HEAD_LAST_MULTI);

	/* Queue current buffer. */
	stroll_slist_nqueue_back(&message->send.buffq,
	                         &message->send.buff->node);

#if defined(CONFIG_GALV_ASSERT_INTERN)
	message->state = GALV_SESS_SGMT_COMPLETE_STAT;
	message->send.buff = NULL;
	message->send.head = NULL;
#endif /* defined(CONFIG_GALV_ASSERT_INTERN) */
}

static
void
galv_sess_fini_send_msg(struct galv_sess_msg * __restrict    message,
                        struct galv_sess_conn * __restrict   session,
                        struct galv_sess_accept * __restrict acceptor __unused)
{
	galv_sess_assert_msg_intern(message);
	galv_sess_assert_conn_intern(session);
	galv_assert_intern(_stroll_fbmap_test(session->xchg_map,
	                                      message->xchg));
	galv_sess_assert_accept_intern(acceptor);

	struct galv_buff *    buff = message->send.buff;
	struct stroll_slist * buffq = &message->send.buffq;

	if (buff)
		galv_buff_release(buff);

	while (!stroll_slist_empty(buffq)) {
		buff = stroll_slist_entry(stroll_slist_dqueue_front(buffq),
		                          struct galv_buff,
		                          node);
		galv_buff_release(buff);
	}
}

static
void
galv_sess_destroy_send_msg(struct galv_sess_conn * __restrict   session,
                           struct galv_sess_accept * __restrict acceptor,
                           struct galv_sess_msg * __restrict    message)
{
	galv_sess_assert_conn_intern(session);
	galv_assert_intern(session->msg_cnt);
	galv_sess_assert_accept_intern(acceptor);
	galv_sess_assert_msg_intern(message);

	unsigned int xchg = message->xchg;

	galv_sess_fini_send_msg(message, session, acceptor);
	_stroll_fbmap_clear(session->xchg_map, xchg);
	galv_sess_free_msg(session, acceptor, message, xchg);
}

static
struct galv_sess_msg *
galv_sess_create_send_msg(struct galv_sess_conn * __restrict session,
                          enum galv_sess_head_type           type,
                          int                                xchange)
{
	galv_sess_assert_conn_intern(session);
	galv_assert_intern(type >= 0);
	galv_assert_intern(type <= GALV_SESS_HEAD_TYPE_NR);
	galv_assert_intern(xchange < (int)GALV_SESS_MSG_XCHG_NR);
	galv_assert_intern((xchange < 0) ||
	                   !_stroll_fbmap_test(session->xchg_map,
	                                       (unsigned int)xchange));

	if (xchange >= 0) {
		struct galv_sess_accept * accept =
			galv_sess_conn_acceptor(session);
		struct galv_sess_msg *    msg;

		msg = galv_sess_alloc_msg(session, accept);
		if (msg) {
			/* Reserve exchange ID. */
			_stroll_fbmap_set(session->xchg_map,
			                  (unsigned int)xchange);

			/* Initialize message for sending purpose. */
			msg->size = 0;
			msg->type = type;
			msg->xchg = (unsigned int)xchange;
			msg->state = GALV_SESS_SGMT_STAT_NR;
			msg->send.buff = NULL;
			stroll_slist_init(&msg->send.buffq);
			msg->sess = session;
			msg->fini = galv_sess_fini_send_msg;
		}

		return msg;
	}

	errno = EBUSY;

	return NULL;
}

struct galv_sess_msg *
galv_sess_create_request(struct galv_sess_conn * __restrict session)
{
	galv_sess_assert_conn_api(session);

	struct galv_sess_msg * msg;
	int                    xchg = _stroll_fbmap_ffc(session->xchg_map,
	                                                GALV_SESS_MSG_XCHG_NR);

	msg = galv_sess_create_send_msg(session,
	                                GALV_SESS_HEAD_REQUEST_TYPE,
	                                xchg);
	if (msg)
		galv_debug("session: request message created [addr:%p id:%u]",
		           msg,
		           msg->xchg);

	return msg;
}

struct galv_sess_msg *
galv_sess_create_reply(struct galv_sess_conn * __restrict session,
                       unsigned int                       xchange)
{
	galv_sess_assert_conn_api(session);
	galv_assert_api(xchange < (int)GALV_SESS_MSG_XCHG_NR);

	if (!_stroll_fbmap_test(session->xchg_map, xchange)) {
		struct galv_sess_msg * msg;
		
		msg = galv_sess_create_send_msg(session,
		                                GALV_SESS_HEAD_REPLY_TYPE,
		                                (int)xchange);
		if (msg)
			galv_debug("session: reply message created "
			           "[addr:%p id:%u]",
			           msg,
			           msg->xchg);

		return msg;
	}

	errno = EBUSY;

	return NULL;
}

void
galv_sess_make_reply(struct galv_sess_msg * __restrict request)
{
	galv_sess_assert_recv_msg_api(request);

	struct galv_sess_conn *   sess = request->sess;
	struct galv_sess_accept * accept = galv_sess_conn_acceptor(sess);
	unsigned int              xchg = request->xchg;

	galv_assert_api(_stroll_fbmap_test(sess->xchg_map, xchg));
	galv_sess_fini_recv_msg(request, sess, accept);
	galv_assert_intern(request->xchg == xchg);

	/*
	 * Reuse original request message exchange ID and initialize message for
	 * (sending) reply purpose.
	 */
	request->size = 0;
	request->type = GALV_SESS_HEAD_REPLY_TYPE;
	request->state = GALV_SESS_SGMT_STAT_NR;
	request->send.buff = NULL;
	stroll_slist_init(&request->send.buffq);
	request->fini = galv_sess_fini_send_msg;

	galv_debug("session: request message recycled as reply "
	           "[addr:%p id:%u]",
	           request,
	           xchg);
}

struct galv_sess_msg *
galv_sess_create_notif(struct galv_sess_conn * __restrict session)
{
	galv_sess_assert_conn_api(session);

	struct galv_sess_msg * msg;
	int                    xchg = _stroll_fbmap_ffc(session->xchg_map,
	                                                GALV_SESS_MSG_XCHG_NR);

	msg = galv_sess_create_send_msg(session,
	                                GALV_SESS_HEAD_NOTIF_TYPE,
	                                xchg);
	if (msg)
		galv_debug("session: notification message created "
		           "[addr:%p id:%u]",
		           msg,
		           msg->xchg);

	return msg;
}

void
galv_sess_push_msg(struct galv_sess_msg * __restrict message)
{
	struct galv_sess_conn *   sess = message->sess;
	struct galv_sess_accept * accept = galv_sess_conn_acceptor(sess);

	galv_sess_complete_send_msg(message);
	galv_buff_join_queue(&sess->send_buffq, &message->send.buffq);
	galv_sess_destroy_send_msg(sess, accept, message);
}

/******************************************************************************
 * Session connection asynchronous handling
 ******************************************************************************/

#if 1
static
int
galv_sess_process_closing_conn(struct galv_sess_conn * session,
                               const struct upoll *    poller)
{
	int ret;

	ret = galv_sess_conn_acceptor(session)->ops->xfer(session);
	if (ret)
		goto apply;

	if (galv_sess_may_pull_msg(session))
		goto apply;

#warning Implement output buffer flushing while closing
	return galv_conn_close(session->conn, poller);

apply:
	galv_conn_apply_watch(session->conn, poller);

	return ret;
}
#else
static
int
galv_sess_process_closing_conn(struct galv_sess_conn * session,
                               const struct upoll *    poller)
{
	int ret;

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
	case -EMSGSIZE:
		/* Message segment size too large. */
	case -ENOMEM:
		/* No more memory available */
		finish me (if !may send goto close...)
		return galv_conn_on_recv_shut(session->conn, 0, poller);

		break;

	default:
		galv_assert_intern(0);
	}

	ret = galv_sess_conn_acceptor(session)->ops->xfer(session);
	if (ret)
		goto apply;

	if (galv_conn_may_send(session->conn)) {
		ret = galv_sess_send(session);
		galv_assert_intern(ret <= 0);
check return value !!
	}

	if (galv_sess_may_pull_msg(session))
		goto apply;

#warning Implement output buffer flushing.
	return galv_conn_close(session->conn, poller);

apply:
	galv_conn_apply_watch(session->conn, poller);

	return ret;
}
#endif

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
		case -EMSGSIZE:
			return galv_conn_on_recv_shut(session->conn,
			                              events,
			                              poller);

		case -EINTR:
		case -ENOMEM:
			goto apply;

		default:
			galv_ratelim_pnotice(
				-ret,
				"session: unexpected receive failure",
				"");
		}
	}

	ret = galv_sess_conn_acceptor(session)->ops->xfer(session);
	if (ret) {
		galv_pdebug(-ret, "session: transfer handler failed");
		goto apply;
	}

	/* Output as many buffers as we can... */
	ret = galv_sess_send(session);
	galv_assert_intern(ret <= 0);
	switch (ret) {
	case 0:
		break;

	case -EPIPE:
	case -ECONNRESET:
		return galv_conn_on_send_shut(session->conn, events, poller);

	case -EINTR:
	case -ENOMEM:
		break;

	default:
		galv_ratelim_pnotice(
			-ret,
			"session: unexpected emit failure",
			"");
	}

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
	struct galv_sess_conn * sess = galv_sess_from_conn(connection);

	galv_debug("session: connection emit end shut down: closing..");

	galv_conn_switch_state(connection, GALV_CONN_CLOSING_STATE);

	return galv_sess_process_closing_conn(sess, poller);
}

static
int
galv_sess_on_recv_shut(struct galv_conn *   connection,
                       uint32_t             events __unused,
                       const struct upoll * poller)
{
	struct galv_sess_conn * sess = galv_sess_from_conn(connection);

	galv_debug("session: connection receive end shut down: flushing..");

	galv_conn_switch_state(connection, GALV_CONN_CLOSING_STATE);

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
	config->max_pload = stroll_align_upper(max_pload,
	                                       __WORDSIZE / CHAR_BIT);
	config->buff_capa = stroll_align_upper(buff_capa,
	                                       __WORDSIZE / CHAR_BIT);
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
	acceptor->max_pload = config->max_pload;
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
	stroll_falloc_init_per_block(
		&acceptor->buff_alloc,
		(unsigned int)max_buff,
		sizeof(struct galv_buff) + config->buff_capa,
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
