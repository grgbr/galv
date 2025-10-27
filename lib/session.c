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

/******************************************************************************
 * Session protocol message and header
 ******************************************************************************/

enum galv_sess_msg_type {
	GALV_SESS_MSG_REQUEST_TYPE = 0,
	GALV_SESS_MSG_REPLY_TYPE   = 1,
	GALV_SESS_MSG_NOTIF_TYPE   = 2,
	GALV_SESS_MSG_TYPE_NR
};

struct galv_sess_msg_head {
	uint8_t  resv; /* Reserved for future use. */
	uint8_t  type; /* Type of exchange */
	uint16_t xchg; /* eXCHGange identification number */
	uint32_t size; /* Message size including this header */
	char     data[0];
} __packed;

static
enum galv_sess_msg_type
galv_sess_msg_head_type(const struct galv_sess_msg_head * __restrict head)
{
	galv_assert_intern(head);

	return (enum galv_sess_msg_type)head->type;
}

static
uint16_t
galv_sess_msg_head_xchg(const struct galv_sess_msg_head * __restrict head)
{
	galv_assert_intern(head);
	galv_assert_intern(stroll_aligned((size_t)&head->xchg,
	                                  sizeof(head->xchg)));

#warning FIXME: do not convert from network byte order if unix socket !
	return be16toh(head->xchg);
}

static
uint32_t
galv_sess_msg_head_size(const struct galv_sess_msg_head * __restrict head)
{
	galv_assert_intern(head);
	galv_assert_intern(stroll_aligned((size_t)&head->size,
	                                  sizeof(head->size)));

#warning FIXME: do not convert from network byte order if unix socket !
	return be32toh(head->size);
}

/******************************************************************************
 * Session connection
 ******************************************************************************/

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
	vecs[1].iov_base = galv_buff_data(nevv);
	vecs[1].iov_len = galv_buff_capacity(nevv);

	ret = galv_conn_recvmsg(session->conn, &mhdr, 0);
	galv_assert_intern(ret);
	if (ret > (ssize_t)tail_size) {
		size_t size = tail_size + galv_buff_capacity(nevv);

		galv_buff_grow_tail(tail_buff, tail_size);
		galv_buff_grow_tail(nevv, (size_t)ret - tail_size);
		galv_buff_nqueue(&session->recv_buffq, nevv);

		ret = ((size_t)ret != size) ? -EAGAIN : 0;
	}
	else if (ret > 0) {
		galv_buff_grow_tail(tail_buff, (size_t)ret);
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
	ret = galv_conn_recv(session->conn, galv_buff_data(buff), size, 0);
	galv_assert_intern(ret);
	if (ret > 0) {
		galv_buff_grow_tail(buff, (size_t)ret);
		galv_buff_nqueue(&session->recv_buffq, buff);

		ret = ((size_t)ret != size) ? -EAGAIN : 0;
	}

	galv_buff_release(buff);

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

		buff = galv_buff_peek_queue_tail(&session->recv_buffq);
		size = galv_buff_avail_tail(buff);
		if (size)
			return galv_sess_recv_tail_buff(session, buff, size);
	}

	return galv_sess_recv_new_buff(session);
}

int
galv_sess_init(struct galv_sess * __restrict session,
               struct galv_conn * __restrict conn,
               unsigned int                  buff_nr,
               size_t                        buff_capa)
{
#define GALV_SESS_BUFF_NR_MIN (2U)
#define GALV_SESS_BUFF_NR_MAX (1024U)
	galv_assert_api(session);
	galv_assert_api(conn);
	galv_assert_api(buff_nr >= GALV_SESS_BUFF_NR_MIN);
	galv_assert_api(buff_nr <= GALV_SESS_BUFF_NR_MAX);

	int err;

	err = galv_buff_init_fabric(&session->buff_fab, buff_nr, buff_capa);
	if (err)
		return err;

	session->conn = conn;
	galv_buff_init_queue(&session->recv_buffq);

	return 0;
}

void
galv_sess_fini(struct galv_sess * __restrict session)
{
	galv_sess_assert_api(session);

	while (!galv_buff_queue_empty(&session->recv_buffq))
		galv_buff_release(galv_buff_dqueue(&session->recv_buffq));
	galv_buff_fini_queue(&session->recv_buffq);

	galv_buff_fini_fabric(&session->buff_fab);
}

#if 0
static
struct galv_buff *
galv_sess_create_buff(struct galv_sess * __restrict sess)
{
	return galv_buff_create(&sess->buff_fab);
}

static
struct galv_buff *
galv_sess_release_buff(struct galv_sess * __restrict sess)
{

}

static
struct galv_sess_msg *
galv_sess_create_msg(struct galv_sess * __restrict sess)
{

}

static
struct galv_sess_msg *
galv_sess_destroy_msg(struct galv_sess * __restrict sess)
{

}

static
void
galv_sess_init(struct galv_sess * __restrict sess)
{

}

static
void
galv_sess_fini(struct galv_sess * __restrict sess)
{

}

/******************************************************************************
 * Session protocol message and header
 ******************************************************************************/

enum galv_sess_sgmt_type {
	GALV_SESS_MSG_REQUEST_TYPE = 0,
	GALV_SESS_MSG_REPLY_TYPE   = 1,
	GALV_SESS_MSG_NOTIF_TYPE   = 2,
	GALV_SESS_MSG_TYPE_NR
};

struct galv_sess_msg_head {
	uint8_t  resv;
	uint8_t  type;
	uint16_t xchg; /* eXCHGange identification number */
	uint32_t size; /* Message size including this header */
	char     data[0];
} __packed;

static inline
enum galv_sess_msg_type
galv_sess_msg_head_type(const struct galv_sess_msg_head * __restrict head)
{
	galv_assert_intern(head);

	return (enum galv_sess_msg_head)head->type;
}

static inline
uint16_t
galv_sess_msg_head_xchg(const struct galv_sess_msg_head * __restrict head)
{
	galv_assert_intern(head);
	galv_assert_intern(stroll_aligned((size_t)&head->xchg,
	                                  sizeof(head->xchg)));

#warning FIXME: do not convert from network byte order if unix socket !
	return be16toh(head->xchg);
}

static inline
uint16_t
galv_sess_msg_head_size(const struct galv_sess_msg_head * __restrict head)
{
	galv_assert_intern(head);
	galv_assert_intern(stroll_aligned((size_t)&head->size,
	                                  sizeof(head->size)));

#warning FIXME: do not convert from network byte order if unix socket !
	return be32toh(head->size);
}

struct galv_sess_msg {
	enum galv_sess_sgmt_type  type;
	unsigned int              xchg;
	size_t                    busy;
	size_t                    size;
};

static
bool
galv_sess_sgmt_complete(const struct galv_sess_sgmt * __restrict segment)
{
	return (segment->multi == GALV_SESS_SGMT_LAST_MULTI) &&
	       (segment->busy == segment->size);
}

static
int
galv_sess_load_sgmt(const struct galv_sess_sgmt * __restrict segment,
                    struct stroll_slist * __restrict         fragments,
                    struct stroll_buff * __restrict          buffer,
                    struct galv_mem * __restrict             mem)
{
	if (galv_sess_sgmt_complete(segment)) {
	}
	else {
		struct galv_sess_frag * frag;
		size_t                  size;

		if (!stroll_slist_empty(fragments)) {
			frag = stroll_slist_last_entry(fragments,
			                               struct galv_sess_frag,
			                               node);
			if (!galv_sess_frag_complete(frag)) {
				segment->busy += galv_sess_load_frag(...);
				return ...;
			}

			CHECK WHAT TO DO IF FRAGMENT IS FULL.
		}


		size = stroll_min(stroll_buff_capacity(buffer) -
		                  stroll_buff_avail_head(buffer),
		                  segment->size);
		if (!size)
			return -EAGAIN;

		frag = galv_sess_alloc_frag();
		if (!frag)
			return -errno;

		segment->busy += galv_sess_init_frag(frag, buff, mem, size);

		galv_sess_nqueue_frag(frag, fragments);

		return 0;
	}
}

/*
 * Parse and setup the FIRST segment of a message.
 */
static
int
galv_sess_setup_sgmt(struct galv_sess_sgmt * __restrict segment,
                     struct stroll_buff * __restrict    buffer,
                     struct galv_mem * __restrict       mem)
{
	struct galv_sess_sgmt_head head;

	if (stroll_buff_busy(buffer) < sizeof(head))
		return -EAGAIN;

	/* Perform a copy since network data may be unaligned... */
	memcpy(&head,
	       stroll_buff_data(buffer, galv_mem_data(mem)),
	       sizeof(head));

	/* Ensure the type of segment is valid. */
	segment->type = galv_sess_sgmt_head_type(&head);
	galv_assert_intern(segment->type >= 0);
	if (segment->type >= GALV_SESS_SGMT_TYPE_NR)
		return -EPROTO;

	/*
	 * Retrieve segment size and make sure it is not larger than our maximum
	 * buffer capacity.
	 */
	segment->size = (size_t)galv_sess_sgmt_head_size(&head);
	if ((segment->size <= sizeof(head)) ||
	    (segment->size > stroll_buff_capacity(buffer)))
		return -EMSGSIZE;

	/* Is this segment part of a multipart message. */
	segment->multi = galv_sess_sgmt_head_multi(&head);

	/* Record exchange identifier for the current message. */
	segment->xchg = (unsigned int)galv_sess_sgmt_head_xchg(&head);

	/* No segment content bytes has been consummed yet. */
	segment->busy = 0;

	/* Exclude header from segment. */
	segment->size -= sizeof(head);

	stroll_buff_grow_head(buffer, sizeof(head));

	return 0;
}

/******************************************************************************
 * A contiguous data subportion of a session message.
 ******************************************************************************/

/*
 * Contiguous within the network byte stream !
 * Stored in a contiguous memory block !
 * References one SINGLE protocol buffer.
 * Is referenced by a SINGLE protocol buffer.
 * May be chained to form a single consistent session message.
 */
struct galv_sess_parcel {
	struct stroll_buff        base;
	struct galv_sess_parcel * next;
	struct galv_mem *         mem;
};

#define galv_sess_assert_parcel(_prcl) \
	galv_assert_intern(_prcl); \
	galv_assert_intern(stroll_buff_capacity(&(_prcl)->base)); \
	galv_assert_intern(!(_prcl)->next || (_prcl)->mem); \
	galv_assert_intern(parcel->mem || !stroll_buff_busy(&parcel->base)); \
	galv_assert_intern(parcel->mem || \
	                   !stroll_buff_avail_head(&parcel->base));

static
size_t
galv_sess_parcel_busy(const struct galv_sess_parcel * __restrict parcel)
{
	galv_sess_assert_parcel(parcel);

	return stroll_buff_busy(&parcel->base);
}

static
bool
galv_sess_parcel_full(const struct galv_sess_parcel * __restrict parcel)
{
	galv_sess_assert_parcel(parcel);

	return !stroll_buff_avail_tail(&parcel->base);
}

static
size_t
galv_sess_load_parcel(struct galv_sess_parcel * __restrict parcel,
                      struct stroll_buff * __restrict      buff,
                      struct galv_mem * __restrict         mem)
{
	galv_sess_assert_parcel(parcel);
	galv_assert_intern(!parcel->next);
	galv_assert_intern(buff);
	galv_assert_intern(stroll_buff_avail_tail(&parcel->base));
	galv_assert_intern(stroll_buff_capacity(buff));
	galv_assert_intern(stroll_buff_capacity(&parcel->base) <=
	                   stroll_buff_capacity(buff));
	galv_assert_intern(stroll_buff_busy(buff));
	galv_assert_intern(mem);
	galv_assert_intern(!parcel->mem || parcel->mem == mem);

	size_t bytes;

	bytes = stroll_min(stroll_buff_busy(buff),
	                   stroll_buff_avail_tail(&parcel->base));

	/* Assign bytes to this parcel. */
	stroll_buff_grow_tail(&parcel->base, bytes);
	/* Tell `buff' that we consummed bytes assigned to this parcel. */
	stroll_buff_grow_head(buff, bytes);

	if (!parcel->mem)
		parcel->mem = galv_mem_acquire(mem);

	return bytes;
}

/*
 * Initialize a parcel.
 *
 * @param[out] parcel Parcel to initialize
 * @param[in]  buff   State of @p mem block data production / consumption
 * @param[in]  mem    Underlying memory block holding network data
 * @param[in]  size   Maximum size of this parcel
 */
static
size_t
galv_sess_init_parcel(struct galv_sess_parcel * __restrict  parcel,
                      const struct stroll_buff * __restrict buff,
                      struct galv_mem * __restrict          mem,
                      size_t                                size)
{
	galv_assert_intern(parcel);
	galv_assert_intern(buff);
	galv_assert_intern(mem);
	galv_assert_intern(size);
	galv_assert_intern(size <= stroll_buff_capacity(buff));

	size_t off = stroll_buff_avail_head(buff);
	size_t bytes = 0;

	size = stroll_min(size, stroll_buff_capacity(buff) - off);
	if (size) {
		/*
		 * There are network bytes sitting into `buff' that must be
		 * assigned to this parcel.
		 * Detect how many of them can be assigned to this parcel, set
		 * it up with them and tell `buff' that we consummed them.
		 */
		bytes = stroll_min(stroll_buff_busy(buff),
		                   stroll_buff_avail_tail(&parcel->base));
		stroll_buff_setup(&parcel->base, off + size, off, bytes);
		stroll_buff_grow_head(buff, bytes);

		parcel->mem = galv_mem_acquire(mem);
	}
	else {
		/*
		 * `buff' does contain no more usable bytes. Setup an empty
		 * parcel so that next buffer given to galv_sess_load_parcel()
		 * may be used to fillup this parcel.
		 */
		stroll_buff_setup(&parcel->base, size, 0, 0);

		parcel->mem = NULL;
	}

	parcel->next = NULL;

	return 0;
}

static
void
galv_sess_fini_parcel(struct galv_sess_parcel * __restrict parcel,
                      struct stroll_lalloc * __restrict    alloc)
{
	galv_sess_assert_parcel(parcel);
	galv_assert_intern(alloc);

	if (parcel->mem)
		galv_mem_release(parcel->mem, alloc);
}

#if 0
/******************************************************************************
 * A session message composed of one single or more parcels.
 ******************************************************************************/

struct galv_sess_msg {
	enum galv_sess_msg_multi  multi;
	enum galv_sess_msg_type   type;
	unsigned int              xchg;
	size_t                    busy;
	/* Size of message excluding protocol header(s). */
	size_t                    size;
	struct galv_sess_parcel   first;
	/*
	 * Last element of parcel chain.
	 * When lacking buffer memory capacity, `last' may be NULL, i.e., when
	 * the protocol header is not followed by parcel data bytes for the
	 * current buffer.
	 */
	struct galv_sess_parcel * last;
};

#define galv_sess_assert_msg(_msg) \
	galv_assert_intern(_msg); \
	galv_assert_intern((_msg)->type >= 0); \
	galv_assert_intern((_msg)->type < GALV_SESS_MSG_TYPE_NR); \
	galv_assert_intern((_msg)->multi >= 0); \
	galv_assert_intern((_msg)->multi < GALV_SESS_MSG_MULTI_NR); \
	galv_assert_intern((_msg)->size); \
	galv_assert_intern((_msg)->busy <= (_msg)->size); \
	galv_assert_intern(!(_msg)->last || (_msg)->busy); \
	galv_assert_intern(!(_msg)->last || !(_msg)->last->next)

static
enum galv_sess_msg_type
galv_sess_msg_type(const struct galv_sess_msg * __restrict msg)
{
	galv_sess_assert_msg(msg);

	return msg->type;
}

static
unsigned int
galv_sess_msg_xchange(const struct galv_sess_msg * __restrict msg)
{
	galv_sess_assert_msg(msg);

	return msg->xchg;
}

static
size_t
galv_sess_msg_size(const struct galv_sess_msg * __restrict msg)
{
	galv_sess_assert_msg(msg);

	return msg->size;
}

static
size_t
galv_sess_msg_busy(const struct galv_sess_msg * __restrict msg)
{
	galv_sess_assert_msg(msg);

	return msg->busy;
}

static
bool
galv_sess_msg_full(const struct galv_sess_msg * __restrict msg)
{
	galv_sess_assert_msg(msg);

	return ((msg->multi == GALV_SESS_MSG_LAST_MULTI) &&
	        (msg->busy == msg->size));
}

static
int
galv_sess_msg_load(struct galv_sess_msg * __restrict msg,
                   struct stroll_buff * __restrict   buff,
                   struct galv_mem * __restrict      mem,
                   struct stroll_palloc * __restrict alloc)
{
	galv_sess_assert_msg(msg);
	galv_assert_intern(!galv_sess_msg_full(msg));
	galv_assert_intern(stroll_buff_busy(buff));

	if (!msg->last) { /* TODO: stroll_unlikely() ?? */
		/*
		 * Last call to galv_sess_msg_init() could not initialize first
		 * parcel since the protocol header was located at the very end
		 * of its network data buffer.
		 * Current buffer, i.e., current `buff' / `mem' combination,
		 * is expected to hold the network parcel data: initialize first
		 * parcel with them.
		 */
		galv_assert_intern(!stroll_buff_avail_head(buff));
		galv_assert_intern(msg->size <= stroll_buff_capacity(buff));

		msg->busy = galv_sess_init_parcel(&msg->first,
		                                  buff,
		                                  mem,
		                                  msg->size);
		msg->last = &msg->first;
	}
	else if (!galv_sess_parcel_full(msg->last)) {
		/* Current (last) parcel is not complete: keep loading it. */
		msg->busy += galv_sess_load_parcel(msg->last, buff);
		galv_assert_intern(msg->busy <= msg->size);
	}

	/*
	 * Try to keep loading message data till completion of current message.
	 */
	while (!galv_sess_msg_full(msg)) {
		IS PARCELL FULL ?? IS THIS A NEW NET PARCEL ALL THE TIME ???

		galv_assert_intern(galv_sess_parcel_full(msg->last));
		galv_assert_intern(msg->multi != GALV_SESS_MSG_LAST_MULTI);

		struct galv_sess_msg_head head;
		enum galv_sess_msg_type   type;
		unsigned int              xchg;
		size_t                    size;

		if (stroll_buff_busy(buff) < sizeof(head))
			return -EAGAIN;

		/* Perform a copy since network data may be unaligned... */
		memcpy(&head,
		       stroll_buff_data(buff, galv_mem_data(mem)),
		       sizeof(head));
		stroll_buff_grow_head(buff, sizeof(head));

		type = galv_sess_msg_head_type(&head);
		if (type != msg->type)
			return -EPROTO;

		xchg = (unsigned int)galv_sess_msg_head_xchgno(&head);
		if (xchg != msg->xchg)
			return -EPROTO;

		msg->multi = galv_sess_msg_head_multi(&head);

		size = (size_t)galv_sess_msg_head_prclsz(&head);
		size -= sizeof(head);
		msg->size += size;

		/*
		 * Compute maximum size of parcel that can fit into current
		 * buffer.
		 */
		size = stroll_min(size,
		                  stroll_buff_capacity(buff) -
		                  stroll_buff_avail_head(buff));
		if (size) {
			struct galv_sess_parcel * prcl;

			/*
			 * Create new parcel and assign to it as many bytes
			 * as the current buffer contains.
			 */
			prcl = stroll_palloc_alloc(alloc);
			if (!prcl)
				return -errno;

			msg->busy += galv_sess_init_parcel(prcl,
			                                   buff,
			                                   mem,
			                                   size);
			msg->last = prcl;
		}
		else
			return -EAGAIN;
	}

	return 0;
}

static
int
galv_sess_msg_init(struct galv_sess_msg * __restrict msg,
                   struct stroll_buff * __restrict   buff,
                   struct galv_mem * __restrict      mem)
{
	galv_assert_intern(msg);
	galv_assert_intern(buff);
	galv_assert_intern(stroll_buff_busy(buff));
	galv_assert_intern(mem);

	struct galv_sess_msg_head head;
	size_t                    sz;

	if (stroll_buff_busy(buff) < sizeof(head))
		return -EAGAIN;

	/* Perform a copy since network data may be unaligned... */
	memcpy(&head,
	       stroll_buff_data(buff, galv_mem_data(mem)),
	       sizeof(head));

	msg->multi = galv_sess_msg_head_multi(&head);

	msg->type = galv_sess_msg_head_type(&head);
	galv_assert_intern(msg->type >= 0);
	if (msg->type >= GALV_SESS_MSG_TYPE_NR)
		return -EPROTO;

	/*
	 * Retrieve first parcel size and make sure it is not larger than our
	 * maximum buffer capacity.
	 */
	msg->size = (size_t)galv_sess_msg_head_prclsz(&head);
	if ((msg->size <= sizeof(head)) ||
	    (msg->size > stroll_buff_capacity(buff)))
		return -EMSGSIZE;

	/* Exclude header from message. */
	msg->size -= sizeof(head);
	stroll_buff_grow_head(buff, sizeof(head));

	/* Extract message exchange identifier. */
	msg->xchg = (unsigned int)galv_sess_msg_head_xchgno(&head);

	/* Compute maximum size of parcel that can fit into current buffer. */
	sz = stroll_min(msg->size,
	                stroll_buff_capacity(buff) -
	                stroll_buff_avail_head(buff));
	if (sz) {
		/*
		 * Assign to first parcel as many as bytes as may fit into the
		 * current buffer.
		 */
		msg->busy = galv_sess_init_parcel(&msg->first, buff, mem, sz);
		msg->last = &msg->first;

		return 0;
	}

	/*
	 * According to `buff', header is located at the very end of the `mem'
	 * area, i.e., subsequent data will be located into next buffer.
	 * Differ parcel initialization to next call to galv_sess_msg_load(),
	 * i.e., when network data buffer is received.
	 */
	msg->busy = 0;
	msg->last = NULL;

	return 0;
}
#endif

#if 0
galv_sess_msg_fini()
#endif




















#if 0

ssize_t
galv_proto_prep_parcel(parcel, buffer, head, size)
{
	galv_assert_intern(galv_proto_buffer_capa(fabric) <
	                   GALV_PROTO_MSG_SIZE_MAX);

	enum galv_proto_multi multi;
	enum galv_proto_type  type;
	size_t                prclsz;
	unsigned int          xchgno;

	if (size < sizeof(*head))
		return -EAGAIN;

	if (head->flags & ~GALV_PROTO_VALID_FLAG_MASK)
		return -EPROTO;

	multi = galv_proto_head_multi(head);
	galv_assert_intern(multi >= 0);
	galv_assert_intern(multi < GALV_PROTO_MULTI_NR);
	if ((multi != GALV_PROTO_NONE_MULTI) &&
	    (multi != GALV_PROTO_START_MULTI))
		return -EPROTO;

	type = galv_proto_head_multi(head);
	galv_assert_intern(type >= 0);
	if (type >= GALV_PROTO_TYPE_NR)
		return -EPROTO;

	prclsz = galv_proto_head_prclsz(head);
	if ((prclsz <= sizeof(*head)) ||
	    (prclsz > galv_proto_buffer_capa(fabric)))
		return -EMSGSIZE;

	xchgno = galv_proto_head_xchgno(head);
	galv_assert_intern(xchgno <  GALV_PROTO_XCHG_MAX)

	msg = galv_proto_conn_find_msg(conn, xchgno);
	if (msg) {
		if (galv_proto_msg_type(msg) != type)
			/* TODO: return an error code to remote peer. */
			return -EPROTO;

		if ((galv_proto_msg_busy(msg) + prclsz) >
		    GALV_PROTO_MSG_SIZE_MAX)
			return -EMSGSIZE;
	}
	else {
		msg = galv_proto_conn_create_msg(conn, type, xchgno);
		if (!msg)
			return -errno;
	}

	if (prclsz > galv_proto_buffer_avail(buffer)) {
		buffer = galv_proto_conn_create_buffer(conn);
		if (!buffer)
			return -errno;

		parcel->start = 0;
		parcel->buff = buffer;
	}
	else {
		parcel->start = galv_proto_buffer_busy(buffer);
		parcel->buff = galv_proto_acquire_buffer(buffer);
	}

	parcel->busy = stroll_min(size, prclsz);
	parcel->size = prclsz;
	galv_proto_buffer_resv(buffer, parcel->busy);
	galv_proto_msg_register_parcel(msg, parcel);

	/* Return the number of bytes consummed by the actual parcel. */
	return parcel->busy;
}

ssize_t
galv_proto_load_parcel(parcel, size)
{
	galv_assert_intern(parcel->buff);
	galv_assert_intern(parcel->busy);
	galv_assert_intern(parcel->size);
	galv_assert_intern(parcel->busy < parcel->size);
	galv_assert_intern((parcel->start + parcel->busy) <
	                   galv_proto_buffer_capa(parcel->buff));

	if (!size)
		return -EAGAIN;

	size = stroll_min(size, galv_proto_parcel_avail(parcel));

	galv_proto_buffer_push(parcel->buff, size);
	galv_proto_parcel_push(parcel, size);
	galv_proto_msg_push(msg, size);

	return size;
}

/*
 * A protocol message composed of one single or more parcels.
 */
struct galv_proto_message {
	enum galv_proto_type type;
	unsigned int         xchange;
	size_t               busy;
	struct stroll_slist  parcels;
};

#define GALV_PROTO_BUFF_SIZE_MAX
#define GALV_PROTO_MSG_SIZE_MAX
#if GALV_PROTO_BUFF_SIZE_MAX > GALV_PROTO_MSG_SIZE_MAX
#error Maximum protocol buffer size not consistent with maximum message size !
#endif /* GALV_PROTO_BUFF_SIZE_MAX > GALV_PROTO_MSG_SIZE_MAX */


galv_proto_create_msg(fabric, buffer, head, size)
{
	galv_assert_intern(size >= sizeof(*head));
	galv_assert_intern(size <= galv_proto_fabric_buffer_capa(fabric));




	msg = galv_proto_alloc_msg(fabric);
	prcl = galv_proto_fabric_parcel(fabric, buffer, msg);
}

galv_proto_fillin_msg()
galv_proto_bundle_msg()

int
galv_proto_recv(conn, buffer)
{
	galv_proto_assert_buffer_intern(buffer);
	galv_assert_intern(galv_proto_buffer_avail(buffer));

	size_t  bytes = galv_proto_buffer_avail_space(buffer));
	ssize_t ret;

	ret = galv_proto_conn_recv(conn,
	                           galv_proto_buffer_avail_data(buffer),
	                           size);
	galv_assert_intern(ret);
	if (ret < 0)
		return ret;

	galv_proto_buff_drain_avail(buffer, size);

	return 0;
}

galv_proto_parse_new_msg()

int
galv_proto_recv_msg(struct galv_proto_buffer * __restrict  buffer)
{
	galv_assert_intern(msg);

	const struct galv_proto_head * head = buff->data;
	enum galv_proto_multi          multi;

	if (buff->busy < sizeof(*head))
		return -EAGAIN;

	if (head->flags & ~GALV_PROTO_VALID_FLAG_MASK)
		return -EPROTO;

	/* FIXME: do not convert from network byte order if unix socket. */
	prclsz = (size_t)(ntohs(head->prclsz));
	if (!prclsz || (prclsz > GALV_PROTO_PARCEL_SIZE_MAX))
		return -EMSGSIZE;

	multi = galv_proto_multi_flag(head);
	if (multi == GALV_PROTO_START_MULTI) {
		const struct galv_proto_multi_head * mhead =
			(const struct galv_proto_multi_head *)head;

		if (size < sizeof(*mhead))
			return -EAGAIN;

		msgsz = (size_t)(ntohl(mhead->msgsz));
		if (!msgsz ||
		    (msgsz > GALV_PROTO_MSG_SIZE_MAX) ||
		    (msgsz < prclsz))
			return -EMSGSIZE;
	}
	else
		msgsz = prclsz;

	parse->multi = multi;
	parse->type = galv_proto_type_flag(head);
	parse->msgsz = msgsz;
	parse->xchgno = head->xchgno;

	return prclsz;
}

/******************************************************************************
 ******************************************************************************
 ******************************************************************************/

struct galv_buffer {
	struct stroll_buffer     base;
	struct stroll_slist_node queue;
	char                     data[0];
};

static
int
galv_sess_conn_recv(struct galv_sess_conn * __restrict sconn)
{
	struct galv_buffer * buff;
	size_t               size;
	ssize_t              bytes;

	if (!stroll_slist_empty(&sconn->recv_queue)) {
		buff = stroll_slist_last_entry(&sconn->recv_queue,
		                               struct galv_buffer,
		                               queue);
		size = stroll_buffer_avail_tail(&buff->base);
		galv_assert_intern(size >= ...);

		bytes = galv_conn_recv(&sconn->base,
		                       stroll_buffer_tail_data(&buff->base),
		                       size,
		                       0);
		galv_assert_intern(bytes);
		if (bytes < 0)
			return bytes;

		stroll_buffer_push_tail(&buff->base, bytes);
	}
	else {
		buff = stroll_balloc_alloc(&sconn->buff_alloc);
		if (buff)
			return -errno;

		size = stroll_balloc_chunk_size(&sconn->buff_alloc);
		stroll_buffer_init_empty(&buff->base, size);

		bytes = galv_conn_recv(&sconn->base,
		                       stroll_buffer_tail_data(&buff->base),
		                       size,
		                       0);
		galv_assert_intern(bytes);
		if (bytes < 0) {
			stroll_balloc_free(&sconn->buff_alloc, buff);
			return bytes;
		}

		stroll_buffer_push_tail(&buff->base, bytes);
		stroll_slist_nqueue_back(&sconn->recv_queue, &buff->queue);
	}

	return 0;
}

/******************************************************************************
 ******************************************************************************
 ******************************************************************************/

/*
 *  A session context object.
 */
struct galv_sess {
	struct stroll_palloc prcl_alloc;
	struct stroll_palloc msg_alloc;
};

struct galv_sess_msg *
galv_sess_alloc_msg(struct galv_sess * __restrict sess);

/*
 *  A session connection over underlying transpost connection.
 */
struct galv_sess_conn {
	struct galv_conn *     conn;
	struct galv_sess *     sess;
	struct galv_sess_msg * msg;
	struct stroll_slist    recv_queue;
};

static
int
galv_sess_conn_complete_msg(struct galv_sess_conn * __restrict sconn,
                            struct galv_sess_msg * __restrict  msg)
{
	struct galv_sess_parcel * prcl;

	prcl = galv_sess_msg_pending_parcel(msg);
	if (prcl) {
		ret = galv_sess_parcel_complete(prcl, msg, sconn);
		if (ret)
			return ret;
	}

	do {
		prcl = galv_sess_alloc_parcel(sconn->sess);
		if (!prcl)
			return -errno;

		ret = galv_sess_parcel_fetch(prcl, msg, sconn);
	} while (!ret);

	if (ret) {
		/*FIXME: do not free if parcel partially complete. */
		prcl = galv_sess_free_parcel(sconn->sess, prcl);
		return ret;
	}

	return 0;
}

static
int
galv_sess_conn_fetch(struct galv_sess_conn * __restrict sconn)
{
	int ret;

	if (sconn->msg) {
		ret = galv_sess_conn_complete_msg(sconn, sconn->msg);
		if (ret)
			return ret;
	}

	do {
		struct galv_sess_msg * msg;

		msg = galv_sess_alloc_msg(sconn->sess);
		if (!msg)
			return -errno;

		ret = galv_sess_conn_fetch_msg(sconn, msg);
	} while (!ret);

	if (ret) {
		/*FIXME: do not free if msg partially complete. */
		galv_sess_free_msg(msg);
		return ret;
	}

	return 0;
}

static
int
galv_sess_conn_on_may_xfer(struct galv_conn * __restrict   conn,
                           uint32_t                        events,
                           const struct upoll * __restrict poller)
{
	struct galv_sess_conn * sconn = galv_sess_conn_from_galv(conn);
	int                     ret;

	if (events & EPOLLIN) {
		ret = galv_sess_conn_fetch(sconn);
		switch (ret) {
		case 0:
			/* TODO: invoke user callback with pointer to messages. */
			break;

		case -EAGAIN:
			galv_conn_watch(&conn->base, EPOLLIN);
			ret = 0;
			/* TODO: invoke user callback with pointer to messages. ? */
			break;

		case -ECONNREFUSED:
			ret = galv_sess_conn_on_recv_closed(conn,
			                                    events,
			                                    poller);
			break;

		case -EINTR:
		case -ENOMEM:
			break;

		default:
			/* Unexpected receive failure */
			ret = 0;
		}
	}

	return ret;
}
#endif
#endif
