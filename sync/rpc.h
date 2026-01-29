#ifndef _GALV_SYNC_RPC_H
#define _GALV_SYNC_RPC_H

#include <galv/session.h>

struct galv_rpc_clnt;
struct galv_rpc_clnt_msg;

typedef int galv_rpc_clnt_fn(struct galv_rpc_clnt_msg *,
                             int,
                             void *);

struct galv_rpc_clnt_msg {
	struct galv_rpc_clnt *   clnt;
	struct dpack_encoder     enc;
	struct dpack_decoder     dec;
	enum galv_sess_head_type type;
	uint32_t                 id;
	galv_rpc_clnt_fn *       hndl;
	void *                   ctx;
	size_t                   off;
	size_t                   busy;
	char                     buff[64U * 1024U];
};

static inline
struct dpack_encoder *
galv_rpc_clnt_msg_encoder(const struct galv_rpc_clnt_msg * __restrict message)
{
STROLL_IGNORE_WARN("-Wcast-qual")
	return (struct dpack_encoder *)&message->enc;
STROLL_RESTORE_WARN
}

static inline
struct dpack_decoder *
galv_rpc_clnt_msg_decoder(const struct galv_rpc_clnt_msg * __restrict message)
{
STROLL_IGNORE_WARN("-Wcast-qual")
	return (struct dpack_decoder *)&message->dec;
STROLL_RESTORE_WARN
}

static inline
enum galv_sess_head_type
galv_rpc_clnt_msg_type(const struct galv_rpc_clnt_msg * __restrict message)
{
	return message->type;
}

static inline
size_t
galv_rpc_clnt_msg_size(const struct galv_rpc_clnt_msg * __restrict message)
{
	return message->busy;
}

static inline
void *
galv_rpc_clnt_msg_context(const struct galv_rpc_clnt_msg * __restrict message)
{
	return message->ctx;
}

struct galv_rpc_clnt {
	int                        sk;
	struct galv_rpc_clnt_msg * msg;
};

extern struct galv_rpc_clnt_msg *
galv_rpc_clnt_create_request(struct galv_rpc_clnt_conn * __restrict rpc,
                             uint32_t                               id,
	                     galv_rpc_fn *                          handle,
                             void *                                 context)
	__export_public;

extern int
galv_rpc_clnt_push_msg(struct galv_rpc_clnt_msg * __restrict message)
	__export_public;

extern void
galv_rpc_clnt_msg_drop(struct galv_rpc_clnt_msg * __restrict message)
	__export_public;

#endif /* _GALV_SYNC_RPC_H */
