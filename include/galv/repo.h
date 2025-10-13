/******************************************************************************
 * Asynchronous connection repository handling
 ******************************************************************************/

#ifndef _GALV_REPO_H
#define _GALV_REPO_H

#include <galv/conn.h>

#define galv_repo_assert_iface_api(_repo) \
	galv_assert_api(_repo); \
	galv_assert_api((_repo)->nr); \
	galv_assert_api((_repo)->cnt <= (_repo)->nr)

struct galv_conn_repo {
	unsigned int             cnt;
	unsigned int             nr;
	struct stroll_dlist_node conns;
};

#define GALV_CONN_REPO_INIT(_repo, _nr) \
	{ \
		.cnt   = 0, \
		.nr    = _nr, \
		.conns = STROLL_DLIST_INIT((_repo).conns), \
	}

static inline
struct galv_conn *
galv_conn_repo_pop(struct galv_conn_repo * __restrict repo)
{
	return stroll_dlist_entry(stroll_dlist_dqueue_front(&repo->conns),
	                          struct galv_conn,
	                          repo);
}

static inline
unsigned int
galv_conn_repo_count(const struct galv_conn_repo * __restrict repo)
{
	galv_repo_assert_iface_api(repo);

	return repo->cnt;
}

static inline
unsigned int
galv_conn_repo_nr(const struct galv_conn_repo * __restrict repo)
{
	galv_repo_assert_iface_api(repo);

	return repo->nr;
}

static inline
bool
galv_conn_repo_empty(const struct galv_conn_repo * __restrict repo)
{
	galv_repo_assert_iface_api(repo);

	return !repo->cnt;
}

static inline
bool
galv_conn_repo_full(const struct galv_conn_repo * __restrict repo)
{
	galv_repo_assert_iface_api(repo);

	return repo->cnt == repo->nr;
}

static inline
void
galv_conn_repo_register(struct galv_conn_repo * __restrict repo,
                        struct galv_conn * __restrict      conn)
{
	galv_repo_assert_iface_api(repo);
	galv_assert_api(repo->cnt < repo->nr);

	stroll_dlist_nqueue_back(&repo->conns, &conn->repo);
	repo->cnt++;
}

static inline
void
galv_conn_repo_unregister(struct galv_conn_repo * __restrict repo,
                          struct galv_conn * __restrict      conn)
{
	galv_repo_assert_iface_api(repo);

	stroll_dlist_remove(&conn->repo);
	repo->cnt--;
}

extern void
galv_conn_repo_init(struct galv_conn_repo * __restrict repo,
                    unsigned int                       max_conn)
	__export_public;

static inline
void
galv_conn_repo_fini(struct galv_conn_repo * __restrict repo __unused)
{
	galv_repo_assert_iface_api(repo);
}

#endif /* _GALV_REPO_H */
