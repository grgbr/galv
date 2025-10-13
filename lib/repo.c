#include "galv/repo.h"
#include "common.h"

void
galv_conn_repo_init(struct galv_conn_repo * __restrict repo,
                    unsigned int                       max_conn)
{
	galv_assert_api(repo);
	galv_assert_api(max_conn);

	repo->cnt = 0;
	repo->nr = max_conn;
	stroll_dlist_init(&repo->conns);
}
