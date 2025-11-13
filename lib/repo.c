#include "galv/repo.h"
#include "common.h"

void
galv_repo_init(struct galv_repo * __restrict repo, unsigned int max_nr)
{
	galv_assert_api(repo);
	galv_assert_api(max_nr);

	repo->cnt = 0;
	repo->nr = max_nr;
	stroll_dlist_init(&repo->elems);
}
