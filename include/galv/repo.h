/****************************************************************************** 
* SPDX-License-Identifier: LGPL-3.0-only
*
* This file is part of Galv.
* Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
*******************************************************************************/

/**
 * @file
 * Connection repository
 *
 * @author    Grégor Boirie <gregor.boirie@free.fr>
 * @date      13 Oct 2025
 * @copyright Copyright (C) 2024 Grégor Boirie.
 * @license   [GNU Lesser General Public License (LGPL) v3]
 *            (https://www.gnu.org/licenses/lgpl+gpl-3.0.txt)
 */

#ifndef _GALV_REPO_H
#define _GALV_REPO_H

#include <galv/cdefs.h>
#include <stroll/dlist.h>

struct galv_repo {
	unsigned int             cnt;
	unsigned int             nr;
	struct stroll_dlist_node elems;
};

#define galv_repo_assert_api(_repo) \
	galv_assert_api(_repo); \
	galv_assert_api((_repo)->nr); \
	galv_assert_api((_repo)->cnt <= (_repo)->nr)

#define GALV_REPO_INIT(_repo, _nr) \
	{ \
		.cnt   = 0, \
		.nr    = _nr, \
		.elems = STROLL_DLIST_INIT((_repo).elems), \
	}

#define galv_repo_foreach_entry(_repo, _entry, _member) \
	stroll_dlist_foreach_entry(&(_repo)->elems, _entry, _member)

#define galv_repo_foreach_entry_safe(_repo, _entry, _member, _tmp) \
	stroll_dlist_foreach_entry_safe(&(_repo)->elems, _entry, _member, _tmp)

static inline
unsigned int
galv_repo_count(const struct galv_repo * __restrict repository)
{
	galv_repo_assert_api(repository);

	return repository->cnt;
}

static inline
unsigned int
galv_repo_nr(const struct galv_repo * __restrict repository)
{
	galv_repo_assert_api(repository);

	return repository->nr;
}

static inline
bool
galv_repo_empty(const struct galv_repo * __restrict repository)
{
	galv_repo_assert_api(repository);

	return !repository->cnt;
}

static inline
bool
galv_repo_full(const struct galv_repo * __restrict repository)
{
	galv_repo_assert_api(repository);

	return repository->cnt == repository->nr;
}

static inline
void
galv_repo_register(struct galv_repo * __restrict         repository,
                   struct stroll_dlist_node * __restrict node)
{
	galv_repo_assert_api(repository);
	galv_assert_api(repository->cnt < repository->nr);

	stroll_dlist_nqueue_back(&repository->elems, node);
	repository->cnt++;
}

static inline
struct stroll_dlist_node *
galv_repo_pop(struct galv_repo * __restrict repository)
{
	galv_repo_assert_api(repository);
	galv_assert_api(repository->cnt);

	struct stroll_dlist_node * node;

	node = stroll_dlist_dqueue_front(&repository->elems);
	repository->cnt--;

	return node;
}

static inline
void
galv_repo_unregister(struct galv_repo * __restrict         repository,
                     struct stroll_dlist_node * __restrict node)
{
	galv_repo_assert_api(repository);
	galv_assert_api(repository->cnt);

	stroll_dlist_remove(node);
	repository->cnt--;
}

extern void
galv_repo_init(struct galv_repo * __restrict repository, unsigned int max_nr)
	__export_public;

static inline
void
galv_repo_fini(struct galv_repo * __restrict repository __unused)
{
	galv_repo_assert_api(repository);
}

#endif /* _GALV_REPO_H */
