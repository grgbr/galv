#ifndef _GALV_CDEFS_H
#define _GALV_CDEFS_H

#include <galv/priv/config.h>

#if defined(CONFIG_GALV_ASSERT_API)

#include <stroll/assert.h>

#define galv_assert_api(_expr) \
	stroll_assert("galv", _expr)

#else  /* !defined(CONFIG_GALV_ASSERT_API) */

#define galv_assert_api(_expr)

#endif /* defined(CONFIG_GALV_ASSERT_API) */

struct elog;

extern void
galv_setup(struct elog * __restrict logger) __export_public;

#endif /* _GALV_CDEFS_H */
