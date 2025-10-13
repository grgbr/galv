/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "utest.h"
#include "galv/cdefs.h"
#include <elog/elog.h>
#include <cute/cute.h>
#include <cute/expect.h>
#include <stdio.h>
#include <stdlib.h>

static char galvut_assert_msg[LINE_MAX];

/*
 * Override libstroll's stroll_assert_fail() and use cute_mock_assert() to
 * validate assertions.
 */
void
stroll_assert_fail(const char * __restrict prefix,
                   const char * __restrict expr,
                   const char * __restrict file,
                   unsigned int            line,
                   const char * __restrict func)
{
	int    ret;
	size_t sz = sizeof(galvut_assert_msg) - 1;

	/*
	 * cute_mock_assert() does not really "return". It uses a nonlocal goto
	 * logic to restore program / stack state that existed before the code
	 * under test called us. This is the way CUTe allows checking for
	 * assertions.
	 * This means that the code below will never reach the abort() call
	 * below (which is just there to prevent GCC from warning us since
	 * stroll_assert_fail() is declared as a function that cannot return).
	 *
	 * Since cute_mock_assert() does not give control back to us, we MUST
	 * use a statically allocated buffer to store assertion messages. We
	 * would not have the opportunity to free(3) a previously allocated
	 * buffer otherwise.
	 * In other words, Valgrind memory leak checker should be happy with
	 * this...
	 */
	ret = snprintf(galvut_assert_msg,
	               sz,
	               "{utest assert} %s:%s:%u:%s:\'%s\'",
	               prefix,
	               file,
	               line,
	               func,
	               expr);
	if (ret > 0) {
		if ((size_t)ret >= sz)
			galvut_assert_msg[sz - 1] = '\0';

		cute_mock_assert(galvut_assert_msg, file, line, func);
	}
	else
		cute_mock_assert("{utest assert} ??", file, line, func);

	/* Not reached (see comment above)... */
	abort();
}

static bool galvut_free_wrapped;

/*
 * Mock Glibc's free(3) for verification purposes.
 *
 * Set galvut_free_wrapped to true from client testing code to enable
 * free(3) argument checking logic.
 */
void
free(void * ptr)
{
	if (galvut_free_wrapped) {
		/*
		 * Disable checking logic implicitly. Client testing code will
		 * have to re-enable it by setting galvut_free_wrapped to
		 * true to perform subsequent validation.
		 *
		 * Watch out ! This MUST be done before calling any
		 * cute_mock_...() function is called since they all rely upon a
		 * working free(3). We would otherwise wrap CUTe's internal
		 * calls to free(3) !
		 */
		galvut_free_wrapped = false;
		/*
		 * free(3) argument checking logic is enabled: do the check
		 * using standard CUTe's cute_mock_ptr_parm() /
		 * cute_mock_mem_parm().
		 * First check pointer value, then content of memory pointed to.
		 */
		cute_mock_ptr_parm(ptr);
		cute_mock_mem_parm(ptr);
	}

	/* Now call the original free(3) function. */
#if defined __GLIBC__
	extern void __libc_free(void *);
	__libc_free(ptr);
#else
#error Glibc is the only C library supported for now !
#endif
}

#if defined(CONFIG_STROLL_VALGRIND)
#include <valgrind/valgrind.h>
#endif

void
galvut_expect_free(const void * parm, size_t size)
{
#if defined(CONFIG_STROLL_VALGRIND)
	/*
	 * As Valgrind overrides C library's malloc(3) / realloc(3) / free(3)
	 * functions, it bypasses our own free(3) wrapper implemented above.
	 * This breaks our mocked free(3) testing mechanism and leads to test
	 * failures.
	 * Inhibit our mocked free(3) based tests when running testsuite under
	 * Valgrind. We may still run the entire testsuite without Valgrind
	 * anyway.
	 */
	if (RUNNING_ON_VALGRIND)
		return;
#endif

	/* Request checking of pointer value. */
	cute_expect_ptr_parm(free, ptr, equal, parm);
	/* Request checking of pointed to memory content. */
	cute_expect_mem_parm(free, ptr, equal, parm, size);

	/* Instruct free() function above to perform checking of arguments. */
	galvut_free_wrapped = true;
}

#if defined(CONFIG_GALV_UNIX_CONN)
extern CUTE_SUITE_DECL(galvut_unix_conn_suite);
#endif

CUTE_GROUP(galvut_group) = {
#if defined(CONFIG_GALV_UNIX_CONN)
	CUTE_REF(galvut_unix_conn_suite),
#endif
};

CUTE_SUITE(galvut_suite, galvut_group);

static const struct elog_stdio_conf galvut_log_cfg = {
	.super.severity = ELOG_DEBUG_SEVERITY,
	.format         = ELOG_TAG_FMT
};

static struct elog_stdio galvut_log;

int
main(int argc, char * const argv[])
{
	int ret;

	elog_init_stdio(&galvut_log, &galvut_log_cfg);

	galv_setup((struct elog *)&galvut_log);

	ret = cute_main(argc, argv, &galvut_suite, "Galv", GALV_VERSION_STRING);

	elog_fini_stdio(&galvut_log);

	return ret;
}
