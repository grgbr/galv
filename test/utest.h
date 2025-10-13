/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _GALV_UTEST_H
#define _GALV_UTEST_H

#include "galv/cdefs.h"
#include <elog/elog.h>
#include <sys/types.h>

#if defined(CONFIG_GALV_LOG)

extern struct elog_stdio galvut_log;

#define galvut_err(_format, ...) \
	elog_err(&galvut_log, "galvut:" _format ".", ## __VA_ARGS__)

#define galvut_warn(_format, ...) \
	elog_warn(&galvut_log, "galvut:" _format ".", ## __VA_ARGS__)

#define galvut_notice(_format, ...) \
	elog_notice(&galvut_log, "galvut:" _format ".", ## __VA_ARGS__)

#define galvut_info(_format, ...) \
	elog_info(&galvut_log, "galvut:" _format ".", ## __VA_ARGS__)

#else /* !defined(CONFIG_GALV_LOG) */

#define galvut_err(_format, ...) \
	do {} while (0)

#define galvut_warn(_format, ...) \
	do {} while (0)

#define galvut_notice(_format, ...) \
	do {} while (0)

#define galvut_info(_format, ...) \
	do {} while (0)

#endif /* defined(CONFIG_GALV_LOG) */

#if defined(CONFIG_GALV_DEBUG)

#define galvut_debug(_format, ...) \
	elog_debug(&galvut_log, "galvut:" _format ".", ## __VA_ARGS__)

#else  /* !defined(CONFIG_GALV_DEBUG) */

#define galvut_debug(_format, ...) \
	do {} while (0)

#endif /* defined(CONFIG_GALV_DEBUG) */

extern void free(void * ptr);
extern void galvut_expect_free(const void * parm, size_t size);

#endif /* _GALV_UTEST_H */
