/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Galv.
 * Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _GALV_COMMON_H
#define _GALV_COMMON_H

#include "galv/cdefs.h"
#include <elog/elog.h>

#if defined(CONFIG_GALV_ASSERT_INTERN)

#include <stroll/assert.h>

#define galv_assert_intern(_expr) \
	stroll_assert("galv", _expr)

#else  /* !defined(CONFIG_GALV_ASSERT_INTERN) */

#define galv_assert_intern(_expr)

#endif /* defined(CONFIG_GALV_ASSERT_INTERN) */

#if defined(CONFIG_GALV_LOG)

extern struct elog * galv_logger;

#define galv_log(_severity, _format, ...) \
	do { \
		if (galv_logger) \
			elog_log(galv_logger, \
			         _severity, \
			         "galv:" _format ".", \
			         ## __VA_ARGS__); \
	} while (0)

#define GALV_RATELIM_BURST (5U)
#define GALV_RATELIM_LAPSE (10U)

#define galv_ratelim_log(_label, _severity, _format, ...) \
	do { \
		if (galv_logger) \
			elog_ratelim_log(galv_logger, \
			                 GALV_RATELIM_BURST, \
			                 GALV_RATELIM_LAPSE, \
			                 "galv:" _label, \
			                 _severity, \
			                 "galv:" _format, \
			                 ## __VA_ARGS__); \
	 } while (0)

#define galv_err(_format, ...) \
	galv_log(ELOG_ERR_SEVERITY, _format, ##__VA_ARGS__)

#define galv_ratelim_err(_label, _format, ...) \
	galv_ratelim_log(_label, \
	                 ELOG_ERR_SEVERITY, \
	                 _format, \
	                 ## __VA_ARGS__)

#define galv_warn(_format, ...) \
	galv_log(ELOG_WARNING_SEVERITY, _format, ##__VA_ARGS__)

#define galv_ratelim_warn(_label, _format, ...) \
	galv_ratelim_log(_label, \
	                 ELOG_WARNING_SEVERITY, \
	                 _format, \
	                 ## __VA_ARGS__)

#define galv_notice(_format, ...) \
	galv_log(ELOG_NOTICE_SEVERITY, _format, ##__VA_ARGS__)

#define galv_ratelim_notice(_label, _format, ...) \
	galv_ratelim_log(_label, \
	                 ELOG_NOTICE_SEVERITY, \
	                 _format, \
	                 ## __VA_ARGS__)

#define galv_info(_format, ...) \
	galv_log(ELOG_INFO_SEVERITY, _format, ##__VA_ARGS__)

#define galv_ratelim_info(_label, _format, ...) \
	galv_ratelim_log(_label, \
	                 ELOG_INFO_SEVERITY, \
	                 _format, \
	                 ## __VA_ARGS__)

#else /* !defined(CONFIG_GALV_LOG) */

#define galv_err(_format, ...) \
	do {} while (0)

#define galv_ratelim_err(_format, ...) \
	do {} while (0)

#define galv_warn(_format, ...) \
	do {} while (0)

#define galv_ratelim_warn(_format, ...) \
	do {} while (0)

#define galv_notice(_format, ...) \
	do {} while (0)

#define galv_ratelim_notice(_format, ...) \
	do {} while (0)

#define galv_info(_format, ...) \
	do {} while (0)

#define galv_ratelim_info(_format, ...) \
	do {} while (0)

#endif /* defined(CONFIG_GALV_LOG) */

#if defined(CONFIG_GALV_DEBUG)

#define galv_debug(_format, ...) \
	galv_log(ELOG_DEBUG_SEVERITY, _format, ##__VA_ARGS__)

#else /* !defined(CONFIG_GALV_DEBUG) */

#define galv_debug(_format, ...) \
	do {} while (0)

#endif /* defined(CONFIG_GALV_DEBUG) */

#endif /* _GALV_COMMON_H */
