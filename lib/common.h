#ifndef _GALV_COMMON_H
#define _GALV_COMMON_H

#include <galv/cdefs.h>
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

#define galv_err(_format, ...) \
	do { \
		if (galv_logger) \
			elog_err(galv_logger, \
			         "galv:" _format ".", \
			         ## __VA_ARGS__); \
	} while (0)

#define galv_warn(_format, ...) \
	do { \
		if (galv_logger) \
			elog_warn(galv_logger, \
			          "galv:" _format ".", \
			          ## __VA_ARGS__); \
	} while (0)

#define galv_notice(_format, ...) \
	do { \
		if (galv_logger) \
			elog_notice(galv_logger, \
			            "galv:" _format ".", \
			            ## __VA_ARGS__); \
	} while (0)

#define galv_info(_format, ...) \
	do { \
		if (galv_logger) \
			elog_info(galv_logger, \
			          "galv:" _format ".", \
			          ## __VA_ARGS__); \
	} while (0)

#else /* !defined(CONFIG_GALV_LOG) */

#define galv_err(_format, ...) \
	do {} while (0)

#define galv_warn(_format, ...) \
	do {} while (0)

#define galv_notice(_format, ...) \
	do {} while (0)

#define galv_info(_format, ...) \
	do {} while (0)

#endif /* defined(CONFIG_GALV_LOG) */

#if defined(CONFIG_GALV_DEBUG)

#define galv_debug(_format, ...) \
	do { \
		if (galv_logger) \
			elog_debug(galv_logger, \
			           "galv:" _format ".", \
			           ## __VA_ARGS__); \
	} while (0)

#else /* !defined(CONFIG_GALV_DEBUG) */

#define galv_debug(_format, ...) \
	do {} while (0)

#endif /* defined(CONFIG_GALV_DEBUG) */

#endif /* _GALV_COMMON_H */
