/****************************************************************************** 
* SPDX-License-Identifier: LGPL-3.0-only
*
* This file is part of Galv.
* Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
*******************************************************************************/

/**
 * @file
 * Connection gate
 *
 * @author    Grégor Boirie <gregor.boirie@free.fr>
 * @date      17 Oct 2025
 * @copyright Copyright (C) 2024 Grégor Boirie.
 * @license   [GNU Lesser General Public License (LGPL) v3]
 *            (https://www.gnu.org/licenses/lgpl+gpl-3.0.txt)
 */

#ifndef _GALV_GATE_H
#define _GALV_GATE_H

#include <galv/conn.h>

struct galv_gate;

typedef int
        galv_gate_track_fn(struct galv_gate * __restrict,
                           const struct galv_conn * __restrict);

typedef void
        galv_gate_untrack_fn(struct galv_gate * __restrict,
                             const struct galv_conn * __restrict);

struct galv_gate_ops {
        galv_gate_track_fn *   track;
        galv_gate_untrack_fn * untrack;
};

#define galv_gate_assert_ops_api(_ops) \
	galv_assert_api(_ops); \
	galv_assert_api((_ops)->track); \
	galv_assert_api((_ops)->untrack)

struct galv_gate {
	const struct galv_gate_ops * ops;
};

#define galv_gate_assert_api(_gate) \
	galv_assert_api(_gate); \
	galv_gate_assert_ops_api((_gate)->ops)

static inline
int
galv_gate_track(struct galv_gate * __restrict       gate,
                const struct galv_conn * __restrict connection)
{
	galv_gate_assert_api(gate);
	galv_conn_assert_api(connection);

	return gate->ops->track(gate, connection);
}

static inline
void
galv_gate_untrack(struct galv_gate * __restrict       gate,
                  const struct galv_conn * __restrict connection)
{
	galv_gate_assert_api(gate);
	galv_conn_assert_api(connection);

	return gate->ops->untrack(gate, connection);
}

static inline
void
galv_gate_init(struct galv_gate * __restrict           gate,
               const struct galv_gate_ops * __restrict ops)
{
	galv_assert_api(gate);
	galv_gate_assert_ops_api(ops);

	gate->ops = ops;
}

extern struct galv_gate galv_gate_dummy __export_public;

#define GALV_GATE_DUMMY (&galv_gate_dummy)

#endif /* _GALV_GATE_H */
