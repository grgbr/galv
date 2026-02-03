/****************************************************************************** 
* SPDX-License-Identifier: LGPL-3.0-only
*
* This file is part of Galv.
* Copyright (C) 2017-2025 Grégor Boirie <gregor.boirie@free.fr>
*******************************************************************************/

#include "galv/gate.h"

static
int
galv_gate_dummy_track(struct galv_gate * __restrict       gate __unused,
                      const struct galv_conn * __restrict connection __unused)
{
	return 0;
}

static
void
galv_gate_dummy_untrack(struct galv_gate * __restrict       gate __unused,
                        const struct galv_conn * __restrict connection __unused)
{
}

static const struct galv_gate_ops galv_gate_dummy_ops = {
	.track   = galv_gate_dummy_track,
	.untrack = galv_gate_dummy_untrack
};

struct galv_gate galv_gate_dummy = {
	.ops = &galv_gate_dummy_ops
};
