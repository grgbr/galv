typedef int
        galv_gate_track_fn(struct galv_gate * __restrict,
                           struct galv_conn * __restrict);

typedef void
        galv_gate_untrack_fn(struct galv_gate * __restrict,
                             struct galv_conn * __restrict);

struct galv_gate_ops {
        galv_gate_track_fn *   track;
        galv_gate_untrack_fn * untrack;
};

struct galv_gate {
	const struct galv_gate_ops * ops;
};

static inline
int
galv_gate_track(struct galv_gate * __restrict gate,
                struct galv_conn * __restrict conn)
{
	galv_gate_assert_api(gate);
	galv_gate_assert_api(gate->track);
	galv_gate_assert_api(gate->untrack);

	return gate->track(gate, conn);
}

static inline
void
galv_gate_untrack(struct galv_gate * __restrict gate,
                  struct galv_conn * __restrict conn)
{
	galv_gate_assert_api(gate);
	galv_gate_assert_api(gate->track);
	galv_gate_assert_api(gate->untrack);

	gate->untrack(gate, conn);
}

static inline
void
galv_gate_init(struct galv_gate * __restrict gate,
               galv_gate_track_fn *          track,
               galv_gate_untrack_fn *        untrack)
{
	galv_gate_assert_api(gate);
	galv_gate_assert_api(track);
	galv_gate_assert_api(untrack);

	gate->track = track;
	gate->untrack = untrack;
}

static inline
void
galv_gate_fini(struct galv_gate * __restrict gate __unused)
{
	galv_gate_assert_api(gate);
	galv_gate_assert_api(gate->track);
	galv_gate_assert_api(gate->untrack);
}
