#include "galv/fabric.h"
#include "common.h"

static
void *
galv_fabric_palloc_alloc(struct galv_fabric * __restrict fabric)
{
	galv_assert_intern(fabric);

	return stroll_palloc_alloc(
		&((struct galv_fabric_palloc *)fabric)->palloc);
}

static
void
galv_fabric_palloc_free(struct galv_fabric * __restrict fabric,
                        void * __restrict               chunk)
{
	galv_assert_intern(fabric);

	stroll_palloc_free(&((struct galv_fabric_palloc *)fabric)->palloc,
	                   chunk);
}

static
void
galv_fabric_palloc_fini(struct galv_fabric * __restrict fabric)
{
	galv_assert_intern(fabric);

	stroll_palloc_fini(&((struct galv_fabric_palloc *)fabric)->palloc);
}

static const struct galv_fabric_ops galv_fabric_palloc_ops = {
	.alloc = galv_fabric_palloc_alloc,
	.free  = galv_fabric_palloc_free,
	.fini  = galv_fabric_palloc_fini
};

int
galv_fabric_palloc_init(struct galv_fabric_palloc * __restrict fabric,
                        unsigned int                           chunk_nr,
                        size_t                                 chunk_size)
{
	galv_assert_api(fabric);
	galv_assert_api(chunk_nr);
	galv_assert_api(chunk_size);

	int err;

	err = stroll_palloc_init(&fabric->palloc, chunk_nr, chunk_size);
	if (err)
		return err;

	fabric->base.ops = &galv_fabric_palloc_ops;

	return 0;
}
