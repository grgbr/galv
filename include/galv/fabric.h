#ifndef _GALV_FABRIC_H
#define _GALV_FABRIC_H

#include <galv/cdefs.h>
#include <stroll/palloc.h>

/******************************************************************************
 * Fabric interface
 ******************************************************************************/

struct galv_fabric;

typedef void *
        galv_fabric_alloc_fn(struct galv_fabric * __restrict);

typedef void
        galv_fabric_free_fn(struct galv_fabric * __restrict, void * __restrict);

typedef void
        galv_fabric_fini_fn(struct galv_fabric * __restrict);

struct galv_fabric_ops {
	galv_fabric_alloc_fn * alloc;
	galv_fabric_free_fn *  free;
	galv_fabric_fini_fn *  fini;
};

#define galv_fabric_assert_ops_api(_ops) \
	galv_assert_api(_ops); \
	galv_assert_api((_ops)->alloc); \
	galv_assert_api((_ops)->free); \
	galv_assert_api((_ops)->fini)

struct galv_fabric {
	const struct galv_fabric_ops * ops;
};

#define galv_fabric_assert_iface_api(_fabric) \
	galv_assert_api(_fabric); \
	galv_fabric_assert_ops_api((_fabric)->ops)

static inline
void *
galv_fabric_alloc(struct galv_fabric * __restrict fabric)
{
	galv_fabric_assert_iface_api(fabric);

	return fabric->ops->alloc(fabric);
}

static inline
void
galv_fabric_free(struct galv_fabric * __restrict fabric,
		 void * __restrict               chunk)
{
	galv_fabric_assert_iface_api(fabric);

	fabric->ops->free(fabric, chunk);
}

static inline
void
galv_fabric_init(struct galv_fabric * __restrict           fabric,
                 const struct galv_fabric_ops * __restrict ops)
{
	galv_assert_api(fabric);
	galv_fabric_assert_ops_api(ops);

	fabric->ops = ops;
}

static inline
void
galv_fabric_fini(struct galv_fabric * __restrict fabric)
{
	galv_fabric_assert_iface_api(fabric);

	fabric->ops->fini(fabric);
}

/******************************************************************************
 * Pre-allocated memory chunk based fabric
 ******************************************************************************/

struct galv_fabric_palloc {
	struct galv_fabric   base;
	struct stroll_palloc palloc;
};

extern int
galv_fabric_palloc_init(struct galv_fabric_palloc * __restrict fabric,
                        unsigned int                           chunk_nr,
                        size_t                                 chunk_size);

#endif /* _GALV_FABRIC_H */
