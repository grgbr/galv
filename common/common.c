#include "common.h"

struct elog * galv_logger = NULL;

void
galv_setup(struct elog * __restrict logger)
{
	galv_logger = logger;
}
