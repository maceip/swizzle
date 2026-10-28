/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BOOT_COMPRESSED_MISC_H
#define _BOOT_COMPRESSED_MISC_H

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/types.h>

static inline void error(const char *msg)
{
	fprintf(stderr, "%s", msg);
	abort();
}

bool swizzle_arch_rdseed64(u64 *out);
bool swizzle_arch_rdrand64(u64 *out);
u64  swizzle_arch_rdtsc64(void);

#endif /* _BOOT_COMPRESSED_MISC_H */
