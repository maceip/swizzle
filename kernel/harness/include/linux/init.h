/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_INIT_H
#define _LINUX_INIT_H

#include <linux/kernel.h>

#define early_initcall(fn) \
	int swizzle_run_early_initcall(void) { return fn(); }

#endif /* _LINUX_INIT_H */
