/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_KERNEL_H
#define _LINUX_KERNEL_H

#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef pr_fmt
#define pr_fmt(fmt) fmt
#endif

#ifndef ALIGN
#define ALIGN(x, a) (((x) + ((typeof(x))(a) - 1)) & ~((typeof(x))(a) - 1))
#endif

#ifndef swap
#define swap(a, b) \
	do { typeof(a) __tmp = (a); (a) = (b); (b) = __tmp; } while (0)
#endif

#ifndef barrier
#define barrier() __asm__ __volatile__("" : : : "memory")
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#ifndef BUG_ON
#define BUG_ON(cond) do { if (unlikely(cond)) abort(); } while (0)
#endif

#define __init
#define __initdata
#define __ro_after_init
#ifndef __used
#define __used __attribute__((used))
#endif
#ifndef __section
#if defined(__APPLE__)
#define __section(S) __attribute__((used))
#else
#define __section(S) __attribute__((section(S)))
#endif
#endif

void swizzle_printk_emerg(const char *fmt, ...);
void swizzle_printk_err(const char *fmt, ...);

#define pr_emerg(fmt, ...) swizzle_printk_emerg(pr_fmt(fmt), ##__VA_ARGS__)
#define pr_err(fmt, ...)   swizzle_printk_err(pr_fmt(fmt), ##__VA_ARGS__)

#endif /* _LINUX_KERNEL_H */
