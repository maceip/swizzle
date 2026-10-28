/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_STRING_H
#define _LINUX_STRING_H

#include <string.h>
#include <linux/types.h>

static inline void memzero_explicit(void *s, size_t count)
{
	volatile uint8_t *p = (volatile uint8_t *)s;
	while (count--)
		*p++ = 0;
	__asm__ __volatile__("" : : "r"(s) : "memory");
}

#endif /* _LINUX_STRING_H */
