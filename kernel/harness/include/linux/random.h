/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_RANDOM_H
#define _LINUX_RANDOM_H

#include <linux/types.h>

void get_random_bytes(void *buf, size_t len);

#endif /* _LINUX_RANDOM_H */
