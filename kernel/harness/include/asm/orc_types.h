/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_ORC_TYPES_H
#define _ASM_ORC_TYPES_H

#include <linux/types.h>

struct orc_entry {
	s16 sp_offset;
	s16 bp_offset;
	u16 flags;
} __attribute__((packed));

#endif /* _ASM_ORC_TYPES_H */
