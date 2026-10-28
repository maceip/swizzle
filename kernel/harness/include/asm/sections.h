/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_SECTIONS_H
#define _ASM_SECTIONS_H

#include <linux/types.h>
#include <asm/orc_types.h>

struct exception_table_entry {
	int insn, fixup, data;
};

extern char _text[];
extern char _end[];

#endif /* _ASM_SECTIONS_H */
