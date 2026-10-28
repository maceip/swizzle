/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_SWIZZLE_BOOT_H
#define _ASM_X86_SWIZZLE_BOOT_H

#include <linux/types.h>

#define SWIZZLE_DESC_MAGIC	0x435345444c5a5753ULL /* "SWZLDESC" */
#define SWIZZLE_RELOC_MAGIC	0x4c5a5753U           /* "SWZL" */

#define SWIZZLE_SEC_TEXT	1U
#define SWIZZLE_SEC_DATA	2U
#define SWIZZLE_SEC_RODATA	3U

#define R_X86_64_64		1U
#define R_X86_64_PC32		2U
#define R_X86_64_PLT32		4U
#define R_X86_64_32S		11U

struct swizzle_kernel_desc {
	u64 magic;
	u64 text_base_va;           /* _text */
	u64 image_end_va;           /* _end */
	u64 relocs_start_va;        /* __start_swizzle_relocs */
	u64 relocs_stop_va;         /* __stop_swizzle_relocs */
	u64 boot_seed_va;           /* swizzle_boot_seed (32 bytes) */
	u64 extable_start_va;       /* __start___ex_table */
	u64 extable_stop_va;        /* __stop___ex_table */
	u64 orc_ip_start_va;        /* __start_orc_unwind_ip */
	u64 orc_ip_stop_va;         /* __stop_orc_unwind_ip */
	u64 orc_entry_start_va;     /* __start_orc_unwind */
	u64 kallsyms_offsets_va;    /* kallsyms_offsets */
	u64 kallsyms_num_syms_va;   /* &kallsyms_num_syms */
	u64 kallsyms_rel_base_va;   /* &kallsyms_relative_base */
	u64 kallsyms_sorted_idx_va; /* swizzle_kallsyms_addr_idx */
} __attribute__((packed));

struct swizzle_header {
	u32 magic;
	u32 version;
	u32 num_sections;
	u32 num_relocs;
} __attribute__((packed));

struct swizzle_sec_entry {
	u32 sec_id;
	u32 flags;
	u64 orig_addr;
	u64 size;
} __attribute__((packed));

struct swizzle_reloc_entry {
	u64 r_offset;
	s64 r_addend;
	u32 sym_sec_id;
	u32 r_type;
} __attribute__((packed));

void swizzle_relocate_kernel(void *output, unsigned long output_len,
			     u8 *scratch_area, unsigned long scratch_len);

#endif /* _ASM_X86_SWIZZLE_BOOT_H */
