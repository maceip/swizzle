// SPDX-License-Identifier: GPL-2.0
/*
 * lib/swizzle_kallsyms.c
 *
 * Address-redacted kallsyms lookup and %pS formatting over in-enclave
 * shuffled symbol tables (swizzle_kallsyms_addr_idx[]).
 *
 * Preserves function_name+0xoffset/0xsize for SRE stack traces while
 * stripping raw hex virtual addresses to prevent pointer leaks.
 */

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/types.h>

extern const int kallsyms_offsets[];
extern const unsigned int kallsyms_num_syms;
extern const unsigned long kallsyms_relative_base;
extern const char * const swizzle_kallsyms_names[];
extern const u32 swizzle_kallsyms_sizes[];
extern u32 swizzle_kallsyms_addr_idx[];

static inline u64 swizzle_sym_va(u32 sym_idx)
{
	s32 off = kallsyms_offsets[sym_idx];

	if (off >= 0)
		return (u64)kallsyms_relative_base + (u64)(u32)off;
	return (u64)kallsyms_relative_base - 1ULL - (u64)(u32)(~off);
}

/*
 * O(log N) binary search over swizzle_kallsyms_addr_idx[], which was sorted
 * in place by arch/x86/boot/compressed/swizzle.c after .text.* permutation.
 */
int swizzle_kallsyms_lookup_size_offset(unsigned long addr,
					unsigned long *symbolsize,
					unsigned long *offset,
					const char **name_out)
{
	u32 n = kallsyms_num_syms;
	s64 lo = 0, hi = (s64)n - 1;
	s64 best = -1;

	if (n == 0)
		return -1;

	while (lo <= hi) {
		s64 mid = lo + ((hi - lo) >> 1);
		u32 sym_idx = swizzle_kallsyms_addr_idx[mid];
		u64 sym_addr = swizzle_sym_va(sym_idx);

		if ((u64)addr < sym_addr) {
			hi = mid - 1;
		} else {
			best = mid;
			lo = mid + 1;
		}
	}

	if (best < 0)
		return -1;

	{
		u32 sym_idx = swizzle_kallsyms_addr_idx[best];
		u64 sym_addr = swizzle_sym_va(sym_idx);
		u32 sym_size = swizzle_kallsyms_sizes[sym_idx];
		u64 delta = (u64)addr - sym_addr;

		if (sym_size == 0 && (u32)(best + 1) < n) {
			u32 next_idx = swizzle_kallsyms_addr_idx[best + 1];
			u64 next_addr = swizzle_sym_va(next_idx);

			if (next_addr > sym_addr)
				sym_size = (u32)(next_addr - sym_addr);
		}

		if (sym_size > 0 && delta >= sym_size)
			return -1;

		if (symbolsize)
			*symbolsize = sym_size;
		if (offset)
			*offset = (unsigned long)delta;
		if (name_out)
			*name_out = swizzle_kallsyms_names[sym_idx];
		return (int)sym_idx;
	}
}

/*
 * Formats an instruction pointer as "function_name+0xoffset/0xsize"
 * without emitting any raw hex virtual address. If the address does not
 * resolve to a known symbol, emits "<redacted-va>" rather than leaking
 * the raw kernel pointer.
 */
int swizzle_sprint_symbol_redacted(char *buffer, size_t buf_len, unsigned long address)
{
	unsigned long offset = 0, size = 0;
	const char *name = NULL;

	if (swizzle_kallsyms_lookup_size_offset(address, &size, &offset, &name) < 0 || !name)
		return snprintf(buffer, buf_len, "<redacted-va>");

	return snprintf(buffer, buf_len, "%s+0x%lx/0x%lx", name, offset, size);
}
