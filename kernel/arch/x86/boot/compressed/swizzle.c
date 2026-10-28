// SPDX-License-Identifier: GPL-2.0
/*
 * arch/x86/boot/compressed/swizzle.c
 *
 * In-enclave early-boot ELF section shuffler, relocation engine, and
 * in-place runtime table sorter (exception table, ORC unwinder, kallsyms).
 */

#include "misc.h"
#include <asm/swizzle_boot.h>
#include <asm/orc_types.h>

#define SWIZZLE_SEED_BYTES	32
#define INT3_INSN_OPCODE	0xcc

struct swizzle_rt_sec {
	u32 sec_id;
	u32 flags;
	u64 orig_addr;
	u64 size;
	u64 shuffled_addr;
};

struct swizzle_extable_entry {
	s32 insn;
	s32 fixup;
	s32 data;
};

struct swizzle_ctx {
	u8 *image_base;
	u64 text_base_va;
	u64 image_size;
	const struct swizzle_kernel_desc *desc;
	struct swizzle_rt_sec *secs;
	u32 *sec_order;
	u32 num_secs;
	u8 *scratch_buf;
	u64 scratch_cap;
};

/*
 * Convert a canonical kernel virtual address (0xffffffff81000000+)
 * to its current pointer in the decompressed physical output buffer.
 */
static inline void *va_to_ptr(const struct swizzle_ctx *ctx, u64 va)
{
	if (va < ctx->text_base_va || (va - ctx->text_base_va) >= ctx->image_size)
		return NULL;
	return ctx->image_base + (va - ctx->text_base_va);
}

static void swizzle_memzero_explicit(void *s, size_t count)
{
	volatile u8 *p = (volatile u8 *)s;

	while (count--)
		*p++ = 0;
	barrier();
}

/* --- Step 1: Hardware Entropy (RDSEED -> RDRAND -> TSC Fallback) --- */

#if defined(__x86_64__) || defined(__i386__)
static inline bool cpu_rdseed64(u64 *out)
{
	unsigned char ok;

	asm volatile("rdseed %0; setc %1" : "=r" (*out), "=qm" (ok));
	return ok != 0;
}

static inline bool cpu_rdrand64(u64 *out)
{
	unsigned char ok;

	asm volatile("rdrand %0; setc %1" : "=r" (*out), "=qm" (ok));
	return ok != 0;
}

static inline u64 cpu_rdtsc64(void)
{
	u32 lo, hi;

	asm volatile("rdtsc" : "=a" (lo), "=d" (hi));
	return ((u64)hi << 32) | lo;
}

static inline void cpu_pause(void)
{
	asm volatile("pause" ::: "memory");
}
#else
static inline bool cpu_rdseed64(u64 *out)
{
	return swizzle_arch_rdseed64(out);
}

static inline bool cpu_rdrand64(u64 *out)
{
	return swizzle_arch_rdrand64(out);
}

static inline u64 cpu_rdtsc64(void)
{
	return swizzle_arch_rdtsc64();
}

static inline void cpu_pause(void)
{
	barrier();
}
#endif

static void swizzle_draw_hardware_seed(u8 seed_out[SWIZZLE_SEED_BYTES])
{
	u64 *words = (u64 *)seed_out;
	int i, retries;

	for (i = 0; i < 4; i++) {
		u64 val = 0;
		bool got = false;

		for (retries = 0; retries < 1024; retries++) {
			if (cpu_rdseed64(&val) && val != 0 && val != ~0ULL) {
				got = true;
				break;
			}
			cpu_pause();
		}
		if (!got) {
			for (retries = 0; retries < 1024; retries++) {
				if (cpu_rdrand64(&val) && val != 0) {
					got = true;
					break;
				}
			}
		}
		if (!got) {
			val = cpu_rdtsc64() ^ (0x9e3779b97f4a7c15ULL * (u64)(i + 1));
		}
		words[i] = val;
	}
}

/* --- Step 2: SwizzlePrng & Fisher-Yates Section Permutation --- */

struct swizzle_prng {
	u64 state[4];
	size_t idx;
};

static void swizzle_prng_init(struct swizzle_prng *prng, const u8 seed[SWIZZLE_SEED_BYTES])
{
	int i;

	memcpy(prng->state, seed, SWIZZLE_SEED_BYTES);
	for (i = 0; i < 4; i++) {
		if (prng->state[i] == 0)
			prng->state[i] = 0x9e3779b97f4a7c15ULL;
	}
	prng->idx = 0;
}

static u64 swizzle_prng_next_u64(struct swizzle_prng *prng)
{
	u64 x = prng->state[prng->idx];

	prng->idx = (prng->idx + 1) & 3;
	x ^= x >> 12;
	x ^= x << 25;
	x ^= x >> 27;
	prng->state[prng->idx] = x;
	return x * 0x2545f4914f6cdd1dULL;
}

static size_t swizzle_prng_next_bounded(struct swizzle_prng *prng, size_t bound)
{
	return (size_t)(swizzle_prng_next_u64(prng) % (u64)bound);
}

static void swizzle_compute_layout(struct swizzle_ctx *ctx,
				   const u8 seed[SWIZZLE_SEED_BYTES])
{
	struct swizzle_prng prng;
	u32 sec_class, i;

	swizzle_prng_init(&prng, seed);

	for (sec_class = SWIZZLE_SEC_TEXT; sec_class <= SWIZZLE_SEC_RODATA; sec_class++) {
		size_t count = 0;
		u64 base_addr = ~0ULL;
		u64 cursor_addr;

		for (i = 0; i < ctx->num_secs; i++) {
			if (ctx->secs[i].flags == sec_class) {
				ctx->sec_order[count++] = i;
				if (ctx->secs[i].orig_addr < base_addr)
					base_addr = ctx->secs[i].orig_addr;
			}
		}

		if (count <= 1)
			continue;

		/* Exact Fisher-Yates match with swizzle-ctl replay_section_shuffle() */
		for (i = (u32)(count - 1); i >= 1; i--) {
			size_t j = swizzle_prng_next_bounded(&prng, (size_t)i + 1);
			u32 tmp = ctx->sec_order[i];

			ctx->sec_order[i] = ctx->sec_order[j];
			ctx->sec_order[j] = tmp;
		}

		cursor_addr = base_addr;
		for (i = 0; i < count; i++) {
			u32 idx = ctx->sec_order[i];

			cursor_addr = (cursor_addr + 15ULL) & ~15ULL;
			ctx->secs[idx].shuffled_addr = cursor_addr;
			cursor_addr += ctx->secs[idx].size;
		}
	}
}

/* --- Step 3: Binary Search VA Translation & ELF Relocations --- */

/*
 * ctx->secs[] is ordered ascending by orig_addr.
 * Binary-searches for the section containing canonical address @orig_va.
 */
static const struct swizzle_rt_sec *find_sec_by_orig_va(const struct swizzle_ctx *ctx,
							u64 orig_va)
{
	s64 lo = 0, hi = (s64)ctx->num_secs - 1;

	while (lo <= hi) {
		s64 mid = lo + ((hi - lo) >> 1);
		const struct swizzle_rt_sec *s = &ctx->secs[mid];

		if (orig_va < s->orig_addr)
			hi = mid - 1;
		else if (orig_va >= s->orig_addr + s->size)
			lo = mid + 1;
		else
			return s;
	}
	return NULL;
}

static inline u64 swizzle_translate_va(const struct swizzle_ctx *ctx, u64 orig_va)
{
	const struct swizzle_rt_sec *s = find_sec_by_orig_va(ctx, orig_va);

	if (!s)
		return orig_va;
	return s->shuffled_addr + (orig_va - s->orig_addr);
}

/*
 * Applies packed SHT_RELA records while sections still reside at orig_addr.
 * Because ld.lld already resolved (S_orig + A) or (S_orig + A - P_orig),
 * we recover S_orig using r_addend (A) so negative structure displacements
 * still bind to the correct target symbol's section, then apply (delta_S - delta_P).
 */
static void swizzle_apply_relocations(const struct swizzle_ctx *ctx,
				      const struct swizzle_reloc_entry *relocs,
				      u32 num_relocs)
{
	u32 i;

	for (i = 0; i < num_relocs; i++) {
		u64 p_orig = relocs[i].r_offset;
		s64 addend = relocs[i].r_addend;
		u32 r_type = relocs[i].r_type;
		void *loc = va_to_ptr(ctx, p_orig);
		const struct swizzle_rt_sec *p_sec, *s_sec;
		s64 delta_p = 0, delta_s = 0;
		u64 s_orig;

		if (!loc)
			continue;

		p_sec = find_sec_by_orig_va(ctx, p_orig);
		if (p_sec)
			delta_p = (s64)(p_sec->shuffled_addr - p_sec->orig_addr);

		switch (r_type) {
		case R_X86_64_64: {
			u64 val = *(u64 *)loc;

			s_orig = (u64)((s64)val - addend);
			s_sec = find_sec_by_orig_va(ctx, s_orig);
			if (s_sec) {
				delta_s = (s64)(s_sec->shuffled_addr - s_sec->orig_addr);
				*(u64 *)loc = (u64)((s64)val + delta_s);
			}
			break;
		}
		case R_X86_64_32S: {
			s64 val = (s64)(*(s32 *)loc);

			s_orig = (u64)(val - addend);
			s_sec = find_sec_by_orig_va(ctx, s_orig);
			if (s_sec) {
				delta_s = (s64)(s_sec->shuffled_addr - s_sec->orig_addr);
				*(s32 *)loc = (s32)(val + delta_s);
			}
			break;
		}
		case R_X86_64_PC32:
		case R_X86_64_PLT32: {
			s64 disp = (s64)(*(s32 *)loc);

			s_orig = (u64)((s64)p_orig + disp - addend);
			s_sec = find_sec_by_orig_va(ctx, s_orig);
			if (s_sec)
				delta_s = (s64)(s_sec->shuffled_addr - s_sec->orig_addr);

			if (delta_s != delta_p)
				*(s32 *)loc = (s32)(disp + delta_s - delta_p);
			break;
		}
		default:
			break;
		}
	}
}

/* --- Step 4: Physical Section Permutation in RAM --- */

static void swizzle_permute_sections_in_ram(struct swizzle_ctx *ctx)
{
	u32 sec_class, i;

	for (sec_class = SWIZZLE_SEC_TEXT; sec_class <= SWIZZLE_SEC_RODATA; sec_class++) {
		u64 min_va = ~0ULL, max_va = 0;
		u64 span;
		u8 pad_byte = (sec_class == SWIZZLE_SEC_TEXT) ? INT3_INSN_OPCODE : 0x00;

		for (i = 0; i < ctx->num_secs; i++) {
			const struct swizzle_rt_sec *s = &ctx->secs[i];

			if (s->flags != sec_class)
				continue;
			if (s->orig_addr < min_va)
				min_va = s->orig_addr;
			if (s->orig_addr + s->size > max_va)
				max_va = s->orig_addr + s->size;
			if (s->shuffled_addr + s->size > max_va)
				max_va = s->shuffled_addr + s->size;
		}

		if (min_va >= max_va)
			continue;

		span = max_va - min_va;
		if (span > ctx->scratch_cap)
			error("Swizzle: section class span exceeds scratch capacity\n");

		/* Fill scratch buffer with INT3 (0xcc) for .text or 0x00 for data */
		memset(ctx->scratch_buf, pad_byte, span);

		for (i = 0; i < ctx->num_secs; i++) {
			const struct swizzle_rt_sec *s = &ctx->secs[i];
			const void *src;

			if (s->flags != sec_class)
				continue;
			src = va_to_ptr(ctx, s->orig_addr);
			if (src)
				memcpy(ctx->scratch_buf + (s->shuffled_addr - min_va),
				       src, s->size);
		}

		memcpy(va_to_ptr(ctx, min_va), ctx->scratch_buf, span);
	}
}

/* --- Step 5: Re-Sorting __ex_table, .orc_unwind_ip, and kallsyms --- */

static inline u64 ex_insn_va(u64 base_va, size_t idx,
			     const struct swizzle_extable_entry *ex)
{
	u64 field_va = base_va + idx * sizeof(*ex);

	return (u64)((s64)field_va + (s64)ex[idx].insn);
}

static inline void swap_ex_entries(u64 base_va,
				   struct swizzle_extable_entry *ex,
				   size_t i, size_t j)
{
	u64 i_base = base_va + i * sizeof(*ex);
	u64 j_base = base_va + j * sizeof(*ex);
	u64 insn_i  = (u64)((s64)i_base + ex[i].insn);
	u64 fixup_i = (u64)((s64)(i_base + 4) + ex[i].fixup);
	u64 insn_j  = (u64)((s64)j_base + ex[j].insn);
	u64 fixup_j = (u64)((s64)(j_base + 4) + ex[j].fixup);
	s32 data_i  = ex[i].data;

	ex[i].insn  = (s32)((s64)insn_j - (s64)i_base);
	ex[i].fixup = (s32)((s64)fixup_j - (s64)(i_base + 4));
	ex[i].data  = ex[j].data;

	ex[j].insn  = (s32)((s64)insn_i - (s64)j_base);
	ex[j].fixup = (s32)((s64)fixup_i - (s64)(j_base + 4));
	ex[j].data  = data_i;
}

static void swizzle_update_and_sort_extable(const struct swizzle_ctx *ctx)
{
	u64 base_va = ctx->desc->extable_start_va;
	u64 stop_va = ctx->desc->extable_stop_va;
	struct swizzle_extable_entry *ex = va_to_ptr(ctx, base_va);
	size_t n = (stop_va - base_va) / sizeof(*ex);
	size_t i, end;

	if (!ex || n <= 1)
		return;

	for (i = 0; i < n; i++) {
		u64 f_insn  = base_va + i * sizeof(*ex);
		u64 f_fixup = f_insn + 4;
		u64 new_insn  = swizzle_translate_va(ctx, (u64)((s64)f_insn + ex[i].insn));
		u64 new_fixup = swizzle_translate_va(ctx, (u64)((s64)f_fixup + ex[i].fixup));

		ex[i].insn  = (s32)((s64)new_insn - (s64)f_insn);
		ex[i].fixup = (s32)((s64)new_fixup - (s64)f_fixup);
	}

	/* Iterative O(N log N) Heapsort with O(1) stack usage */
	for (i = n / 2; i > 0; i--) {
		size_t root = i - 1;

		for (;;) {
			size_t child = 2 * root + 1;

			if (child >= n)
				break;
			if (child + 1 < n &&
			    ex_insn_va(base_va, child, ex) < ex_insn_va(base_va, child + 1, ex))
				child++;
			if (ex_insn_va(base_va, root, ex) >= ex_insn_va(base_va, child, ex))
				break;
			swap_ex_entries(base_va, ex, root, child);
			root = child;
		}
	}

	for (end = n - 1; end > 0; end--) {
		size_t root = 0;

		swap_ex_entries(base_va, ex, 0, end);
		for (;;) {
			size_t child = 2 * root + 1;

			if (child >= end)
				break;
			if (child + 1 < end &&
			    ex_insn_va(base_va, child, ex) < ex_insn_va(base_va, child + 1, ex))
				child++;
			if (ex_insn_va(base_va, root, ex) >= ex_insn_va(base_va, child, ex))
				break;
			swap_ex_entries(base_va, ex, root, child);
			root = child;
		}
	}
}

static inline u64 orc_ip_va(u64 base_va, size_t idx, const s32 *ip)
{
	return (u64)((s64)(base_va + idx * sizeof(s32)) + (s64)ip[idx]);
}

static inline void swap_orc_entries(u64 base_va, s32 *ip,
				    struct orc_entry *orc,
				    size_t i, size_t j)
{
	u64 va_i = orc_ip_va(base_va, i, ip);
	u64 va_j = orc_ip_va(base_va, j, ip);
	struct orc_entry tmp_orc = orc[i];

	ip[i] = (s32)((s64)va_j - (s64)(base_va + i * sizeof(s32)));
	ip[j] = (s32)((s64)va_i - (s64)(base_va + j * sizeof(s32)));
	orc[i] = orc[j];
	orc[j] = tmp_orc;
}

static void swizzle_update_and_sort_orc(const struct swizzle_ctx *ctx)
{
	u64 ip_base_va = ctx->desc->orc_ip_start_va;
	u64 ip_stop_va = ctx->desc->orc_ip_stop_va;
	s32 *ip = va_to_ptr(ctx, ip_base_va);
	struct orc_entry *orc = va_to_ptr(ctx, ctx->desc->orc_entry_start_va);
	size_t n = (ip_stop_va - ip_base_va) / sizeof(s32);
	size_t i, end;

	if (!ip || !orc || n <= 1)
		return;

	for (i = 0; i < n; i++) {
		u64 f_va = ip_base_va + i * sizeof(s32);
		u64 orig_va = (u64)((s64)f_va + (s64)ip[i]);
		u64 new_va = swizzle_translate_va(ctx, orig_va);

		ip[i] = (s32)((s64)new_va - (s64)f_va);
	}

	for (i = n / 2; i > 0; i--) {
		size_t root = i - 1;

		for (;;) {
			size_t child = 2 * root + 1;

			if (child >= n)
				break;
			if (child + 1 < n &&
			    orc_ip_va(ip_base_va, child, ip) < orc_ip_va(ip_base_va, child + 1, ip))
				child++;
			if (orc_ip_va(ip_base_va, root, ip) >= orc_ip_va(ip_base_va, child, ip))
				break;
			swap_orc_entries(ip_base_va, ip, orc, root, child);
			root = child;
		}
	}

	for (end = n - 1; end > 0; end--) {
		size_t root = 0;

		swap_orc_entries(ip_base_va, ip, orc, 0, end);
		for (;;) {
			size_t child = 2 * root + 1;

			if (child >= end)
				break;
			if (child + 1 < end &&
			    orc_ip_va(ip_base_va, child, ip) < orc_ip_va(ip_base_va, child + 1, ip))
				child++;
			if (orc_ip_va(ip_base_va, root, ip) >= orc_ip_va(ip_base_va, child, ip))
				break;
			swap_orc_entries(ip_base_va, ip, orc, root, child);
			root = child;
		}
	}
}

/*
 * Updates kallsyms_offsets[] in-place (preserving index alignment with
 * kallsyms_names[] and kallsyms_seqs_of_names[] for eBPF fentry/kprobe lookup)
 * and sorts swizzle_kallsyms_addr_idx[] by new symbol VA for O(log N) %pS lookup.
 */
static void swizzle_update_and_sort_kallsyms(const struct swizzle_ctx *ctx)
{
	s32 *offsets = va_to_ptr(ctx, ctx->desc->kallsyms_offsets_va);
	const u32 *num_syms_ptr = va_to_ptr(ctx, ctx->desc->kallsyms_num_syms_va);
	const u64 *rel_base_ptr = va_to_ptr(ctx, ctx->desc->kallsyms_rel_base_va);
	u32 *sorted_idx = va_to_ptr(ctx, ctx->desc->kallsyms_sorted_idx_va);
	u32 n, i, end;
	u64 rel_base;

	if (!offsets || !num_syms_ptr || !rel_base_ptr)
		return;

	n = *num_syms_ptr;
	rel_base = *rel_base_ptr;

	for (i = 0; i < n; i++) {
		u64 orig_va;
		u64 new_va;

		if (offsets[i] >= 0)
			orig_va = rel_base + (u64)(u32)offsets[i];
		else
			orig_va = rel_base - 1ULL - (u64)(u32)(~offsets[i]);

		new_va = swizzle_translate_va(ctx, orig_va);
		if (new_va >= rel_base)
			offsets[i] = (s32)(new_va - rel_base);

		if (sorted_idx)
			sorted_idx[i] = i;
	}

	if (!sorted_idx || n <= 1)
		return;

	for (i = n / 2; i > 0; i--) {
		u32 root = i - 1;

		for (;;) {
			u32 child = 2 * root + 1;

			if (child >= n)
				break;
			if (child + 1 < n &&
			    offsets[sorted_idx[child]] < offsets[sorted_idx[child + 1]])
				child++;
			if (offsets[sorted_idx[root]] >= offsets[sorted_idx[child]])
				break;
			swap(sorted_idx[root], sorted_idx[child]);
			root = child;
		}
	}

	for (end = n - 1; end > 0; end--) {
		u32 root = 0;

		swap(sorted_idx[0], sorted_idx[end]);
		for (;;) {
			u32 child = 2 * root + 1;

			if (child >= end)
				break;
			if (child + 1 < end &&
			    offsets[sorted_idx[child]] < offsets[sorted_idx[child + 1]])
				child++;
			if (offsets[sorted_idx[root]] >= offsets[sorted_idx[child]])
				break;
			swap(sorted_idx[root], sorted_idx[child]);
			root = child;
		}
	}
}

/* --- Main Entry Point Invoked from arch/x86/boot/compressed/misc.c --- */

void swizzle_relocate_kernel(void *output, unsigned long output_len,
			     u8 *scratch_area, unsigned long scratch_len)
{
	const struct swizzle_kernel_desc *desc = NULL;
	const struct swizzle_header *hdr;
	const struct swizzle_sec_entry *disk_secs;
	const struct swizzle_reloc_entry *disk_relocs;
	struct swizzle_ctx ctx = { 0 };
	u8 seed[SWIZZLE_SEED_BYTES];
	u8 *boot_seed_dst;
	u64 offset;
	u32 i;
	size_t meta_bytes;

	/* Scan decompressed image for the 8-byte aligned SWZLDESC structure */
	for (offset = 0; offset + sizeof(*desc) <= output_len; offset += 8) {
		const u64 *cand = (const u64 *)((const u8 *)output + offset);

		if (*cand == SWIZZLE_DESC_MAGIC) {
			desc = (const struct swizzle_kernel_desc *)cand;
			break;
		}
	}
	if (!desc)
		return;

	ctx.image_base   = (u8 *)output;
	ctx.text_base_va = desc->text_base_va;
	ctx.image_size   = desc->image_end_va - desc->text_base_va;
	ctx.desc         = desc;

	hdr = va_to_ptr(&ctx, desc->relocs_start_va);
	if (!hdr || hdr->magic != SWIZZLE_RELOC_MAGIC || hdr->num_sections == 0)
		return;

	ctx.num_secs = hdr->num_sections;
	disk_secs = (const struct swizzle_sec_entry *)(hdr + 1);
	disk_relocs = (const struct swizzle_reloc_entry *)(disk_secs + hdr->num_sections);

	/* Carve runtime tracking arrays from the front of scratch_area */
	meta_bytes = ALIGN(ctx.num_secs * sizeof(struct swizzle_rt_sec), 64) +
		     ALIGN(ctx.num_secs * sizeof(u32), 64);
	if (scratch_len <= meta_bytes)
		error("Swizzle: insufficient scratch space for section metadata\n");

	ctx.secs = (struct swizzle_rt_sec *)scratch_area;
	ctx.sec_order = (u32 *)(scratch_area +
				ALIGN(ctx.num_secs * sizeof(struct swizzle_rt_sec), 64));
	ctx.scratch_buf = scratch_area + meta_bytes;
	ctx.scratch_cap = scratch_len - meta_bytes;

	for (i = 0; i < ctx.num_secs; i++) {
		ctx.secs[i].sec_id        = disk_secs[i].sec_id;
		ctx.secs[i].flags         = disk_secs[i].flags;
		ctx.secs[i].orig_addr     = disk_secs[i].orig_addr;
		ctx.secs[i].size          = disk_secs[i].size;
		ctx.secs[i].shuffled_addr = disk_secs[i].orig_addr;
	}

	/* 1. Draw hardware seed via RDSEED and pass to kernel swizzle_boot_seed */
	swizzle_draw_hardware_seed(seed);
	boot_seed_dst = va_to_ptr(&ctx, desc->boot_seed_va);
	if (boot_seed_dst)
		memcpy(boot_seed_dst, seed, SWIZZLE_SEED_BYTES);

	/* 2. Run Fisher-Yates section permutation matching swizzle-ctl */
	swizzle_compute_layout(&ctx, seed);

	/* 3. Patch ELF relocations while sections sit at orig_addr */
	swizzle_apply_relocations(&ctx, disk_relocs, hdr->num_relocs);

	/* 4. Update & re-sort __ex_table, .orc_unwind_ip, and kallsyms */
	swizzle_update_and_sort_extable(&ctx);
	swizzle_update_and_sort_orc(&ctx);
	swizzle_update_and_sort_kallsyms(&ctx);

	/* 5. Physically permute .text.*, .data.*, and .rodata.* in RAM */
	swizzle_permute_sections_in_ram(&ctx);

	/* 6. Scrub local seed, packed relocations, and scratch memory */
	swizzle_memzero_explicit(seed, sizeof(seed));
	swizzle_memzero_explicit((void *)hdr,
				 desc->relocs_stop_va - desc->relocs_start_va);
	swizzle_memzero_explicit(scratch_area, scratch_len);
}
