// SPDX-License-Identifier: GPL-2.0
/*
 * kernel/harness/swizzle_c_bridge.c
 *
 * Thin C wrapper exposing kernel/arch/x86/boot/compressed/swizzle.c,
 * kernel/kernel/swizzle_panic.c, kernel/lib/swizzle_kallsyms.c, and
 * kernel/mm/swizzle_slab.c to the Rust test and verification suite.
 */

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/panic_notifier.h>
#include <linux/buildid.h>
#include <asm/swizzle_boot.h>

extern u8 swizzle_boot_seed[32];
extern int swizzle_run_early_initcall(void);
extern void swizzle_reset_panic_log(void);
extern const char *swizzle_get_panic_log(void);
extern void swizzle_set_test_hw_seed(const u8 seed[32]);

extern void swizzle_kmalloc_seed_init(u64 hw_seed);
extern u32 swizzle_kmalloc_cache_index(unsigned long caller_ret_ip, size_t size);
extern u32 swizzle_slab_jitter(u32 *freelist_order, u32 num_objects, u64 jitter_seed);
extern int swizzle_sprint_symbol_redacted(char *buffer, size_t buf_len, unsigned long address);

/* Backing storage for linker-populated symbols used by kernel/swizzle_panic.c */
extern u8 __start_swizzle_hpke_pub[];
extern u8 __stop_swizzle_hpke_pub[];

#if defined(__APPLE__)
__asm__(
	".data\n"
	".balign 8\n"
	".globl ___start_swizzle_hpke_pub\n"
	".globl ___stop_swizzle_hpke_pub\n"
	"___start_swizzle_hpke_pub:\n"
	".space 32\n"
	"___stop_swizzle_hpke_pub:\n"
);
#else
__asm__(
	".data\n"
	".balign 8\n"
	".globl __start_swizzle_hpke_pub\n"
	".globl __stop_swizzle_hpke_pub\n"
	"__start_swizzle_hpke_pub:\n"
	".space 32\n"
	"__stop_swizzle_hpke_pub:\n"
);
#endif

int kallsyms_offsets[256];
unsigned int kallsyms_num_syms = 0;
unsigned long kallsyms_relative_base = 0xffffffff81000000ULL;
const char *swizzle_kallsyms_names[256];
u32 swizzle_kallsyms_sizes[256];
u32 swizzle_kallsyms_addr_idx[256];

/*
 * Runs the C early-boot decompression stub swizzle_relocate_kernel() with
 * an optional deterministic 32-byte hardware RDSEED override.
 */
void swizzle_c_relocate_kernel_with_seed(void *output, unsigned long output_len,
					 u8 *scratch_area, unsigned long scratch_len,
					 const u8 *opt_seed_32)
{
	swizzle_set_test_hw_seed(opt_seed_32);
	swizzle_relocate_kernel(output, output_len, scratch_area, scratch_len);
	swizzle_set_test_hw_seed(NULL);
}

/*
 * Runs the C kernel/swizzle_panic.c early_initcall HPKE sealer and triggers
 * the registered panic notifier, copying the formatted panic log lines into
 * @out_log and returning whether swizzle_boot_seed was zeroed.
 */
int swizzle_c_seal_and_panic(const u8 pubkey[32],
			     const u8 build_id[32],
			     const u8 boot_seed[32],
			     char *out_log,
			     size_t out_log_cap,
			     int *seed_zeroed_out)
{
	int rc;
	size_t i;
	int all_zero = 1;

	memcpy(__start_swizzle_hpke_pub, pubkey, 32);
	memcpy(vmlinux_build_id, build_id, 32);
	memcpy(swizzle_boot_seed, boot_seed, 32);

	panic_notifier_list.head = NULL;
	swizzle_reset_panic_log();

	rc = swizzle_run_early_initcall();
	if (rc != 0)
		return rc;

	for (i = 0; i < 32; i++) {
		if (swizzle_boot_seed[i] != 0)
			all_zero = 0;
	}
	if (seed_zeroed_out)
		*seed_zeroed_out = all_zero;

	if (panic_notifier_list.head && panic_notifier_list.head->notifier_call) {
		panic_notifier_list.head->notifier_call(panic_notifier_list.head, 0, NULL);
	}

	if (out_log && out_log_cap > 0) {
		const char *log = swizzle_get_panic_log();
		strncpy(out_log, log, out_log_cap - 1);
		out_log[out_log_cap - 1] = '\0';
	}
	return 0;
}

/*
 * Configures the C kallsyms tables and formats @address via
 * swizzle_sprint_symbol_redacted().
 */
int swizzle_c_test_kallsyms_redact(u64 rel_base,
				   u32 num_syms,
				   const s32 *offsets,
				   const u32 *sizes,
				   const u32 *sorted_idx,
				   const char * const *names,
				   u64 query_addr,
				   char *out_buf,
				   size_t out_cap)
{
	u32 i;
	if (num_syms > 256)
		num_syms = 256;
	kallsyms_relative_base = (unsigned long)rel_base;
	kallsyms_num_syms = num_syms;
	for (i = 0; i < num_syms; i++) {
		kallsyms_offsets[i] = offsets[i];
		swizzle_kallsyms_sizes[i] = sizes[i];
		swizzle_kallsyms_addr_idx[i] = sorted_idx[i];
		swizzle_kallsyms_names[i] = names[i];
	}
	return swizzle_sprint_symbol_redacted(out_buf, out_cap, (unsigned long)query_addr);
}
