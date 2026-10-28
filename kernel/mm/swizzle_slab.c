// SPDX-License-Identifier: GPL-2.0
/*
 * mm/swizzle_slab.c
 *
 * Per-boot kmalloc cache segregation (CONFIG_RANDOM_KMALLOC_CACHES=y) and
 * early-boot slab freelist pre-allocation jitter (swizzle_slab_jitter)
 * to defeat deterministic heap feng shui and cross-cache overflow layouts.
 */

#include <linux/kernel.h>
#include <linux/random.h>
#include <linux/string.h>
#include <linux/types.h>

#define SWIZZLE_RANDOM_KMALLOC_CACHES_NR	16U
#define SWIZZLE_JITTER_SLOTS_MAX		64U

static u64 swizzle_kmalloc_seed __ro_after_init;

/*
 * Initializes the per-boot 64-bit kmalloc caller-IP hash seed from hardware
 * entropy during early slab setup.
 */
void swizzle_kmalloc_seed_init(u64 hw_seed)
{
	if (hw_seed == 0)
		get_random_bytes(&hw_seed, sizeof(hw_seed));
	if (hw_seed == 0)
		hw_seed = 0x9e3779b97f4a7c15ULL;
	swizzle_kmalloc_seed = hw_seed;
}

/*
 * Hashes caller _RET_IP_ and allocation size with the per-boot 64-bit hardware
 * seed (SipHash/SplitMix64 mixing) to select one of 16 segregated kmalloc-cg-*
 * caches.
 */
u32 swizzle_kmalloc_cache_index(unsigned long caller_ret_ip, size_t size)
{
	u64 z = ((u64)caller_ret_ip ^ swizzle_kmalloc_seed) +
		((u64)size * 0x9e3779b97f4a7c15ULL);

	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
	z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
	z = z ^ (z >> 31);
	return (u32)(z & (SWIZZLE_RANDOM_KMALLOC_CACHES_NR - 1U));
}

/*
 * Perturbs a slab page's initial freelist order and pins a small random subset
 * of dummy slots across early-boot kmalloc caches so adjacent object slots do
 * not follow a predictable sequential layout.
 */
u32 swizzle_slab_jitter(u32 *freelist_order, u32 num_objects, u64 jitter_seed)
{
	u64 state = jitter_seed ? jitter_seed : 0x2545f4914f6cdd1dULL;
	u32 i, pinned_dummies;

	if (!freelist_order || num_objects == 0)
		return 0;

	for (i = 0; i < num_objects; i++)
		freelist_order[i] = i;

	for (i = num_objects - 1; i >= 1; i--) {
		u32 j;
		u32 tmp;

		state ^= state >> 12;
		state ^= state << 25;
		state ^= state >> 27;
		j = (u32)((state * 0x2545f4914f6cdd1dULL) % (u64)(i + 1));

		tmp = freelist_order[i];
		freelist_order[i] = freelist_order[j];
		freelist_order[j] = tmp;
	}

	/* Pin 1..min(num_objects/8, 8) initial slots as randomized pre-allocations */
	state ^= state >> 12;
	state ^= state << 25;
	state ^= state >> 27;
	pinned_dummies = (num_objects >= 8) ?
		(1U + (u32)((state * 0x2545f4914f6cdd1dULL) % (u64)((num_objects / 8 > 8) ? 8 : (num_objects / 8)))) : 0U;

	return pinned_dummies;
}
