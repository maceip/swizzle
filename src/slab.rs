// SPDX-License-Identifier: Apache-2.0
//! Kernel Heap & Slab Allocator diversification (`CONFIG_RANDOM_KMALLOC_CACHES=y`
//! and `swizzle_slab_jitter`) matching `kernel/mm/swizzle_slab.c`.

use crate::prng::{GOLDEN_GAMMA_FALLBACK, XORSHIFT64_STAR_MULT};

pub const RANDOM_KMALLOC_CACHES_NR: u32 = 16;

/// Hashes the caller return address (`_RET_IP_`) and allocation size with the per-boot
/// 64-bit hardware seed to select one of 16 segregated `kmalloc-cg-*` caches,
/// matching `swizzle_kmalloc_cache_index()` in `kernel/mm/swizzle_slab.c`.
pub fn kmalloc_cache_index(caller_ret_ip: u64, size: usize, hw_seed: u64) -> u32 {
    let seed = if hw_seed == 0 {
        GOLDEN_GAMMA_FALLBACK
    } else {
        hw_seed
    };
    let mut z = (caller_ret_ip ^ seed).wrapping_add((size as u64).wrapping_mul(GOLDEN_GAMMA_FALLBACK));
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^= z >> 31;
    (z as u32) & (RANDOM_KMALLOC_CACHES_NR - 1)
}

/// Perturbs a slab page's initial freelist order and computes the number of pinned
/// dummy pre-allocations, matching `swizzle_slab_jitter()` in `kernel/mm/swizzle_slab.c` bit-for-bit.
pub fn slab_jitter(num_objects: u32, jitter_seed: u64) -> (Vec<u32>, u32) {
    if num_objects == 0 {
        return (Vec::new(), 0);
    }

    let mut state = if jitter_seed != 0 {
        jitter_seed
    } else {
        XORSHIFT64_STAR_MULT
    };

    let mut freelist_order: Vec<u32> = (0..num_objects).collect();
    for i in (1..num_objects as usize).rev() {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        let j = ((state.wrapping_mul(XORSHIFT64_STAR_MULT)) % ((i as u64) + 1)) as usize;
        freelist_order.swap(i, j);
    }

    state ^= state >> 12;
    state ^= state << 25;
    state ^= state >> 27;
    let pinned_dummies = if num_objects >= 8 {
        let cap = (num_objects / 8).min(8) as u64;
        1 + ((state.wrapping_mul(XORSHIFT64_STAR_MULT)) % cap) as u32
    } else {
        0
    };

    (freelist_order, pinned_dummies)
}
