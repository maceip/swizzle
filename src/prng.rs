// SPDX-License-Identifier: Apache-2.0
//! Deterministic `xorshift64*` PRNG matching `arch/x86/boot/compressed/swizzle.c`.

use byteorder::{LittleEndian, ReadBytesExt};
use std::io::Cursor;

pub const SWIZZLE_SEED_LEN: usize = 32;
pub const GOLDEN_GAMMA_FALLBACK: u64 = 0x9e3779b97f4a7c15;
pub const XORSHIFT64_STAR_MULT: u64 = 0x2545f4914f6cdd1d;

/// Deterministic 256-bit state `xorshift64*` PRNG matching `struct swizzle_prng`
/// in `arch/x86/boot/compressed/swizzle.c`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwizzlePrng {
    state: [u64; 4],
    idx: usize,
}

impl SwizzlePrng {
    /// Initializes the PRNG state from a 32-byte little-endian hardware seed (`Seed_B` or `Seed_C`).
    /// Any zero 64-bit word is replaced with `0x9e3779b97f4a7c15` to avoid degenerate xorshift state.
    pub fn from_seed(seed: &[u8; SWIZZLE_SEED_LEN]) -> Self {
        let mut rdr = Cursor::new(seed);
        let mut state = [0u64; 4];
        for s in &mut state {
            *s = rdr.read_u64::<LittleEndian>().unwrap();
            if *s == 0 {
                *s = GOLDEN_GAMMA_FALLBACK;
            }
        }
        Self { state, idx: 0 }
    }

    /// Advances the PRNG state and returns the next 64-bit pseudorandom word.
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state[self.idx];
        self.idx = (self.idx + 1) & 3;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state[self.idx] = x;
        x.wrapping_mul(XORSHIFT64_STAR_MULT)
    }

    /// Returns a bounded index in `0..bound` matching `swizzle_prng_next_bounded` in C.
    pub fn next_bounded(&mut self, bound: usize) -> usize {
        debug_assert!(bound > 0);
        (self.next_u64() % (bound as u64)) as usize
    }
}
