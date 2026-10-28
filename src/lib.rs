// SPDX-License-Identifier: Apache-2.0
//! # Swizzle (v3)
//!
//! Durable, fail-open kernel diversification library and Symbol Vault toolkit for
//! per-boot in-enclave layout randomization.
//!
//! ## Architecture Overview
//! - **Tier 1 (Asynchronous Cohort Builder)**: Compiles a single Superset Archive (`vmlinux-superset.a`)
//!   with Cacheline-Bucketed Surgical RANDSTRUCT and a Pinned eBPF Attach Manifest, links per-profile
//!   kernels with `ld.lld --gc-sections --emit-relocs`, packs `.rela.*` records into `.init.swizzle_relocs`
//!   (`SWZL`), generates `.BTF` once via `pahole -J`, and embeds the Symbol Vault's 32-byte X25519 HPKE
//!   public key into `.rodata.swizzle_hpke_pub`.
//! - **Tier 2 (In-Enclave Early-Boot Stub)**: Executes inside the hardware trust boundary (AMD SEV-SNP,
//!   Intel TDX, TPM 2.0 + UEFI Secure Boot) after static measurement. Draws a 256-bit `Seed_B` via CPU
//!   `RDSEED`, permutes `.text.*`, `.data.*`, and `.rodata.*` in RAM, patches `R_X86_64_*` relocations,
//!   re-sorts `__ex_table`, `.orc_unwind_ip`, and `kallsyms` in place via an $O(1)$-stack iterative
//!   heapsort, seals `Seed_B` with RFC 9180 HPKE into `__ro_after_init` memory, and scrubs all plaintext
//!   seeds and relocation tables via `memzero_explicit()`.

pub mod attest;
pub mod c_bridge;
pub mod hpke_vault;
pub mod ko;
pub mod prng;
pub mod randstruct;
pub mod relocs;
pub mod slab;
pub mod tables;
