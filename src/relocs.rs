// SPDX-License-Identifier: Apache-2.0
//! Tier 1 `SWZL` packed relocation format (`packed_relocs.bin`), ELF section extractor,
//!Frozen VDSO boundary enforcement, and Tier 2 deterministic Fisher-Yates section shuffler.

use crate::prng::{SwizzlePrng, SWIZZLE_SEED_LEN};
use anyhow::{bail, Context, Result};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Cursor, Read, Write};
use std::path::Path;

pub const SWIZZLE_DESC_MAGIC: u64 = 0x435345444c5a5753; // "SWZLDESC"
pub const SWIZZLE_RELOC_MAGIC: u32 = 0x4c5a5753; // "SWZL"
pub const SWIZZLE_RELOC_VERSION: u32 = 1;
pub const KERNEL_TEXT_BASE: u64 = 0xffffffff81000000;
pub const INT3_INSN_OPCODE: u8 = 0xcc;

pub const SWIZZLE_SEC_TEXT: u32 = 1;
pub const SWIZZLE_SEC_DATA: u32 = 2;
pub const SWIZZLE_SEC_RODATA: u32 = 3;

pub const R_X86_64_64: u32 = 1;
pub const R_X86_64_PC32: u32 = 2;
pub const R_X86_64_PLT32: u32 = 4;
pub const R_X86_64_32S: u32 = 11;

/// High-value writable kernel globals protected by randomized guard padding and trap pages.
pub const GUARDED_GLOBAL_TARGETS: &[&str] = &["modprobe_path", "core_pattern", "poweroff_cmd"];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SectionEntry {
    pub sec_id: u32,
    pub flags: u32,
    pub orig_addr: u64,
    pub size: u64,
    pub shuffled_addr: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelocEntry {
    pub r_offset: u64,
    pub r_addend: i64,
    pub sym_sec_id: u32,
    pub r_type: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackedRelocs {
    pub version: u32,
    pub sections: Vec<SectionEntry>,
    pub relocs: Vec<RelocEntry>,
}

/// Returns `true` if the section belongs to the Frozen VDSO boundary (`arch/*/entry/vdso/`),
/// which must be excluded from permutation so CRIU container checkpoints restore cleanly.
pub fn is_frozen_vdso_section(sec_name: &str) -> bool {
    sec_name.contains("vdso") || sec_name.starts_with(".text.vdso") || sec_name.starts_with(".rodata.vdso")
}

/// Classifies an ELF section name into `SWIZZLE_SEC_TEXT` (1), `SWIZZLE_SEC_DATA` (2),
/// `SWIZZLE_SEC_RODATA` (3), or `None` if excluded (e.g. VDSO, `.init.swizzle_relocs`, `.rodata.swizzle_desc`).
pub fn classify_shuffleable_section(sec_name: &str) -> Option<u32> {
    if is_frozen_vdso_section(sec_name)
        || sec_name.starts_with(".rodata.swizzle_")
        || sec_name.starts_with(".init.swizzle_")
    {
        return None;
    }
    if sec_name == ".text" || sec_name.starts_with(".text.") {
        Some(SWIZZLE_SEC_TEXT)
    } else if sec_name == ".data" || sec_name.starts_with(".data.") {
        Some(SWIZZLE_SEC_DATA)
    } else if sec_name == ".rodata" || sec_name.starts_with(".rodata.") {
        Some(SWIZZLE_SEC_RODATA)
    } else {
        None
    }
}

impl PackedRelocs {
    /// Serializes the section and relocation tables into the binary `SWZL` format (`packed_relocs.bin`).
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(16 + self.sections.len() * 24 + self.relocs.len() * 24);
        out.write_u32::<LittleEndian>(SWIZZLE_RELOC_MAGIC)?;
        out.write_u32::<LittleEndian>(self.version)?;
        out.write_u32::<LittleEndian>(self.sections.len() as u32)?;
        out.write_u32::<LittleEndian>(self.relocs.len() as u32)?;

        for s in &self.sections {
            out.write_u32::<LittleEndian>(s.sec_id)?;
            out.write_u32::<LittleEndian>(s.flags)?;
            out.write_u64::<LittleEndian>(s.orig_addr)?;
            out.write_u64::<LittleEndian>(s.size)?;
        }

        for r in &self.relocs {
            out.write_u64::<LittleEndian>(r.r_offset)?;
            out.write_i64::<LittleEndian>(r.r_addend)?;
            out.write_u32::<LittleEndian>(r.sym_sec_id)?;
            out.write_u32::<LittleEndian>(r.r_type)?;
        }

        Ok(out)
    }

    /// Parses a binary `SWZL` (`packed_relocs.bin`) buffer.
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        let mut cur = Cursor::new(buf);
        let mut magic = [0u8; 4];
        cur.read_exact(&mut magic)
            .context("Truncated SWZL header in packed_relocs.bin")?;
        if &magic != b"SWZL" {
            bail!("Invalid magic in packed_relocs.bin (expected SWZL)");
        }

        let version = cur.read_u32::<LittleEndian>()?;
        let num_sections = cur.read_u32::<LittleEndian>()? as usize;
        let num_relocs = cur.read_u32::<LittleEndian>()? as usize;

        let mut sections = Vec::with_capacity(num_sections);
        for _ in 0..num_sections {
            let sec_id = cur.read_u32::<LittleEndian>()?;
            let flags = cur.read_u32::<LittleEndian>()?;
            let orig_addr = cur.read_u64::<LittleEndian>()?;
            let size = cur.read_u64::<LittleEndian>()?;
            sections.push(SectionEntry {
                sec_id,
                flags,
                orig_addr,
                size,
                shuffled_addr: orig_addr,
            });
        }

        let mut relocs = Vec::with_capacity(num_relocs);
        for _ in 0..num_relocs {
            if (cur.position() as usize) >= buf.len() {
                break;
            }
            let r_offset = cur.read_u64::<LittleEndian>()?;
            let r_addend = cur.read_i64::<LittleEndian>()?;
            let sym_sec_id = cur.read_u32::<LittleEndian>()?;
            let r_type = cur.read_u32::<LittleEndian>()?;
            relocs.push(RelocEntry {
                r_offset,
                r_addend,
                sym_sec_id,
                r_type,
            });
        }

        Ok(Self {
            version,
            sections,
            relocs,
        })
    }

    pub fn write_to_file(&self, path: &Path) -> Result<()> {
        let bytes = self.to_bytes()?;
        File::create(path)?.write_all(&bytes)?;
        Ok(())
    }

    pub fn read_from_file(path: &Path) -> Result<Self> {
        let mut f = File::open(path).context("Failed to open packed_relocs.bin")?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        Self::from_bytes(&buf)
    }
}

/// Applies the deterministic Fisher-Yates section permutation within each section class
/// (`1 = .text`, `2 = .data`, `3 = .rodata`), matching `swizzle_compute_layout` in
/// `arch/x86/boot/compressed/swizzle.c` bit-for-bit.
pub fn compute_section_shuffle(sections: &mut [SectionEntry], seed: &[u8; SWIZZLE_SEED_LEN]) {
    let mut prng = SwizzlePrng::from_seed(seed);
    for sec_class in SWIZZLE_SEC_TEXT..=SWIZZLE_SEC_RODATA {
        let mut indices: Vec<usize> = sections
            .iter()
            .enumerate()
            .filter(|(_, s)| s.flags == sec_class)
            .map(|(i, _)| i)
            .collect();

        if indices.len() <= 1 {
            continue;
        }

        let base_addr = indices
            .iter()
            .map(|&i| sections[i].orig_addr)
            .min()
            .unwrap_or(KERNEL_TEXT_BASE);

        for i in (1..indices.len()).rev() {
            let j = prng.next_bounded(i + 1);
            indices.swap(i, j);
        }

        let mut cursor_addr = base_addr;
        for idx in indices {
            // Align each section to 16 bytes
            cursor_addr = (cursor_addr + 15) & !15;
            sections[idx].shuffled_addr = cursor_addr;
            cursor_addr += sections[idx].size;
        }
    }
}

/// Loads `packed_relocs.bin` and replays the Fisher-Yates section permutation for `seed`.
pub fn replay_section_shuffle(
    relocs_path: &Path,
    seed: &[u8; SWIZZLE_SEED_LEN],
) -> Result<Vec<SectionEntry>> {
    let mut packed = PackedRelocs::read_from_file(relocs_path)?;
    compute_section_shuffle(&mut packed.sections, seed);
    Ok(packed.sections)
}

/// Binary-searches `sections` (ordered ascending by `orig_addr`) for the section containing `orig_va`.
pub fn find_section_by_orig_va(sections: &[SectionEntry], orig_va: u64) -> Option<&SectionEntry> {
    let mut lo: isize = 0;
    let mut hi: isize = sections.len() as isize - 1;
    while lo <= hi {
        let mid = lo + ((hi - lo) >> 1);
        let s = &sections[mid as usize];
        if orig_va < s.orig_addr {
            hi = mid - 1;
        } else if orig_va >= s.orig_addr + s.size {
            lo = mid + 1;
        } else {
            return Some(s);
        }
    }
    None
}

/// Translates a canonical unshuffled virtual address `orig_va` to its shuffled in-enclave VA.
pub fn translate_orig_to_shuffled_va(sections: &[SectionEntry], orig_va: u64) -> u64 {
    match find_section_by_orig_va(sections, orig_va) {
        Some(s) => s.shuffled_addr + (orig_va - s.orig_addr),
        None => orig_va,
    }
}

/// Resolves an in-enclave shuffled `rip_val` back to `(SectionEntry, offset_in_sec, canonical_vmlinux_va)`.
pub fn resolve_shuffled_rip(
    sections: &[SectionEntry],
    rip_val: u64,
) -> Option<(&SectionEntry, u64, u64)> {
    let sec = sections
        .iter()
        .find(|s| rip_val >= s.shuffled_addr && rip_val < s.shuffled_addr + s.size)?;
    let delta = rip_val - sec.shuffled_addr;
    let canonical_addr = sec.orig_addr + delta;
    Some((sec, delta, canonical_addr))
}
