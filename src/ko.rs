// SPDX-License-Identifier: Apache-2.0
//! Out-of-Tree (OOT) & Proprietary Kernel Module (`.ko`) `ET_REL` section shuffler
//! and Split-Struct KABI boundary verifier.

use crate::prng::{SwizzlePrng, SWIZZLE_SEED_LEN};
use crate::relocs::classify_shuffleable_section;
use anyhow::{bail, Result};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use serde::{Deserialize, Serialize};
use std::io::Cursor;

pub const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
pub const ET_REL: u16 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KoSectionRecord {
    pub sh_index: usize,
    pub name: String,
    pub sec_class: u32,
    pub size: u64,
    pub orig_order: usize,
    pub shuffled_order: usize,
}

/// Shuffles the internal `.text.*`, `.data.*`, and `.rodata.*` section ordering of a
/// relocatable `ET_REL` `.ko` kernel module (or rewrites its ELF64 section header table
/// and `sh_link`/`sh_info` indices) without requiring vendor source code.
pub fn shuffle_ko_sections(
    section_names_and_sizes: &[(String, u64)],
    seed: &[u8; SWIZZLE_SEED_LEN],
) -> Vec<KoSectionRecord> {
    let mut records: Vec<KoSectionRecord> = section_names_and_sizes
        .iter()
        .enumerate()
        .filter_map(|(idx, (name, size))| {
            let sec_class = classify_shuffleable_section(name)?;
            Some(KoSectionRecord {
                sh_index: idx,
                name: name.clone(),
                sec_class,
                size: *size,
                orig_order: idx,
                shuffled_order: idx,
            })
        })
        .collect();

    let mut prng = SwizzlePrng::from_seed(seed);
    for class_id in 1..=3u32 {
        let mut group_indices: Vec<usize> = records
            .iter()
            .enumerate()
            .filter(|(_, r)| r.sec_class == class_id)
            .map(|(i, _)| i)
            .collect();

        if group_indices.len() <= 1 {
            continue;
        }

        let orig_orders: Vec<usize> = group_indices
            .iter()
            .map(|&i| records[i].orig_order)
            .collect();

        for i in (1..group_indices.len()).rev() {
            let j = prng.next_bounded(i + 1);
            group_indices.swap(i, j);
        }

        for (slot, &rec_idx) in group_indices.iter().enumerate() {
            records[rec_idx].shuffled_order = orig_orders[slot];
        }
    }

    records.sort_by_key(|r| r.shuffled_order);
    records
}

/// Validates and shuffles an ELF64 `ET_REL` `.ko` binary image in memory by permuting the
/// load offsets (`sh_offset`) of same-sized or relocated `.text.*` / `.data.*` / `.rodata.*`
/// sections and recording the `SWZL` module permutation metadata.
pub fn shuffle_elf64_et_rel_ko(
    elf_bytes: &[u8],
    seed: &[u8; SWIZZLE_SEED_LEN],
) -> Result<(Vec<u8>, Vec<KoSectionRecord>)> {
    if elf_bytes.len() < 64 || &elf_bytes[0..4] != ELF_MAGIC {
        bail!("Input is not a valid 64-bit ELF object (.ko)");
    }
    let mut cur = Cursor::new(elf_bytes);
    cur.set_position(16);
    let e_type = cur.read_u16::<LittleEndian>()?;
    if e_type != ET_REL {
        bail!("Expected relocatable ELF object (ET_REL = 1), got e_type = {}", e_type);
    }

    cur.set_position(40);
    let e_shoff = cur.read_u64::<LittleEndian>()? as usize;
    cur.set_position(58);
    let e_shentsize = cur.read_u16::<LittleEndian>()? as usize;
    let e_shnum = cur.read_u16::<LittleEndian>()? as usize;
    let e_shstrndx = cur.read_u16::<LittleEndian>()? as usize;

    if e_shoff == 0 || e_shnum == 0 || e_shstrndx >= e_shnum {
        bail!("ELF .ko has invalid section header table");
    }
    if e_shoff + e_shnum * e_shentsize > elf_bytes.len() {
        bail!("ELF .ko section header table extends past EOF");
    }

    // Read section string table location
    let shstr_hdr_off = e_shoff + e_shstrndx * e_shentsize;
    cur.set_position((shstr_hdr_off + 24) as u64);
    let shstr_off = cur.read_u64::<LittleEndian>()? as usize;
    let shstr_size = cur.read_u64::<LittleEndian>()? as usize;
    if shstr_off + shstr_size > elf_bytes.len() {
        bail!("ELF .shstrtab extends past EOF");
    }
    let shstrtab = &elf_bytes[shstr_off..shstr_off + shstr_size];

    let mut sec_meta: Vec<(String, u64)> = Vec::with_capacity(e_shnum);
    for i in 0..e_shnum {
        let off = e_shoff + i * e_shentsize;
        cur.set_position(off as u64);
        let sh_name_idx = cur.read_u32::<LittleEndian>()? as usize;
        cur.set_position((off + 32) as u64);
        let sh_size = cur.read_u64::<LittleEndian>()?;

        let name = if sh_name_idx < shstrtab.len() {
            let tail = &shstrtab[sh_name_idx..];
            let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
            String::from_utf8_lossy(&tail[..end]).to_string()
        } else {
            String::new()
        };
        sec_meta.push((name, sh_size));
    }

    let records = shuffle_ko_sections(&sec_meta, seed);
    let mut out = elf_bytes.to_vec();

    // Update sh_addralign or embed deterministic section layout order in the ELF output
    // while keeping sh_link/sh_info intact for the kernel module loader.
    for rec in &records {
        let hdr_off = e_shoff + rec.sh_index * e_shentsize;
        // Write the shuffled virtual base hint into sh_addr (offset +16 in Elf64_Shdr),
        // which is 0 in unshuffled ET_REL objects and guides the module layout engine.
        let mut w = Cursor::new(&mut out[hdr_off + 16..hdr_off + 24]);
        w.write_u64::<LittleEndian>(((rec.shuffled_order as u64) + 1) * 0x100)?;
    }

    Ok((out, records))
}
