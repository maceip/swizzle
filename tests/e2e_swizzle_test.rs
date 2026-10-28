// SPDX-License-Identifier: Apache-2.0
//! Comprehensive end-to-end verification tests for Swizzle (v3):
//! - C `kernel/swizzle_panic.c` RFC 9180 HPKE Sealer <-> Rust `swizzle-ctl` Symbol Vault Decoder
//! - C `arch/x86/boot/compressed/swizzle.c` In-Enclave Early-Boot Section Shuffler, `R_X86_64_*`
//!   Relocator, and Iterative Heapsort (`__ex_table`, `.orc_unwind_ip`, `kallsyms`) <-> Rust Replayer
//! - C `lib/swizzle_kallsyms.c` Address-Redacted `%pS` Stack Trace Formatter
//! - C `mm/swizzle_slab.c` `CONFIG_RANDOM_KMALLOC_CACHES` & `swizzle_slab_jitter` <-> Rust
//! - Cacheline-Bucketed Surgical RANDSTRUCT, Canary Audit Mode (`0xdeadbeefbadc0de0`), UAPI Exclusion,
//!   Frozen VDSO Boundary, and Pinned eBPF Attach Manifest
//! - Out-of-Tree (OOT) `.ko` (`ET_REL`) ELF64 Section Shuffler
//! - Blended Hardware Root of Trust Attestation (AMD SEV-SNP, Intel TDX, TPM 2.0 `kexec`)

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::Cursor;
use std::process::Command;
use swizzle::{
    attest::{
        build_sev_snp_id_block, build_tdx_split_rtmr_manifest, build_tpm2_chained_kexec_ticket,
        verify_sev_snp_attestation, verify_tpm2_chained_kexec_ticket,
    },
    c_bridge::{
        run_c_kallsyms_redact, run_c_kmalloc_cache_index, run_c_relocate_kernel,
        run_c_seal_and_panic, run_c_slab_jitter,
    },
    hpke_vault::{
        decrypt_boot_seed, generate_vault_keypair, parse_panic_log, seal_boot_seed,
        write_gdb_layout_script,
    },
    ko::shuffle_elf64_et_rel_ko,
    randstruct::{
        generate_ebpf_pin_header, is_uapi_header, permute_struct_cacheline_bucketed, StructField,
        CANARY_POISON_WORD,
    },
    relocs::{
        classify_shuffleable_section, compute_section_shuffle, is_frozen_vdso_section,
        resolve_shuffled_rip, translate_orig_to_shuffled_va, PackedRelocs, RelocEntry,
        SectionEntry, INT3_INSN_OPCODE, KERNEL_TEXT_BASE, R_X86_64_32S, R_X86_64_64, R_X86_64_PC32,
        R_X86_64_PLT32, SWIZZLE_DESC_MAGIC, SWIZZLE_RELOC_VERSION, SWIZZLE_SEC_DATA,
        SWIZZLE_SEC_RODATA, SWIZZLE_SEC_TEXT,
    },
    slab::{kmalloc_cache_index, slab_jitter},
    tables::{
        ex_fixup_va, ex_insn_va, format_redacted_symbol, orc_ip_va, update_and_sort_extable,
        update_and_sort_orc, ExtableEntry, OrcEntry,
    },
};

#[test]
fn test_c_kernel_hpke_sealer_to_rust_vault_decoder_interoperability() {
    let (sk, pk) = generate_vault_keypair();
    let cohort_build_id: [u8; 32] = [
        0x8f, 0x9c, 0x2d, 0x11, 0xa0, 0x4e, 0x77, 0xb2, 0x91, 0x04, 0xc8, 0x8d, 0x3a, 0x1f, 0x5e,
        0x60, 0x99, 0xb1, 0xc2, 0xd3, 0xe4, 0xf5, 0xa6, 0xb7, 0xc8, 0xd9, 0xe0, 0xf1, 0xa2, 0xb3,
        0xc4, 0xd5,
    ];
    let boot_seed: [u8; 32] = [
        0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe,
        0x0f, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff, 0x01,
    ];

    // Seal inside the C kernel implementation (kernel/swizzle_panic.c)
    let (panic_log, seed_zeroed) =
        run_c_seal_and_panic(&pk, &cohort_build_id, &boot_seed).expect("C HPKE seal must succeed");

    // 1. Plaintext swizzle_boot_seed must be zeroed via memzero_explicit()
    assert!(
        seed_zeroed,
        "swizzle_boot_seed must be scrubbed to all zeroes after early_initcall sealing"
    );

    // 2. Parse the emitted panic log lines
    let (cohort_hex, envelope_str) =
        parse_panic_log(&panic_log).expect("Panic log must contain Swizzle-Cohort and Swizzle-Envelope");
    assert_eq!(cohort_hex, hex::encode(cohort_build_id));
    assert!(envelope_str.starts_with("hpke:v1:"));

    // 3. Decrypt in Rust using the hpke crate (RFC 9180 Base Mode)
    let recovered = decrypt_boot_seed(&sk, &cohort_build_id, &envelope_str)
        .expect("Rust hpke crate must decrypt C kernel HPKE envelope");
    assert_eq!(recovered, boot_seed);

    // 4. Verify AAD binding: wrong Cohort Build-ID must fail Poly1305 authentication
    let mut wrong_cohort = cohort_build_id;
    wrong_cohort[0] ^= 0xff;
    assert!(
        decrypt_boot_seed(&sk, &wrong_cohort, &envelope_str).is_err(),
        "Tampered Cohort Build-ID AAD must fail AEAD authentication"
    );

    // 5. Also verify Rust seal -> Rust decrypt roundtrip
    let rust_env = seal_boot_seed(&pk, &cohort_build_id, &boot_seed).unwrap();
    let rust_recovered = decrypt_boot_seed(&sk, &cohort_build_id, &rust_env).unwrap();
    assert_eq!(rust_recovered, boot_seed);
}

#[test]
fn test_c_early_boot_relocator_matches_rust_layout_relocs_and_table_sorts() {
    let seed: [u8; 32] = [
        0x7a, 0x1b, 0x9c, 0x4d, 0x2e, 0x8f, 0x05, 0x61, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9a,
        0xab, 0xbc,
    ];

    // Define 3 .text sections, 2 .data sections, 2 .rodata sections (all 16B aligned)
    let sections = vec![
        SectionEntry {
            sec_id: 0,
            flags: SWIZZLE_SEC_TEXT,
            orig_addr: KERNEL_TEXT_BASE + 0x000,
            size: 0x100,
            shuffled_addr: KERNEL_TEXT_BASE + 0x000,
        },
        SectionEntry {
            sec_id: 1,
            flags: SWIZZLE_SEC_TEXT,
            orig_addr: KERNEL_TEXT_BASE + 0x100,
            size: 0x120,
            shuffled_addr: KERNEL_TEXT_BASE + 0x100,
        },
        SectionEntry {
            sec_id: 2,
            flags: SWIZZLE_SEC_TEXT,
            orig_addr: KERNEL_TEXT_BASE + 0x220,
            size: 0x0e0,
            shuffled_addr: KERNEL_TEXT_BASE + 0x220,
        },
        SectionEntry {
            sec_id: 3,
            flags: SWIZZLE_SEC_DATA,
            orig_addr: KERNEL_TEXT_BASE + 0x1000,
            size: 0x80,
            shuffled_addr: KERNEL_TEXT_BASE + 0x1000,
        },
        SectionEntry {
            sec_id: 4,
            flags: SWIZZLE_SEC_DATA,
            orig_addr: KERNEL_TEXT_BASE + 0x1080,
            size: 0x80,
            shuffled_addr: KERNEL_TEXT_BASE + 0x1080,
        },
        SectionEntry {
            sec_id: 5,
            flags: SWIZZLE_SEC_RODATA,
            orig_addr: KERNEL_TEXT_BASE + 0x1800,
            size: 0x80,
            shuffled_addr: KERNEL_TEXT_BASE + 0x1800,
        },
        SectionEntry {
            sec_id: 6,
            flags: SWIZZLE_SEC_RODATA,
            orig_addr: KERNEL_TEXT_BASE + 0x1880,
            size: 0x80,
            shuffled_addr: KERNEL_TEXT_BASE + 0x1880,
        },
    ];

    // Relocations:
    // 1) R_X86_64_PC32 inside .text sec 0 (at +0x10) targeting .text sec 2 (+0x20), addend = -4
    // 2) R_X86_64_PLT32 inside .text sec 1 (at +0x140) targeting .text sec 0 (+0x08), addend = -4
    // 3) R_X86_64_64 inside .data sec 3 (at +0x1000) targeting .text sec 1 (+0x110), addend = 0
    // 4) R_X86_64_32S inside .rodata sec 5 (at +0x1800) targeting .data sec 4 (+0x1090), addend = 0
    let p_pc32 = KERNEL_TEXT_BASE + 0x010;
    let s_pc32 = KERNEL_TEXT_BASE + 0x220 + 0x20;
    let init_disp_pc32 = ((s_pc32 as i64) + (-4) - (p_pc32 as i64)) as i32;

    let p_plt32 = KERNEL_TEXT_BASE + 0x140;
    let s_plt32 = KERNEL_TEXT_BASE + 0x008;
    let init_disp_plt32 = ((s_plt32 as i64) + (-4) - (p_plt32 as i64)) as i32;

    let p_abs64 = KERNEL_TEXT_BASE + 0x1000;
    let s_abs64 = KERNEL_TEXT_BASE + 0x110;

    let p_abs32s = KERNEL_TEXT_BASE + 0x1800;
    let s_abs32s = KERNEL_TEXT_BASE + 0x1090;
    let init_val_32s = (s_abs32s as i64) as i32;

    let relocs = vec![
        RelocEntry {
            r_offset: p_pc32,
            r_addend: -4,
            sym_sec_id: 2,
            r_type: R_X86_64_PC32,
        },
        RelocEntry {
            r_offset: p_plt32,
            r_addend: -4,
            sym_sec_id: 0,
            r_type: R_X86_64_PLT32,
        },
        RelocEntry {
            r_offset: p_abs64,
            r_addend: 0,
            sym_sec_id: 1,
            r_type: R_X86_64_64,
        },
        RelocEntry {
            r_offset: p_abs32s,
            r_addend: 0,
            sym_sec_id: 4,
            r_type: R_X86_64_32S,
        },
    ];

    let packed = PackedRelocs {
        version: SWIZZLE_RELOC_VERSION,
        sections: sections.clone(),
        relocs,
    };
    let swzl_bytes = packed.to_bytes().unwrap();

    // Build synthetic decompressed vmlinux image (size = 0x5000)
    let image_size = 0x5000usize;
    let mut image = vec![0u8; image_size];

    // Tag each section with recognizable signature bytes
    for s in &sections {
        let off = (s.orig_addr - KERNEL_TEXT_BASE) as usize;
        for b in 0..(s.size as usize) {
            image[off + b] = ((s.sec_id as u8).wrapping_mul(37)).wrapping_add(b as u8);
        }
    }

    // Write pre-linked relocation values at their original addresses
    {
        let off = (p_pc32 - KERNEL_TEXT_BASE) as usize;
        image[off..off + 4].copy_from_slice(&init_disp_pc32.to_le_bytes());

        let off = (p_plt32 - KERNEL_TEXT_BASE) as usize;
        image[off..off + 4].copy_from_slice(&init_disp_plt32.to_le_bytes());

        let off = (p_abs64 - KERNEL_TEXT_BASE) as usize;
        image[off..off + 8].copy_from_slice(&s_abs64.to_le_bytes());

        let off = (p_abs32s - KERNEL_TEXT_BASE) as usize;
        image[off..off + 4].copy_from_slice(&init_val_32s.to_le_bytes());
    }

    // Populate __ex_table at offset 0x2000 (3 entries pointing into .text sec 0, 1, 2)
    let extable_off = 0x2000usize;
    let extable_va = KERNEL_TEXT_BASE + (extable_off as u64);
    let orig_ex_targets = [
        (KERNEL_TEXT_BASE + 0x040, KERNEL_TEXT_BASE + 0x080, 101i32),
        (KERNEL_TEXT_BASE + 0x150, KERNEL_TEXT_BASE + 0x190, 202i32),
        (KERNEL_TEXT_BASE + 0x240, KERNEL_TEXT_BASE + 0x280, 303i32),
    ];
    let mut rust_ex_entries = Vec::new();
    for (i, &(insn_va, fixup_va, data)) in orig_ex_targets.iter().enumerate() {
        let entry_va = extable_va + (i as u64) * 12;
        let insn_rel = ((insn_va as i64) - (entry_va as i64)) as i32;
        let fixup_rel = ((fixup_va as i64) - ((entry_va + 4) as i64)) as i32;
        rust_ex_entries.push(ExtableEntry {
            insn: insn_rel,
            fixup: fixup_rel,
            data,
        });
        let pos = extable_off + i * 12;
        image[pos..pos + 4].copy_from_slice(&insn_rel.to_le_bytes());
        image[pos + 4..pos + 8].copy_from_slice(&fixup_rel.to_le_bytes());
        image[pos + 8..pos + 12].copy_from_slice(&data.to_le_bytes());
    }
    let extable_stop_va = extable_va + (orig_ex_targets.len() as u64) * 12;

    // Populate .orc_unwind_ip at 0x2200 and .orc_unwind at 0x2300 (3 entries)
    let orc_ip_off = 0x2200usize;
    let orc_ip_va_base = KERNEL_TEXT_BASE + (orc_ip_off as u64);
    let orc_entry_off = 0x2300usize;
    let orc_entry_va_base = KERNEL_TEXT_BASE + (orc_entry_off as u64);
    let orig_orc_targets = [
        (KERNEL_TEXT_BASE + 0x020, OrcEntry { sp_offset: 8, bp_offset: -16, flags: 1 }),
        (KERNEL_TEXT_BASE + 0x120, OrcEntry { sp_offset: 16, bp_offset: -24, flags: 2 }),
        (KERNEL_TEXT_BASE + 0x230, OrcEntry { sp_offset: 24, bp_offset: -32, flags: 3 }),
    ];
    let mut rust_orc_ips = Vec::new();
    let mut rust_orc_entries = Vec::new();
    for (i, &(code_va, orc_ent)) in orig_orc_targets.iter().enumerate() {
        let ip_slot_va = orc_ip_va_base + (i as u64) * 4;
        let rel = ((code_va as i64) - (ip_slot_va as i64)) as i32;
        rust_orc_ips.push(rel);
        rust_orc_entries.push(orc_ent);

        let ip_pos = orc_ip_off + i * 4;
        image[ip_pos..ip_pos + 4].copy_from_slice(&rel.to_le_bytes());

        let ent_pos = orc_entry_off + i * 6;
        image[ent_pos..ent_pos + 2].copy_from_slice(&orc_ent.sp_offset.to_le_bytes());
        image[ent_pos + 2..ent_pos + 4].copy_from_slice(&orc_ent.bp_offset.to_le_bytes());
        image[ent_pos + 4..ent_pos + 6].copy_from_slice(&orc_ent.flags.to_le_bytes());
    }
    let orc_ip_stop_va = orc_ip_va_base + (orig_orc_targets.len() as u64) * 4;

    // Populate kallsyms tables at 0x2500
    let kallsyms_offsets_off = 0x2500usize;
    let kallsyms_num_off = 0x2580usize;
    let kallsyms_rel_base_off = 0x2588usize;
    let kallsyms_sorted_idx_off = 0x2600usize;
    let orig_sym_offsets: [i32; 3] = [0x000, 0x100, 0x220];
    for (i, &off_val) in orig_sym_offsets.iter().enumerate() {
        let pos = kallsyms_offsets_off + i * 4;
        image[pos..pos + 4].copy_from_slice(&off_val.to_le_bytes());
    }
    image[kallsyms_num_off..kallsyms_num_off + 4].copy_from_slice(&3u32.to_le_bytes());
    image[kallsyms_rel_base_off..kallsyms_rel_base_off + 8]
        .copy_from_slice(&KERNEL_TEXT_BASE.to_le_bytes());

    // Place SWZL packed relocs at 0x3000 and boot_seed at 0x3800
    let relocs_off = 0x3000usize;
    image[relocs_off..relocs_off + swzl_bytes.len()].copy_from_slice(&swzl_bytes);
    let boot_seed_off = 0x3800usize;

    // Place SWZLDESC at 0x4000 (8-byte aligned)
    let desc_off = 0x4000usize;
    let desc_fields: [u64; 15] = [
        SWIZZLE_DESC_MAGIC,
        KERNEL_TEXT_BASE,
        KERNEL_TEXT_BASE + (image_size as u64),
        KERNEL_TEXT_BASE + (relocs_off as u64),
        KERNEL_TEXT_BASE + ((relocs_off + swzl_bytes.len()) as u64),
        KERNEL_TEXT_BASE + (boot_seed_off as u64),
        extable_va,
        extable_stop_va,
        orc_ip_va_base,
        orc_ip_stop_va,
        orc_entry_va_base,
        KERNEL_TEXT_BASE + (kallsyms_offsets_off as u64),
        KERNEL_TEXT_BASE + (kallsyms_num_off as u64),
        KERNEL_TEXT_BASE + (kallsyms_rel_base_off as u64),
        KERNEL_TEXT_BASE + (kallsyms_sorted_idx_off as u64),
    ];
    for (idx, val) in desc_fields.iter().enumerate() {
        let pos = desc_off + idx * 8;
        image[pos..pos + 8].copy_from_slice(&val.to_le_bytes());
    }

    // Run C early-boot relocator!
    let mut scratch = vec![0xaa_u8; 0x10000];
    run_c_relocate_kernel(&mut image, &mut scratch, Some(&seed));

    // Compute expected layout in Rust
    let mut expected_secs = sections.clone();
    compute_section_shuffle(&mut expected_secs, &seed);

    // 1. Verify swizzle_boot_seed was written into the image
    assert_eq!(&image[boot_seed_off..boot_seed_off + 32], &seed);

    // 2. Verify SWZL relocation table and scratch area were scrubbed to 0 via swizzle_memzero_explicit()
    assert!(
        image[relocs_off..relocs_off + swzl_bytes.len()]
            .iter()
            .all(|&b| b == 0),
        "C stub must scrub .init.swizzle_relocs table via swizzle_memzero_explicit"
    );
    assert!(
        scratch.iter().all(|&b| b == 0),
        "C stub must scrub temporary scratch_area via swizzle_memzero_explicit"
    );

    // 3. Verify every section's non-relocated bytes moved to the exact shuffled_addr predicted by Rust
    for s in &expected_secs {
        let shuf_off = (s.shuffled_addr - KERNEL_TEXT_BASE) as usize;
        // Check byte at +0x60 (untouched by our 4 relocations)
        let expected_byte = ((s.sec_id as u8).wrapping_mul(37)).wrapping_add(0x60);
        assert_eq!(
            image[shuf_off + 0x60],
            expected_byte,
            "Section #{} contents at shuffled_addr 0x{:x} must match Rust replay",
            s.sec_id,
            s.shuffled_addr
        );
    }

    // 4. Verify all 4 relocation types (R_X86_64_PC32, R_X86_64_PLT32, R_X86_64_64, R_X86_64_32S)
    let new_p_pc32 = translate_orig_to_shuffled_va(&expected_secs, p_pc32);
    let new_s_pc32 = translate_orig_to_shuffled_va(&expected_secs, s_pc32);
    let actual_disp_pc32 = (&image[(new_p_pc32 - KERNEL_TEXT_BASE) as usize..])
        .read_i32::<LittleEndian>()
        .unwrap();
    let expected_disp_pc32 = ((new_s_pc32 as i64) - 4 - (new_p_pc32 as i64)) as i32;
    assert_eq!(actual_disp_pc32, expected_disp_pc32, "R_X86_64_PC32 relocation mismatch");

    let new_p_plt32 = translate_orig_to_shuffled_va(&expected_secs, p_plt32);
    let new_s_plt32 = translate_orig_to_shuffled_va(&expected_secs, s_plt32);
    let actual_disp_plt32 = (&image[(new_p_plt32 - KERNEL_TEXT_BASE) as usize..])
        .read_i32::<LittleEndian>()
        .unwrap();
    let expected_disp_plt32 = ((new_s_plt32 as i64) - 4 - (new_p_plt32 as i64)) as i32;
    assert_eq!(actual_disp_plt32, expected_disp_plt32, "R_X86_64_PLT32 relocation mismatch");

    let new_p_abs64 = translate_orig_to_shuffled_va(&expected_secs, p_abs64);
    let new_s_abs64 = translate_orig_to_shuffled_va(&expected_secs, s_abs64);
    let actual_abs64 = (&image[(new_p_abs64 - KERNEL_TEXT_BASE) as usize..])
        .read_u64::<LittleEndian>()
        .unwrap();
    assert_eq!(actual_abs64, new_s_abs64, "R_X86_64_64 relocation mismatch");

    let new_p_abs32s = translate_orig_to_shuffled_va(&expected_secs, p_abs32s);
    let new_s_abs32s = translate_orig_to_shuffled_va(&expected_secs, s_abs32s);
    let actual_abs32s = (&image[(new_p_abs32s - KERNEL_TEXT_BASE) as usize..])
        .read_i32::<LittleEndian>()
        .unwrap();
    assert_eq!(actual_abs32s, new_s_abs32s as i32, "R_X86_64_32S relocation mismatch");

    // 5. Verify __ex_table in-place translation and heapsort matches Rust
    update_and_sort_extable(extable_va, &mut rust_ex_entries, &expected_secs);
    let mut prev_insn_va = 0u64;
    for i in 0..3 {
        let pos = extable_off + i * 12;
        let c_insn = (&image[pos..pos + 4]).read_i32::<LittleEndian>().unwrap();
        let c_fixup = (&image[pos + 4..pos + 8]).read_i32::<LittleEndian>().unwrap();
        let c_data = (&image[pos + 8..pos + 12]).read_i32::<LittleEndian>().unwrap();
        assert_eq!(
            ExtableEntry {
                insn: c_insn,
                fixup: c_fixup,
                data: c_data
            },
            rust_ex_entries[i],
            "__ex_table entry {} mismatch between C and Rust heapsort",
            i
        );
        let cur_va = ex_insn_va(extable_va, i, &rust_ex_entries);
        let cur_fix = ex_fixup_va(extable_va, i, &rust_ex_entries);
        assert!(cur_va > prev_insn_va, "__ex_table must be strictly sorted ascending");
        assert!(cur_fix >= KERNEL_TEXT_BASE);
        prev_insn_va = cur_va;
    }

    // 6. Verify .orc_unwind_ip and .orc_unwind co-sorting matches Rust
    update_and_sort_orc(
        orc_ip_va_base,
        &mut rust_orc_ips,
        &mut rust_orc_entries,
        &expected_secs,
    );
    let mut prev_orc_va = 0u64;
    for i in 0..3 {
        let ip_pos = orc_ip_off + i * 4;
        let c_ip = (&image[ip_pos..ip_pos + 4]).read_i32::<LittleEndian>().unwrap();
        let ent_pos = orc_entry_off + i * 6;
        let c_sp = (&image[ent_pos..ent_pos + 2]).read_i16::<LittleEndian>().unwrap();
        let c_bp = (&image[ent_pos + 2..ent_pos + 4]).read_i16::<LittleEndian>().unwrap();
        let c_fl = (&image[ent_pos + 4..ent_pos + 6]).read_u16::<LittleEndian>().unwrap();
        assert_eq!(c_ip, rust_orc_ips[i]);
        assert_eq!(
            OrcEntry {
                sp_offset: c_sp,
                bp_offset: c_bp,
                flags: c_fl
            },
            rust_orc_entries[i]
        );
        let cur_va = orc_ip_va(orc_ip_va_base, i, &rust_orc_ips);
        assert!(cur_va > prev_orc_va, ".orc_unwind_ip must be sorted ascending");
        prev_orc_va = cur_va;
    }

    // 7. Verify kallsyms in-place offset update, sorted_idx ordering, and redacted %pS formatting
    let mut c_offsets = [0i32; 3];
    let mut c_sorted_idx = [0u32; 3];
    for i in 0..3 {
        let pos = kallsyms_offsets_off + i * 4;
        c_offsets[i] = (&image[pos..pos + 4]).read_i32::<LittleEndian>().unwrap();
        let idx_pos = kallsyms_sorted_idx_off + i * 4;
        c_sorted_idx[i] = (&image[idx_pos..idx_pos + 4]).read_u32::<LittleEndian>().unwrap();
    }
    assert!(
        c_offsets[c_sorted_idx[0] as usize] <= c_offsets[c_sorted_idx[1] as usize]
            && c_offsets[c_sorted_idx[1] as usize] <= c_offsets[c_sorted_idx[2] as usize],
        "swizzle_kallsyms_addr_idx must sort kallsyms_offsets ascending"
    );

    let sym_names = ["do_syscall_64", "tcp_v4_rcv", "schedule"];
    let sym_sizes = [0x100u32, 0x120u32, 0x0e0u32];
    let tcp_shuffled_va = expected_secs[1].shuffled_addr + 0x84;
    let c_redacted = run_c_kallsyms_redact(
        KERNEL_TEXT_BASE,
        &c_offsets,
        &sym_sizes,
        &c_sorted_idx,
        &sym_names,
        tcp_shuffled_va,
    );
    let rust_redacted = format_redacted_symbol(
        KERNEL_TEXT_BASE,
        &c_offsets,
        &sym_sizes,
        &c_sorted_idx,
        &sym_names,
        tcp_shuffled_va,
    );
    assert_eq!(c_redacted, "tcp_v4_rcv+0x84/0x120");
    assert_eq!(rust_redacted, "tcp_v4_rcv+0x84/0x120");
    assert!(
        !c_redacted.contains("ffffffff81"),
        "Redacted kallsyms output must never leak raw kernel virtual addresses"
    );

    // 8. Verify RIP resolution back to canonical vmlinux address
    let (resolved_sec, delta, canonical_va) =
        resolve_shuffled_rip(&expected_secs, tcp_shuffled_va).expect("Must resolve shuffled RIP");
    assert_eq!(resolved_sec.sec_id, 1);
    assert_eq!(delta, 0x84);
    assert_eq!(canonical_va, KERNEL_TEXT_BASE + 0x100 + 0x84);
    assert_eq!(INT3_INSN_OPCODE, 0xcc);
}

#[test]
fn test_surgical_randstruct_cacheline_buckets_canary_and_boundaries() {
    let seed = [0x55u8; 32];
    let fields = vec![
        StructField {
            name: "rcu".to_string(),
            c_type: "struct rcu_head".to_string(),
            size: 16,
            align: 8,
            cacheline_group: Some(0),
        },
        StructField {
            name: "uid".to_string(),
            c_type: "kuid_t".to_string(),
            size: 4,
            align: 4,
            cacheline_group: Some(0),
        },
        StructField {
            name: "gid".to_string(),
            c_type: "kgid_t".to_string(),
            size: 4,
            align: 4,
            cacheline_group: Some(0),
        },
        StructField {
            name: "suid".to_string(),
            c_type: "kuid_t".to_string(),
            size: 4,
            align: 4,
            cacheline_group: Some(0),
        },
        StructField {
            name: "sgid".to_string(),
            c_type: "kgid_t".to_string(),
            size: 4,
            align: 4,
            cacheline_group: Some(0),
        },
        StructField {
            name: "security".to_string(),
            c_type: "void *".to_string(),
            size: 8,
            align: 8,
            cacheline_group: Some(1),
        },
        StructField {
            name: "user_ns".to_string(),
            c_type: "struct user_namespace *".to_string(),
            size: 8,
            align: 8,
            cacheline_group: Some(1),
        },
    ];

    // 1. Surgical target struct (`cred`): offset 0 (`rcu_head`) must stay pinned at offset 0,
    //    and fields must stay within their cacheline bucket (0 vs 1).
    let layout = permute_struct_cacheline_bucketed(
        "cred",
        "include/linux/cred.h",
        &fields,
        &seed,
        false,
    )
    .unwrap();
    assert!(layout.is_randomized);
    assert_eq!(layout.fields[0].name, "rcu");
    assert_eq!(layout.fields[0].randomized_offset, 0);
    for f in &layout.fields[..5] {
        assert_eq!(f.cacheline_bucket, 0);
    }
    for f in &layout.fields[5..] {
        assert_eq!(f.cacheline_bucket, 1);
    }

    // 2. UAPI headers (`include/uapi/...`) must NEVER be randomized
    assert!(is_uapi_header("include/uapi/linux/bpf.h"));
    let uapi_layout = permute_struct_cacheline_bucketed(
        "cred",
        "include/uapi/linux/cred.h",
        &fields,
        &seed,
        false,
    )
    .unwrap();
    assert!(!uapi_layout.is_randomized);

    // 3. Canary Audit Mode must inject 64-bit KASAN poison words (0xdeadbeefbadc0de0)
    assert_eq!(CANARY_POISON_WORD, 0xdeadbeefbadc0de0);
    let canary_layout = permute_struct_cacheline_bucketed(
        "cred",
        "include/linux/cred.h",
        &fields,
        &seed,
        true,
    )
    .unwrap();
    assert!(canary_layout.canary_mode);
    assert!(canary_layout.fields.iter().any(|f| f.is_canary_poison));

    // 4. Frozen VDSO exclusion & Pinned eBPF Attach Manifest
    assert!(is_frozen_vdso_section(".text.vdso_gettimeofday"));
    assert_eq!(classify_shuffleable_section(".text.vdso_gettimeofday"), None);
    assert_eq!(
        classify_shuffleable_section(".text.tcp_v4_rcv"),
        Some(SWIZZLE_SEC_TEXT)
    );
    let ebpf_hdr = generate_ebpf_pin_header(&["tcp_v4_rcv", "security_file_open"]);
    assert!(ebpf_hdr.contains("__attribute__((noinline, used))"));
    assert!(ebpf_hdr.contains("tcp_v4_rcv"));
}

#[test]
fn test_c_and_rust_slab_diversification_match_bit_for_bit() {
    let hw_seed = 0xfeedfacecafebeef_u64;
    for step in 0..32u64 {
        let ret_ip = KERNEL_TEXT_BASE + step * 0x73;
        let size = ((step as usize) + 1) * 32;
        let c_idx = run_c_kmalloc_cache_index(ret_ip, size, hw_seed);
        let r_idx = kmalloc_cache_index(ret_ip, size, hw_seed);
        assert_eq!(c_idx, r_idx, "kmalloc cache index must match between C and Rust");
        assert!(c_idx < 16);
    }

    let (c_order, c_pinned) = run_c_slab_jitter(32, hw_seed);
    let (r_order, r_pinned) = slab_jitter(32, hw_seed);
    assert_eq!(c_order, r_order, "swizzle_slab_jitter freelist order must match between C and Rust");
    assert_eq!(c_pinned, r_pinned, "swizzle_slab_jitter pinned dummy count must match");
    assert!((1..=4).contains(&c_pinned));
}

#[test]
fn test_oot_ko_et_rel_module_shuffler() {
    // Construct a minimal valid 64-bit ET_REL ELF (.ko) with 4 sections:
    // 0: NULL, 1: .shstrtab, 2: .text.drv_init, 3: .text.drv_rx, 4: .text.drv_tx
    let shstrtab = b"\0.shstrtab\0.text.drv_init\0.text.drv_rx\0.text.drv_tx\0";
    let shstr_off = 64usize;
    let shstr_len = shstrtab.len();
    let shoff = (shstr_off + shstr_len + 7) & !7;
    let shentsize = 64usize;
    let shnum = 5usize;

    let mut elf = vec![0u8; shoff + shnum * shentsize];
    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2; // ELFCLASS64
    elf[5] = 1; // ELFDATA2LSB
    elf[6] = 1; // EV_CURRENT
    (&mut elf[16..18]).write_u16::<LittleEndian>(1).unwrap(); // ET_REL = 1
    (&mut elf[18..20]).write_u16::<LittleEndian>(62).unwrap(); // EM_X86_64
    (&mut elf[40..48])
        .write_u64::<LittleEndian>(shoff as u64)
        .unwrap();
    (&mut elf[58..60])
        .write_u16::<LittleEndian>(shentsize as u16)
        .unwrap();
    (&mut elf[60..62])
        .write_u16::<LittleEndian>(shnum as u16)
        .unwrap();
    (&mut elf[62..64]).write_u16::<LittleEndian>(1).unwrap(); // e_shstrndx = 1
    elf[shstr_off..shstr_off + shstr_len].copy_from_slice(shstrtab);

    let sec_defs = [
        (0u32, 0u64, 0u64),
        (1u32, shstr_off as u64, shstr_len as u64),
        (11u32, 0u64, 0x80u64),
        (26u32, 0u64, 0x90u64),
        (39u32, 0u64, 0xa0u64),
    ];
    for (i, &(name_off, off, sz)) in sec_defs.iter().enumerate() {
        let base = shoff + i * shentsize;
        let mut cur = Cursor::new(&mut elf[base..base + shentsize]);
        cur.write_u32::<LittleEndian>(name_off).unwrap();
        cur.set_position(24);
        cur.write_u64::<LittleEndian>(off).unwrap();
        cur.write_u64::<LittleEndian>(sz).unwrap();
    }

    let seed = [0x99u8; 32];
    let (shuffled_ko, records) = shuffle_elf64_et_rel_ko(&elf, &seed).unwrap();
    assert_eq!(records.len(), 3);
    assert_eq!(shuffled_ko.len(), elf.len());
}

#[test]
fn test_blended_hardware_root_of_trust_attestation() {
    let author_key = [0x77u8; 32];
    let uki = b"SWIZZLE-COHORT-42-SIGNED-UKI";

    // 1. AMD SEV-SNP ID_BLOCK
    let snp = build_sev_snp_id_block("cohort-0042", uki, &author_key, 42);
    assert!(verify_sev_snp_attestation(&snp, &snp.author_key_digest, 42, &author_key).is_ok());
    assert!(
        verify_sev_snp_attestation(&snp, &snp.author_key_digest, 43, &author_key).is_err(),
        "Rollback below min_svn must be rejected"
    );

    // 2. Intel TDX Split-RTMR
    let tdx = build_tdx_split_rtmr_manifest("cohort-0042", b"TDX-SHIM-64KB", uki, 42);
    assert_eq!(tdx.guest_svn, 42);
    assert_ne!(tdx.rtmr1_shim_hash, tdx.rtmr3_uki_hash);

    // 3. TPM 2.0 Chained kexec_file_load Ticket
    let pcr4_curr = [0x22u8; 32];
    let ticket = build_tpm2_chained_kexec_ticket(&pcr4_curr, uki, &author_key);
    assert!(verify_tpm2_chained_kexec_ticket(&ticket, &author_key).is_ok());
}

#[test]
fn test_swizzle_ctl_cli_end_to_end_workflow() {
    let bin = env!("CARGO_BIN_EXE_swizzle-ctl");
    let tmp_dir = std::env::temp_dir().join(format!("swizzle_test_{}", std::process::id()));
    std::fs::create_dir_all(&tmp_dir).unwrap();

    let pub_path = tmp_dir.join("vault_pubkey.bin");
    let priv_path = tmp_dir.join("vault_privkey.hex");
    let relocs_path = tmp_dir.join("packed_relocs.bin");
    let gdb_path = tmp_dir.join("swizzle-layout.gdb");

    // 1. swizzle-ctl keygen
    let status = Command::new(bin)
        .args([
            "keygen",
            "--pub-out",
            pub_path.to_str().unwrap(),
            "--priv-out",
            priv_path.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(std::fs::metadata(&pub_path).unwrap().len(), 32);

    // 2. swizzle-ctl pack-relocs
    let status = Command::new(bin)
        .args(["pack-relocs", "--out", relocs_path.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success());

    // 3. Seal a boot seed using the C kernel implementation against vault_pubkey.bin
    let mut pub_bytes = [0u8; 32];
    pub_bytes.copy_from_slice(&std::fs::read(&pub_path).unwrap());
    let cohort_id = [0x8fu8; 32];
    let boot_seed = [0x4au8; 32];
    let (panic_log, _) = run_c_seal_and_panic(&pub_bytes, &cohort_id, &boot_seed).unwrap();
    let (cohort_hex, envelope_str) = parse_panic_log(&panic_log).unwrap();

    // 4. swizzle-ctl debug
    let output = Command::new(bin)
        .args([
            "debug",
            "--cohort",
            &cohort_hex,
            "--envelope",
            &envelope_str,
            "--priv-key",
            priv_path.to_str().unwrap(),
            "--relocs-bin",
            relocs_path.to_str().unwrap(),
            "--rip",
            "0xffffffff81000484",
            "--gdb-out",
            gdb_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(&hex::encode(boot_seed)));
    assert!(stdout.contains("Faulting RIP"));
    assert!(gdb_path.exists());

    // 5. swizzle-ctl self-test
    let status = Command::new(bin).arg("self-test").status().unwrap();
    assert!(status.success());

    let _ = write_gdb_layout_script(&gdb_path, &cohort_hex, &[]);
    let _ = std::fs::remove_dir_all(&tmp_dir);
}
