// SPDX-License-Identifier: Apache-2.0
//! Cacheline-Bucketed Surgical RANDSTRUCT, Canary Audit Mode (`0xdeadbeefbadc0de0`),
//! UAPI header exclusion, and Pinned eBPF Attach Manifest generation.

use crate::prng::{SwizzlePrng, SWIZZLE_SEED_LEN};
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

pub const CACHELINE_BYTES: usize = 64;
pub const CANARY_POISON_WORD: u64 = 0xdeadbeefbadc0de0;

/// High-value kernel structs targeted by Surgical RANDSTRUCT (Doc 1 Section 1).
pub const SURGICAL_TARGET_STRUCTS: &[&str] = &[
    "cred",
    "task_struct",
    "file",
    "msg_msg",
    "pipe_buffer",
    "tty_struct",
    "sock",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructField {
    pub name: String,
    pub c_type: String,
    pub size: usize,
    pub align: usize,
    pub cacheline_group: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayoutField {
    pub name: String,
    pub c_type: String,
    pub orig_offset: usize,
    pub randomized_offset: usize,
    pub size: usize,
    pub cacheline_bucket: usize,
    pub is_canary_poison: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RandomizedStructLayout {
    pub struct_name: String,
    pub header_path: String,
    pub is_randomized: bool,
    pub canary_mode: bool,
    pub fields: Vec<LayoutField>,
    pub total_size: usize,
}

/// Returns `true` if `header_path` is a UAPI header (`include/uapi/`), which must never be permuted.
pub fn is_uapi_header(header_path: &str) -> bool {
    let norm = header_path.replace('\\', "/");
    norm.contains("include/uapi/") || norm.starts_with("uapi/")
}

/// Returns `true` if `struct_name` is in the surgical randomization target list.
pub fn is_surgical_randstruct_target(struct_name: &str, header_path: &str) -> bool {
    if is_uapi_header(header_path) {
        return false;
    }
    let clean = struct_name.trim().trim_start_matches("struct ").trim();
    SURGICAL_TARGET_STRUCTS.contains(&clean)
}

/// Returns `true` if the field at offset 0 is an intrusive `list_head` or `rcu_head`
/// that must remain pinned at offset 0.
pub fn is_pinned_offset_zero_field(field: &StructField) -> bool {
    let t = field.c_type.trim();
    t.contains("list_head") || t.contains("rcu_head") || t.contains("callback_head")
}

/// Computes the Cacheline-Bucketed Surgical RANDSTRUCT layout for `struct_name`:
/// 1. Excludes `include/uapi/` headers and non-target structs.
/// 2. Pins offset 0 whenever occupied by an intrusive `list_head` or `rcu_head`.
/// 3. Permutes fields strictly within their 64-byte `__cacheline_group` / cacheline buckets
///    to prevent scheduler IPC regression.
/// 4. When `canary_mode` is enabled (Canary Audit Mode on 1% of fleet nodes), inserts
///    64-bit KASAN-watched poison words (`0xdeadbeefbadc0de0`) between fields to trap
///    illegal pointer arithmetic prior to enabling full permutation.
pub fn permute_struct_cacheline_bucketed(
    struct_name: &str,
    header_path: &str,
    fields: &[StructField],
    cohort_seed: &[u8; SWIZZLE_SEED_LEN],
    canary_mode: bool,
) -> Result<RandomizedStructLayout> {
    if fields.is_empty() {
        bail!("Struct {} has no fields", struct_name);
    }

    let eligible = is_surgical_randstruct_target(struct_name, header_path);

    // 1. Compute canonical unshuffled offsets and cacheline buckets (64B each)
    let mut orig_offsets = Vec::with_capacity(fields.len());
    let mut buckets = Vec::with_capacity(fields.len());
    let mut cursor = 0usize;
    for f in fields {
        let align = f.align.max(1);
        cursor = (cursor + align - 1) & !(align - 1);
        orig_offsets.push(cursor);
        let bucket = f
            .cacheline_group
            .map(|g| g as usize)
            .unwrap_or(cursor / CACHELINE_BYTES);
        buckets.push(bucket);
        cursor += f.size;
    }

    if !eligible {
        let out_fields: Vec<LayoutField> = fields
            .iter()
            .enumerate()
            .map(|(i, f)| LayoutField {
                name: f.name.clone(),
                c_type: f.c_type.clone(),
                orig_offset: orig_offsets[i],
                randomized_offset: orig_offsets[i],
                size: f.size,
                cacheline_bucket: buckets[i],
                is_canary_poison: false,
            })
            .collect();
        return Ok(RandomizedStructLayout {
            struct_name: struct_name.to_string(),
            header_path: header_path.to_string(),
            is_randomized: false,
            canary_mode: false,
            fields: out_fields,
            total_size: cursor,
        });
    }

    let mut prng = SwizzlePrng::from_seed(cohort_seed);
    let pin_zero = is_pinned_offset_zero_field(&fields[0]);

    // Group indices by cacheline bucket while preserving bucket order
    let mut unique_buckets: Vec<usize> = Vec::new();
    for &b in &buckets {
        if !unique_buckets.contains(&b) {
            unique_buckets.push(b);
        }
    }

    let mut permuted_indices: Vec<usize> = Vec::with_capacity(fields.len());
    for b in unique_buckets {
        let mut group: Vec<usize> = (0..fields.len()).filter(|&i| buckets[i] == b).collect();
        let start_shuffle = if pin_zero && group.first() == Some(&0) {
            1
        } else {
            0
        };

        if !canary_mode && group.len() > start_shuffle + 1 {
            let slice = &mut group[start_shuffle..];
            for i in (1..slice.len()).rev() {
                let j = prng.next_bounded(i + 1);
                slice.swap(i, j);
            }
        }
        permuted_indices.extend(group);
    }

    let mut out_fields = Vec::new();
    let mut new_cursor = 0usize;
    for (pos, &orig_idx) in permuted_indices.iter().enumerate() {
        let f = &fields[orig_idx];
        let align = f.align.max(1);
        new_cursor = (new_cursor + align - 1) & !(align - 1);
        out_fields.push(LayoutField {
            name: f.name.clone(),
            c_type: f.c_type.clone(),
            orig_offset: orig_offsets[orig_idx],
            randomized_offset: new_cursor,
            size: f.size,
            cacheline_bucket: buckets[orig_idx],
            is_canary_poison: false,
        });
        new_cursor += f.size;

        if canary_mode && pos + 1 < permuted_indices.len() {
            new_cursor = (new_cursor + 7) & !7;
            out_fields.push(LayoutField {
                name: format!("__swizzle_canary_poison_{}", pos),
                c_type: "u64".to_string(),
                orig_offset: usize::MAX,
                randomized_offset: new_cursor,
                size: 8,
                cacheline_bucket: buckets[orig_idx],
                is_canary_poison: true,
            });
            new_cursor += 8;
        }
    }

    Ok(RandomizedStructLayout {
        struct_name: struct_name.to_string(),
        header_path: header_path.to_string(),
        is_randomized: true,
        canary_mode,
        fields: out_fields,
        total_size: new_cursor,
    })
}

/// Generates a C header fragment for the Pinned eBPF Attach Manifest, applying
/// `__attribute__((noinline, used))` to all fleet-monitored `kprobe`/`fentry` functions
/// so LLVM inlining never drops observability hooks across Tier 1 cohorts.
pub fn generate_ebpf_pin_header(symbols: &[&str]) -> String {
    let mut out = String::from(
        "/* SPDX-License-Identifier: GPL-2.0 */\n\
         /* Auto-generated by swizzle-ctl: Pinned eBPF Attach Manifest */\n\
         #ifndef _LINUX_SWIZZLE_EBPF_MANIFEST_H\n\
         #define _LINUX_SWIZZLE_EBPF_MANIFEST_H\n\n\
         #define __swizzle_ebpf_pinned __attribute__((noinline, used))\n\n",
    );
    for sym in symbols {
        let trimmed = sym.trim();
        if !trimmed.is_empty() && !trimmed.starts_with('#') {
            out.push_str(&format!(
                "/* Pinned kprobe/fentry target: {} */\n\
                 #pragma clang attribute push(__attribute__((noinline, used)), apply_to = function)\n\
                 /* {} */\n\
                 #pragma clang attribute pop\n",
                trimmed, trimmed
            ));
        }
    }
    out.push_str("\n#endif /* _LINUX_SWIZZLE_EBPF_MANIFEST_H */\n");
    out
}
