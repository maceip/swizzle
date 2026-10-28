// SPDX-License-Identifier: Apache-2.0
//! Runtime table translation and $O(1)$-stack iterative heapsort for `__ex_table`,
//! `.orc_unwind_ip` / `.orc_unwind`, and `kallsyms`, plus address-redacted `%pS` formatting.

use crate::relocs::{translate_orig_to_shuffled_va, SectionEntry};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtableEntry {
    pub insn: i32,
    pub fixup: i32,
    pub data: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OrcEntry {
    pub sp_offset: i16,
    pub bp_offset: i16,
    pub flags: u16,
}

#[inline]
pub fn ex_insn_va(base_va: u64, idx: usize, ex: &[ExtableEntry]) -> u64 {
    let field_va = base_va + (idx as u64) * 12;
    ((field_va as i64) + (ex[idx].insn as i64)) as u64
}

#[inline]
pub fn ex_fixup_va(base_va: u64, idx: usize, ex: &[ExtableEntry]) -> u64 {
    let field_va = base_va + (idx as u64) * 12 + 4;
    ((field_va as i64) + (ex[idx].fixup as i64)) as u64
}

#[inline]
fn swap_ex_entries(base_va: u64, ex: &mut [ExtableEntry], i: usize, j: usize) {
    if i == j {
        return;
    }
    let i_base = base_va + (i as u64) * 12;
    let j_base = base_va + (j as u64) * 12;
    let insn_i = ((i_base as i64) + (ex[i].insn as i64)) as u64;
    let fixup_i = (((i_base + 4) as i64) + (ex[i].fixup as i64)) as u64;
    let insn_j = ((j_base as i64) + (ex[j].insn as i64)) as u64;
    let fixup_j = (((j_base + 4) as i64) + (ex[j].fixup as i64)) as u64;
    let data_i = ex[i].data;

    ex[i].insn = ((insn_j as i64) - (i_base as i64)) as i32;
    ex[i].fixup = ((fixup_j as i64) - ((i_base + 4) as i64)) as i32;
    ex[i].data = ex[j].data;

    ex[j].insn = ((insn_i as i64) - (j_base as i64)) as i32;
    ex[j].fixup = ((fixup_i as i64) - ((j_base + 4) as i64)) as i32;
    ex[j].data = data_i;
}

/// Translates PC-relative `__ex_table` entries across shuffled sections and sorts them in place
/// using the exact iterative $O(N \log N)$ heapsort from `arch/x86/boot/compressed/swizzle.c`.
pub fn update_and_sort_extable(
    base_va: u64,
    ex: &mut [ExtableEntry],
    sections: &[SectionEntry],
) {
    let n = ex.len();
    if n == 0 {
        return;
    }

    for i in 0..n {
        let f_insn = base_va + (i as u64) * 12;
        let f_fixup = f_insn + 4;
        let orig_insn = ((f_insn as i64) + (ex[i].insn as i64)) as u64;
        let orig_fixup = ((f_fixup as i64) + (ex[i].fixup as i64)) as u64;
        let new_insn = translate_orig_to_shuffled_va(sections, orig_insn);
        let new_fixup = translate_orig_to_shuffled_va(sections, orig_fixup);

        ex[i].insn = ((new_insn as i64) - (f_insn as i64)) as i32;
        ex[i].fixup = ((new_fixup as i64) - (f_fixup as i64)) as i32;
    }

    if n <= 1 {
        return;
    }

    for i in (1..=(n / 2)).rev() {
        let mut root = i - 1;
        loop {
            let mut child = 2 * root + 1;
            if child >= n {
                break;
            }
            if child + 1 < n && ex_insn_va(base_va, child, ex) < ex_insn_va(base_va, child + 1, ex)
            {
                child += 1;
            }
            if ex_insn_va(base_va, root, ex) >= ex_insn_va(base_va, child, ex) {
                break;
            }
            swap_ex_entries(base_va, ex, root, child);
            root = child;
        }
    }

    for end in (1..n).rev() {
        let mut root = 0;
        swap_ex_entries(base_va, ex, 0, end);
        loop {
            let mut child = 2 * root + 1;
            if child >= end {
                break;
            }
            if child + 1 < end
                && ex_insn_va(base_va, child, ex) < ex_insn_va(base_va, child + 1, ex)
            {
                child += 1;
            }
            if ex_insn_va(base_va, root, ex) >= ex_insn_va(base_va, child, ex) {
                break;
            }
            swap_ex_entries(base_va, ex, root, child);
            root = child;
        }
    }
}

#[inline]
pub fn orc_ip_va(base_va: u64, idx: usize, ip: &[i32]) -> u64 {
    let field_va = base_va + (idx as u64) * 4;
    ((field_va as i64) + (ip[idx] as i64)) as u64
}

#[inline]
fn swap_orc_entries(base_va: u64, ip: &mut [i32], orc: &mut [OrcEntry], i: usize, j: usize) {
    if i == j {
        return;
    }
    let va_i = orc_ip_va(base_va, i, ip);
    let va_j = orc_ip_va(base_va, j, ip);
    ip[i] = ((va_j as i64) - ((base_va + (i as u64) * 4) as i64)) as i32;
    ip[j] = ((va_i as i64) - ((base_va + (j as u64) * 4) as i64)) as i32;
    orc.swap(i, j);
}

/// Translates PC-relative `.orc_unwind_ip` entries and co-sorts `.orc_unwind` in place.
pub fn update_and_sort_orc(
    ip_base_va: u64,
    ip: &mut [i32],
    orc: &mut [OrcEntry],
    sections: &[SectionEntry],
) {
    let n = ip.len().min(orc.len());
    if n == 0 {
        return;
    }

    for i in 0..n {
        let f_va = ip_base_va + (i as u64) * 4;
        let orig_va = ((f_va as i64) + (ip[i] as i64)) as u64;
        let new_va = translate_orig_to_shuffled_va(sections, orig_va);
        ip[i] = ((new_va as i64) - (f_va as i64)) as i32;
    }

    if n <= 1 {
        return;
    }

    for i in (1..=(n / 2)).rev() {
        let mut root = i - 1;
        loop {
            let mut child = 2 * root + 1;
            if child >= n {
                break;
            }
            if child + 1 < n
                && orc_ip_va(ip_base_va, child, ip) < orc_ip_va(ip_base_va, child + 1, ip)
            {
                child += 1;
            }
            if orc_ip_va(ip_base_va, root, ip) >= orc_ip_va(ip_base_va, child, ip) {
                break;
            }
            swap_orc_entries(ip_base_va, ip, orc, root, child);
            root = child;
        }
    }

    for end in (1..n).rev() {
        let mut root = 0;
        swap_orc_entries(ip_base_va, ip, orc, 0, end);
        loop {
            let mut child = 2 * root + 1;
            if child >= end {
                break;
            }
            if child + 1 < end
                && orc_ip_va(ip_base_va, child, ip) < orc_ip_va(ip_base_va, child + 1, ip)
            {
                child += 1;
            }
            if orc_ip_va(ip_base_va, root, ip) >= orc_ip_va(ip_base_va, child, ip) {
                break;
            }
            swap_orc_entries(ip_base_va, ip, orc, root, child);
            root = child;
        }
    }
}

/// Formats an address as a redacted `kallsyms` string (`function_name+0xoffset/0xsize`),
/// stripping raw hex virtual addresses so stack traces leak zero pointer information.
pub fn format_redacted_symbol(
    rel_base: u64,
    offsets: &[i32],
    sizes: &[u32],
    sorted_idx: &[u32],
    names: &[&str],
    query_va: u64,
) -> String {
    let n = sorted_idx.len();
    if n == 0 {
        return "<redacted-va>".to_string();
    }

    let sym_va = |sym_idx: usize| -> u64 {
        let off = offsets[sym_idx];
        if off >= 0 {
            rel_base + (off as u32 as u64)
        } else {
            rel_base - 1 - ((!off) as u32 as u64)
        }
    };

    let mut lo: isize = 0;
    let mut hi: isize = (n as isize) - 1;
    let mut best: isize = -1;

    while lo <= hi {
        let mid = lo + ((hi - lo) >> 1);
        let sym_idx = sorted_idx[mid as usize] as usize;
        let s_addr = sym_va(sym_idx);
        if query_va < s_addr {
            hi = mid - 1;
        } else {
            best = mid;
            lo = mid + 1;
        }
    }

    if best < 0 {
        return "<redacted-va>".to_string();
    }

    let sym_idx = sorted_idx[best as usize] as usize;
    let s_addr = sym_va(sym_idx);
    let s_size = sizes[sym_idx] as u64;
    let delta = query_va - s_addr;
    if s_size > 0 && delta >= s_size {
        return "<redacted-va>".to_string();
    }

    format!("{}+0x{:x}/0x{:x}", names[sym_idx], delta, s_size)
}
