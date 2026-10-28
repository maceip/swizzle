// SPDX-License-Identifier: Apache-2.0
//! FFI bridge to the compiled C kernel implementations in:
//! - `kernel/arch/x86/boot/compressed/swizzle.c`
//! - `kernel/kernel/swizzle_panic.c`
//! - `kernel/lib/swizzle_kallsyms.c`
//! - `kernel/mm/swizzle_slab.c`

use anyhow::{bail, Result};
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_ulong};

extern "C" {
    fn swizzle_c_relocate_kernel_with_seed(
        output: *mut u8,
        output_len: c_ulong,
        scratch_area: *mut u8,
        scratch_len: c_ulong,
        opt_seed_32: *const u8,
    );

    fn swizzle_c_seal_and_panic(
        pubkey: *const u8,
        build_id: *const u8,
        boot_seed: *const u8,
        out_log: *mut c_char,
        out_log_cap: usize,
        seed_zeroed_out: *mut c_int,
    ) -> c_int;

    fn swizzle_c_test_kallsyms_redact(
        rel_base: u64,
        num_syms: u32,
        offsets: *const i32,
        sizes: *const u32,
        sorted_idx: *const u32,
        names: *const *const c_char,
        query_addr: u64,
        out_buf: *mut c_char,
        out_cap: usize,
    ) -> c_int;

    fn swizzle_kmalloc_seed_init(hw_seed: u64);
    fn swizzle_kmalloc_cache_index(caller_ret_ip: c_ulong, size: usize) -> u32;
    fn swizzle_slab_jitter(freelist_order: *mut u32, num_objects: u32, jitter_seed: u64) -> u32;
}

/// Invokes the C `swizzle_relocate_kernel()` implementation from `arch/x86/boot/compressed/swizzle.c`
/// on a decompressed kernel image buffer in RAM.
pub fn run_c_relocate_kernel(
    image_buf: &mut [u8],
    scratch_buf: &mut [u8],
    opt_seed: Option<&[u8; 32]>,
) {
    let seed_ptr = opt_seed.map(|s| s.as_ptr()).unwrap_or(std::ptr::null());
    unsafe {
        swizzle_c_relocate_kernel_with_seed(
            image_buf.as_mut_ptr(),
            image_buf.len() as c_ulong,
            scratch_buf.as_mut_ptr(),
            scratch_buf.len() as c_ulong,
            seed_ptr,
        );
    }
}

/// Invokes the C `swizzle_seal_boot_seed_init()` and `swizzle_panic_notify()` in `kernel/swizzle_panic.c`,
/// returning `(panic_log_output, was_plaintext_seed_scrubbed)`.
pub fn run_c_seal_and_panic(
    pubkey: &[u8; 32],
    build_id: &[u8; 32],
    boot_seed: &[u8; 32],
) -> Result<(String, bool)> {
    let mut log_buf = vec![0u8; 2048];
    let mut seed_zeroed: c_int = 0;

    let rc = unsafe {
        swizzle_c_seal_and_panic(
            pubkey.as_ptr(),
            build_id.as_ptr(),
            boot_seed.as_ptr(),
            log_buf.as_mut_ptr() as *mut c_char,
            log_buf.len(),
            &mut seed_zeroed,
        )
    };
    if rc != 0 {
        bail!("swizzle_c_seal_and_panic failed with rc={}", rc);
    }

    let c_str = unsafe { CStr::from_ptr(log_buf.as_ptr() as *const c_char) };
    Ok((c_str.to_string_lossy().into_owned(), seed_zeroed != 0))
}

/// Invokes the C `swizzle_sprint_symbol_redacted()` in `kernel/lib/swizzle_kallsyms.c`.
pub fn run_c_kallsyms_redact(
    rel_base: u64,
    offsets: &[i32],
    sizes: &[u32],
    sorted_idx: &[u32],
    names: &[&str],
    query_addr: u64,
) -> String {
    let n = offsets
        .len()
        .min(sizes.len())
        .min(sorted_idx.len())
        .min(names.len());
    let c_strings: Vec<CString> = names[..n]
        .iter()
        .map(|&s| CString::new(s).unwrap())
        .collect();
    let c_ptrs: Vec<*const c_char> = c_strings.iter().map(|cs| cs.as_ptr()).collect();
    let mut out_buf = vec![0u8; 256];

    unsafe {
        swizzle_c_test_kallsyms_redact(
            rel_base,
            n as u32,
            offsets.as_ptr(),
            sizes.as_ptr(),
            sorted_idx.as_ptr(),
            c_ptrs.as_ptr(),
            query_addr,
            out_buf.as_mut_ptr() as *mut c_char,
            out_buf.len(),
        );
        CStr::from_ptr(out_buf.as_ptr() as *const c_char)
            .to_string_lossy()
            .into_owned()
    }
}

/// Invokes the C `swizzle_kmalloc_cache_index()` in `kernel/mm/swizzle_slab.c`.
pub fn run_c_kmalloc_cache_index(caller_ret_ip: u64, size: usize, hw_seed: u64) -> u32 {
    unsafe {
        swizzle_kmalloc_seed_init(hw_seed);
        swizzle_kmalloc_cache_index(caller_ret_ip as c_ulong, size)
    }
}

/// Invokes the C `swizzle_slab_jitter()` in `kernel/mm/swizzle_slab.c`.
pub fn run_c_slab_jitter(num_objects: u32, jitter_seed: u64) -> (Vec<u32>, u32) {
    let mut order = vec![0u32; num_objects as usize];
    let pinned = unsafe { swizzle_slab_jitter(order.as_mut_ptr(), num_objects, jitter_seed) };
    (order, pinned)
}
