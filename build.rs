fn main() {
    println!("cargo:rerun-if-changed=kernel/arch/x86/include/asm/swizzle_boot.h");
    println!("cargo:rerun-if-changed=kernel/arch/x86/boot/compressed/swizzle.c");
    println!("cargo:rerun-if-changed=kernel/kernel/swizzle_panic.c");
    println!("cargo:rerun-if-changed=kernel/lib/swizzle_kallsyms.c");
    println!("cargo:rerun-if-changed=kernel/mm/swizzle_slab.c");
    println!("cargo:rerun-if-changed=kernel/harness/linux_crypto_shim.c");
    println!("cargo:rerun-if-changed=kernel/harness/swizzle_c_bridge.c");

    cc::Build::new()
        .include("kernel/harness/include")
        .include("kernel/arch/x86/include")
        .include("kernel/arch/x86/boot/compressed")
        .define("SWIZZLE_OMIT_KDESC_SYMBOL", None)
        .file("kernel/arch/x86/boot/compressed/swizzle.c")
        .file("kernel/kernel/swizzle_panic.c")
        .file("kernel/lib/swizzle_kallsyms.c")
        .file("kernel/mm/swizzle_slab.c")
        .file("kernel/harness/linux_crypto_shim.c")
        .file("kernel/harness/swizzle_c_bridge.c")
        .flag_if_supported("-Wno-unused-parameter")
        .compile("swizzle_kernel_c");
}
