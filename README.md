<img width="544"  alt="39655" src="https://github.com/user-attachments/assets/674c5582-c975-41e7-9293-921c9f9894c9" />

___
durable, fail-open kernel diversification library for per-boot layout randomization.

normally, every server running the same kernel release has the exact same internal map. if an attacker leaks a single pointer, they know the exact distance to every function, setting, and data structure—letting them chain together existing code snippets (rop/jop), overwrite privileged globals, or line up adjacent objects on the heap. swizzle breaks that assumption by shuffling the order of kernel functions, struct fields, and heap caches on every boot so every machine has a different layout and pre-calculated exploits crash.

randomizing a kernel binary usually changes its hash and breaks hardware root-of-trust checks like uefi secure boot, tpm 2.0, amd sev-snp, and intel tdx. swizzle keeps hardware attestation intact by shipping one signed kernel image per build cohort that the hardware verifies and measures first. once inside the trusted guest memory boundary, the early-boot stub draws fresh cpu randomness (`rdseed`) and shuffles its own sections in ram before the kernel starts. if a machine panics, it prints a small encrypted seed (`hpke`) so engineers can replay the exact layout in a debugger without storing per-boot binaries or leaking raw addresses.

<p align="center">
  <img src="assets/architecture.svg" alt="Swizzle 3-Tier Architecture" width="100%" />
</p>

### layout

- [`kernel/arch/x86/include/asm/swizzle_boot.h`](kernel/arch/x86/include/asm/swizzle_boot.h): kernel descriptor (`SWZLDESC`) and packed relocation (`SWZL`) structs.
- [`kernel/arch/x86/boot/compressed/swizzle.c`](kernel/arch/x86/boot/compressed/swizzle.c): early-boot section shuffler, `R_X86_64_*` relocator, and in-place table heapsort.
- [`kernel/kernel/swizzle_panic.c`](kernel/kernel/swizzle_panic.c): early-boot rfc 9180 hpke seed sealer and lockless panic notifier.
- [`kernel/lib/swizzle_kallsyms.c`](kernel/lib/swizzle_kallsyms.c) & [`kernel/mm/swizzle_slab.c`](kernel/mm/swizzle_slab.c): address-redacted stack traces (`%pS`) and slab freelist jitter.
- [`kernel/patches/0001-x86-boot-swizzle-integration.patch`](kernel/patches/0001-x86-boot-swizzle-integration.patch): kernel wiring for `misc.c`, `boot.h`, `vmlinux.lds.S`, and `vsprintf.c`.
- [`src/`](src/lib.rs): rust diversification library (`swizzle`) and symbol vault cli (`swizzle-ctl`).
- [`scripts/render_diagram.py`](scripts/render_diagram.py): renders the 3-tier architecture diagram with 24-bit ansi orange-to-red gradient borders (`#ff9e00` -> `#d90429`) and exports [`assets/architecture.svg`](assets/architecture.svg).

### usage

```bash
# render the 24-bit ansi gradient diagram in your terminal
./scripts/render_diagram.py

# generate symbol vault keypair
cargo run -- keygen --pub-out vault_pubkey.bin --priv-out vault_privkey.hex

# pack cohort relocations
cargo run -- pack-relocs --out packed_relocs.bin

# decrypt a panic envelope and replay the boot layout
cargo run -- debug \
  --cohort 8f9c2d11a04e77b29104c88d3a1f5e6099b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5 \
  --envelope "hpke:v1:<32B_enc_hex>:<48B_ct_tag_hex>" \
  --priv-key vault_privkey.hex \
  --relocs-bin packed_relocs.bin \
  --rip 0xffffffff81000484 \
  --gdb-out swizzle-layout.gdb

# run c-to-rust end-to-end verification
cargo run -- self-test
```
