<img width="544"  alt="39655" src="https://github.com/user-attachments/assets/674c5582-c975-41e7-9293-921c9f9894c9" />

___
durable, fail-open kernel diversification library for per-boot layout randomization.

prevents relative offset calculation, rop/jop gadget chains, static kernel data overwrites (`modprobe_path`, `core_pattern`, `poweroff_cmd`), cross-cache heap feng shui, and `/proc/kallsyms` or panic log pointer leaks through cacheline-bucketed surgical struct permutation (`randstruct`), in-enclave per-boot elf section shuffling (`.text.*`, `.data.*`, `.rodata.*`), and caller-ip slab cache segregation (`kmalloc-cg-*`).

preserves hardware root of trust and confidential vm attestation across amd sev-snp (`id_block` author key pinning + `guest_svn`), intel tdx (`rtmr[1..3]` split-rtmr and corim), and bare-metal tpm 2.0 + uefi secure boot (`systemd-pcrlock` and chained `kexec` tickets) by measuring a deterministic signed cohort uki first and executing per-boot `rdseed` relinking and rfc 9180 hpke panic seed sealing inside the hardware-isolated decompression stub.

---

### architecture (v3: two-tier pipeline)

```text
┌────────────────────────────────────────────────────────────────────────────┐
│ tier 1: asynchronous cohort builder (runs every 1–6h on build cluster)     │
│  1. compiles superset archive (vmlinux-superset.a) with cohort seed_c:     │
│     - cacheline-bucketed randstruct + pinned ebpf noinline manifest        │
│  2. per hardware profile (e.g., microvm, baremetal-mlx5):                  │
│     - links vmlinux via ld.lld --gc-sections --emit-relocs                 │
│     - generates .btf once via pahole -j (valid across all boots in cohort) │
│     - embeds symbol vault x25519 hpke public key + early-boot stub         │
│  3. signs cohort uki offline/hsm + publishes sev-snp id_block / pcrlock    │
└──────────────────────────────────────┬─────────────────────────────────────┘
                                       │ (cached on cdn / local rack pxe / disk)
                                       ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ tier 2: in-enclave early-boot stub (runs locally on every boot in ~45ms)   │
│  1. hardware measures static cohort uki (pcr[4] / rtmr[1] / snp launch)    │
│  2. firmware/verifier checks cohort signature (solution a + solution b)    │
│  3. decompression stub (arch/x86/boot/compressed/swizzle.c) executes:      │
│     - draws 256-bit boot seed_b via cpu rdseed inside hardware package     │
│     - permutes .text.*, .data.*, .rodata.* virtual addresses in ram        │
│     - applies .rela.* relocations (r_x86_64_*) across shuffled sections    │
│     - re-sorts __ex_table, .orc_unwind_ip, & kallsyms in place (heapsort)  │
│     - passes seed_b to kernel/swizzle_panic.c (rfc 9180 hpke early seal)   │
│     - scrubs .rela.* tables & plaintext seed via memzero_explicit()        │
└────────────────────────────────────────────────────────────────────────────┘
```

### layout

- `kernel/arch/x86/include/asm/swizzle_boot.h`: kernel descriptor (`SWZLDESC`) and packed relocation (`SWZL`) structs.
- `kernel/arch/x86/boot/compressed/swizzle.c`: freestanding in-enclave early-boot section shuffler, `R_X86_64_*` relocator, and $O(1)$-stack iterative heapsort for `__ex_table`, `.orc_unwind_ip`, and `kallsyms`.
- `kernel/kernel/swizzle_panic.c`: early-boot rfc 9180 base mode hpke sealer (`DHKEM(X25519, HKDF-SHA256)`, `HKDF-SHA256`, `ChaCha20Poly1305`) and lockless panic notifier.
- `kernel/lib/swizzle_kallsyms.c` & `kernel/mm/swizzle_slab.c`: address-redacted `%pS` formatting (`function_name+0xoffset/0xsize`) and per-boot slab freelist jitter (`swizzle_slab_jitter`).
- `kernel/patches/0001-x86-boot-swizzle-integration.patch`: kernel integration patch for `misc.c`, `boot.h`, `vmlinux.lds.S`, and `vsprintf.c`.
- `src/`: rust diversification library (`swizzle`) and symbol vault cli (`swizzle-ctl`).

### usage (`swizzle-ctl`)

```bash
# generate symbol vault x25519 hpke keypair
cargo run -- keygen --pub-out vault_pubkey.bin --priv-out vault_privkey.hex

# pack tier 1 cohort relocations (packed_relocs.bin)
cargo run -- pack-relocs --out packed_relocs.bin

# decrypt a panic hpke envelope, replay in-enclave shuffle, and resolve faulting rip
cargo run -- debug \
  --cohort 8f9c2d11a04e77b29104c88d3a1f5e6099b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5 \
  --envelope "hpke:v1:<32B_enc_hex>:<48B_ct_tag_hex>" \
  --priv-key vault_privkey.hex \
  --relocs-bin packed_relocs.bin \
  --rip 0xffffffff81000484 \
  --gdb-out swizzle-layout.gdb

# run full c-to-rust end-to-end verification
cargo run -- self-test
```
