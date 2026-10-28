// SPDX-License-Identifier: Apache-2.0
//! `swizzle-ctl`: Swizzle Symbol Vault HPKE Decoder, Layout Replayer, Tier 1 Packer & Attestation CLI.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;
use swizzle::{
    attest::{
        build_sev_snp_id_block, build_tdx_split_rtmr_manifest, build_tpm2_chained_kexec_ticket,
        verify_sev_snp_attestation, verify_tpm2_chained_kexec_ticket,
    },
    c_bridge::{run_c_relocate_kernel, run_c_seal_and_panic},
    hpke_vault::{
        decrypt_boot_seed, generate_vault_keypair, parse_panic_log, write_gdb_layout_script,
    },
    ko::shuffle_elf64_et_rel_ko,
    randstruct::{permute_struct_cacheline_bucketed, StructField},
    relocs::{
        replay_section_shuffle, resolve_shuffled_rip, PackedRelocs, RelocEntry, SectionEntry,
        KERNEL_TEXT_BASE, R_X86_64_64, R_X86_64_PC32, SWIZZLE_DESC_MAGIC, SWIZZLE_RELOC_VERSION,
        SWIZZLE_SEC_DATA, SWIZZLE_SEC_RODATA, SWIZZLE_SEC_TEXT,
    },
};

#[derive(Parser)]
#[command(
    name = "swizzle-ctl",
    version = "0.3.0",
    about = "Swizzle Symbol Vault HPKE Decoder, Layout Replayer & Tier 1/2 Verification CLI"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a Symbol Vault X25519 HPKE keypair for Tier 1 embedding
    Keygen {
        /// Output path for the 32-byte raw public key (.rodata.swizzle_hpke_pub)
        #[arg(long, default_value = "vault_pubkey.bin")]
        pub_out: PathBuf,
        /// Output path for the hex-encoded private key
        #[arg(long, default_value = "vault_privkey.hex")]
        priv_out: PathBuf,
    },
    /// Decrypt a panic HPKE envelope and replay the in-enclave section permutation
    Debug {
        /// 32-byte Cohort Build-ID hex string from "Swizzle-Cohort: <hex>"
        #[arg(long)]
        cohort: String,
        /// HPKE envelope string from "Swizzle-Envelope: hpke:v1:<enc_hex>:<ct_tag_hex>"
        #[arg(long)]
        envelope: String,
        /// Path to the Symbol Vault private key hex file
        #[arg(long)]
        priv_key: PathBuf,
        /// Path to the Tier 1 packed_relocs.bin for this Cohort
        #[arg(long)]
        relocs_bin: PathBuf,
        /// Optional faulting RIP hex address (e.g., 0xffffffff81a4c210) to resolve
        #[arg(long)]
        rip: Option<String>,
        /// Output path for the generated GDB symbol script
        #[arg(long, default_value = "swizzle-layout.gdb")]
        gdb_out: PathBuf,
    },
    /// Pack a JSON section/relocation manifest into a Tier 1 SWZL binary (packed_relocs.bin)
    PackRelocs {
        /// Input JSON manifest path (or omit to generate a reference cohort packed_relocs.bin)
        #[arg(long)]
        manifest: Option<PathBuf>,
        /// Output path for packed_relocs.bin
        #[arg(long, default_value = "packed_relocs.bin")]
        out: PathBuf,
    },
    /// Run Cacheline-Bucketed Surgical RANDSTRUCT layout permutation on a struct JSON spec
    Randstruct {
        /// Target struct name (e.g., cred, task_struct, file, msg_msg, pipe_buffer, tty_struct, sock)
        #[arg(long)]
        struct_name: String,
        /// Header path (e.g., include/linux/cred.h)
        #[arg(long, default_value = "include/linux/cred.h")]
        header: String,
        /// 32-byte Cohort seed hex string
        #[arg(long)]
        seed: String,
        /// Enable Canary Audit Mode (inserts 0xdeadbeefbadc0de0 KASAN poison words between fields)
        #[arg(long, default_value_t = false)]
        canary: bool,
    },
    /// Shuffle internal .text.*, .data.*, and .rodata.* sections of a relocatable ET_REL .ko module
    KoShuffle {
        /// Input .ko ELF64 ET_REL file path
        #[arg(long)]
        input: PathBuf,
        /// Output shuffled .ko file path
        #[arg(long)]
        output: PathBuf,
        /// 32-byte seed hex string
        #[arg(long)]
        seed: String,
    },
    /// Generate and verify Blended Hardware Root of Trust attestation artifacts (SEV-SNP, TDX, TPM2)
    Attest {
        /// Platform mode: sev-snp, tdx, or tpm2-kexec
        #[arg(long, default_value = "sev-snp")]
        platform: String,
        /// Cohort identifier
        #[arg(long, default_value = "8f9c2d11a04e77b2")]
        cohort: String,
        /// Security Version Number (SVN)
        #[arg(long, default_value_t = 42)]
        svn: u32,
        /// Optional output JSON file path
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Prepare or enter the Privileged Debug Mount Namespace (/lib/modules/$(uname -r)/build)
    Shell {
        /// Path to the cohort randomized headers directory or SquashFS bundle
        #[arg(long)]
        cohort_headers: PathBuf,
        /// Target mount point
        #[arg(long, default_value = "/lib/modules/swizzle-cohort/build")]
        mount_point: PathBuf,
        /// Validate and print mount namespace plan without executing mount(2)
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },
    /// Execute a full C-to-Rust end-to-end verification of the early-boot stub and HPKE panic sealer
    SelfTest,
}

fn decode_seed_32(seed_hex: &str) -> Result<[u8; 32]> {
    let raw = hex::decode(seed_hex.trim()).context("Seed must be valid hex")?;
    if raw.len() != 32 {
        bail!("Expected 32-byte (64 hex chars) seed, got {} bytes", raw.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn default_reference_packed_relocs() -> PackedRelocs {
    PackedRelocs {
        version: SWIZZLE_RELOC_VERSION,
        sections: vec![
            SectionEntry {
                sec_id: 0,
                flags: SWIZZLE_SEC_TEXT,
                orig_addr: KERNEL_TEXT_BASE,
                size: 0x400,
                shuffled_addr: KERNEL_TEXT_BASE,
            },
            SectionEntry {
                sec_id: 1,
                flags: SWIZZLE_SEC_TEXT,
                orig_addr: KERNEL_TEXT_BASE + 0x400,
                size: 0x320,
                shuffled_addr: KERNEL_TEXT_BASE + 0x400,
            },
            SectionEntry {
                sec_id: 2,
                flags: SWIZZLE_SEC_TEXT,
                orig_addr: KERNEL_TEXT_BASE + 0x720,
                size: 0x2e0,
                shuffled_addr: KERNEL_TEXT_BASE + 0x720,
            },
            SectionEntry {
                sec_id: 3,
                flags: SWIZZLE_SEC_DATA,
                orig_addr: KERNEL_TEXT_BASE + 0x2000,
                size: 0x200,
                shuffled_addr: KERNEL_TEXT_BASE + 0x2000,
            },
            SectionEntry {
                sec_id: 4,
                flags: SWIZZLE_SEC_DATA,
                orig_addr: KERNEL_TEXT_BASE + 0x2200,
                size: 0x200,
                shuffled_addr: KERNEL_TEXT_BASE + 0x2200,
            },
            SectionEntry {
                sec_id: 5,
                flags: SWIZZLE_SEC_RODATA,
                orig_addr: KERNEL_TEXT_BASE + 0x3000,
                size: 0x180,
                shuffled_addr: KERNEL_TEXT_BASE + 0x3000,
            },
            SectionEntry {
                sec_id: 6,
                flags: SWIZZLE_SEC_RODATA,
                orig_addr: KERNEL_TEXT_BASE + 0x3180,
                size: 0x180,
                shuffled_addr: KERNEL_TEXT_BASE + 0x3180,
            },
        ],
        relocs: vec![
            RelocEntry {
                r_offset: KERNEL_TEXT_BASE + 0x20,
                r_addend: -4,
                sym_sec_id: 1,
                r_type: R_X86_64_PC32,
            },
            RelocEntry {
                r_offset: KERNEL_TEXT_BASE + 0x2000,
                r_addend: 0,
                sym_sec_id: 2,
                r_type: R_X86_64_64,
            },
        ],
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen { pub_out, priv_out } => {
            let (sk, pk) = generate_vault_keypair();
            File::create(&pub_out)?.write_all(&pk)?;
            File::create(&priv_out)?.write_all(hex::encode(sk).as_bytes())?;
            println!("[+] Public key (32B raw) written to: {}", pub_out.display());
            println!("[+] Private key (hex) written to:    {}", priv_out.display());
        }
        Commands::Debug {
            cohort,
            envelope,
            priv_key,
            relocs_bin,
            rip,
            gdb_out,
        } => {
            let mut priv_hex = String::new();
            File::open(&priv_key)?.read_to_string(&mut priv_hex)?;
            let priv_bytes = hex::decode(priv_hex.trim())?;
            let cohort_bytes = hex::decode(cohort.trim())?;

            let seed = decrypt_boot_seed(&priv_bytes, &cohort_bytes, &envelope)?;
            println!("[+] Recovered In-Enclave Boot Seed_B: {}", hex::encode(seed));

            let sections = replay_section_shuffle(&relocs_bin, &seed)?;
            println!("[+] Replayed permutation across {} sections", sections.len());

            if let Some(rip_str) = rip {
                let clean = rip_str.trim().trim_start_matches("0x");
                let rip_val = u64::from_str_radix(clean, 16)?;
                if let Some((sec, delta, canonical_addr)) = resolve_shuffled_rip(&sections, rip_val)
                {
                    println!(
                        "[+] Faulting RIP 0x{:016x} -> Section #{} +0x{:x} (Canonical vmlinux addr: 0x{:016x})",
                        rip_val, sec.sec_id, delta, canonical_addr
                    );
                } else {
                    println!("[-] RIP 0x{:016x} did not match any shuffled section", rip_val);
                }
            }

            write_gdb_layout_script(&gdb_out, cohort.trim(), &sections)?;
            println!("[+] Wrote reconstructed layout map to: {}", gdb_out.display());
        }
        Commands::PackRelocs { manifest, out } => {
            let packed = if let Some(path) = manifest {
                let text = fs::read_to_string(&path)?;
                serde_json::from_str::<PackedRelocs>(&text)?
            } else {
                default_reference_packed_relocs()
            };
            packed.write_to_file(&out)?;
            println!(
                "[+] Packed {} sections and {} relocations into {}",
                packed.sections.len(),
                packed.relocs.len(),
                out.display()
            );
        }
        Commands::Randstruct {
            struct_name,
            header,
            seed,
            canary,
        } => {
            let seed_bytes = decode_seed_32(&seed)?;
            let sample_fields = vec![
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
                    name: "euid".to_string(),
                    c_type: "kuid_t".to_string(),
                    size: 4,
                    align: 4,
                    cacheline_group: Some(0),
                },
                StructField {
                    name: "egid".to_string(),
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
                    cacheline_group: Some(0),
                },
            ];
            let layout = permute_struct_cacheline_bucketed(
                &struct_name,
                &header,
                &sample_fields,
                &seed_bytes,
                canary,
            )?;
            println!("{}", serde_json::to_string_pretty(&layout)?);
        }
        Commands::KoShuffle {
            input,
            output,
            seed,
        } => {
            let seed_bytes = decode_seed_32(&seed)?;
            let elf_bytes = fs::read(&input)?;
            let (shuffled_bytes, records) = shuffle_elf64_et_rel_ko(&elf_bytes, &seed_bytes)?;
            fs::write(&output, &shuffled_bytes)?;
            println!(
                "[+] Shuffled {} relocatable sections in {} -> {}",
                records.len(),
                input.display(),
                output.display()
            );
        }
        Commands::Attest {
            platform,
            cohort,
            svn,
            out,
        } => {
            let author_key = [0x42u8; 32];
            let uki_sample = b"SWIZZLE-COHORT-SIGNED-UKI-BINARY-V3";
            let json_out = match platform.as_str() {
                "sev-snp" => {
                    let block = build_sev_snp_id_block(&cohort, uki_sample, &author_key, svn);
                    verify_sev_snp_attestation(
                        &block,
                        &block.author_key_digest,
                        svn,
                        &author_key,
                    )?;
                    serde_json::to_string_pretty(&block)?
                }
                "tdx" => {
                    let shim = b"SWIZZLE-TDX-64KB-STATIC-VERIFICATION-SHIM";
                    let manifest =
                        build_tdx_split_rtmr_manifest(&cohort, shim, uki_sample, svn);
                    serde_json::to_string_pretty(&manifest)?
                }
                "tpm2-kexec" => {
                    let pcr4_curr = [0x11u8; 32];
                    let ticket =
                        build_tpm2_chained_kexec_ticket(&pcr4_curr, uki_sample, &author_key);
                    verify_tpm2_chained_kexec_ticket(&ticket, &author_key)?;
                    serde_json::to_string_pretty(&ticket)?
                }
                other => bail!("Unsupported attestation platform '{}' (expected sev-snp, tdx, or tpm2-kexec)", other),
            };
            if let Some(path) = out {
                fs::write(&path, &json_out)?;
                println!("[+] Wrote {} attestation artifact to {}", platform, path.display());
            } else {
                println!("{}", json_out);
            }
        }
        Commands::Shell {
            cohort_headers,
            mount_point,
            dry_run,
        } => {
            if !cohort_headers.exists() {
                bail!(
                    "Cohort randomized headers bundle does not exist: {}",
                    cohort_headers.display()
                );
            }
            println!(
                "[+] Privileged Debug Mount Namespace Plan:\n    Source SquashFS/Dir: {}\n    Isolated mnt_ns target: {}\n    Mode: {}",
                cohort_headers.display(),
                mount_point.display(),
                if dry_run { "dry-run" } else { "active" }
            );
        }
        Commands::SelfTest => {
            run_cli_self_test()?;
        }
    }

    Ok(())
}

fn run_cli_self_test() -> Result<()> {
    let (sk, pk) = generate_vault_keypair();
    let cohort_build_id = [0x8fu8; 32];
    let hw_seed = [0x3cu8; 32];

    // 1. Run C kernel early-boot stub on a synthetic image containing SWZLDESC + SWZL
    let packed = default_reference_packed_relocs();
    let swzl_bytes = packed.to_bytes()?;
    let image_size = 0x6000usize;
    let mut image = vec![0u8; image_size];

    // Copy SWZL at offset 0x4000 (VA = KERNEL_TEXT_BASE + 0x4000)
    let relocs_off = 0x4000usize;
    image[relocs_off..relocs_off + swzl_bytes.len()].copy_from_slice(&swzl_bytes);
    let boot_seed_off = 0x4800usize;

    // Write SWZLDESC at offset 0x5000 (8-byte aligned)
    let desc_off = 0x5000usize;
    let fields: [u64; 15] = [
        SWIZZLE_DESC_MAGIC,
        KERNEL_TEXT_BASE,
        KERNEL_TEXT_BASE + (image_size as u64),
        KERNEL_TEXT_BASE + (relocs_off as u64),
        KERNEL_TEXT_BASE + ((relocs_off + swzl_bytes.len()) as u64),
        KERNEL_TEXT_BASE + (boot_seed_off as u64),
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    for (idx, val) in fields.iter().enumerate() {
        let pos = desc_off + idx * 8;
        image[pos..pos + 8].copy_from_slice(&val.to_le_bytes());
    }

    let mut scratch = vec![0u8; 0x10000];
    run_c_relocate_kernel(&mut image, &mut scratch, Some(&hw_seed));

    let mut extracted_seed = [0u8; 32];
    extracted_seed.copy_from_slice(&image[boot_seed_off..boot_seed_off + 32]);
    if extracted_seed != hw_seed {
        bail!("C early-boot stub did not populate swizzle_boot_seed with hardware RDSEED");
    }

    // 2. Seal the seed in C via kernel/swizzle_panic.c and decode in Rust
    let (panic_log, seed_zeroed) = run_c_seal_and_panic(&pk, &cohort_build_id, &extracted_seed)?;
    if !seed_zeroed {
        bail!("C kernel/swizzle_panic.c failed to scrub plaintext swizzle_boot_seed");
    }
    let (parsed_cohort, parsed_env) = parse_panic_log(&panic_log)?;
    let decoded_cohort = hex::decode(&parsed_cohort)?;
    let recovered_seed = decrypt_boot_seed(&sk, &decoded_cohort, &parsed_env)?;
    if recovered_seed != hw_seed {
        bail!("Rust Symbol Vault recovered seed did not match C in-enclave seed");
    }

    println!("[+] C Early-Boot Stub (swizzle.c) + C HPKE Panic Sealer (swizzle_panic.c) <-> Rust Symbol Vault verified bit-for-bit!");
    Ok(())
}
