// SPDX-License-Identifier: Apache-2.0
//! RFC 9180 Base Mode HPKE (`DHKEM(X25519, HKDF-SHA256)`, `HKDF-SHA256`, `ChaCha20Poly1305`)
//! early-boot sealer, panic banner parser, and Symbol Vault decoder.

use crate::prng::SWIZZLE_SEED_LEN;
use crate::relocs::SectionEntry;
use anyhow::{bail, Context, Result};
use hpke::{
    aead::ChaCha20Poly1305,
    kdf::HkdfSha256,
    kem::X25519HkdfSha256,
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable,
};
use rand::rngs::OsRng;
use std::fs::File;
use std::io::Write;
use std::path::Path;

pub const SWIZZLE_INFO: &[u8] = b"swizzle-panic-v1";
pub const SWIZZLE_ENC_LEN: usize = 32;
pub const SWIZZLE_CT_TAG_LEN: usize = 48; // 32B Seed_B + 16B Poly1305 Tag

/// Generates a Symbol Vault X25519 HPKE keypair `(priv_key_32b, pub_key_32b)`.
pub fn generate_vault_keypair() -> ([u8; 32], [u8; 32]) {
    let (sk, pk) = X25519HkdfSha256::gen_keypair(&mut OsRng);
    let mut sk_bytes = [0u8; 32];
    let mut pk_bytes = [0u8; 32];
    sk_bytes.copy_from_slice(sk.to_bytes().as_slice());
    pk_bytes.copy_from_slice(pk.to_bytes().as_slice());
    (sk_bytes, pk_bytes)
}

/// Seals a 32-byte boot seed (`Seed_B`) against the Symbol Vault X25519 public key and Cohort Build-ID
/// using RFC 9180 Base Mode, returning the wire string `hpke:v1:<32B_enc_hex>:<48B_ct_tag_hex>`.
pub fn seal_boot_seed(
    pub_key_bytes: &[u8],
    cohort_build_id: &[u8],
    seed: &[u8; SWIZZLE_SEED_LEN],
) -> Result<String> {
    let pk_r = <X25519HkdfSha256 as KemTrait>::PublicKey::from_bytes(pub_key_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid X25519 public key: {:?}", e))?;

    let (encapped_key, mut sender_ctx) = hpke::setup_sender::<
        ChaCha20Poly1305,
        HkdfSha256,
        X25519HkdfSha256,
        _,
    >(&OpModeS::Base, &pk_r, SWIZZLE_INFO, &mut OsRng)
    .map_err(|e| anyhow::anyhow!("HPKE sender key schedule failed: {:?}", e))?;

    let ct_tag = sender_ctx
        .seal(seed, cohort_build_id)
        .map_err(|e| anyhow::anyhow!("HPKE AEAD seal failed: {:?}", e))?;

    Ok(format!(
        "hpke:v1:{}:{}",
        hex::encode(encapped_key.to_bytes()),
        hex::encode(ct_tag)
    ))
}

/// Decrypts an `hpke:v1:<32B_enc_hex>:<48B_ct_tag_hex>` panic envelope using the Symbol Vault
/// X25519 private key and verifies the `cohort_build_id` (`NT_GNU_BUILD_ID`) AEAD tag.
pub fn decrypt_boot_seed(
    priv_key_bytes: &[u8],
    cohort_build_id: &[u8],
    envelope_str: &str,
) -> Result<[u8; SWIZZLE_SEED_LEN]> {
    let trimmed = envelope_str.trim().strip_prefix("hpke:v1:").unwrap_or(envelope_str.trim());
    let parts: Vec<&str> = trimmed.split(':').collect();
    if parts.len() != 2 {
        bail!("Expected envelope format hpke:v1:<32B_enc_hex>:<48B_ct_tag_hex>");
    }

    let enc_bytes = hex::decode(parts[0]).context("Invalid hex in HPKE enc field")?;
    let ct_tag_bytes = hex::decode(parts[1]).context("Invalid hex in HPKE ct_tag field")?;

    if enc_bytes.len() != SWIZZLE_ENC_LEN || ct_tag_bytes.len() != SWIZZLE_CT_TAG_LEN {
        bail!(
            "Invalid envelope lengths: enc={}B (expected 32), ct_tag={}B (expected 48)",
            enc_bytes.len(),
            ct_tag_bytes.len()
        );
    }

    let sk_r = <X25519HkdfSha256 as KemTrait>::PrivateKey::from_bytes(priv_key_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid X25519 private key: {:?}", e))?;
    let encapped_key = <X25519HkdfSha256 as KemTrait>::EncappedKey::from_bytes(&enc_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid X25519 encapped key: {:?}", e))?;

    let mut receiver_ctx = hpke::setup_receiver::<
        ChaCha20Poly1305,
        HkdfSha256,
        X25519HkdfSha256,
    >(&OpModeR::Base, &sk_r, &encapped_key, SWIZZLE_INFO)
    .map_err(|e| anyhow::anyhow!("HPKE key schedule failed: {:?}", e))?;

    let plaintext = receiver_ctx
        .open(&ct_tag_bytes, cohort_build_id)
        .map_err(|e| {
            anyhow::anyhow!(
                "HPKE AEAD tag verification failed (Cohort mismatch?): {:?}",
                e
            )
        })?;

    let mut seed = [0u8; SWIZZLE_SEED_LEN];
    seed.copy_from_slice(&plaintext);
    Ok(seed)
}

/// Parses `Swizzle-Cohort: <hex>` and `Swizzle-Envelope: <hpke:v1:...>` lines from a raw kernel panic log.
pub fn parse_panic_log(log_text: &str) -> Result<(String, String)> {
    let mut cohort_hex: Option<String> = None;
    let mut envelope_str: Option<String> = None;

    for line in log_text.lines() {
        if let Some((_, rest)) = line.split_once("Swizzle-Cohort:") {
            let token = rest.split_whitespace().next().unwrap_or("").trim();
            if !token.is_empty() {
                cohort_hex = Some(token.to_string());
            }
        }
        if let Some((_, rest)) = line.split_once("Swizzle-Envelope:") {
            let token = rest.split_whitespace().next().unwrap_or("").trim();
            if !token.is_empty() {
                envelope_str = Some(token.to_string());
            }
        }
    }

    match (cohort_hex, envelope_str) {
        (Some(c), Some(e)) => Ok((c, e)),
        _ => bail!("Panic log missing Swizzle-Cohort or Swizzle-Envelope lines"),
    }
}

/// Writes the reconstructed section layout GDB script (`swizzle-layout.gdb`).
pub fn write_gdb_layout_script(
    gdb_out: &Path,
    cohort: &str,
    sections: &[SectionEntry],
) -> Result<()> {
    let mut gdb_file = File::create(gdb_out)?;
    writeln!(
        gdb_file,
        "# Auto-generated by swizzle-ctl for Cohort {}",
        cohort
    )?;
    for sec in sections {
        writeln!(
            gdb_file,
            "# sec_id={} orig=0x{:016x} shuffled=0x{:016x} size=0x{:x}",
            sec.sec_id, sec.orig_addr, sec.shuffled_addr, sec.size
        )?;
    }

    if let Some(first_text) = sections.iter().find(|s| s.flags == 1) {
        write!(
            gdb_file,
            "add-symbol-file vmlinux.debug 0x{:016x}",
            first_text.shuffled_addr
        )?;
        for sec in sections.iter().skip(1) {
            let class_prefix = match sec.flags {
                1 => ".text.sec",
                2 => ".data.sec",
                3 => ".rodata.sec",
                _ => ".sec",
            };
            write!(
                gdb_file,
                " -s {}_{} 0x{:016x}",
                class_prefix, sec.sec_id, sec.shuffled_addr
            )?;
        }
        writeln!(gdb_file)?;
    }

    Ok(())
}
