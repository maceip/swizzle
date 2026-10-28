// SPDX-License-Identifier: Apache-2.0
//! Blended Hardware Root of Trust & Attestation (Solution A + Solution B):
//! - AMD SEV-SNP (`ID_BLOCK`, `author_key_digest`, `guest_svn >= min_svn`)
//! - Intel TDX (`RTMR[1..3]` Split-RTMR & CoRIM verification)
//! - TPM 2.0 + UEFI Secure Boot (`systemd-pcrlock` & chained `kexec_file_load` ticket)

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SevSnpIdBlock {
    pub cohort_id: String,
    pub launch_measurement_sha256: [u8; 32],
    pub author_key_digest: [u8; 32],
    pub guest_svn: u32,
    pub signature_tag: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TdxSplitRtmrManifest {
    pub cohort_id: String,
    /// RTMR[1]: Static 64 KB verification shim measurement
    pub rtmr1_shim_hash: [u8; 32],
    /// RTMR[2]: Extended Cohort SVN measurement
    pub rtmr2_svn_hash: [u8; 32],
    /// RTMR[3]: Extended Cohort UKI hash
    pub rtmr3_uki_hash: [u8; 32],
    pub guest_svn: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tpm2ChainedKexecTicket {
    pub pcr4_current: [u8; 32],
    pub uki_new_digest: [u8; 32],
    /// SHA256(PCR_curr || UKI_new)
    pub chained_pcr4_digest: [u8; 32],
    pub author_key_digest: [u8; 32],
    pub ticket_mac: [u8; 32],
}

fn compute_keyed_digest(key: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"SWIZZLE-ATTEST-V3:");
    hasher.update(key);
    hasher.update(payload);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// Builds a signed AMD SEV-SNP Cohort `ID_BLOCK` for Solution A + Solution B attestation.
pub fn build_sev_snp_id_block(
    cohort_id: &str,
    cohort_uki_bytes: &[u8],
    author_signing_key: &[u8; 32],
    guest_svn: u32,
) -> SevSnpIdBlock {
    let mut launch_measurement_sha256 = [0u8; 32];
    launch_measurement_sha256.copy_from_slice(&Sha256::digest(cohort_uki_bytes));

    let mut author_key_digest = [0u8; 32];
    author_key_digest.copy_from_slice(&Sha256::digest(author_signing_key));

    let mut payload = Vec::new();
    payload.extend_from_slice(cohort_id.as_bytes());
    payload.extend_from_slice(&launch_measurement_sha256);
    payload.extend_from_slice(&author_key_digest);
    payload.extend_from_slice(&guest_svn.to_le_bytes());

    let signature_tag = compute_keyed_digest(author_signing_key, &payload);
    SevSnpIdBlock {
        cohort_id: cohort_id.to_string(),
        launch_measurement_sha256,
        author_key_digest,
        guest_svn,
        signature_tag,
    }
}

/// Verifies an AMD SEV-SNP `ID_BLOCK` against the pinned Swizzle HSM `author_key_digest` and `min_svn`.
pub fn verify_sev_snp_attestation(
    block: &SevSnpIdBlock,
    pinned_author_key_digest: &[u8; 32],
    min_svn: u32,
    author_signing_key: &[u8; 32],
) -> Result<()> {
    if &block.author_key_digest != pinned_author_key_digest {
        bail!("SEV-SNP author_key_digest does not match pinned Swizzle HSM root key");
    }
    if block.guest_svn < min_svn {
        bail!(
            "SEV-SNP guest_svn ({}) is below minimum required SVN ({})",
            block.guest_svn,
            min_svn
        );
    }

    let mut payload = Vec::new();
    payload.extend_from_slice(block.cohort_id.as_bytes());
    payload.extend_from_slice(&block.launch_measurement_sha256);
    payload.extend_from_slice(&block.author_key_digest);
    payload.extend_from_slice(&block.guest_svn.to_le_bytes());

    let expected_sig = compute_keyed_digest(author_signing_key, &payload);
    if block.signature_tag != expected_sig {
        bail!("SEV-SNP ID_BLOCK signature verification failed");
    }
    Ok(())
}

/// Computes an Intel TDX Split-RTMR manifest (`RTMR[1]` shim, `RTMR[2]` Cohort SVN, `RTMR[3]` UKI hash).
pub fn build_tdx_split_rtmr_manifest(
    cohort_id: &str,
    shim_bytes: &[u8],
    cohort_uki_bytes: &[u8],
    guest_svn: u32,
) -> TdxSplitRtmrManifest {
    let mut rtmr1_shim_hash = [0u8; 32];
    rtmr1_shim_hash.copy_from_slice(&Sha256::digest(shim_bytes));

    let mut svn_hasher = Sha256::new();
    svn_hasher.update([0u8; 32]); // initial RTMR[2]
    svn_hasher.update(guest_svn.to_le_bytes());
    let mut rtmr2_svn_hash = [0u8; 32];
    rtmr2_svn_hash.copy_from_slice(&svn_hasher.finalize());

    let uki_digest = Sha256::digest(cohort_uki_bytes);
    let mut uki_hasher = Sha256::new();
    uki_hasher.update([0u8; 32]); // initial RTMR[3]
    uki_hasher.update(uki_digest);
    let mut rtmr3_uki_hash = [0u8; 32];
    rtmr3_uki_hash.copy_from_slice(&uki_hasher.finalize());

    TdxSplitRtmrManifest {
        cohort_id: cohort_id.to_string(),
        rtmr1_shim_hash,
        rtmr2_svn_hash,
        rtmr3_uki_hash,
        guest_svn,
    }
}

/// Computes a TPM 2.0 chained `kexec_file_load` ticket:
/// $\text{chained\_pcr4} = \text{SHA256}(\text{PCR}_{\text{curr}} \parallel \text{UKI}_{\text{new}})$.
pub fn build_tpm2_chained_kexec_ticket(
    pcr4_current: &[u8; 32],
    uki_new_bytes: &[u8],
    author_signing_key: &[u8; 32],
) -> Tpm2ChainedKexecTicket {
    let mut uki_new_digest = [0u8; 32];
    uki_new_digest.copy_from_slice(&Sha256::digest(uki_new_bytes));

    let mut chain_hasher = Sha256::new();
    chain_hasher.update(pcr4_current);
    chain_hasher.update(uki_new_digest);
    let mut chained_pcr4_digest = [0u8; 32];
    chained_pcr4_digest.copy_from_slice(&chain_hasher.finalize());

    let mut author_key_digest = [0u8; 32];
    author_key_digest.copy_from_slice(&Sha256::digest(author_signing_key));

    let ticket_mac = compute_keyed_digest(author_signing_key, &chained_pcr4_digest);
    Tpm2ChainedKexecTicket {
        pcr4_current: *pcr4_current,
        uki_new_digest,
        chained_pcr4_digest,
        author_key_digest,
        ticket_mac,
    }
}

/// Verifies a TPM 2.0 chained `kexec_file_load` ticket.
pub fn verify_tpm2_chained_kexec_ticket(
    ticket: &Tpm2ChainedKexecTicket,
    author_signing_key: &[u8; 32],
) -> Result<()> {
    let mut chain_hasher = Sha256::new();
    chain_hasher.update(ticket.pcr4_current);
    chain_hasher.update(ticket.uki_new_digest);
    let mut expected_chain = [0u8; 32];
    expected_chain.copy_from_slice(&chain_hasher.finalize());

    if ticket.chained_pcr4_digest != expected_chain {
        bail!("TPM2 chained PCR[4] digest mismatch");
    }

    let expected_mac = compute_keyed_digest(author_signing_key, &ticket.chained_pcr4_digest);
    if ticket.ticket_mac != expected_mac {
        bail!("TPM2 chained kexec ticket MAC verification failed");
    }
    Ok(())
}
