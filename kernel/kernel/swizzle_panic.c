// SPDX-License-Identifier: GPL-2.0
/*
 * kernel/swizzle_panic.c
 *
 * Early-boot RFC 9180 HPKE sealer (DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
 * ChaCha20Poly1305) and lockless panic notifier for Swizzle boot seeds.
 */

#define pr_fmt(fmt) "swizzle: " fmt

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/panic_notifier.h>
#include <linux/random.h>
#include <linux/string.h>
#include <linux/buildid.h>
#include <linux/cache.h>
#include <crypto/curve25519.h>
#include <crypto/sha2.h>
#include <crypto/chacha20poly1305.h>
#include <asm/swizzle_boot.h>
#include <asm/sections.h>

#define SWIZZLE_SEED_LEN	32
#define SWIZZLE_ENC_LEN		32
#define SWIZZLE_TAG_LEN		CHACHA20POLY1305_AUTHTAG_SIZE /* 16 */
#define SWIZZLE_CT_TAG_LEN	(SWIZZLE_SEED_LEN + SWIZZLE_TAG_LEN) /* 48 */
#define SWIZZLE_BUILD_ID_LEN	32 /* --build-id=sha256 */

/*
 * Populated by arch/x86/boot/compressed/swizzle.c before jumping to
 * start_kernel(). Placed in .init.data so free_initmem() unmaps the page,
 * and explicitly scrubbed via memzero_explicit() immediately after sealing.
 */
u8 __initdata swizzle_boot_seed[SWIZZLE_SEED_LEN];

/*
 * Symbol Vault X25519 public key embedded by the Tier 1 build into
 * .rodata.swizzle_hpke_pub (defined in arch/x86/kernel/vmlinux.lds.S).
 */
extern const u8 __start_swizzle_hpke_pub[];
extern const u8 __stop_swizzle_hpke_pub[];

/*
 * Runtime tables referenced by swizzle_kdesc (.rodata.swizzle_desc).
 */
extern const struct exception_table_entry __start___ex_table[];
extern const struct exception_table_entry __stop___ex_table[];
extern const int __start_orc_unwind_ip[];
extern const int __stop_orc_unwind_ip[];
extern const struct orc_entry __start_orc_unwind[];
extern const u8 __start_swizzle_relocs[];
extern const u8 __stop_swizzle_relocs[];
extern const int kallsyms_offsets[];
extern const unsigned int kallsyms_num_syms;
extern const unsigned long kallsyms_relative_base;
extern u32 swizzle_kallsyms_addr_idx[];

#ifndef SWIZZLE_OMIT_KDESC_SYMBOL
const struct swizzle_kernel_desc swizzle_kdesc
__section(".rodata.swizzle_desc") __used = {
	.magic                  = SWIZZLE_DESC_MAGIC,
	.text_base_va           = (u64)(uintptr_t)_text,
	.image_end_va           = (u64)(uintptr_t)_end,
	.relocs_start_va        = (u64)(uintptr_t)__start_swizzle_relocs,
	.relocs_stop_va         = (u64)(uintptr_t)__stop_swizzle_relocs,
	.boot_seed_va           = (u64)(uintptr_t)swizzle_boot_seed,
	.extable_start_va       = (u64)(uintptr_t)__start___ex_table,
	.extable_stop_va        = (u64)(uintptr_t)__stop___ex_table,
	.orc_ip_start_va        = (u64)(uintptr_t)__start_orc_unwind_ip,
	.orc_ip_stop_va         = (u64)(uintptr_t)__stop_orc_unwind_ip,
	.orc_entry_start_va     = (u64)(uintptr_t)__start_orc_unwind,
	.kallsyms_offsets_va    = (u64)(uintptr_t)kallsyms_offsets,
	.kallsyms_num_syms_va   = (u64)(uintptr_t)&kallsyms_num_syms,
	.kallsyms_rel_base_va   = (u64)(uintptr_t)&kallsyms_relative_base,
	.kallsyms_sorted_idx_va = (u64)(uintptr_t)swizzle_kallsyms_addr_idx,
};
#endif

/*
 * Sealed output stored in __ro_after_init so it is immutable once boot finishes
 * and safe to read locklessly inside the panic path.
 */
static u8 swizzle_hpke_enc[SWIZZLE_ENC_LEN] __ro_after_init;
static u8 swizzle_hpke_ct_tag[SWIZZLE_CT_TAG_LEN] __ro_after_init;
static u8 swizzle_cohort_build_id[SWIZZLE_BUILD_ID_LEN] __ro_after_init;
static bool swizzle_envelope_ready __ro_after_init;

/* RFC 9180 Suite IDs */
static const u8 KEM_SUITE_ID[5]   = { 'K', 'E', 'M', 0x00, 0x20 };
static const u8 HPKE_SUITE_ID[10] = {
	'H', 'P', 'K', 'E', 0x00, 0x20, 0x00, 0x01, 0x00, 0x03
};
static const u8 HPKE_VERSION_LABEL[7] = { 'H', 'P', 'K', 'E', '-', 'v', '1' };
static const u8 SWIZZLE_INFO[] = "swizzle-panic-v1";

/*
 * Minimal synchronous HMAC-SHA256 over lib/crypto/sha256.c for early_initcall.
 */
static void __init swizzle_hmac_sha256(const u8 *key, size_t key_len,
				       const u8 *data, size_t data_len,
				       u8 out[SHA256_DIGEST_SIZE])
{
	struct sha256_state sctx;
	u8 k_ipad[SHA256_BLOCK_SIZE];
	u8 k_opad[SHA256_BLOCK_SIZE];
	u8 tk[SHA256_DIGEST_SIZE];
	size_t i;

	if (key_len > SHA256_BLOCK_SIZE) {
		sha256(key, key_len, tk);
		key = tk;
		key_len = SHA256_DIGEST_SIZE;
	}

	memset(k_ipad, 0x36, SHA256_BLOCK_SIZE);
	memset(k_opad, 0x5c, SHA256_BLOCK_SIZE);
	for (i = 0; i < key_len; i++) {
		k_ipad[i] ^= key[i];
		k_opad[i] ^= key[i];
	}

	sha256_init(&sctx);
	sha256_update(&sctx, k_ipad, SHA256_BLOCK_SIZE);
	sha256_update(&sctx, data, data_len);
	sha256_final(&sctx, out);

	sha256_init(&sctx);
	sha256_update(&sctx, k_opad, SHA256_BLOCK_SIZE);
	sha256_update(&sctx, out, SHA256_DIGEST_SIZE);
	sha256_final(&sctx, out);

	memzero_explicit(k_ipad, sizeof(k_ipad));
	memzero_explicit(k_opad, sizeof(k_opad));
	memzero_explicit(tk, sizeof(tk));
	memzero_explicit(&sctx, sizeof(sctx));
}

/*
 * RFC 9180 Section 4: LabeledExtract(salt, label, ikm)
 * labeled_ikm = "HPKE-v1" || suite_id || label || ikm
 */
static void __init hpke_labeled_extract(const u8 *suite_id, size_t suite_len,
					const u8 *salt, size_t salt_len,
					const char *label,
					const u8 *ikm, size_t ikm_len,
					u8 prk_out[SHA256_DIGEST_SIZE])
{
	u8 buf[256];
	u8 zero_salt[SHA256_DIGEST_SIZE] = { 0 };
	size_t label_len = strlen(label);
	size_t pos = 0;

	BUG_ON(sizeof(HPKE_VERSION_LABEL) + suite_len + label_len + ikm_len > sizeof(buf));

	memcpy(buf + pos, HPKE_VERSION_LABEL, sizeof(HPKE_VERSION_LABEL));
	pos += sizeof(HPKE_VERSION_LABEL);
	memcpy(buf + pos, suite_id, suite_len);
	pos += suite_len;
	memcpy(buf + pos, label, label_len);
	pos += label_len;
	if (ikm_len) {
		memcpy(buf + pos, ikm, ikm_len);
		pos += ikm_len;
	}

	if (!salt || salt_len == 0) {
		salt = zero_salt;
		salt_len = SHA256_DIGEST_SIZE;
	}

	swizzle_hmac_sha256(salt, salt_len, buf, pos, prk_out);
	memzero_explicit(buf, sizeof(buf));
}

/*
 * RFC 9180 Section 4: LabeledExpand(prk, label, info, L)
 * labeled_info = uint16_be(L) || "HPKE-v1" || suite_id || label || info
 * (Since L <= 32 for X25519/ChaCha20Poly1305, a single HKDF block counter 0x01 suffices.)
 */
static void __init hpke_labeled_expand(const u8 *suite_id, size_t suite_len,
				       const u8 prk[SHA256_DIGEST_SIZE],
				       const char *label,
				       const u8 *info, size_t info_len,
				       u8 *out, size_t out_len)
{
	u8 buf[256];
	u8 block[SHA256_DIGEST_SIZE];
	size_t label_len = strlen(label);
	size_t pos = 0;

	BUG_ON(out_len > SHA256_DIGEST_SIZE);
	BUG_ON(2 + sizeof(HPKE_VERSION_LABEL) + suite_len + label_len + info_len + 1 > sizeof(buf));

	buf[pos++] = (u8)((out_len >> 8) & 0xff);
	buf[pos++] = (u8)(out_len & 0xff);
	memcpy(buf + pos, HPKE_VERSION_LABEL, sizeof(HPKE_VERSION_LABEL));
	pos += sizeof(HPKE_VERSION_LABEL);
	memcpy(buf + pos, suite_id, suite_len);
	pos += suite_len;
	memcpy(buf + pos, label, label_len);
	pos += label_len;
	if (info_len) {
		memcpy(buf + pos, info, info_len);
		pos += info_len;
	}
	buf[pos++] = 0x01; /* HKDF block counter 1 */

	swizzle_hmac_sha256(prk, SHA256_DIGEST_SIZE, buf, pos, block);
	memcpy(out, block, out_len);

	memzero_explicit(buf, sizeof(buf));
	memzero_explicit(block, sizeof(block));
}

static int swizzle_panic_notify(struct notifier_block *nb,
				unsigned long action, void *data)
{
	(void)nb;
	(void)action;
	(void)data;

	if (!swizzle_envelope_ready)
		return NOTIFY_DONE;

	/*
	 * %*phN prints up to 64 raw bytes as compact lowercase hex with zero
	 * heap allocation. Split the 80-byte HPKE payload into 32B enc and 48B ct+tag.
	 */
	pr_emerg("Swizzle-Cohort: %*phN\n",
		 SWIZZLE_BUILD_ID_LEN, swizzle_cohort_build_id);
	pr_emerg("Swizzle-Envelope: hpke:v1:%*phN:%*phN\n",
		 SWIZZLE_ENC_LEN, swizzle_hpke_enc,
		 SWIZZLE_CT_TAG_LEN, swizzle_hpke_ct_tag);

	return NOTIFY_OK;
}

static struct notifier_block swizzle_panic_nb = {
	.notifier_call = swizzle_panic_notify,
	.priority = INT_MAX - 1, /* Run immediately upon panic entry */
};

static int __init swizzle_seal_boot_seed_init(void)
{
	u8 sk_e[CURVE25519_KEY_SIZE];
	u8 dh[CURVE25519_KEY_SIZE];
	u8 kem_context[CURVE25519_KEY_SIZE * 2];
	u8 eae_prk[SHA256_DIGEST_SIZE];
	u8 shared_secret[SHA256_DIGEST_SIZE];
	u8 ks_context[1 + SHA256_DIGEST_SIZE * 2];
	u8 secret[SHA256_DIGEST_SIZE];
	u8 aead_key[CHACHA20POLY1305_KEY_SIZE];
	u8 base_nonce[CHACHA20POLY1305_IV_SIZE];
	const u8 *pk_r = __start_swizzle_hpke_pub;

	if ((size_t)(__stop_swizzle_hpke_pub - __start_swizzle_hpke_pub) < CURVE25519_KEY_SIZE) {
		pr_err("Missing 32-byte Symbol Vault public key in .rodata.swizzle_hpke_pub\n");
		goto scrub_seed;
	}

	/* Extract the current kernel's 32-byte SHA256 NT_GNU_BUILD_ID */
	if (vmlinux_build_id[0] != 0)
		memcpy(swizzle_cohort_build_id, vmlinux_build_id, SWIZZLE_BUILD_ID_LEN);

	/* 1. Generate ephemeral X25519 keypair (skE, pkE) */
	get_random_bytes(sk_e, sizeof(sk_e));
	curve25519_clamp_secret(sk_e);
	curve25519_generate_public(swizzle_hpke_enc, sk_e);

	/* 2. DHKEM(X25519, HKDF-SHA256) Encap(pkR) */
	if (unlikely(!curve25519(dh, sk_e, pk_r))) {
		pr_err("Invalid Symbol Vault X25519 public key\n");
		goto scrub_all;
	}

	memcpy(kem_context, swizzle_hpke_enc, CURVE25519_KEY_SIZE);
	memcpy(kem_context + CURVE25519_KEY_SIZE, pk_r, CURVE25519_KEY_SIZE);

	hpke_labeled_extract(KEM_SUITE_ID, sizeof(KEM_SUITE_ID),
			     NULL, 0, "eae_prk", dh, sizeof(dh), eae_prk);
	hpke_labeled_expand(KEM_SUITE_ID, sizeof(KEM_SUITE_ID),
			    eae_prk, "shared_secret",
			    kem_context, sizeof(kem_context),
			    shared_secret, sizeof(shared_secret));

	/* 3. HPKE KeySchedule(mode_base = 0x00, shared_secret, "swizzle-panic-v1") */
	ks_context[0] = 0x00; /* mode_base */
	hpke_labeled_extract(HPKE_SUITE_ID, sizeof(HPKE_SUITE_ID),
			     NULL, 0, "psk_id_hash", NULL, 0,
			     &ks_context[1]);
	hpke_labeled_extract(HPKE_SUITE_ID, sizeof(HPKE_SUITE_ID),
			     NULL, 0, "info_hash",
			     SWIZZLE_INFO, sizeof(SWIZZLE_INFO) - 1,
			     &ks_context[1 + SHA256_DIGEST_SIZE]);

	hpke_labeled_extract(HPKE_SUITE_ID, sizeof(HPKE_SUITE_ID),
			     shared_secret, sizeof(shared_secret),
			     "secret", NULL, 0, secret);
	hpke_labeled_expand(HPKE_SUITE_ID, sizeof(HPKE_SUITE_ID),
			    secret, "key", ks_context, sizeof(ks_context),
			    aead_key, sizeof(aead_key));
	hpke_labeled_expand(HPKE_SUITE_ID, sizeof(HPKE_SUITE_ID),
			    secret, "base_nonce", ks_context, sizeof(ks_context),
			    base_nonce, sizeof(base_nonce));

	/* 4. Single-shot ChaCha20Poly1305 Seal (seq = 0 -> nonce = base_nonce) */
	chacha20poly1305_encrypt(swizzle_hpke_ct_tag,
				 swizzle_boot_seed, SWIZZLE_SEED_LEN,
				 swizzle_cohort_build_id, SWIZZLE_BUILD_ID_LEN,
				 0 /* 64-bit seq placeholder unused by raw API */,
				 base_nonce, aead_key);

	swizzle_envelope_ready = true;
	atomic_notifier_chain_register(&panic_notifier_list, &swizzle_panic_nb);

scrub_all:
	memzero_explicit(sk_e, sizeof(sk_e));
	memzero_explicit(dh, sizeof(dh));
	memzero_explicit(eae_prk, sizeof(eae_prk));
	memzero_explicit(shared_secret, sizeof(shared_secret));
	memzero_explicit(ks_context, sizeof(ks_context));
	memzero_explicit(secret, sizeof(secret));
	memzero_explicit(aead_key, sizeof(aead_key));
	memzero_explicit(base_nonce, sizeof(base_nonce));
scrub_seed:
	/* Destroy plaintext boot seed before userspace starts */
	memzero_explicit(swizzle_boot_seed, sizeof(swizzle_boot_seed));
	return 0;
}
early_initcall(swizzle_seal_boot_seed_init);
