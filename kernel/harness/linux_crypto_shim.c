// SPDX-License-Identifier: GPL-2.0
/*
 * kernel/harness/linux_crypto_shim.c
 *
 * Standards-compliant implementations of Linux lib/crypto primitives:
 *   - SHA-256 (FIPS 180-4)
 *   - X25519 scalar multiplication (RFC 7748)
 *   - ChaCha20-Poly1305 IETF AEAD (RFC 8439)
 *   - Kernel %*phN hex formatter and entropy hooks
 */

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/random.h>
#include <linux/panic_notifier.h>
#include <linux/buildid.h>
#include <crypto/sha2.h>
#include <crypto/curve25519.h>
#include <crypto/chacha20poly1305.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>

/* --- 1. FIPS 180-4 SHA-256 --- */

static const u32 K256[64] = {
	0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
	0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
	0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
	0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
	0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
	0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
	0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
	0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
	0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
	0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
	0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL,
	0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
	0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
	0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
	0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
	0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};

static inline u32 rotr32(u32 x, unsigned int n)
{
	return (x >> n) | (x << (32 - n));
}

static void sha256_transform(u32 state[8], const u8 block[64])
{
	u32 w[64];
	u32 a, b, c, d, e, f, g, h;
	int i;

	for (i = 0; i < 16; i++) {
		w[i] = ((u32)block[i * 4 + 0] << 24) |
		       ((u32)block[i * 4 + 1] << 16) |
		       ((u32)block[i * 4 + 2] << 8)  |
		       ((u32)block[i * 4 + 3]);
	}
	for (i = 16; i < 64; i++) {
		u32 s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
		u32 s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}

	a = state[0]; b = state[1]; c = state[2]; d = state[3];
	e = state[4]; f = state[5]; g = state[6]; h = state[7];

	for (i = 0; i < 64; i++) {
		u32 S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
		u32 ch = (e & f) ^ ((~e) & g);
		u32 temp1 = h + S1 + ch + K256[i] + w[i];
		u32 S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
		u32 maj = (a & b) ^ (a & c) ^ (b & c);
		u32 temp2 = S0 + maj;

		h = g; g = f; f = e; e = d + temp1;
		d = c; c = b; b = a; a = temp1 + temp2;
	}

	state[0] += a; state[1] += b; state[2] += c; state[3] += d;
	state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void sha256_init(struct sha256_state *sctx)
{
	sctx->state[0] = 0x6a09e667UL;
	sctx->state[1] = 0xbb67ae85UL;
	sctx->state[2] = 0x3c6ef372UL;
	sctx->state[3] = 0xa54ff53aUL;
	sctx->state[4] = 0x510e527fUL;
	sctx->state[5] = 0x9b05688cUL;
	sctx->state[6] = 0x1f83d9abUL;
	sctx->state[7] = 0x5be0cd19UL;
	sctx->count = 0;
}

void sha256_update(struct sha256_state *sctx, const u8 *data, size_t len)
{
	size_t idx = (size_t)(sctx->count & 0x3f);
	sctx->count += len;

	if (idx) {
		size_t left = SHA256_BLOCK_SIZE - idx;
		if (len < left) {
			memcpy(sctx->buf + idx, data, len);
			return;
		}
		memcpy(sctx->buf + idx, data, left);
		sha256_transform(sctx->state, sctx->buf);
		data += left;
		len -= left;
	}

	while (len >= SHA256_BLOCK_SIZE) {
		sha256_transform(sctx->state, data);
		data += SHA256_BLOCK_SIZE;
		len -= SHA256_BLOCK_SIZE;
	}

	if (len)
		memcpy(sctx->buf, data, len);
}

void sha256_final(struct sha256_state *sctx, u8 out[SHA256_DIGEST_SIZE])
{
	u64 bits = sctx->count * 8ULL;
	size_t idx = (size_t)(sctx->count & 0x3f);
	u8 pad[SHA256_BLOCK_SIZE];
	int i;

	memset(pad, 0, sizeof(pad));
	pad[0] = 0x80;
	if (idx < 56) {
		sha256_update(sctx, pad, 56 - idx);
	} else {
		sha256_update(sctx, pad, 120 - idx);
	}

	for (i = 0; i < 8; i++)
		pad[i] = (u8)(bits >> (56 - 8 * i));
	sha256_update(sctx, pad, 8);

	for (i = 0; i < 8; i++) {
		out[i * 4 + 0] = (u8)(sctx->state[i] >> 24);
		out[i * 4 + 1] = (u8)(sctx->state[i] >> 16);
		out[i * 4 + 2] = (u8)(sctx->state[i] >> 8);
		out[i * 4 + 3] = (u8)(sctx->state[i]);
	}
}

void sha256(const u8 *data, size_t len, u8 out[SHA256_DIGEST_SIZE])
{
	struct sha256_state sctx;
	sha256_init(&sctx);
	sha256_update(&sctx, data, len);
	sha256_final(&sctx, out);
}

/* --- 2. RFC 7748 X25519 (TweetNaCl / WireGuard 16-limb GF(2^255-19)) --- */

typedef s64 gf[16];

static void carry25519(gf o)
{
	int i;
	for (i = 0; i < 16; i++) {
		o[i] += (1LL << 16);
		s64 c = o[i] >> 16;
		o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
		o[i] -= c << 16;
	}
}

static void sel25519(gf p, gf q, int b)
{
	s64 t, c = ~(b - 1);
	int i;
	for (i = 0; i < 16; i++) {
		t = c & (p[i] ^ q[i]);
		p[i] ^= t;
		q[i] ^= t;
	}
}

static void pack25519(u8 *o, const gf n)
{
	int i, j, b;
	gf m, t;
	for (i = 0; i < 16; i++)
		t[i] = n[i];
	carry25519(t);
	carry25519(t);
	carry25519(t);
	for (j = 0; j < 2; j++) {
		m[0] = t[0] - 0xffed;
		for (i = 1; i < 15; i++) {
			m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
			m[i - 1] &= 0xffff;
		}
		m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
		b = (m[15] >> 16) & 1;
		m[14] &= 0xffff;
		sel25519(t, m, 1 - b);
	}
	for (i = 0; i < 16; i++) {
		o[2 * i] = (u8)(t[i] & 0xff);
		o[2 * i + 1] = (u8)(t[i] >> 8);
	}
}

static void unpack25519(gf o, const u8 *n)
{
	int i;
	for (i = 0; i < 16; i++)
		o[i] = n[2 * i] + ((s64)n[2 * i + 1] << 8);
	o[15] &= 0x7fff;
}

static void gf_add(gf o, const gf a, const gf b)
{
	int i;
	for (i = 0; i < 16; i++)
		o[i] = a[i] + b[i];
}

static void gf_sub(gf o, const gf a, const gf b)
{
	int i;
	for (i = 0; i < 16; i++)
		o[i] = a[i] - b[i];
}

static void gf_mul(gf o, const gf a, const gf b)
{
	s64 i, j, t[31];
	for (i = 0; i < 31; i++)
		t[i] = 0;
	for (i = 0; i < 16; i++)
		for (j = 0; j < 16; j++)
			t[i + j] += a[i] * b[j];
	for (i = 0; i < 15; i++)
		t[i] += 38 * t[i + 16];
	for (i = 0; i < 16; i++)
		o[i] = t[i];
	carry25519(o);
	carry25519(o);
}

static void gf_sqr(gf o, const gf a)
{
	gf_mul(o, a, a);
}

static void inv25519(gf o, const gf i)
{
	gf c;
	int a;
	for (a = 0; a < 16; a++)
		c[a] = i[a];
	for (a = 253; a >= 0; a--) {
		gf_sqr(c, c);
		if (a != 2 && a != 4)
			gf_mul(c, c, i);
	}
	for (a = 0; a < 16; a++)
		o[a] = c[a];
}

bool curve25519(u8 mypublic[CURVE25519_KEY_SIZE],
		const u8 secret[CURVE25519_KEY_SIZE],
		const u8 basepoint[CURVE25519_KEY_SIZE])
{
	u8 z[32];
	gf x, a, b, c, d, e, f, _121665;
	int i, r;
	u8 diff = 0;

	memset(_121665, 0, sizeof(_121665));
	_121665[0] = 0xdb41;
	_121665[1] = 1;

	memcpy(z, secret, 32);
	curve25519_clamp_secret(z);
	unpack25519(x, basepoint);

	for (i = 0; i < 16; i++) {
		b[i] = x[i];
		d[i] = a[i] = c[i] = 0;
	}
	a[0] = d[0] = 1;

	for (i = 254; i >= 0; --i) {
		r = (z[i >> 3] >> (i & 7)) & 1;
		sel25519(a, b, r);
		sel25519(c, d, r);
		gf_add(e, a, c);
		gf_sub(a, a, c);
		gf_add(c, b, d);
		gf_sub(b, b, d);
		gf_sqr(d, e);
		gf_sqr(f, a);
		gf_mul(a, c, a);
		gf_mul(c, b, e);
		gf_add(e, a, c);
		gf_sub(a, a, c);
		gf_sqr(b, a);
		gf_sub(c, d, f);
		gf_mul(a, c, _121665);
		gf_add(a, a, d);
		gf_mul(c, c, a);
		gf_mul(a, d, f);
		gf_mul(d, b, x);
		gf_sqr(b, e);
		sel25519(a, b, r);
		sel25519(c, d, r);
	}
	inv25519(c, c);
	gf_mul(a, a, c);
	pack25519(mypublic, a);

	for (i = 0; i < 32; i++)
		diff |= mypublic[i];
	return diff != 0;
}

bool curve25519_generate_public(u8 pub[CURVE25519_KEY_SIZE],
				const u8 secret[CURVE25519_KEY_SIZE])
{
	static const u8 basepoint[32] = { 9 };
	return curve25519(pub, secret, basepoint);
}

/* --- 3. RFC 8439 ChaCha20-Poly1305 IETF AEAD --- */

static inline u32 rotl32(u32 x, unsigned int n)
{
	return (x << n) | (x >> (32 - n));
}

static inline u32 load_le32(const u8 *p)
{
	return ((u32)p[0]) | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

static inline void store_le32(u8 *p, u32 v)
{
	p[0] = (u8)(v);
	p[1] = (u8)(v >> 8);
	p[2] = (u8)(v >> 16);
	p[3] = (u8)(v >> 24);
}

static inline void store_le64(u8 *p, u64 v)
{
	int i;
	for (i = 0; i < 8; i++)
		p[i] = (u8)(v >> (8 * i));
}

#define QR(a, b, c, d) do { \
	a += b; d ^= a; d = rotl32(d, 16); \
	c += d; b ^= c; b = rotl32(b, 12); \
	a += b; d ^= a; d = rotl32(d, 8);  \
	c += d; b ^= c; b = rotl32(b, 7);  \
} while (0)

static void chacha20_block(u8 out[64], const u8 key[32], u32 counter, const u8 nonce[12])
{
	u32 s[16], x[16];
	int i;

	s[0]  = 0x61707865UL;
	s[1]  = 0x3320646eUL;
	s[2]  = 0x79622d32UL;
	s[3]  = 0x6b206574UL;
	for (i = 0; i < 8; i++)
		s[4 + i] = load_le32(key + 4 * i);
	s[12] = counter;
	s[13] = load_le32(nonce + 0);
	s[14] = load_le32(nonce + 4);
	s[15] = load_le32(nonce + 8);

	for (i = 0; i < 16; i++)
		x[i] = s[i];

	for (i = 0; i < 10; i++) {
		QR(x[0], x[4], x[8],  x[12]);
		QR(x[1], x[5], x[9],  x[13]);
		QR(x[2], x[6], x[10], x[14]);
		QR(x[3], x[7], x[11], x[15]);
		QR(x[0], x[5], x[10], x[15]);
		QR(x[1], x[6], x[11], x[12]);
		QR(x[2], x[7], x[8],  x[13]);
		QR(x[3], x[4], x[9],  x[14]);
	}

	for (i = 0; i < 16; i++)
		store_le32(out + 4 * i, x[i] + s[i]);
}

static void poly1305_blocks(u32 h[5], const u32 r[4], const u32 s_r[4],
			    const u8 *m, size_t bytes, u32 hibit)
{
	while (bytes >= 16) {
		u64 d0, d1, d2, d3, d4;
		u32 c;

		h[0] += (load_le32(m + 0)) & 0x3ffffff;
		h[1] += (load_le32(m + 3) >> 2) & 0x3ffffff;
		h[2] += (load_le32(m + 6) >> 4) & 0x3ffffff;
		h[3] += (load_le32(m + 9) >> 6) & 0x3ffffff;
		h[4] += (load_le32(m + 12) >> 8) | hibit;

		d0 = (u64)h[0]*r[0] + (u64)h[1]*s_r[3] + (u64)h[2]*s_r[2] + (u64)h[3]*s_r[1] + (u64)h[4]*s_r[0];
		d1 = (u64)h[0]*r[1] + (u64)h[1]*r[0]   + (u64)h[2]*s_r[3] + (u64)h[3]*s_r[2] + (u64)h[4]*s_r[1];
		d2 = (u64)h[0]*r[2] + (u64)h[1]*r[1]   + (u64)h[2]*r[0]   + (u64)h[3]*s_r[3] + (u64)h[4]*s_r[2];
		d3 = (u64)h[0]*r[3] + (u64)h[1]*r[2]   + (u64)h[2]*r[1]   + (u64)h[3]*r[0]   + (u64)h[4]*s_r[3];
		d4 = (u64)h[0]*0    + (u64)h[1]*r[3]   + (u64)h[2]*r[2]   + (u64)h[3]*r[1]   + (u64)h[4]*r[0];

		c = (u32)(d0 >> 26); h[0] = (u32)d0 & 0x3ffffff;
		d1 += c; c = (u32)(d1 >> 26); h[1] = (u32)d1 & 0x3ffffff;
		d2 += c; c = (u32)(d2 >> 26); h[2] = (u32)d2 & 0x3ffffff;
		d3 += c; c = (u32)(d3 >> 26); h[3] = (u32)d3 & 0x3ffffff;
		d4 += c; c = (u32)(d4 >> 26); h[4] = (u32)d4 & 0x3ffffff;
		h[0] += c * 5; c = h[0] >> 26; h[0] &= 0x3ffffff;
		h[1] += c;

		m += 16;
		bytes -= 16;
	}
}

static void poly1305_update_padded(u32 h[5], const u32 r[4], const u32 s_r[4],
				   const u8 *data, size_t len)
{
	size_t full = len & ~15ULL;
	if (full)
		poly1305_blocks(h, r, s_r, data, full, 1U << 24);
	if (len & 15ULL) {
		u8 pad[16] = { 0 };
		memcpy(pad, data + full, len & 15ULL);
		poly1305_blocks(h, r, s_r, pad, 16, 1U << 24);
	}
}

void chacha20poly1305_encrypt(u8 *dst, const u8 *src, size_t src_len,
			      const u8 *ad, size_t ad_len,
			      u64 seq,
			      const u8 iv[CHACHA20POLY1305_IV_SIZE],
			      const u8 key[CHACHA20POLY1305_KEY_SIZE])
{
	u8 otk[64];
	u8 block[64];
	u8 nonce[12];
	u32 r[4], s_r[4], h[5] = { 0 };
	u32 pad_s[4];
	u8 lens[16];
	u32 counter = 1;
	size_t offset = 0;
	u64 f;
	u32 c, mask, g[5];
	int i;

	memcpy(nonce, iv, 12);
	for (i = 0; i < 8; i++)
		nonce[11 - i] ^= (u8)(seq >> (8 * i));

	/* 1. Poly1305 one-time key with counter = 0 */
	chacha20_block(otk, key, 0, nonce);

	/* 2. ChaCha20 encrypt starting at counter = 1 */
	while (offset < src_len) {
		size_t chunk = (src_len - offset > 64) ? 64 : (src_len - offset);
		size_t j;
		chacha20_block(block, key, counter++, nonce);
		for (j = 0; j < chunk; j++)
			dst[offset + j] = src[offset + j] ^ block[j];
		offset += chunk;
	}

	/* 3. Poly1305 MAC over ad || pad16(ad) || ct || pad16(ct) || le64(ad_len) || le64(ct_len) */
	{
		u32 r0 = (load_le32(otk +  0)) & 0x3ffffff;
		u32 r1 = (load_le32(otk +  3) >> 2) & 0x3ffff03;
		u32 r2 = (load_le32(otk +  6) >> 4) & 0x3ffc0ff;
		u32 r3 = (load_le32(otk +  9) >> 6) & 0x3f03fff;
		u32 r4_limb = (load_le32(otk + 12) >> 8) & 0x00fffff;
		u32 s1 = r1 * 5;
		u32 s2 = r2 * 5;
		u32 s3 = r3 * 5;
		u32 s4 = r4_limb * 5;
		u32 h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;

		#define POLY_BLOCK(blk_ptr) do { \
			u64 d0, d1, d2, d3, d4; \
			u32 cc; \
			h0 += (load_le32((blk_ptr) + 0)) & 0x3ffffff; \
			h1 += (load_le32((blk_ptr) + 3) >> 2) & 0x3ffffff; \
			h2 += (load_le32((blk_ptr) + 6) >> 4) & 0x3ffffff; \
			h3 += (load_le32((blk_ptr) + 9) >> 6) & 0x3ffffff; \
			h4 += (load_le32((blk_ptr) + 12) >> 8) | (1U << 24); \
			d0 = (u64)h0*r0 + (u64)h1*s4 + (u64)h2*s3 + (u64)h3*s2 + (u64)h4*s1; \
			d1 = (u64)h0*r1 + (u64)h1*r0 + (u64)h2*s4 + (u64)h3*s3 + (u64)h4*s2; \
			d2 = (u64)h0*r2 + (u64)h1*r1 + (u64)h2*r0 + (u64)h3*s4 + (u64)h4*s3; \
			d3 = (u64)h0*r3 + (u64)h1*r2 + (u64)h2*r1 + (u64)h3*r0 + (u64)h4*s4; \
			d4 = (u64)h0*r4_limb + (u64)h1*r3 + (u64)h2*r2 + (u64)h3*r1 + (u64)h4*r0; \
			cc = (u32)(d0 >> 26); h0 = (u32)d0 & 0x3ffffff; \
			d1 += cc; cc = (u32)(d1 >> 26); h1 = (u32)d1 & 0x3ffffff; \
			d2 += cc; cc = (u32)(d2 >> 26); h2 = (u32)d2 & 0x3ffffff; \
			d3 += cc; cc = (u32)(d3 >> 26); h3 = (u32)d3 & 0x3ffffff; \
			d4 += cc; cc = (u32)(d4 >> 26); h4 = (u32)d4 & 0x3ffffff; \
			h0 += cc * 5; cc = h0 >> 26; h0 &= 0x3ffffff; \
			h1 += cc; \
		} while (0)

		for (offset = 0; offset < ad_len; offset += 16) {
			u8 chunk[16] = { 0 };
			size_t take = (ad_len - offset > 16) ? 16 : (ad_len - offset);
			memcpy(chunk, ad + offset, take);
			POLY_BLOCK(chunk);
		}
		for (offset = 0; offset < src_len; offset += 16) {
			u8 chunk[16] = { 0 };
			size_t take = (src_len - offset > 16) ? 16 : (src_len - offset);
			memcpy(chunk, dst + offset, take);
			POLY_BLOCK(chunk);
		}
		store_le64(lens + 0, (u64)ad_len);
		store_le64(lens + 8, (u64)src_len);
		POLY_BLOCK(lens);

		#undef POLY_BLOCK

		/* Final reduction */
		c = h1 >> 26; h1 &= 0x3ffffff;
		h2 += c; c = h2 >> 26; h2 &= 0x3ffffff;
		h3 += c; c = h3 >> 26; h3 &= 0x3ffffff;
		h4 += c; c = h4 >> 26; h4 &= 0x3ffffff;
		h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
		h1 += c;

		g[0] = h0 + 5; c = g[0] >> 26; g[0] &= 0x3ffffff;
		g[1] = h1 + c; c = g[1] >> 26; g[1] &= 0x3ffffff;
		g[2] = h2 + c; c = g[2] >> 26; g[2] &= 0x3ffffff;
		g[3] = h3 + c; c = g[3] >> 26; g[3] &= 0x3ffffff;
		g[4] = h4 + c - (1U << 26);

		mask = (g[4] >> 31) - 1;
		for (i = 0; i < 5; i++)
			g[i] &= mask;
		mask = ~mask;
		h0 = (h0 & mask) | g[0];
		h1 = (h1 & mask) | g[1];
		h2 = (h2 & mask) | g[2];
		h3 = (h3 & mask) | g[3];
		h4 = (h4 & mask) | g[4];

		h0 = ((h0) | (h1 << 26)) & 0xffffffffU;
		h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffffU;
		h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffffU;
		h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffffU;

		for (i = 0; i < 4; i++)
			pad_s[i] = load_le32(otk + 16 + 4 * i);

		f = (u64)h0 + pad_s[0]; h0 = (u32)f;
		f = (u64)h1 + pad_s[1] + (f >> 32); h1 = (u32)f;
		f = (u64)h2 + pad_s[2] + (f >> 32); h2 = (u32)f;
		f = (u64)h3 + pad_s[3] + (f >> 32); h3 = (u32)f;

		store_le32(dst + src_len + 0, h0);
		store_le32(dst + src_len + 4, h1);
		store_le32(dst + src_len + 8, h2);
		store_le32(dst + src_len + 12, h3);
	}
	(void)poly1305_update_padded;
	(void)h;
	(void)r;
	(void)s_r;
}

/* --- 4. Kernel Printk (%*phN support) & Entropy Hooks --- */

struct atomic_notifier_head panic_notifier_list = { 0 };
u8 vmlinux_build_id[32] = { 0 };

static char swizzle_last_panic_log[2048];
static size_t swizzle_last_panic_pos;

void swizzle_reset_panic_log(void)
{
	memset(swizzle_last_panic_log, 0, sizeof(swizzle_last_panic_log));
	swizzle_last_panic_pos = 0;
}

const char *swizzle_get_panic_log(void)
{
	return swizzle_last_panic_log;
}

/*
 * Implements Linux kernel %*phN compact lowercase hex dump formatting
 * used by kernel/swizzle_panic.c.
 */
static void swizzle_vprintk_buf(const char *fmt, va_list ap)
{
	const char *p = fmt;

	while (*p && swizzle_last_panic_pos + 2 < sizeof(swizzle_last_panic_log)) {
		if (p[0] == '%' && p[1] == '*' && p[2] == 'p' && p[3] == 'h' && p[4] == 'N') {
			int len = va_arg(ap, int);
			const u8 *buf = va_arg(ap, const u8 *);
			int i;
			for (i = 0; i < len && swizzle_last_panic_pos + 3 < sizeof(swizzle_last_panic_log); i++) {
				snprintf(swizzle_last_panic_log + swizzle_last_panic_pos,
					 sizeof(swizzle_last_panic_log) - swizzle_last_panic_pos,
					 "%02x", buf[i]);
				swizzle_last_panic_pos += 2;
			}
			p += 5;
		} else {
			swizzle_last_panic_log[swizzle_last_panic_pos++] = *p++;
		}
	}
	swizzle_last_panic_log[swizzle_last_panic_pos] = '\0';
}

void swizzle_printk_emerg(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	swizzle_vprintk_buf(fmt, ap);
	va_end(ap);
}

void swizzle_printk_err(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	swizzle_vprintk_buf(fmt, ap);
	va_end(ap);
}

static bool swizzle_override_seed_active;
static u64  swizzle_override_seed_words[4];
static int  swizzle_override_seed_idx;

void swizzle_set_test_hw_seed(const u8 seed[32])
{
	if (seed) {
		memcpy(swizzle_override_seed_words, seed, 32);
		swizzle_override_seed_active = true;
		swizzle_override_seed_idx = 0;
	} else {
		swizzle_override_seed_active = false;
	}
}

void get_random_bytes(void *buf, size_t len)
{
	int fd = open("/dev/urandom", O_RDONLY);
	if (fd >= 0) {
		ssize_t r = read(fd, buf, len);
		(void)r;
		close(fd);
	}
}

bool swizzle_arch_rdseed64(u64 *out)
{
	if (swizzle_override_seed_active) {
		*out = swizzle_override_seed_words[swizzle_override_seed_idx & 3];
		swizzle_override_seed_idx = (swizzle_override_seed_idx + 1) & 3;
		return true;
	}
	get_random_bytes(out, sizeof(*out));
	return *out != 0 && *out != ~0ULL;
}

bool swizzle_arch_rdrand64(u64 *out)
{
	return swizzle_arch_rdseed64(out);
}

u64 swizzle_arch_rdtsc64(void)
{
	u64 v = 0;
	get_random_bytes(&v, sizeof(v));
	return v;
}
