/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _CRYPTO_SHA2_H
#define _CRYPTO_SHA2_H

#include <linux/types.h>

#define SHA256_DIGEST_SIZE 32
#define SHA256_BLOCK_SIZE  64

struct sha256_state {
	u32 state[8];
	u64 count;
	u8 buf[SHA256_BLOCK_SIZE];
};

void sha256_init(struct sha256_state *sctx);
void sha256_update(struct sha256_state *sctx, const u8 *data, size_t len);
void sha256_final(struct sha256_state *sctx, u8 out[SHA256_DIGEST_SIZE]);
void sha256(const u8 *data, size_t len, u8 out[SHA256_DIGEST_SIZE]);

#endif /* _CRYPTO_SHA2_H */
