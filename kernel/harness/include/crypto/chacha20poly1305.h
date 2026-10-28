/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _CRYPTO_CHACHA20POLY1305_H
#define _CRYPTO_CHACHA20POLY1305_H

#include <linux/types.h>

#define CHACHA20POLY1305_KEY_SIZE     32
#define CHACHA20POLY1305_IV_SIZE      12
#define CHACHA20POLY1305_AUTHTAG_SIZE 16

void chacha20poly1305_encrypt(u8 *dst, const u8 *src, size_t src_len,
			      const u8 *ad, size_t ad_len,
			      u64 seq,
			      const u8 iv[CHACHA20POLY1305_IV_SIZE],
			      const u8 key[CHACHA20POLY1305_KEY_SIZE]);

#endif /* _CRYPTO_CHACHA20POLY1305_H */
