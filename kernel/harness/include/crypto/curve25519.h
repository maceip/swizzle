/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _CRYPTO_CURVE25519_H
#define _CRYPTO_CURVE25519_H

#include <linux/types.h>

#define CURVE25519_KEY_SIZE 32

#ifndef __must_check
#define __must_check __attribute__((warn_unused_result))
#endif

static inline void curve25519_clamp_secret(u8 secret[CURVE25519_KEY_SIZE])
{
	secret[0] &= 248;
	secret[31] = (secret[31] & 127) | 64;
}

bool __must_check curve25519(u8 mypublic[CURVE25519_KEY_SIZE],
			     const u8 secret[CURVE25519_KEY_SIZE],
			     const u8 basepoint[CURVE25519_KEY_SIZE]);

bool curve25519_generate_public(u8 pub[CURVE25519_KEY_SIZE],
				const u8 secret[CURVE25519_KEY_SIZE]);

#endif /* _CRYPTO_CURVE25519_H */
