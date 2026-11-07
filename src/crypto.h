/* AES-128 and SHA-256, our own small implementations (no crypto library on the live USB or in vcpkg needed). Not
 * constant time: fine for LDN, whose keys are all fixed constants or sent in the clear anyway. */
#ifndef CRYPTO_H
#define CRYPTO_H

#include "common.h"

typedef struct Aes128 { u8 rk[11][16]; } Aes128;

void aes128_init(Aes128 *a, const u8 key[16]);
void aes128_encrypt_block(const Aes128 *a, const u8 in[16], u8 out[16]);
void aes128_decrypt_block(const Aes128 *a, const u8 in[16], u8 out[16]);
/* one block of ECB decryption under key (the key derivation's step) */
void aes128_ecb_decrypt1(const u8 key[16], const u8 in[16], u8 out[16]);
/* AES-CTR in place, 128-bit big-endian counter starting at iv */
void aes128_ctr(const Aes128 *a, const u8 iv[16], u8 *data, size_t n);

typedef struct Sha256 { u32 h[8]; u64 len; u8 buf[64]; size_t fill; } Sha256;
void sha256_init(Sha256 *s);
void sha256_update(Sha256 *s, const void *p, size_t n);
void sha256_final(Sha256 *s, u8 out[32]);
void sha256(const void *p, size_t n, u8 out[32]);

/* constant-time compare, returns true when equal */
bool ct_equal(const void *a, const void *b, size_t n);

#endif
