#include "ccmp.h"
#include "crypto.h"

size_t ccmp_hdr_len(const u8 *f, size_t len) {
    if (len < 24 || ((f[0] >> 2) & 3) != 2) return 0;
    size_t h = 24;
    if ((f[1] & 3) == 3) h += 6;                            /* ToDS and FromDS: a fourth address */
    if (f[0] & 0x80) h += 2;                                /* QoS data */
    return h <= len ? h : 0;
}

/* nonce: priority | A2 | PN5..PN0;  AAD: masked FC, A1-A3, masked sequence control, [A4], [masked QoS control] */
static void nonce_aad(const u8 *f, size_t h, u64 pn, u8 nonce[13], u8 aad[32], size_t *aad_len) {
    bool qos = f[0] & 0x80, a4 = (f[1] & 3) == 3;
    nonce[0] = qos ? (u8)(f[h - 2] & 0x0F) : 0;
    memcpy(nonce + 1, f + 10, 6);
    for (int i = 0; i < 6; i++) nonce[7 + i] = (u8)(pn >> (8 * (5 - i)));
    size_t n = 0;
    aad[n++] = (u8)(f[0] & 0x8F);                           /* subtype bits 4-6 masked */
    aad[n++] = (u8)((f[1] & ~0x38) | 0x40);                 /* retry, power management, more data masked */
    memcpy(aad + n, f + 4, 18);                             /* A1, A2, A3 */
    n += 18;
    aad[n++] = (u8)(f[22] & 0x0F);                          /* fragment number only */
    aad[n++] = 0;
    if (a4) { memcpy(aad + n, f + 24, 6); n += 6; }
    if (qos) { aad[n++] = (u8)(f[h - 2] & 0x0F); aad[n++] = 0; }  /* TID only */
    *aad_len = n;
}

/* CCM with M = 8, L = 2: the CBC-MAC tag (unencrypted) over aad and the plaintext */
static void cbc_mac(const Aes128 *a, const u8 nonce[13], const u8 *aad, size_t aad_len, const u8 *p, size_t n,
                    u8 tag[8]) {
    u8 x[16], b[16];
    b[0] = 0x59;                                            /* Adata, M = 8, L = 2 */
    memcpy(b + 1, nonce, 13);
    b[14] = (u8)(n >> 8);
    b[15] = (u8)n;
    aes128_encrypt_block(a, b, x);
    /* AAD with its 2-byte length in front, zero-padded to blocks */
    u8 ab[2 + 32 + 14] = {0};
    ab[0] = (u8)(aad_len >> 8);
    ab[1] = (u8)aad_len;
    memcpy(ab + 2, aad, aad_len);
    size_t al = (2 + aad_len + 15) / 16 * 16;
    for (size_t o = 0; o < al; o += 16) {
        for (int i = 0; i < 16; i++) x[i] ^= ab[o + i];
        aes128_encrypt_block(a, x, x);
    }
    for (size_t o = 0; o < n; o += 16) {
        size_t k = n - o < 16 ? n - o : 16;
        for (size_t i = 0; i < k; i++) x[i] ^= p[o + i];
        aes128_encrypt_block(a, x, x);
    }
    memcpy(tag, x, 8);
}

/* CTR with A_i = 0x01 | nonce | i: i = 0 for the tag, from 1 for the data */
static void ctr_block(const Aes128 *a, const u8 nonce[13], u16 i, u8 s[16]) {
    u8 b[16];
    b[0] = 0x01;
    memcpy(b + 1, nonce, 13);
    b[14] = (u8)(i >> 8);
    b[15] = (u8)i;
    aes128_encrypt_block(a, b, s);
}

static void ctr_crypt(const Aes128 *a, const u8 nonce[13], const u8 *in, u8 *out, size_t n) {
    u8 s[16];
    for (size_t o = 0; o < n; o += 16) {
        ctr_block(a, nonce, (u16)(o / 16 + 1), s);
        size_t k = n - o < 16 ? n - o : 16;
        for (size_t i = 0; i < k; i++) out[o + i] = in[o + i] ^ s[i];
    }
}

bool ccmp_decrypt(const u8 key[16], const u8 *f, size_t len, u8 *out, size_t *out_len, u64 *pn_out) {
    size_t h = ccmp_hdr_len(f, len);
    if (!h || !(f[1] & 0x40) || len < h + 8 + 8) return false;
    const u8 *c = f + h;
    if (!(c[3] & 0x20)) return false;                       /* ExtIV must be set */
    u64 pn = (u64)c[0] | (u64)c[1] << 8 | (u64)c[4] << 16 | (u64)c[5] << 24 | (u64)c[6] << 32 | (u64)c[7] << 40;
    size_t n = len - h - 8 - 8;
    u8 nonce[13], aad[32], tag[8], s0[16];
    size_t aad_len;
    nonce_aad(f, h, pn, nonce, aad, &aad_len);
    Aes128 a;
    aes128_init(&a, key);
    ctr_crypt(&a, nonce, c + 8, out, n);
    cbc_mac(&a, nonce, aad, aad_len, out, n, tag);
    ctr_block(&a, nonce, 0, s0);
    for (int i = 0; i < 8; i++) tag[i] ^= s0[i];
    if (!ct_equal(tag, f + len - 8, 8)) return false;
    *out_len = n;
    if (pn_out) *pn_out = pn;
    return true;
}

size_t ccmp_encrypt(const u8 key[16], const u8 *hdr, size_t h, const u8 *body, size_t n, u64 pn, int key_id, u8 *out,
                    size_t cap) {
    if (h + 8 + n + 8 > cap || h < 24) return 0;
    memcpy(out, hdr, h);
    out[1] |= 0x40;                                         /* protected */
    u8 *c = out + h;
    c[0] = (u8)pn;
    c[1] = (u8)(pn >> 8);
    c[2] = 0;
    c[3] = (u8)(0x20 | (key_id & 3) << 6);                  /* ExtIV, key index */
    c[4] = (u8)(pn >> 16);
    c[5] = (u8)(pn >> 24);
    c[6] = (u8)(pn >> 32);
    c[7] = (u8)(pn >> 40);
    u8 nonce[13], aad[32], tag[8], s0[16];
    size_t aad_len;
    nonce_aad(out, h, pn, nonce, aad, &aad_len);
    Aes128 a;
    aes128_init(&a, key);
    cbc_mac(&a, nonce, aad, aad_len, body, n, tag);
    ctr_crypt(&a, nonce, body, c + 8, n);
    ctr_block(&a, nonce, 0, s0);
    for (int i = 0; i < 8; i++) out[h + 8 + n + i] = tag[i] ^ s0[i];
    return h + 8 + n + 8;
}
