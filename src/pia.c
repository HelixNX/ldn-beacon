#include "pia.h"

u32 crc32_ieee(const u8 *p, size_t n) {
    u32 c = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) {
        c ^= p[i];
        for (int k = 0; k < 8; k++) c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1)));
    }
    return ~c;
}

/* GF(2^128) multiply, GCM's bit order (bitwise; packets are small) */
static void gf_mul(u8 x[16], const u8 h[16]) {
    u8 z[16] = {0}, v[16];
    memcpy(v, h, 16);
    for (int i = 0; i < 128; i++) {
        if (x[i >> 3] & (0x80 >> (i & 7)))
            for (int k = 0; k < 16; k++) z[k] ^= v[k];
        bool lsb = v[15] & 1;
        for (int k = 15; k > 0; k--) v[k] = (u8)(v[k] >> 1 | v[k - 1] << 7);
        v[0] >>= 1;
        if (lsb) v[0] ^= 0xE1;
    }
    memcpy(x, z, 16);
}

static void ghash_blocks(u8 y[16], const u8 h[16], const u8 *p, size_t n) {
    for (size_t i = 0; i < n; i += 16) {
        size_t m = n - i < 16 ? n - i : 16;
        for (size_t k = 0; k < m; k++) y[k] ^= p[i + k];
        gf_mul(y, h);
    }
}

static void gcm_tag(const Aes128 *a, const u8 nonce[12], const u8 *aad, size_t aad_len, const u8 *ct, size_t n,
                    u8 tag[16]) {
    u8 h[16] = {0}, y[16] = {0}, j0[16], lens[16], s[16];
    aes128_encrypt_block(a, h, h);
    ghash_blocks(y, h, aad, aad_len);
    ghash_blocks(y, h, ct, n);
    u64 al = (u64)aad_len * 8, cl = (u64)n * 8;
    for (int i = 0; i < 8; i++) {
        lens[i] = (u8)(al >> (56 - 8 * i));
        lens[8 + i] = (u8)(cl >> (56 - 8 * i));
    }
    ghash_blocks(y, h, lens, 16);
    memcpy(j0, nonce, 12);
    j0[12] = j0[13] = j0[14] = 0;
    j0[15] = 1;
    aes128_encrypt_block(a, j0, s);
    for (int i = 0; i < 16; i++) tag[i] = s[i] ^ y[i];
}

static void gcm_ctr(const Aes128 *a, const u8 nonce[12], u8 *data, size_t n) {
    u8 iv[16];
    memcpy(iv, nonce, 12);
    iv[12] = iv[13] = iv[14] = 0;
    iv[15] = 2;                                     /* J0 + 1 */
    aes128_ctr(a, iv, data, n);
}

void gcm_encrypt(const Aes128 *a, const u8 nonce[12], const u8 *aad, size_t aad_len, u8 *data, size_t n, u8 *tag,
                 size_t tag_len) {
    u8 t[16];
    gcm_ctr(a, nonce, data, n);
    gcm_tag(a, nonce, aad, aad_len, data, n, t);
    memcpy(tag, t, tag_len);
}

bool gcm_decrypt(const Aes128 *a, const u8 nonce[12], const u8 *aad, size_t aad_len, u8 *data, size_t n,
                 const u8 *tag, size_t tag_len) {
    u8 t[16];
    gcm_tag(a, nonce, aad, aad_len, data, n, t);
    if (!ct_equal(t, tag, tag_len)) return false;
    gcm_ctr(a, nonce, data, n);
    return true;
}

void pia_net_init(PiaNet *p, const u8 game_key[16], const u8 ssid[16], const PiaVariant *v) {
    Aes128 g;
    aes128_init(&g, game_key);
    if (v->key_decrypt) aes128_decrypt_block(&g, ssid, p->session_key);
    else aes128_encrypt_block(&g, ssid, p->session_key);
    aes128_init(&p->key, p->session_key);
    p->network_id = crc32_ieee(ssid + 1, 15);
}

bool pia_is_packet(const u8 *p, size_t n) {
    return n >= PIA_HDR && p[0] == 0x32 && p[1] == 0xAB && p[2] == 0x98 && p[3] == 0x64 && (p[4] & 0x80) &&
           PIA_HDR + (size_t)p[0xB] <= n;
}

static void nonce_of(const PiaNet *net, const PiaVariant *v, u32 src_ip, const u8 *p, u8 nonce[12]) {
    u8 c[4], ip[4];
    for (int i = 0; i < 4; i++) {
        c[i] = (u8)(net->network_id >> (v->crc_le ? 8 * i : 24 - 8 * i));
        ip[i] = (u8)(src_ip >> (v->ip_le ? 8 * i : 24 - 8 * i));
    }
    for (int i = 0; i < 4; i++) nonce[i] = c[i] ^ ip[i];
    memcpy(nonce + 4, p + 0xC, 8);
}

static size_t aad_len(const PiaVariant *v) { return v->aad == 1 ? 0xC : v->aad == 2 ? 0x14 : 0; }

bool pia_decrypt(const PiaNet *net, const PiaVariant *v, u32 src_ip, u8 *p, size_t n) {
    if (!pia_is_packet(p, n)) return false;
    u8 nonce[12];
    nonce_of(net, v, src_ip, p, nonce);
    size_t body = n - PIA_HDR - p[0xB];
    return gcm_decrypt(&net->key, nonce, p, aad_len(v), p + PIA_HDR, body, p + 0x14, PIA_TAG);
}

void pia_encrypt(const PiaNet *net, const PiaVariant *v, u32 src_ip, u8 *p, size_t n) {
    if (!pia_is_packet(p, n)) return;
    u8 nonce[12];
    nonce_of(net, v, src_ip, p, nonce);
    size_t body = n - PIA_HDR - p[0xB];
    gcm_encrypt(&net->key, nonce, p, aad_len(v), p + PIA_HDR, body, p + 0x14, PIA_TAG);
}
