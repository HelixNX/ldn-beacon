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

/* ---- messages ---------------------------------------------------------------------------------------------- */
#include <zlib.h>

u64 pia_constant_id(const u8 mac[6]) {
    return (u64)mac[2] << 56 | (u64)mac[4] << 48 | (u64)mac[5] << 40 | (u64)mac[3] << 32 | (u64)mac[1] << 24 |
           (u64)mac[0] << 16;
}

void pia_map_add(PiaMap *m, u32 from_ip, u32 to_ip, const u8 from_mac[6], const u8 to_mac[6]) {
    if (m->n >= 8) return;
    m->from_ip[m->n] = from_ip;
    m->to_ip[m->n] = to_ip;
    m->from_cid[m->n] = pia_constant_id(from_mac);
    m->to_cid[m->n] = pia_constant_id(to_mac);
    m->n++;
}

static u64 be_n(const u8 *p, int n) {
    u64 v = 0;
    for (int i = 0; i < n; i++) v = v << 8 | p[i];
    return v;
}

static void put_be(u8 *p, u64 v, int n) {
    for (int i = n - 1; i >= 0; i--, v >>= 8) p[i] = (u8)v;
}

static unsigned rewrite_bytes(u8 *p, size_t n, const PiaMap *m) {
    unsigned r = 0;
    for (size_t i = 0; i < n;) {
        bool hit = false;
        for (int k = 0; k < m->n && !hit; k++) {
            if (i + 8 <= n && m->from_cid[k] != m->to_cid[k] && be_n(p + i, 8) == m->from_cid[k]) {
                put_be(p + i, m->to_cid[k], 8);
                i += 8;
                hit = true;
            } else if (i + 4 <= n && m->from_ip[k] != m->to_ip[k] && be_n(p + i, 4) == m->from_ip[k]) {
                put_be(p + i, m->to_ip[k], 4);
                i += 4;
                hit = true;
            }
        }
        if (hit) r++; else i++;
    }
    return r;
}

typedef struct { u8 flags, mflags, proto; u32 port; u64 dest; u16 size; const u8 *payload; } Msg;

/* one message at *pos (fields not present: the previous message's); false at the end (padding) or on garbage */
static bool next_msg(const u8 *b, size_t len, size_t *pos, Msg *m) {
    size_t i = *pos;
    if (i >= len || b[i] == 0xFF) return false;
    size_t start = i;
    m->flags = b[i++];
    if (m->flags & 1) { if (i + 1 > len) return false; m->mflags = b[i++]; }
    if (m->flags & 2) { if (i + 2 > len) return false; m->size = (u16)be_n(b + i, 2); i += 2; }
    if (m->flags & 4) { if (i + 4 > len) return false; m->proto = b[i]; m->port = (u32)be_n(b + i + 1, 3); i += 4; }
    if (m->flags & 8) { if (i + 8 > len) return false; m->dest = be_n(b + i, 8); i += 8; }
    if (i + m->size > len) return false;
    m->payload = b + i;
    i += m->size;
    i = start + ((i - start + 3) & ~(size_t)3);
    *pos = i < len ? i : len;
    return true;
}

size_t pia_rewrite(const u8 *in, size_t n, u8 *out, size_t cap, const PiaMap *m, unsigned *replaced) {
    if (!pia_is_packet(in, n) || cap < PIA_HDR) return 0;
    size_t foot = in[0xB], body = n - PIA_HDR - foot;
    const u8 *b = in + PIA_HDR;
    memcpy(out, in, PIA_HDR);
    size_t o = PIA_HDR, pos = 0;
    Msg msg = {0};
    unsigned rep = 0;
    static u8 raw[8192], comp[8192];
    while (next_msg(b, body, &pos, &msg)) {
        const u8 *pl = msg.payload;
        size_t pn = msg.size;
        if (msg.mflags & 0x20) {                        /* zlib-compressed payload */
            uLongf rn = sizeof raw;
            if (uncompress(raw, &rn, msg.payload, msg.size) != Z_OK) return 0;
            unsigned r = rewrite_bytes(raw, rn, m);
            rep += r;
            if (r) {
                uLongf cn = sizeof comp;
                if (compress2(comp, &cn, raw, rn, Z_DEFAULT_COMPRESSION) != Z_OK) return 0;
                pl = comp;
                pn = cn;
            }
        } else if (pn <= sizeof raw) {
            memcpy(raw, pl, pn);
            rep += rewrite_bytes(raw, pn, m);
            pl = raw;
        }
        size_t start = o;
        if (o + 16 + pn + 3 > cap) return 0;
        out[o++] = (u8)(msg.flags | 0x0F);              /* every field written out */
        out[o++] = msg.mflags;
        put_be(out + o, pn, 2); o += 2;
        out[o] = msg.proto; put_be(out + o + 1, msg.port, 3); o += 4;
        put_be(out + o, msg.dest, 8); o += 8;
        memcpy(out + o, pl, pn); o += pn;
        while ((o - start) & 3) out[o++] = 0;
    }
    if (pos < body && b[pos] != 0xFF) return 0;        /* stopped on something that is not padding */
    while ((o - PIA_HDR) & 15) { if (o >= cap) return 0; out[o++] = 0xFF; }
    if (o + foot > cap) return 0;
    memcpy(out + o, in + n - foot, foot);
    o += foot;
    if (replaced) *replaced = rep;
    return o;
}

void pia_dump(const u8 *p, size_t n) {
    if (!pia_is_packet(p, n)) return;
    size_t body = n - PIA_HDR - p[0xB], pos = 0;
    Msg msg = {0};
    static u8 raw[8192];
    while (next_msg(p + PIA_HDR, body, &pos, &msg)) {
        const u8 *pl = msg.payload;
        size_t pn = msg.size;
        uLongf rn = sizeof raw;
        bool z = (msg.mflags & 0x20) && uncompress(raw, &rn, msg.payload, msg.size) == Z_OK;
        if (z) { pl = raw; pn = rn; }
        printf("    message: flags %02x, message flags %02x, protocol %02x port %06x, destination %016llx, %u bytes%s:",
               msg.flags, msg.mflags, msg.proto, msg.port, (unsigned long long)msg.dest, msg.size,
               z ? " (inflated)" : "");
        for (size_t k = 0; k < pn; k++) printf("%s%02x", k % 32 ? "" : "\n      ", pl[k]);
        printf("\n");
    }
}
