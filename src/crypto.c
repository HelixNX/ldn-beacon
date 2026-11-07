#include "crypto.h"

/* ---- AES-128 (FIPS-197). The S-boxes are computed once from GF(2^8) inverses rather than typed in. ---- */

static u8 sbox[256], inv_sbox[256];
static bool tables_ready;

static u8 xt(u8 a) { return (u8)((a << 1) ^ ((a & 0x80) ? 0x1B : 0)); }

static u8 gmul(u8 a, u8 b) {
    u8 r = 0;
    while (b) {
        if (b & 1) r ^= a;
        a = xt(a);
        b >>= 1;
    }
    return r;
}

static void make_tables(void) {
    if (tables_ready) return;
    /* walk the field with generator 3: p = 3^i, q = 3^-i, so q is p's inverse */
    u8 p = 1, q = 1;
    do {
        p = (u8)(p ^ xt(p));                     /* p * 3 */
        q ^= (u8)(q << 1);                       /* q / 3 */
        q ^= (u8)(q << 2);
        q ^= (u8)(q << 4);
        if (q & 0x80) q ^= 0x09;
        u8 x = (u8)(q ^ (q << 1 | q >> 7) ^ (q << 2 | q >> 6) ^ (q << 3 | q >> 5) ^ (q << 4 | q >> 4));
        sbox[p] = (u8)(x ^ 0x63);
    } while (p != 1);
    sbox[0] = 0x63;
    for (int i = 0; i < 256; i++) inv_sbox[sbox[i]] = (u8)i;
    tables_ready = true;
}

void aes128_init(Aes128 *a, const u8 key[16]) {
    make_tables();
    u8 *w = &a->rk[0][0];
    memcpy(w, key, 16);
    u8 rcon = 1;
    for (int i = 16; i < 176; i += 4) {
        u8 t[4] = {w[i - 4], w[i - 3], w[i - 2], w[i - 1]};
        if (i % 16 == 0) {
            u8 t0 = t[0];
            t[0] = (u8)(sbox[t[1]] ^ rcon);
            t[1] = sbox[t[2]];
            t[2] = sbox[t[3]];
            t[3] = sbox[t0];
            rcon = xt(rcon);
        }
        for (int j = 0; j < 4; j++) w[i + j] = (u8)(w[i - 16 + j] ^ t[j]);
    }
}

/* state s[c*4 + r], column-major as the bytes come in */
static void shift_rows(u8 s[16], bool inv) {
    u8 o[16];
    for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++) o[c * 4 + r] = s[(inv ? (c - r + 4) % 4 : (c + r) % 4) * 4 + r];
    memcpy(s, o, 16);
}

static void mix_columns(u8 s[16], bool inv) {
    for (int c = 0; c < 4; c++) {
        u8 *x = s + c * 4, a = x[0], b = x[1], d = x[2], e = x[3];
        if (!inv) {
            x[0] = (u8)(gmul(a, 2) ^ gmul(b, 3) ^ d ^ e);
            x[1] = (u8)(a ^ gmul(b, 2) ^ gmul(d, 3) ^ e);
            x[2] = (u8)(a ^ b ^ gmul(d, 2) ^ gmul(e, 3));
            x[3] = (u8)(gmul(a, 3) ^ b ^ d ^ gmul(e, 2));
        } else {
            x[0] = (u8)(gmul(a, 14) ^ gmul(b, 11) ^ gmul(d, 13) ^ gmul(e, 9));
            x[1] = (u8)(gmul(a, 9) ^ gmul(b, 14) ^ gmul(d, 11) ^ gmul(e, 13));
            x[2] = (u8)(gmul(a, 13) ^ gmul(b, 9) ^ gmul(d, 14) ^ gmul(e, 11));
            x[3] = (u8)(gmul(a, 11) ^ gmul(b, 13) ^ gmul(d, 9) ^ gmul(e, 14));
        }
    }
}

static void add_key(u8 s[16], const u8 k[16]) { for (int i = 0; i < 16; i++) s[i] ^= k[i]; }

void aes128_encrypt_block(const Aes128 *a, const u8 in[16], u8 out[16]) {
    u8 s[16];
    memcpy(s, in, 16);
    add_key(s, a->rk[0]);
    for (int r = 1; r <= 10; r++) {
        for (int i = 0; i < 16; i++) s[i] = sbox[s[i]];
        shift_rows(s, false);
        if (r != 10) mix_columns(s, false);
        add_key(s, a->rk[r]);
    }
    memcpy(out, s, 16);
}

void aes128_decrypt_block(const Aes128 *a, const u8 in[16], u8 out[16]) {
    u8 s[16];
    memcpy(s, in, 16);
    add_key(s, a->rk[10]);
    for (int r = 9; r >= 0; r--) {
        shift_rows(s, true);
        for (int i = 0; i < 16; i++) s[i] = inv_sbox[s[i]];
        add_key(s, a->rk[r]);
        if (r != 0) mix_columns(s, true);
    }
    memcpy(out, s, 16);
}

void aes128_ecb_decrypt1(const u8 key[16], const u8 in[16], u8 out[16]) {
    Aes128 a;
    aes128_init(&a, key);
    aes128_decrypt_block(&a, in, out);
}

void aes128_ctr(const Aes128 *a, const u8 iv[16], u8 *data, size_t n) {
    u8 ctr[16], ks[16];
    memcpy(ctr, iv, 16);
    for (size_t off = 0; off < n; off += 16) {
        aes128_encrypt_block(a, ctr, ks);
        size_t k = n - off < 16 ? n - off : 16;
        for (size_t i = 0; i < k; i++) data[off + i] ^= ks[i];
        for (int i = 15; i >= 0 && ++ctr[i] == 0; i--) {}
    }
}

/* ---- SHA-256 (FIPS 180-4) ---- */

static const u32 K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

#define ROR(x, n) ((x) >> (n) | (x) << (32 - (n)))

static void sha256_block(Sha256 *s, const u8 *p) {
    u32 w[64];
    for (int i = 0; i < 16; i++) w[i] = (u32)p[i * 4] << 24 | (u32)p[i * 4 + 1] << 16 | (u32)p[i * 4 + 2] << 8 | p[i * 4 + 3];
    for (int i = 16; i < 64; i++) {
        u32 s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3);
        u32 s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    u32 a = s->h[0], b = s->h[1], c = s->h[2], d = s->h[3], e = s->h[4], f = s->h[5], g = s->h[6], h = s->h[7];
    for (int i = 0; i < 64; i++) {
        u32 t1 = h + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ((e & f) ^ (~e & g)) + K256[i] + w[i];
        u32 t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d; s->h[4] += e; s->h[5] += f; s->h[6] += g; s->h[7] += h;
}

void sha256_init(Sha256 *s) {
    static const u32 iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                              0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    memcpy(s->h, iv, sizeof iv);
    s->len = 0;
    s->fill = 0;
}

void sha256_update(Sha256 *s, const void *pv, size_t n) {
    const u8 *p = (const u8 *)pv;
    s->len += n;
    while (n) {
        size_t k = 64 - s->fill < n ? 64 - s->fill : n;
        memcpy(s->buf + s->fill, p, k);
        s->fill += k;
        p += k;
        n -= k;
        if (s->fill == 64) { sha256_block(s, s->buf); s->fill = 0; }
    }
}

void sha256_final(Sha256 *s, u8 out[32]) {
    u64 bits = s->len * 8;
    u8 pad = 0x80, zero = 0;
    sha256_update(s, &pad, 1);
    while (s->fill != 56) sha256_update(s, &zero, 1);
    u8 l[8];
    for (int i = 0; i < 8; i++) l[i] = (u8)(bits >> (56 - 8 * i));
    sha256_update(s, l, 8);
    for (int i = 0; i < 8; i++) {
        out[i * 4] = (u8)(s->h[i] >> 24); out[i * 4 + 1] = (u8)(s->h[i] >> 16);
        out[i * 4 + 2] = (u8)(s->h[i] >> 8); out[i * 4 + 3] = (u8)s->h[i];
    }
}

void sha256(const void *p, size_t n, u8 out[32]) {
    Sha256 s;
    sha256_init(&s);
    sha256_update(&s, p, n);
    sha256_final(&s, out);
}

bool ct_equal(const void *a, const void *b, size_t n) {
    const u8 *x = (const u8 *)a, *y = (const u8 *)b;
    u8 d = 0;
    for (size_t i = 0; i < n; i++) d |= (u8)(x[i] ^ y[i]);
    return d == 0;
}
