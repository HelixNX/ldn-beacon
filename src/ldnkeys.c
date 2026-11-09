#include "ldnkeys.h"
#include "crypto.h"
#include "nxfs.h"
#include <stdlib.h>

const char *const ldn_default_dirs[] = {".", "../keys", "../firmware", "../pkmn-violet/rom"};
const int ldn_ndefault_dirs = 4;

/* The constants, by the SHA-256 of their value: binary keys anywhere in a module's read-only data, the game's
 * strings NUL-terminated there. */
enum { C_ADV, C_DATA, C_HMAC, NFW };
static const struct { const char *name; int len; u8 hash[32]; } fw_consts[NFW] = {
    {"the advertisement input key", 16,
     {0xeb, 0x57, 0xde, 0x76, 0x2e, 0x6e, 0x1f, 0xe2, 0x0d, 0x68, 0xbd, 0xc9, 0x91, 0xcc, 0x67, 0xae,
      0x2d, 0x52, 0xe9, 0xe7, 0xd8, 0x8c, 0x3c, 0xfc, 0x6c, 0xd1, 0xf3, 0xe8, 0x1c, 0x3c, 0x98, 0x94}},
    {"the data input key", 16,
     {0xb2, 0xf5, 0x5f, 0x26, 0xca, 0x23, 0x59, 0x71, 0x9e, 0xe6, 0xa8, 0x1d, 0xd7, 0x1a, 0x93, 0xee,
      0x57, 0x56, 0x6d, 0x23, 0x25, 0x25, 0x9a, 0x26, 0xf4, 0x93, 0x7c, 0x84, 0x33, 0x12, 0x58, 0x32}},
    {"the challenge HMAC key", 32,
     {0x58, 0x47, 0xc0, 0x8e, 0x5f, 0x48, 0x63, 0x43, 0x55, 0x7e, 0x6c, 0xd9, 0xce, 0x78, 0xf4, 0x44,
      0x09, 0xa9, 0x87, 0x17, 0xe5, 0xfe, 0x2a, 0xf7, 0x74, 0x97, 0x7a, 0x98, 0xb6, 0xc9, 0x63, 0x12}},
};
/* the firmware modules they are in (22.5.0: the input keys in ldn, the HMAC key in es); each is searched for all */
static const u64 fw_programs[] = {0x0100000000000018ull /* ldn */, 0x0100000000000033ull /* es */};

static const struct {
    const char *name, *title;
    u64 programs[2];
    int pass_len;
    u8 pass_hash[32], pia_hash[32];
} games[] = {
    {"scarlet_violet", "Pokemon Scarlet / Violet", {0x0100A3D008C5C000ull, 0x01008F6008C5E000ull}, 64,
     {0x4a, 0xfd, 0x1d, 0x00, 0xa2, 0x11, 0x28, 0x3d, 0x07, 0x19, 0x05, 0x1b, 0x8b, 0xac, 0x31, 0xa5,
      0x5c, 0x46, 0xd8, 0x10, 0xa3, 0x61, 0xb3, 0xb1, 0xc6, 0x16, 0xea, 0xd7, 0xae, 0x03, 0x80, 0xae},
     {0x80, 0xec, 0xbc, 0x97, 0xca, 0xa1, 0x99, 0x27, 0x00, 0x52, 0x99, 0xb2, 0xbd, 0x77, 0x0d, 0x57,
      0x80, 0xae, 0xc2, 0x66, 0x0f, 0xd4, 0xe7, 0x1b, 0x93, 0xbc, 0x30, 0xad, 0xa8, 0x32, 0x6c, 0x51}},
};

/* every window of 16 and 32 bytes against the firmware constants not found yet */
static void scan_binary(const u8 *b, size_t n, u8 val[NFW][32], bool have[NFW]) {
    for (size_t i = 0; i + 16 <= n; i++) {
        if (!(b[i] | b[i + 1] | b[i + 2] | b[i + 3])) continue;     /* no key starts with four zero bytes */
        for (int len = 16; len <= 32; len += 16) {
            if (i + len > n) break;
            bool want = false;
            for (int c = 0; c < NFW; c++) want |= !have[c] && fw_consts[c].len == len;
            if (!want) continue;
            u8 h[32];
            sha256(b + i, len, h);
            for (int c = 0; c < NFW; c++)
                if (!have[c] && fw_consts[c].len == len && !memcmp(h, fw_consts[c].hash, 32)) {
                    memcpy(val[c], b + i, len);
                    have[c] = true;
                }
        }
    }
}

/* a NUL-terminated printable string of len characters whose SHA-256 is hash */
static bool scan_string(const u8 *b, size_t n, int len, const u8 hash[32], u8 *out) {
    for (size_t i = 0; i + len < n; i++) {
        if (b[i + len] != 0) continue;
        int j = 0;
        while (j < len && b[i + j] >= 0x20 && b[i + j] < 0x7f) j++;
        if (j < len) continue;
        u8 h[32];
        sha256(b + i, len, h);
        if (!memcmp(h, hash, 32)) { memcpy(out, b + i, len); return true; }
    }
    return false;
}

bool ldn_keys_load(LdnKeys *k, const char *const *dirs, int ndirs, const char *game) {
    memset(k, 0, sizeof *k);
    if (!ndirs) { dirs = ldn_default_dirs; ndirs = ldn_ndefault_dirs; }
    int g = -1;
    if (game) {
        for (int i = 0; i < (int)(sizeof games / sizeof *games); i++)
            if (!strcmp(games[i].name, game)) g = i;
        if (g < 0) { fprintf(stderr, "keys: unknown game \"%s\" (known: scarlet_violet)\n", game); return false; }
    }
    char err[300];
    NxFs *fs = nxfs_open(dirs, ndirs, err, sizeof err);
    if (!fs) { fprintf(stderr, "keys: %s\n", err); return false; }
    bool ok = true;

    static const char *pk[] = {"master_key_00", "aes_kek_generation_source", "aes_key_generation_source"};
    const u8 *pv[3];
    for (int i = 0; i < 3; i++)
        if (!(pv[i] = nxfs_key(fs, pk[i], 16))) { fprintf(stderr, "keys: prod.keys has no %s\n", pk[i]); ok = false; }

    u8 val[NFW][32];
    bool have[NFW] = {0}, any_fw = false;
    for (size_t p = 0; p < sizeof fw_programs / sizeof *fw_programs; p++) {
        size_t n;
        u8 *ro;
        for (int w = 0; (ro = nxfs_main_rodata(fs, fw_programs[p], w, &n)); w++) {
            any_fw = true;
            scan_binary(ro, n, val, have);
            free(ro);
        }
    }
    if (!any_fw) {
        fprintf(stderr, "keys: no firmware found (its NCAs, from your Switch, in a --files directory or its firmware/ "
                        "folder; %d NCAs seen)\n", nxfs_nca_count(fs));
        ok = false;
    } else
        for (int c = 0; c < NFW; c++)
            if (!have[c]) { fprintf(stderr, "keys: %s is not in the firmware's ldn / es modules\n", fw_consts[c].name); ok = false; }

    if (g >= 0) {
        bool any = false, pass = false;
        for (int p = 0; p < 2; p++) {
            size_t n;
            u8 *ro;
            for (int w = 0; (ro = nxfs_main_rodata(fs, games[g].programs[p], w, &n)); w++) {
                any = true;
                if (!pass) pass = scan_string(ro, n, games[g].pass_len, games[g].pass_hash, (u8 *)k->passphrase);
                if (!k->have_pia_key) k->have_pia_key = scan_string(ro, n, 16, games[g].pia_hash, k->pia_game_key);
                free(ro);
            }
        }
        if (!any) {
            fprintf(stderr, "keys: %s not found (its NSPs, from your Switch, in a --files directory; %d NSPs seen)\n",
                    games[g].title, nxfs_nsp_count(fs));
            ok = false;
        } else {
            if (!pass) { fprintf(stderr, "keys: %s's LDN passphrase was not found in its code\n", games[g].title); ok = false; }
            if (!k->have_pia_key) { fprintf(stderr, "keys: %s's Pia key was not found in its code\n", games[g].title); ok = false; }
        }
    }
    if (ok) {
        u8 k1[16], k2[16];
        aes128_ecb_decrypt1(pv[0], pv[1], k1);                  /* master_key_00, kek source */
        aes128_ecb_decrypt1(k1, val[C_ADV], k2);                /* advertisement input key */
        aes128_ecb_decrypt1(k2, pv[2], k->adv_kek);             /* key generation source */
        aes128_ecb_decrypt1(k1, val[C_DATA], k2);               /* data input key */
        aes128_ecb_decrypt1(k2, pv[2], k->data_kek);
        memcpy(k->challenge_hmac, val[C_HMAC], 32);
    }
    memset(val, 0, sizeof val);
    nxfs_close(fs);
    return ok;
}

void ldn_derive(const u8 kek[16], const void *input, size_t n, u8 key[16]) {
    u8 h[32];
    sha256(input, n, h);
    aes128_ecb_decrypt1(kek, h, key);
}

void ldn_data_key(const LdnKeys *k, const u8 server_random[16], u8 key[16]) {
    u8 in[16 + sizeof k->passphrase];
    size_t n = strlen(k->passphrase);
    memcpy(in, server_random, 16);
    memcpy(in + 16, k->passphrase, n);
    ldn_derive(k->data_kek, in, 16 + n, key);
}
