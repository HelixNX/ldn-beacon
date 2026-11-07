#include "ldnkeys.h"
#include "crypto.h"
#include <ctype.h>

enum { NKEYS = 7 };
static const char *const names[NKEYS] = {
    "master_key_00", "aes_kek_generation_source", "aes_key_generation_source",
    "ldn_advertisement_input_key", "ldn_data_input_key", "ldn_challenge_hmac_key", NULL /* passphrase */
};

static char *trim(char *s) {
    while (isspace((unsigned char)*s)) s++;
    char *e = s + strlen(s);
    while (e > s && isspace((unsigned char)e[-1])) *--e = 0;
    return s;
}

static bool hexn(const char *s, u8 *out, size_t n) {
    if (strlen(s) != n * 2) return false;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (!isxdigit((unsigned char)s[i * 2]) || !isxdigit((unsigned char)s[i * 2 + 1])) return false;
        sscanf(s + i * 2, "%2x", &v);
        out[i] = (u8)v;
    }
    return true;
}

bool ldn_keys_load(LdnKeys *k, const char *const *files, int nfiles, const char *passphrase_name) {
    static const u8 size[NKEYS - 1] = {16, 16, 16, 16, 16, 32};
    u8 val[NKEYS - 1][32];
    bool have[NKEYS] = {0};
    memset(k, 0, sizeof *k);
    for (int f = 0; f < nfiles; f++) {
        FILE *fp = fopen(files[f], "r");
        if (!fp) { fprintf(stderr, "keys: cannot open %s\n", files[f]); return false; }
        char line[512];
        while (fgets(line, sizeof line, fp)) {
            char *eq = strchr(line, '=');
            if (line[0] == '#' || !eq) continue;
            *eq = 0;
            char *name = trim(line), *v = trim(eq + 1);
            for (int i = 0; i < NKEYS - 1; i++)
                if (!strcmp(name, names[i])) {
                    if (!hexn(v, val[i], size[i])) {
                        fprintf(stderr, "keys: %s in %s is not %u hex bytes\n", name, files[f], size[i]);
                        fclose(fp);
                        return false;
                    }
                    have[i] = true;
                }
            static const char pp[] = "ldn_passphrase_";
            if (passphrase_name && !strncmp(passphrase_name, pp, sizeof pp - 1) && !strncmp(name, "pia_game_key_", 13) &&
                !strcmp(name + 13, passphrase_name + sizeof pp - 1) && strlen(v) == 16) {
                memcpy(k->pia_game_key, v, 16);
                k->have_pia_key = true;
            }
            if (passphrase_name && !strcmp(name, passphrase_name) && strlen(v) < sizeof k->passphrase) {
                strcpy(k->passphrase, v);
                have[NKEYS - 1] = true;
            }
        }
        fclose(fp);
    }
    bool ok = true;
    for (int i = 0; i < NKEYS - 1; i++)
        if (!have[i]) { fprintf(stderr, "keys: %s missing\n", names[i]); ok = false; }
    if (passphrase_name && !have[NKEYS - 1]) { fprintf(stderr, "keys: %s missing\n", passphrase_name); ok = false; }
    if (!ok) return false;

    u8 k1[16], k2[16];
    aes128_ecb_decrypt1(val[0], val[1], k1);                    /* master_key_00, kek source */
    aes128_ecb_decrypt1(k1, val[3], k2);                        /* advertisement input key */
    aes128_ecb_decrypt1(k2, val[2], k->adv_kek);                /* key generation source */
    aes128_ecb_decrypt1(k1, val[4], k2);                        /* data input key */
    aes128_ecb_decrypt1(k2, val[2], k->data_kek);
    memcpy(k->challenge_hmac, val[5], 32);
    return true;
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
