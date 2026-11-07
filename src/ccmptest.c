/* ccmptest: checks ccmp.c against IEEE 802.11's CCMP test vector, then tries keys on the protected data frames of a
 * radiotap capture (with and without a trailing FCS) and prints what decrypts.
 *   ccmptest [-d dir] [capture.pcap key-hex...]      (-d: each decrypted body to dir/frame<N>.bin) */
#include "ccmp.h"
#include "rd.h"
#include <stdlib.h>

static bool unhex(const char *s, u8 *out, size_t n) {
    if (strlen(s) != n * 2) return false;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(s + 2 * i, "%2x", &v) != 1) return false;
        out[i] = (u8)v;
    }
    return true;
}

static bool self_test(void) {
    /* IEEE 802.11-2016 M.6.4 (CCMP test vector) */
    static const u8 key[16] = {0xc9, 0x7c, 0x1f, 0x67, 0xce, 0x37, 0x11, 0x85,
                               0x51, 0x4a, 0x8a, 0x19, 0xf2, 0xbd, 0xd5, 0x2f};
    static const u8 hdr[24] = {0x08, 0x48, 0xc3, 0x2c, 0x0f, 0xd2, 0xe1, 0x28, 0xa5, 0x7c, 0x50, 0x30,
                               0xf1, 0x84, 0x44, 0x08, 0xab, 0xae, 0xa5, 0xb8, 0xfc, 0xba, 0x80, 0x33};
    static const u8 plain[20] = {0xf8, 0xba, 0x1a, 0x55, 0xd0, 0x2f, 0x85, 0xae, 0x96, 0x7b,
                                 0xb6, 0x2f, 0xb6, 0xcd, 0xa8, 0xeb, 0x7e, 0x78, 0xa0, 0x50};
    static const u8 expect[] = {0x08, 0x48, 0xc3, 0x2c, 0x0f, 0xd2, 0xe1, 0x28, 0xa5, 0x7c, 0x50, 0x30, 0xf1,
                                0x84, 0x44, 0x08, 0xab, 0xae, 0xa5, 0xb8, 0xfc, 0xba, 0x80, 0x33, 0x0c, 0xe7,
                                0x00, 0x20, 0x76, 0x97, 0x03, 0xb5, 0xf3, 0xd0, 0xa2, 0xfe, 0x9a, 0x3d, 0xbf,
                                0x23, 0x42, 0xa6, 0x43, 0xe4, 0x32, 0x46, 0xe8, 0x0c, 0x3c, 0x04, 0xd0, 0x19,
                                0x78, 0x45, 0xce, 0x0b, 0x16, 0xf9, 0x76, 0x23};
    u8 out[128], back[64];
    size_t n = ccmp_encrypt(key, hdr, 24, plain, 20, 0xB5039776E70Cull, out, sizeof out);
    bool enc_ok = n == sizeof expect && !memcmp(out, expect, n);
    size_t bn;
    u64 pn;
    bool dec_ok = ccmp_decrypt(key, expect, sizeof expect, back, &bn, &pn) && bn == 20 && !memcmp(back, plain, 20) &&
                  pn == 0xB5039776E70Cull;
    printf("self test: encrypt %s, decrypt %s\n", enc_ok ? "ok" : "MISMATCH", dec_ok ? "ok" : "FAILED");
    if (!enc_ok) {
        printf("  got   ");
        for (size_t i = 0; i < n; i++) printf("%02x", out[i]);
        printf("\n");
    }
    return enc_ok && dec_ok;
}

int main(int argc, char **argv) {
    const char *dump = NULL;
    if (argc >= 3 && !strcmp(argv[1], "-d")) {
        dump = argv[2];
        argv += 2;
        argc -= 2;
    }
    bool ok = self_test();
    if (argc < 3) return ok ? 0 : 1;
    u8 keys[8][16];
    int nkeys = 0;
    for (int i = 2; i < argc && nkeys < 8; i++)
        if (unhex(argv[i], keys[nkeys], 16)) nkeys++;
        else fprintf(stderr, "not a 16-byte hex key: %s\n", argv[i]);
    FILE *f = fopen(argv[1], "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", argv[1]); return 1; }
    u8 gh[24];
    if (fread(gh, 1, 24, f) != 24) return 1;
    static u8 p[65536], out[65536];
    unsigned idx = 0, prot = 0, good = 0;
    for (;;) {
        u8 rh[16];
        if (fread(rh, 1, 16, f) != 16) break;
        u32 cl = (u32)rh[8] | (u32)rh[9] << 8 | (u32)rh[10] << 16 | (u32)rh[11] << 24;
        if (cl > sizeof p || fread(p, 1, cl, f) != cl) break;
        idx++;
        if (cl < 4) continue;
        size_t rl = (size_t)(p[2] | p[3] << 8);
        if (rl >= cl) continue;
        const u8 *fr = p + rl;
        size_t len = cl - rl;
        if (!ccmp_hdr_len(fr, len) || !(fr[1] & 0x40)) continue;
        prot++;
        for (int k = 0; k < nkeys; k++)
            for (int fcs = 0; fcs < 2; fcs++) {
                size_t on;
                u64 pn;
                if (!ccmp_decrypt(keys[k], fr, len - (fcs ? 4 : 0), out, &on, &pn)) continue;
                good++;
                if (dump) {
                    char path[512];
                    snprintf(path, sizeof path, "%s/frame%u.bin", dump, idx);
                    FILE *o = fopen(path, "wb");
                    if (o) { fwrite(out, 1, on, o); fclose(o); }
                }
                printf("frame %u from %02x:%02x:%02x:%02x:%02x:%02x: key %d%s, PN %llx, %zu bytes:", idx, fr[10],
                       fr[11], fr[12], fr[13], fr[14], fr[15], k, fcs ? " (FCS trimmed)" : "", (unsigned long long)pn,
                       on);
                for (size_t i = 0; i < on && i < 96; i++) printf("%s%02x", i % 32 ? "" : "\n    ", out[i]);
                printf("%s\n", on > 96 ? " ..." : "");
            }
    }
    printf("%u frames, %u protected data frames, %u decrypted\n", idx, prot, good);
    return ok ? 0 : 1;
}
