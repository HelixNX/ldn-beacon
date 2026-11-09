/* authtest: parses decrypted LDN authentication requests (files from ccmptest -d: LLC/SNAP header + LDN frame),
 * builds the response the beacon would send, wraps it in a CCMP data frame and decrypts it again.
 *   authtest [--files dir]... [--data-key hex] [--out file] request.bin... */
#include "ccmp.h"
#include "ldnauth.h"
#include <stdlib.h>

int main(int argc, char **argv) {
    const char *dirs[8], *outp = NULL;
    int ndirs = 0, bad = 0;
    u8 dkey[16] = {0};
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--files") && i + 1 < argc && ndirs < 8) { dirs[ndirs++] = argv[++i]; continue; }
        if (!strcmp(argv[i], "--out") && i + 1 < argc) { outp = argv[++i]; continue; }
        if (!strcmp(argv[i], "--data-key") && i + 1 < argc) {
            const char *h = argv[++i];
            for (int j = 0; j < 16 && h[2 * j]; j++) { unsigned v; sscanf(h + 2 * j, "%2x", &v); dkey[j] = (u8)v; }
            continue;
        }
    }
    LdnKeys keys;
    if (!ldn_keys_load(&keys, dirs, ndirs, NULL)) return 1;
    static const u8 own_id[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--files") || !strcmp(argv[i], "--out") || !strcmp(argv[i], "--data-key")) { i++; continue; }
        FILE *f = fopen(argv[i], "rb");
        if (!f) { fprintf(stderr, "cannot open %s\n", argv[i]); return 1; }
        static u8 b[4096];
        size_t n = fread(b, 1, sizeof b, f);
        fclose(f);
        LdnAuthRequest r;
        bool ok = n > 8 && ldn_auth_parse(&keys, b + 8, n - 8, &r);
        printf("%s: %s, version %u, user \"%s\", app version %u, platform %u, challenge %s (P %u Q %u flags %u)\n",
               argv[i], ok ? "request" : "NOT A REQUEST", r.version, r.user_name, r.app_version, r.platform,
               !r.has_challenge ? "none" : r.challenge_ok ? "HMAC ok" : "HMAC BAD", r.p, r.q, r.flags);
        if (!ok || !r.challenge_ok) { bad++; continue; }
        u8 resp[1024];
        size_t rn = ldn_auth_response(&keys, &r, LDN_AUTH_OK, own_id, r.flags, resp, sizeof resp);
        /* the frame the beacon sends: QoS data, FromDS, LLC/SNAP + EtherType 0x88B7 */
        u8 body[1100], hdr[26] = {0x88, 0x02, 0, 0, 0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0x02, 0x00, 0x00, 0x00, 0x00,
                                  0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x10, 0x00, 0x00, 0x00};
        static const u8 llc[8] = {0xAA, 0xAA, 0x03, 0, 0, 0, 0x88, 0xB7};
        memcpy(body, llc, 8);
        memcpy(body + 8, resp, rn);
        u8 fr[1300], back[1300];
        size_t fn = ccmp_encrypt(dkey, hdr, 26, body, 8 + rn, 1, 0, fr, sizeof fr), bn = 0;
        u64 pn;
        bool rt = fn && ccmp_decrypt(dkey, fr, fn, back, &bn, &pn) && bn == 8 + rn && !memcmp(back, body, bn);
        printf("  response %zu bytes (LDN), frame %zu bytes, CCMP round trip %s\n", rn, fn, rt ? "ok" : "FAILED");
        if (!rt) bad++;
        if (outp) {
            FILE *o = fopen(outp, "wb");
            if (o) { fwrite(resp, 1, rn, o); fclose(o); }
            outp = NULL;
        }
    }
    return bad ? 1 : 0;
}
