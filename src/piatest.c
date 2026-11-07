/* piatest: checks pia.c's AES-GCM against NIST's vector, then finds the Pia variant (pia.h) that authenticates the
 * Pia packets in a beacon capture: CCMP-decrypts the data frames with the network's data key, takes UDP payloads
 * starting with Pia's magic, and tries every SSID candidate x source address x PiaVariant.
 *   piatest capture.pcap data-key-hex game-key(16 chars) [ip:a.b.c.d]... [hex:32 hex digits | str:text]...
 *           [map:a.b.c.d=e.f.g.h,mac=mac]... [as:a.b.c.d]
 * ip: the address the sender encrypted with (default: the packet's source); str: the first 16 bytes, zero-padded.
 * map / as: rewrite the first packet's messages with these address and MAC pairs (pia_rewrite), encrypt it as from
 * the "as" address, check that it decrypts again, and print the messages before and after. */
#include "ccmp.h"
#include "pia.h"
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

static bool gcm_self_test(void) {
    /* NIST GCM test case 2 (AES-128, zero key, zero 96-bit IV, one zero block) */
    static const u8 c2[16] = {0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
                              0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78};
    static const u8 t2[16] = {0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
                              0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf};
    u8 key[16] = {0}, nonce[12] = {0}, d[16] = {0}, tag[16];
    Aes128 a;
    aes128_init(&a, key);
    gcm_encrypt(&a, nonce, NULL, 0, d, 16, tag, 16);
    bool ok = !memcmp(d, c2, 16) && !memcmp(tag, t2, 16) && gcm_decrypt(&a, nonce, NULL, 0, d, 16, tag, 16);
    u8 zero[16] = {0};
    ok = ok && !memcmp(d, zero, 16);
    printf("GCM self test: %s\n", ok ? "ok" : "FAILED");
    return ok;
}

typedef struct { u32 src, dst; u16 sport, dport; size_t n; u8 p[1500]; } Pkt;
static Pkt pk[4096];
static int npk;

int main(int argc, char **argv) {
    bool ok = gcm_self_test();
    if (argc < 4) return ok ? 0 : 1;
    u8 dkey[16], gkey[16];
    if (!unhex(argv[2], dkey, 16) || strlen(argv[3]) != 16) { fprintf(stderr, "bad keys\n"); return 2; }
    memcpy(gkey, argv[3], 16);
    u8 ssid[16][16];
    char ssid_name[16][64];
    u32 ips[8], as_ip = 0;
    int nssid = 0, nip = 0;
    PiaMap map = {0};
    for (int i = 4; i < argc; i++) {
        unsigned a, b, c, d;
        unsigned e, g, h, j, m1[6], m2[6];
        if (!strncmp(argv[i], "map:", 4) &&
            sscanf(argv[i] + 4, "%u.%u.%u.%u=%u.%u.%u.%u,%x:%x:%x:%x:%x:%x=%x:%x:%x:%x:%x:%x", &a, &b, &c, &d, &e, &g,
                   &h, &j, &m1[0], &m1[1], &m1[2], &m1[3], &m1[4], &m1[5], &m2[0], &m2[1], &m2[2], &m2[3], &m2[4],
                   &m2[5]) == 20) {
            u8 x[6], y[6];
            for (int k = 0; k < 6; k++) { x[k] = (u8)m1[k]; y[k] = (u8)m2[k]; }
            pia_map_add(&map, a << 24 | b << 16 | c << 8 | d, e << 24 | g << 16 | h << 8 | j, x, y);
        } else if (!strncmp(argv[i], "as:", 3) && sscanf(argv[i] + 3, "%u.%u.%u.%u", &a, &b, &c, &d) == 4)
            as_ip = a << 24 | b << 16 | c << 8 | d;
        else if (!strncmp(argv[i], "ip:", 3) && sscanf(argv[i] + 3, "%u.%u.%u.%u", &a, &b, &c, &d) == 4 && nip < 8)
            ips[nip++] = a << 24 | b << 16 | c << 8 | d;
        else if (!strncmp(argv[i], "hex:", 4) && nssid < 16 && unhex(argv[i] + 4, ssid[nssid], 16))
            snprintf(ssid_name[nssid++], 64, "%s", argv[i]);
        else if (!strncmp(argv[i], "str:", 4) && nssid < 16) {
            memset(ssid[nssid], 0, 16);
            size_t l = strlen(argv[i] + 4);
            memcpy(ssid[nssid], argv[i] + 4, l < 16 ? l : 16);
            snprintf(ssid_name[nssid++], 64, "%s", argv[i]);
        } else fprintf(stderr, "ignored: %s\n", argv[i]);
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", argv[1]); return 1; }
    u8 gh[24];
    if (fread(gh, 1, 24, f) != 24) return 1;
    static u8 p[65536], out[65536];
    for (;;) {
        u8 rh[16];
        if (fread(rh, 1, 16, f) != 16) break;
        u32 cl = (u32)rh[8] | (u32)rh[9] << 8 | (u32)rh[10] << 16 | (u32)rh[11] << 24;
        if (cl > sizeof p || fread(p, 1, cl, f) != cl) break;
        if (cl < 4) continue;
        size_t rl = (size_t)(p[2] | p[3] << 8);
        if (rl >= cl) continue;
        size_t on;
        u64 pn;
        if (!ccmp_hdr_len(p + rl, cl - rl) || !(p[rl + 1] & 0x40) || !ccmp_decrypt(dkey, p + rl, cl - rl, out, &on, &pn))
            continue;
        if (on < 8 + 28 || out[6] != 0x08 || out[7] != 0x00 || out[8 + 9] != 17) continue;
        const u8 *ip = out + 8;
        size_t ihl = (size_t)(ip[0] & 15) * 4;
        if (on < 8 + ihl + 8) continue;
        const u8 *udp = ip + ihl;
        size_t ulen = (size_t)(udp[4] << 8 | udp[5]);
        if (ulen < 8 || 8 + ihl + ulen > on || !pia_is_packet(udp + 8, ulen - 8) || npk >= 4096) continue;
        Pkt *k = &pk[npk++];
        k->src = (u32)ip[12] << 24 | (u32)ip[13] << 16 | (u32)ip[14] << 8 | ip[15];
        k->dst = (u32)ip[16] << 24 | (u32)ip[17] << 16 | (u32)ip[18] << 8 | ip[19];
        k->sport = (u16)(udp[0] << 8 | udp[1]);
        k->dport = (u16)(udp[2] << 8 | udp[3]);
        k->n = ulen - 8;
        memcpy(k->p, udp + 8, k->n);
    }
    printf("%d Pia packets\n", npk);
    if (!npk) return 1;
    for (int i = 0; i < npk && i < 3; i++) {
        printf("  %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u, %zu bytes:", pk[i].src >> 24, pk[i].src >> 16 & 255,
               pk[i].src >> 8 & 255, pk[i].src & 255, pk[i].sport, pk[i].dst >> 24, pk[i].dst >> 16 & 255,
               pk[i].dst >> 8 & 255, pk[i].dst & 255, pk[i].dport, pk[i].n);
        for (size_t k = 0; k < 28; k++) printf(" %02x", pk[i].p[k]);
        printf("\n");
    }
    if (!nip) ips[nip++] = pk[0].src;
    int found = 0;
    for (int s = 0; s < nssid; s++)
        for (int ii = 0; ii < nip; ii++)
            for (int vi = 0; vi < 24; vi++) {
                PiaVariant v = {.key_decrypt = (u8)(vi & 1), .crc_le = (u8)(vi >> 1 & 1), .ip_le = (u8)(vi >> 2 & 1),
                                .aad = (u8)(vi >> 3)};
                PiaNet net;
                pia_net_init(&net, gkey, ssid[s], &v);
                int good = 0;
                static u8 b[1500];
                for (int i = 0; i < npk; i++) {
                    memcpy(b, pk[i].p, pk[i].n);
                    good += pia_decrypt(&net, &v, ips[ii], b, pk[i].n);
                }
                if (!good) continue;
                found++;
                printf("%s, ip %u.%u.%u.%u, key %s, network id %08x (%s), ip %s, aad %u: %d of %d authenticate\n",
                       ssid_name[s], ips[ii] >> 24, ips[ii] >> 16 & 255, ips[ii] >> 8 & 255, ips[ii] & 255,
                       v.key_decrypt ? "decrypt" : "encrypt", net.network_id, v.crc_le ? "LE" : "BE",
                       v.ip_le ? "LE" : "BE", v.aad, good, npk);
                memcpy(b, pk[0].p, pk[0].n);
                pia_decrypt(&net, &v, ips[ii], b, pk[0].n);
                printf("  first packet's messages:\n");
                pia_dump(b, pk[0].n);
                if (map.n && as_ip) {
                    static u8 w[2048];
                    unsigned rep = 0;
                    size_t wn = pia_rewrite(b, pk[0].n, w, sizeof w, &map, &rep);
                    if (!wn) printf("  rewrite: the messages do not parse\n");
                    else {
                        pia_encrypt(&net, &v, as_ip, w, wn);
                        bool back = pia_decrypt(&net, &v, as_ip, w, wn);
                        printf("  rewritten: %u replaced, %zu -> %zu bytes, encrypted as from %u.%u.%u.%u: %s\n", rep,
                               pk[0].n, wn, as_ip >> 24, as_ip >> 16 & 255, as_ip >> 8 & 255, as_ip & 255,
                               back ? "decrypts again" : "DOES NOT DECRYPT");
                        if (back) pia_dump(w, wn);
                    }
                    memcpy(b, pk[0].p, pk[0].n);
                    pia_decrypt(&net, &v, ips[ii], b, pk[0].n);
                }
                /* re-encrypting must give the packet back */
                pia_encrypt(&net, &v, ips[ii], b, pk[0].n);
                printf("  re-encrypted: %s\n", memcmp(b, pk[0].p, pk[0].n) ? "DIFFERS" : "identical");
            }
    if (!found) printf("no candidate authenticates\n");
    return ok && found ? 0 : 1;
}
