/* advdump: decrypts the LDN advertisements in a capture and prints them as the room would see them (NetworkInfo).
 *   advdump [--files dir]... [-a] capture.pcap
 * Keys from your own files (ldnkeys.h; --files, default: ldn-beacon/ and the workspace). Reads pcap with radiotap
 * (linktype 127) or bare 802.11 (105). Each distinct advertisement is printed once (-a: every one), and re-encoded
 * to check that adv_encode gives back the same bytes. */
#include "adv.h"
#include "rd.h"
#include <stdlib.h>

static void print_advert(const LdnAdvert *a, const u8 src[6]) {
    LdnNetworkInfo n;
    adv_to_network_info(a, src, &n);
    char ssid[33];
    memcpy(ssid, n.ssid.raw, 32);
    ssid[32] = 0;
    printf("  host %02x:%02x:%02x:%02x:%02x:%02x, LDN version %u, encryption %u, nonce %08x\n", src[0], src[1],
           src[2], src[3], src[4], src[5], a->version, a->encryption, a->nonce);
    printf("  local communication id %016llx, scene %u, ssid %s\n",
           (unsigned long long)n.id.intent.local_communication_id, n.id.intent.scene_id, ssid);
    printf("  channel %u band %u, security %u, accept policy %u, %u of %u participants, app data %u bytes\n",
           a->channel, a->band, a->security_level, a->accept_policy, a->participant_count, a->max_participants,
           a->app_data_size);
    printf("  server random ");
    for (int i = 0; i < 16; i++) printf("%02x", a->server_random[i]);
    printf(", auth token ");
    for (int i = 0; i < 8; i++) printf("%02x", a->auth_token[i]);
    printf("\n");
    for (int i = 0; i < ADV_PARTICIPANTS; i++) {
        const LdnAdvParticipant *p = &a->participants[i];
        if (!p->connected && !p->ipv4) continue;
        printf("    %d: \"%s\" %u.%u.%u.%u %02x:%02x:%02x:%02x:%02x:%02x connected %u platform %u version %u\n", i,
               p->user_name, p->ipv4 >> 24, (p->ipv4 >> 16) & 255, (p->ipv4 >> 8) & 255, p->ipv4 & 255, p->mac[0],
               p->mac[1], p->mac[2], p->mac[3], p->mac[4], p->mac[5], p->connected, p->platform, p->app_version);
    }
    printf("  app data:");
    for (int i = 0; i < a->app_data_size; i++) printf("%s%02x", i % 32 ? "" : "\n    ", a->app_data[i]);
    printf("\n");
}

int main(int argc, char **argv) {
    const char *dirs[8];
    int ndirs = 0;
    bool all = false;
    const char *path = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--files") && i + 1 < argc && ndirs < 8) dirs[ndirs++] = argv[++i];
        else if (!strcmp(argv[i], "-a")) all = true;
        else if (argv[i][0] != '-' && !path) path = argv[i];
        else { fprintf(stderr, "usage: advdump [--files dir]... [-a] capture.pcap\n"); return 2; }
    }
    if (!path) { fprintf(stderr, "usage: advdump [--files dir]... [-a] capture.pcap\n"); return 2; }
    LdnKeys keys;
    if (!ldn_keys_load(&keys, dirs, ndirs, NULL)) return 1;

    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", path); return 1; }
    u8 gh[24];
    if (fread(gh, 1, 24, f) != 24) { fprintf(stderr, "%s: no pcap header\n", path); return 1; }
    u32 magic = (u32)gh[0] | (u32)gh[1] << 8 | (u32)gh[2] << 16 | (u32)gh[3] << 24;
    if (magic != 0xA1B2C3D4 && magic != 0xA1B23C4D) { fprintf(stderr, "%s: not a little-endian pcap\n", path); return 1; }
    u32 linktype = (u32)gh[20] | (u32)gh[21] << 8;
    if (linktype != 127 && linktype != 105) { fprintf(stderr, "linktype %u: want 127 or 105\n", linktype); return 1; }

    static u8 pkt[65536];
    u8 last[ADV_FRAME_SIZE];
    size_t last_len = 0;
    unsigned frames = 0, adverts = 0, failed = 0, distinct = 0, roundtrip_bad = 0;
    for (;;) {
        u8 rh[16];
        if (fread(rh, 1, 16, f) != 16) break;
        u32 cap = (u32)rh[8] | (u32)rh[9] << 8 | (u32)rh[10] << 16 | (u32)rh[11] << 24;
        if (cap > sizeof pkt || fread(pkt, 1, cap, f) != cap) { fprintf(stderr, "truncated record\n"); break; }
        frames++;
        Rd r = rd_init(pkt, cap);
        if (linktype == 127) {
            rd_skip(&r, 2);
            u16 rtlen = rd_le16(&r);
            if (rtlen < 4) continue;
            rd_skip(&r, rtlen - 4u);
        }
        u8 fc0 = rd_u8(&r), fc1 = rd_u8(&r);
        rd_skip(&r, 2 + 6);                         /* duration, receiver */
        u8 src[6];
        rd_copy(&r, src, 6);
        rd_skip(&r, 6 + 2);                         /* BSSID, sequence */
        if (fc1 & 0x80) rd_skip(&r, 4);             /* +HTC */
        if (r.err || (fc0 & 0x0C) != 0 || (fc0 >> 4) != 13) continue;   /* management, action */
        const u8 *body = pkt + r.off;
        size_t blen = rd_left(&r);
        LdnAdvert a;
        AdvStatus st = adv_decode(&keys, body, blen, &a);
        if (st == ADV_NOT_ADVERT) continue;
        adverts++;
        if (st != ADV_OK) {
            if (failed++ < 5) printf("frame %u: %s\n", frames, adv_status_name(st));
            continue;
        }
        size_t flen = blen < ADV_FRAME_SIZE ? blen : ADV_FRAME_SIZE;
        bool fresh = !(last_len == flen && !memcmp(last, body, flen));
        u8 re[ADV_FRAME_SIZE];
        size_t rl = adv_encode(&keys, &a, re, sizeof re);
        bool same = rl == ADV_FRAME_SIZE && flen == ADV_FRAME_SIZE && !memcmp(re, body, rl);
        if (!same) roundtrip_bad++;
        if (fresh || all) {
            distinct += fresh;
            printf("frame %u: advertisement%s, re-encoded %s\n", frames, fresh ? "" : " (repeat)",
                   same ? "identical" : "DIFFERENT");
            print_advert(&a, src);
            memcpy(last, body, flen);
            last_len = flen;
        }
    }
    fclose(f);
    printf("%u frames, %u advertisements (%u distinct runs), %u failed, %u re-encoded differently\n", frames,
           adverts, distinct, failed, roundtrip_bad);
    return failed || roundtrip_bad ? 1 : 0;
}
