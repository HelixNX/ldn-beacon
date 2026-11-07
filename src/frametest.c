/* frametest: builds what the beacon would put on the air for a room network and writes it as a pcap, so it can be
 * checked without a radio (advdump decodes it, Wireshark shows the beacon).
 *   frametest [-k keyfile]... netinfo.bin out.pcap      (netinfo.bin: a raw NetworkInfo, from roomtest --dump) */
#include "frames.h"
#include <stdlib.h>

static void put32(FILE *f, u32 v) { u8 b[4] = {(u8)v, (u8)(v >> 8), (u8)(v >> 16), (u8)(v >> 24)}; fwrite(b, 1, 4, f); }
static void put16(FILE *f, u16 v) { u8 b[2] = {(u8)v, (u8)(v >> 8)}; fwrite(b, 1, 2, f); }

static void record(FILE *f, const u8 *p, size_t n, u32 t_ms) {
    put32(f, t_ms / 1000);
    put32(f, t_ms % 1000 * 1000);
    put32(f, (u32)n);
    put32(f, (u32)n);
    fwrite(p, 1, n, f);
}

int main(int argc, char **argv) {
    const char *keyfiles[8], *in = NULL, *out = NULL;
    int nkeys = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-k") && i + 1 < argc && nkeys < 8) keyfiles[nkeys++] = argv[++i];
        else if (!in) in = argv[i];
        else if (!out) out = argv[i];
    }
    if (!in || !out) { fprintf(stderr, "usage: frametest [-k keyfile]... netinfo.bin out.pcap\n"); return 2; }
    if (!nkeys) { keyfiles[0] = "../keys/prod.keys"; keyfiles[1] = "../keys/ldn.txt"; nkeys = 2; }
    LdnKeys keys;
    if (!ldn_keys_load(&keys, keyfiles, nkeys, NULL)) return 1;

    LdnNetworkInfo n;
    FILE *f = fopen(in, "rb");
    if (!f || fread(&n, sizeof n, 1, f) != 1) { fprintf(stderr, "cannot read a NetworkInfo from %s\n", in); return 1; }
    fclose(f);

    static const u8 bssid[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    HostSession s = {0};
    host_session_update(&s, &n);
    LdnAdvert a;
    host_advert(&s, &n, bssid, 6, &a);

    f = fopen(out, "wb");
    if (!f) { fprintf(stderr, "cannot write %s\n", out); return 1; }
    put32(f, 0xA1B2C3D4); put16(f, 2); put16(f, 4); put32(f, 0); put32(f, 0); put32(f, 65535); put32(f, 105);
    u8 fr[FRAME_MAX];
    for (u32 i = 0; i < 5; i++) {
        size_t k = frame_beacon(fr, sizeof fr, bssid, (u16)(i * 2), (u64)i * 102400, 6);
        if (!k) { fprintf(stderr, "beacon: no room\n"); return 1; }
        record(f, fr, k, i * 100);
        k = frame_advert(fr, sizeof fr, &keys, &a, bssid, (u16)(i * 2 + 1));
        if (!k) { fprintf(stderr, "advertisement: encode failed\n"); return 1; }
        record(f, fr, k, i * 100 + 1);
    }
    static const u8 asker[6] = {0x38, 0xC6, 0xCE, 0x00, 0x00, 0x01};
    size_t k = frame_probe_resp(fr, sizeof fr, &s, bssid, asker, 10, 512000, 6);
    if (!k) { fprintf(stderr, "probe response: no room\n"); return 1; }
    record(f, fr, k, 500);
    fclose(f);
    printf("wrote %s: 5 beacons, 5 advertisements and a probe response (subnet 169.254.%u.0, nonce %08x)\n", out, s.subnet, s.nonce);
    return 0;
}
