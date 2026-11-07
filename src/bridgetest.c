/* bridgetest: IPv4 / UDP build and parse (checksums checked independently), and ARP parse on a captured frame.
 *   bridgetest [decrypted-frame.bin]      (from ccmptest -d: LLC/SNAP header + payload) */
#include "bridge.h"

int main(int argc, char **argv) {
    int bad = 0;
    u8 payload[100], pkt[200];
    for (int i = 0; i < 100; i++) payload[i] = (u8)(i * 7 + 1);
    u32 src = 0xA9FE0F01, dst = 0xA9FE0F02;
    size_t n = ipv4_udp_build(pkt, sizeof pkt, src, dst, 49152, 49153, payload, 99, 0x1234);
    bool ip_ok = n == 20 + 8 + 99 && inet_fold(inet_sum(pkt, 20, 0)) == 0;
    u8 pseudo[12] = {pkt[12], pkt[13], pkt[14], pkt[15], pkt[16], pkt[17], pkt[18], pkt[19], 0, 17, 0, 8 + 99};
    bool udp_ok = inet_fold(inet_sum(pkt + 20, 8 + 99, inet_sum(pseudo, 12, 0))) == 0;
    u32 s, d;
    u16 sp, dp;
    size_t off, len;
    IpStatus st = ipv4_udp_parse(pkt, n, &s, &d, &sp, &dp, &off, &len);
    bool parse_ok = st == IP_OK && s == src && d == dst && sp == 49152 && dp == 49153 && len == 99 &&
                    !memcmp(pkt + off, payload, 99);
    printf("ipv4/udp: %zu bytes, IP checksum %s, UDP checksum %s, parse %s\n", n, ip_ok ? "ok" : "BAD",
           udp_ok ? "ok" : "BAD", parse_ok ? "ok" : "BAD");
    bad += !ip_ok + !udp_ok + !parse_ok;
    pkt[6] = 0x20;                                          /* more fragments */
    if (ipv4_udp_parse(pkt, n, &s, &d, &sp, &dp, &off, &len) != IP_FRAGMENT) { printf("fragment not seen\n"); bad++; }

    Arp a = {.op = 2, .sha = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, .spa = 0xA9FE0F01,
             .tha = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55}, .tpa = 0xA9FE0F02};
    Arp b;
    u8 ab[64];
    size_t an = arp_build(ab, sizeof ab, &a);
    bool arp_ok = an == 28 && arp_parse(ab, an, &b) && !memcmp(&a, &b, sizeof a);
    printf("arp: build / parse %s\n", arp_ok ? "ok" : "BAD");
    bad += !arp_ok;

    if (argc > 1) {
        FILE *f = fopen(argv[1], "rb");
        u8 fr[2048];
        size_t fn = f ? fread(fr, 1, sizeof fr, f) : 0;
        if (f) fclose(f);
        if (fn > 8 && fr[6] == 0x08 && fr[7] == 0x06 && arp_parse(fr + 8, fn - 8, &b))
            printf("%s: ARP op %u from %02x:%02x:%02x:%02x:%02x:%02x %u.%u.%u.%u for %u.%u.%u.%u\n", argv[1], b.op,
                   b.sha[0], b.sha[1], b.sha[2], b.sha[3], b.sha[4], b.sha[5], b.spa >> 24, (b.spa >> 16) & 255,
                   (b.spa >> 8) & 255, b.spa & 255, b.tpa >> 24, (b.tpa >> 16) & 255, (b.tpa >> 8) & 255, b.tpa & 255);
        else { printf("%s: not an ARP frame\n", argv[1]); bad++; }
    }
    return bad ? 1 : 0;
}
