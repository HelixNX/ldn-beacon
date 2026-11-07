#include "bridge.h"
#include "rd.h"

u32 inet_sum(const u8 *p, size_t n, u32 sum) {
    for (size_t i = 0; i + 1 < n; i += 2) sum += (u32)(p[i] << 8 | p[i + 1]);
    if (n & 1) sum += (u32)p[n - 1] << 8;
    return sum;
}

u16 inet_fold(u32 sum) {
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (u16)~sum;
}

size_t ipv4_udp_build(u8 *out, size_t cap, u32 src, u32 dst, u16 sport, u16 dport, const u8 *payload, size_t n,
                      u16 id) {
    size_t total = 20 + 8 + n;
    if (total > cap || total > 0xFFFF) return 0;
    Wr w = wr_init(out, cap);
    wr_u8(&w, 0x45);                                        /* IPv4, 20-byte header */
    wr_u8(&w, 0);
    wr_be16(&w, (u16)total);
    wr_be16(&w, id);
    wr_be16(&w, 0);                                         /* no fragmentation flags */
    wr_u8(&w, 64);                                          /* TTL */
    wr_u8(&w, 17);                                          /* UDP */
    wr_be16(&w, 0);                                         /* checksum, below */
    wr_be32(&w, src);
    wr_be32(&w, dst);
    u16 ck = inet_fold(inet_sum(out, 20, 0));
    out[10] = (u8)(ck >> 8);
    out[11] = (u8)ck;
    wr_be16(&w, sport);
    wr_be16(&w, dport);
    wr_be16(&w, (u16)(8 + n));
    wr_be16(&w, 0);
    wr_bytes(&w, payload, n);
    if (w.err) return 0;
    /* UDP checksum over the pseudo header (addresses, protocol, length) and the datagram */
    u8 pseudo[12];
    memcpy(pseudo, out + 12, 8);
    pseudo[8] = 0;
    pseudo[9] = 17;
    pseudo[10] = (u8)((8 + n) >> 8);
    pseudo[11] = (u8)(8 + n);
    u16 uck = inet_fold(inet_sum(out + 20, 8 + n, inet_sum(pseudo, 12, 0)));
    if (!uck) uck = 0xFFFF;                                 /* 0 means "none" */
    out[26] = (u8)(uck >> 8);
    out[27] = (u8)uck;
    return total;
}

IpStatus ipv4_udp_parse(const u8 *p, size_t n, u32 *src, u32 *dst, u16 *sport, u16 *dport, size_t *payload_off,
                        size_t *len) {
    if (n < 20 || (p[0] >> 4) != 4) return IP_NOT_IPV4;
    size_t ihl = (size_t)(p[0] & 15) * 4;
    size_t total = (size_t)(p[2] << 8 | p[3]);
    if (ihl < 20 || total < ihl || total > n) return IP_BAD;
    if (p[9] != 17) return IP_NOT_UDP;
    if ((p[6] & 0x20) || ((p[6] & 0x1F) << 8 | p[7])) return IP_FRAGMENT;   /* more fragments, or an offset */
    if (total < ihl + 8) return IP_BAD;
    *src = (u32)p[12] << 24 | (u32)p[13] << 16 | (u32)p[14] << 8 | p[15];
    *dst = (u32)p[16] << 24 | (u32)p[17] << 16 | (u32)p[18] << 8 | p[19];
    const u8 *u = p + ihl;
    *sport = (u16)(u[0] << 8 | u[1]);
    *dport = (u16)(u[2] << 8 | u[3]);
    size_t ulen = (size_t)(u[4] << 8 | u[5]);
    if (ulen < 8 || ihl + ulen > total) return IP_BAD;
    *payload_off = ihl + 8;
    *len = ulen - 8;
    return IP_OK;
}

bool arp_parse(const u8 *p, size_t n, Arp *a) {
    Rd r = rd_init(p, n);
    u16 htype = rd_be16(&r), ptype = rd_be16(&r);
    u8 hlen = rd_u8(&r), plen = rd_u8(&r);
    a->op = rd_be16(&r);
    rd_copy(&r, a->sha, 6);
    a->spa = rd_be32(&r);
    rd_copy(&r, a->tha, 6);
    a->tpa = rd_be32(&r);
    return !r.err && htype == 1 && ptype == 0x0800 && hlen == 6 && plen == 4;
}

size_t arp_build(u8 *out, size_t cap, const Arp *a) {
    Wr w = wr_init(out, cap);
    wr_be16(&w, 1);
    wr_be16(&w, 0x0800);
    wr_u8(&w, 6);
    wr_u8(&w, 4);
    wr_be16(&w, a->op);
    wr_bytes(&w, a->sha, 6);
    wr_be32(&w, a->spa);
    wr_bytes(&w, a->tha, 6);
    wr_be32(&w, a->tpa);
    return w.err ? 0 : w.off;
}
