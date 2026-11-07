/* IPv4 / UDP and ARP for the bridge between the room's proxy packets (bare UDP payloads between room addresses) and
 * the LDN network on the air (Ethernet-style frames between 169.254.X.Y addresses). Addresses are host-order u32s.
 * Only unfragmented UDP is carried: the room relays datagrams, and Pia's stay under the LDN network's 1400-byte MTU. */
#ifndef BRIDGE_H
#define BRIDGE_H

#include "common.h"

enum { ETHERTYPE_IPV4 = 0x0800, ETHERTYPE_ARP = 0x0806 };

/* an IPv4 packet with a UDP datagram (both checksums filled); returns its size, 0 if it does not fit */
size_t ipv4_udp_build(u8 *out, size_t cap, u32 src, u32 dst, u16 sport, u16 dport, const u8 *payload, size_t n,
                      u16 id);

typedef enum { IP_OK, IP_NOT_IPV4, IP_NOT_UDP, IP_FRAGMENT, IP_BAD } IpStatus;
/* p: an IPv4 packet; on IP_OK the UDP payload is at p[*payload_off], *len bytes */
IpStatus ipv4_udp_parse(const u8 *p, size_t n, u32 *src, u32 *dst, u16 *sport, u16 *dport, size_t *payload_off,
                        size_t *len);

typedef struct Arp { u16 op; u8 sha[6]; u32 spa; u8 tha[6]; u32 tpa; } Arp;   /* op 1 request, 2 reply */
bool arp_parse(const u8 *p, size_t n, Arp *a);
size_t arp_build(u8 *out, size_t cap, const Arp *a);     /* 28 bytes */

/* the Internet checksum's ones' complement sum (unfolded) */
u32 inet_sum(const u8 *p, size_t n, u32 sum);
u16 inet_fold(u32 sum);

#endif
