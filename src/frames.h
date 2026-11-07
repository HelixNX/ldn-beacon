/* What the beacon puts on the air when the room hosts: an 802.11 beacon like a Switch's and the LDN advertisement,
 * built from the host member's NetworkInfo (room ScanResp). Portable: testable on any OS (frametest). */
#ifndef FRAMES_H
#define FRAMES_H

#include "adv.h"

enum { FRAME_MAX = 2048 };

/* What a room network gets on the air beyond its NetworkInfo: values a console makes up per network (the recomp
 * leaves them zero) and the 169.254.X.0/24 subnet. Kept while the room's session id stays the same. */
typedef struct HostSession {
    u8 session_id[16];
    u8 server_random[16], auth_token[8];
    u32 nonce;
    u8 subnet;                  /* X of 169.254.X.Y: the host is .1, room node i is .(i + 1) */
} HostSession;

/* true when n is a new network (another session id): s is filled with fresh random values */
bool host_session_update(HostSession *s, const LdnNetworkInfo *n);

/* the advertisement for room network n, hosted on the air as bssid on channel (2.4 GHz) */
void host_advert(const HostSession *s, const LdnNetworkInfo *n, const u8 bssid[6], u8 channel, LdnAdvert *a);

/* whole 802.11 frames (no radiotap, no FCS); return the size, 0 if cap is too small */
size_t frame_beacon(u8 *out, size_t cap, const u8 bssid[6], u16 seq, u64 tsf_us, u8 channel);
size_t frame_advert(u8 *out, size_t cap, const LdnKeys *k, const LdnAdvert *a, const u8 bssid[6], u16 seq);
/* the network's SSID: the session id's 32 hex digits (lowercase, as a Switch probes for it) */
void host_ssid(const HostSession *s, char out[33]);
/* the answer to a probe request for our SSID: the beacon's body with the SSID shown, to dest */
size_t frame_probe_resp(u8 *out, size_t cap, const HostSession *s, const u8 bssid[6], const u8 dest[6], u16 seq,
                        u64 tsf_us, u8 channel);

#endif
