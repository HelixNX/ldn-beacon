#include "frames.h"
#include "rd.h"

bool host_session_update(HostSession *s, const LdnNetworkInfo *n) {
    u8 id[16];
    memcpy(id, &n->id.session, 16);
    static const u8 zero[16];
    if (!memcmp(id, s->session_id, 16) && memcmp(id, zero, 16)) return false;
    memcpy(s->session_id, id, 16);
    if (!memcmp(id, zero, 16)) random_bytes(s->session_id, 16);    /* a room host without one */
    /* the server random is the host's security parameter, as it is on a console: the game reads it on both sides
     * (GetSecurityParameter: it and the session id), and Pia's packets only make sense to a station that got the
     * host's (run 13: with a made-up one the Switch received the host's Pia packets and never answered). A recomp
     * host may leave it zero; zero is used then too, for the same reason */
    memcpy(s->server_random, n->security_parameter, 16);
    random_bytes(s->auth_token, 8);
    if (n->random_authentication_id) memcpy(s->auth_token, &n->random_authentication_id, 8);
    random_bytes(&s->nonce, 4);
    u8 x;
    random_bytes(&x, 1);
    s->subnet = (u8)(1 + x % 254);
    return true;
}

void host_advert(const HostSession *s, const LdnNetworkInfo *n, const u8 bssid[6], u8 channel, LdnAdvert *a) {
    adv_from_network_info(n, a);
    memcpy(a->session.ssid, s->session_id, 16);
    memcpy(a->server_random, s->server_random, 16);
    memcpy(a->auth_token, s->auth_token, 8);
    a->nonce = s->nonce;
    a->channel = channel;
    a->band = 2;
    /* the room's addresses (192.168.1.x) become the LDN network's; the host's MAC is ours (the BSSID) */
    for (int i = 0; i < ADV_PARTICIPANTS; i++) {
        LdnAdvParticipant *p = &a->participants[i];
        if (!p->connected) { memset(p, 0, sizeof *p); continue; }
        p->ipv4 = 0xA9FE0000u | (u32)s->subnet << 8 | (u32)(i + 1);
        if (i == 0) memcpy(p->mac, bssid, 6);
        p->platform = 0;
    }
}

static const u8 bcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

/* addr3: the BSSID in beacons; the advertisement has the wildcard BSSID there (as a Switch sends it: a station
 * that is not in our network drops action frames naming another BSS) */
static void hdr(Wr *w, u8 subtype, const u8 dest[6], const u8 bssid[6], const u8 addr3[6], u16 seq) {
    wr_u8(w, (u8)(subtype << 4));               /* management */
    wr_u8(w, 0);
    wr_zero(w, 2);                              /* duration */
    wr_bytes(w, dest, 6);
    wr_bytes(w, bssid, 6);
    wr_bytes(w, addr3, 6);
    u16 sc = (u16)(seq << 4);
    wr_u8(w, (u8)sc);                           /* sequence control, little-endian */
    wr_u8(w, (u8)(sc >> 8));
}

static void ie(Wr *w, u8 id, const void *p, u8 n) { wr_u8(w, id); wr_u8(w, n); wr_bytes(w, p, n); }

/* a beacon (to everyone, SSID hidden) or a probe response (to dest, with the SSID; no TIM): the same body */
static size_t bss_frame(u8 *out, size_t cap, u8 subtype, const u8 dest[6], const u8 bssid[6], u16 seq, u64 tsf_us,
                        u8 channel, const char *ssid_text) {
    Wr w = wr_init(out, cap);
    hdr(&w, subtype, dest, bssid, bssid, seq);
    for (int i = 0; i < 8; i++) wr_u8(&w, (u8)(tsf_us >> (8 * i)));    /* timestamp, little-endian */
    wr_u8(&w, 100); wr_u8(&w, 0);               /* beacon interval 100 TU */
    wr_u8(&w, 0x11); wr_u8(&w, 0x04);           /* capabilities: ESS, privacy, short slot time */
    /* the elements a Switch's beacon carries (captured 2026-11-06), in its order */
    u8 ssid[32] = {0};                          /* beacons: hidden, 32 zero bytes */
    if (ssid_text) memcpy(ssid, ssid_text, 32);
    static const u8 rates[] = {0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24};
    static const u8 tim[] = {0x01, 0x02, 0x00, 0x00};
    static const u8 erp[] = {0x00};
    static const u8 ext_rates[] = {0x30, 0x48, 0x60, 0x6C};
    static const u8 rsn[] = {0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04,
                             0x01, 0x00, 0x00, 0x0F, 0xAC, 0x02, 0x0C, 0x00};   /* WPA2: CCMP, PSK */
    static const u8 ht_cap[26] = {0x0D, 0x09, 0x03, 0xFF, [15] = 0x01};
    u8 ht_op[22] = {channel};
    static const u8 ext_cap[] = {0x00};
    static const u8 he_cap[] = {0x23, 0x01, 0x08, 0x00, 0x1A, 0x00, 0x00, 0x00, 0x20, 0x0A, 0x00, 0x0D,
                                0xC0, 0x9F, 0x04, 0x00, 0x00, 0x00, 0xFE, 0xFF, 0xFE, 0xFF, 0x08, 0x1C};
    static const u8 he_op[] = {0x24, 0x00, 0x00, 0x00, 0x81, 0xFC, 0xFF};
    static const u8 nintendo[] = {0x00, 0x22, 0xAA, 0x10, 0x01, 0x02};
    static const u8 wmm[] = {0x00, 0x50, 0xF2, 0x02, 0x01, 0x01, 0x80, 0x10, 0x03, 0xA4, 0x00, 0x00,
                             0x27, 0xA4, 0x00, 0x00, 0x42, 0x43, 0x5E, 0x00, 0x62, 0x32, 0x2F, 0x00};
    ie(&w, 0, ssid, sizeof ssid);
    ie(&w, 1, rates, sizeof rates);
    ie(&w, 3, &channel, 1);
    if (subtype == 8) ie(&w, 5, tim, sizeof tim);
    ie(&w, 42, erp, sizeof erp);
    ie(&w, 50, ext_rates, sizeof ext_rates);
    ie(&w, 48, rsn, sizeof rsn);
    ie(&w, 45, ht_cap, sizeof ht_cap);
    ie(&w, 61, ht_op, sizeof ht_op);
    ie(&w, 127, ext_cap, sizeof ext_cap);
    ie(&w, 255, he_cap, sizeof he_cap);
    ie(&w, 255, he_op, sizeof he_op);
    ie(&w, 221, nintendo, sizeof nintendo);
    ie(&w, 221, wmm, sizeof wmm);
    return w.err ? 0 : w.off;
}

size_t frame_beacon(u8 *out, size_t cap, const u8 bssid[6], u16 seq, u64 tsf_us, u8 channel) {
    return bss_frame(out, cap, 8, bcast, bssid, seq, tsf_us, channel, NULL);
}

void host_ssid(const HostSession *s, char out[33]) {
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 16; i++) {
        out[i * 2] = hex[s->session_id[i] >> 4];
        out[i * 2 + 1] = hex[s->session_id[i] & 15];
    }
    out[32] = 0;
}

size_t frame_probe_resp(u8 *out, size_t cap, const HostSession *s, const u8 bssid[6], const u8 dest[6], u16 seq,
                        u64 tsf_us, u8 channel) {
    char ssid[33];
    host_ssid(s, ssid);
    return bss_frame(out, cap, 5, dest, bssid, seq, tsf_us, channel, ssid);
}

size_t frame_advert(u8 *out, size_t cap, const LdnKeys *k, const LdnAdvert *a, const u8 bssid[6], u16 seq) {
    Wr w = wr_init(out, cap);
    hdr(&w, 13, bcast, bssid, bcast, seq);      /* action */
    if (w.err) return 0;
    size_t n = adv_encode(k, a, out + w.off, cap - w.off);
    return n ? w.off + n : 0;
}
