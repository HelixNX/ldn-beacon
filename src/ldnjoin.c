/* ldnjoin: the S3 joins a real console's LDN network as a station (design item 2's first half, and the way to see a
 * console's own Pia packets). It scans channels for an advertisement, decrypts it, joins the host's hidden network
 * (the S3 installs the data key itself: no 4-way handshake), sends the LDN authentication request (layout as kinnay's
 * LDN library builds a station's, behaviour only), waits to see itself in the advertisement, answers ARP, and logs
 * every frame the host sends: IPv4 / UDP in full, and each Pia packet tried against the candidate key / nonce
 * derivations (the session id's raw bytes, its hex digits, the server random; every PiaVariant). Nothing is sent to
 * the game: the point is to read what a console sends to a new station.
 *   ldnjoin [--radio s3[:port]] [--channels 1,6,11] [--name text] [-k keyfile]... [--pcap file] [--token raw]
 * The token goes into the challenge reversed (as kinnay) unless --token raw; after a "bad challenge" status the next
 * attempt flips it. */
#include "adv.h"
#include "bridge.h"
#include "ldnauth.h"
#include "pia.h"
#include "radio.h"
#include <signal.h>
#include <stdlib.h>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <time.h>
#endif

#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_ARG(m) (m)[0], (m)[1], (m)[2], (m)[3], (m)[4], (m)[5]

static volatile sig_atomic_t quit;
static void on_signal(int s) { (void)s; quit = 1; }

static Radio radio;
static LdnKeys keys;
static LdnAdvert adv;
static u8 host_mac[6], data_key[16], client_random[16], device_id[8];
static char ssid_hex[33];
static u8 channel_now;
static bool token_raw;

enum { SCAN, JOINING, AUTH, JOINED } state = SCAN;
static u64 state_ms, last_req_ms;
static int req_tries, join_tries;
static u32 my_ip;
static unsigned cnt_ip, cnt_udp, cnt_pia, cnt_pia_ok, cnt_arp, cnt_other, cnt_adv;

static void set_state(int s) { state = s; state_ms = now_ms(); }

/* ---- Pia: which derivation authenticates the console's packets ------------------------------------------------- */
typedef struct { const char *name; u8 ssid[16]; } Cand;
static Cand cands[3];
static int ncands;
static int found_cand = -1, found_var = -1;

static void pia_try(const u8 *p, size_t n, u32 src_ip) {
    cnt_pia++;
    static u8 b[2048];
    if (n > sizeof b) return;
    for (int c = 0; c < ncands; c++)
        for (int v = 0; v < 8; v++)
            for (int a = 0; a < 3; a++) {
                PiaVariant var = {.key_decrypt = (u8)(v & 1), .crc_le = (u8)(v >> 1 & 1), .ip_le = (u8)(v >> 2 & 1),
                                  .aad = (u8)a};
                PiaNet net;
                pia_net_init(&net, keys.pia_game_key, cands[c].ssid, &var);
                memcpy(b, p, n);
                if (!pia_decrypt(&net, &var, src_ip, b, n)) continue;
                cnt_pia_ok++;
                int vi = v | a << 3;
                if (c != found_cand || vi != found_var || cnt_pia_ok <= 3) {
                    logf_(0, "pia: AUTHENTICATES with %s, key %s, network id %08x %s, ip %s, aad %u (%zu bytes)",
                          cands[c].name, var.key_decrypt ? "decrypt" : "encrypt", net.network_id,
                          var.crc_le ? "LE" : "BE", var.ip_le ? "LE" : "BE", var.aad, n);
                    pia_dump(b, n);
                    fflush(stdout);
                }
                found_cand = c;
                found_var = vi;
                return;
            }
    static unsigned bad;
    if (bad++ < 10) logf_(0, "pia: packet (%zu bytes) authenticates with no candidate", n);
}

/* ---- frames from the host ---------------------------------------------------------------------------------------- */
static void hexline(const char *what, const u8 *p, size_t n, size_t max) {
    char s[2 * 256 + 1];
    size_t m = n < max ? n : max, o = 0;
    for (size_t i = 0; i < m && o + 3 < sizeof s; i++) o += (size_t)snprintf(s + o, sizeof s - o, "%02x", p[i]);
    logf_(0, "%s (%zu bytes): %s%s", what, n, s, n > m ? "..." : "");
}

static void on_ldn(const u8 *p, size_t n) {
    u8 cr[16];
    int st = ldn_auth_response_status(p, n, cr);
    if (st < 0) {
        if (n >= 5 && (p[3] << 8 | p[4]) == LDN_PKT_DISCONNECT)
            logf_(0, "ldn: the host disconnects us (reason %u)", n > 6 ? p[6] : 0);
        else hexline("ldn: other control frame", p, n, 64);
        return;
    }
    if (memcmp(cr, client_random, 16)) { logf_(0, "ldn: an authentication response for another client random"); return; }
    logf_(0, "ldn: authentication response, status %d (%s) after %llu ms", st,
          st == 0 ? "accepted" : st == 1 ? "denied by policy" : st == 2 ? "malformed" : st == 4 ? "bad version" :
          st == 6 ? "bad challenge" : "?", (unsigned long long)(now_ms() - last_req_ms));
    if (st == 0 && state == AUTH) {
        set_state(JOINED);
        logf_(0, "ldn: in; waiting for the advertisement to list " MAC_FMT, MAC_ARG(radio.sta_mac));
    } else if (st == LDN_AUTH_BAD_CHALLENGE) {
        token_raw = !token_raw;
        logf_(0, "ldn: next attempt with the token %s", token_raw ? "as sent" : "reversed");
    }
}

static void send_arp_reply(const Arp *q) {
    Arp r = {.op = 2, .spa = my_ip, .tpa = q->spa};
    memcpy(r.sha, radio.sta_mac, 6);
    memcpy(r.tha, q->sha, 6);
    u8 b[64];
    size_t k = arp_build(b, sizeof b, &r);
    if (k) s3_send_eth_sta(&radio, q->sha, ETHERTYPE_ARP, b, k);
}

static void on_llc(const u8 *pl, size_t n, const u8 src[6]) {
    if (n < 8 || pl[0] != 0xAA || pl[1] != 0xAA || pl[2] != 0x03) return;
    u16 et = (u16)(pl[6] << 8 | pl[7]);
    const u8 *p = pl + 8;
    n -= 8;
    if (et == LDN_ETHERTYPE) { on_ldn(p, n); return; }
    if (et == ETHERTYPE_ARP) {
        Arp a;
        if (!arp_parse(p, n, &a)) return;
        cnt_arp++;
        logf_(0, "arp: %s from " MAC_FMT " %u.%u.%u.%u for %u.%u.%u.%u", a.op == 1 ? "request" : "reply", MAC_ARG(a.sha),
              a.spa >> 24, a.spa >> 16 & 255, a.spa >> 8 & 255, a.spa & 255, a.tpa >> 24, a.tpa >> 16 & 255,
              a.tpa >> 8 & 255, a.tpa & 255);
        if (a.op == 1 && my_ip && a.tpa == my_ip) send_arp_reply(&a);
        return;
    }
    if (et != ETHERTYPE_IPV4) { cnt_other++; return; }
    cnt_ip++;
    u32 s, d;
    u16 sp, dp;
    size_t off, len;
    IpStatus st = ipv4_udp_parse(p, n, &s, &d, &sp, &dp, &off, &len);
    if (st != IP_OK) {
        if (cnt_ip <= 20) hexline("ip: not plain UDP", p, n, 64);
        return;
    }
    cnt_udp++;
    if (cnt_udp <= 40) {
        char what[96];
        snprintf(what, sizeof what, "udp " MAC_FMT " %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u", MAC_ARG(src), s >> 24,
                 s >> 16 & 255, s >> 8 & 255, s & 255, sp, d >> 24, d >> 16 & 255, d >> 8 & 255, d & 255, dp);
        hexline(what, p + off, len, 160);
    }
    if (pia_is_packet(p + off, len) && keys.have_pia_key) pia_try(p + off, len, s);
}

static void on_data(const u8 *f, size_t n) {
    const u8 *a2 = f + 10;
    size_t h = (f[0] & 0x80) ? 26 : 24;
    if (f[1] & 0x40) {          /* the S3 decrypted it already: CCMP header and MIC kept */
        if (n < h + 8 + 8 + 8) return;
        on_llc(f + h + 8, n - h - 16, a2);
    } else if (n > h)
        on_llc(f + h, n - h, a2);
}

/* advertisement from the host: our address once it lists us */
static void on_adv(const LdnAdvert *a) {
    cnt_adv++;
    for (int i = 0; i < ADV_PARTICIPANTS; i++) {
        const LdnAdvParticipant *q = &a->participants[i];
        if (q->connected && !memcmp(q->mac, radio.sta_mac, 6) && my_ip != q->ipv4) {
            my_ip = q->ipv4;
            logf_(0, "adv: the host lists us as participant %d, %u.%u.%u.%u, %u of %u (after %llu ms in)", i,
                  my_ip >> 24, my_ip >> 16 & 255, my_ip >> 8 & 255, my_ip & 255, a->participant_count,
                  a->max_participants, (unsigned long long)(now_ms() - state_ms));
            for (int k = 0; k < ADV_PARTICIPANTS; k++)
                if (a->participants[k].connected)
                    logf_(0, "  %d: %u.%u.%u.%u " MAC_FMT " \"%s\" platform %u app version %u", k,
                          a->participants[k].ipv4 >> 24, a->participants[k].ipv4 >> 16 & 255,
                          a->participants[k].ipv4 >> 8 & 255, a->participants[k].ipv4 & 255,
                          MAC_ARG(a->participants[k].mac), a->participants[k].user_name, a->participants[k].platform,
                          a->participants[k].app_version);
        }
    }
}

static void on_frame(const u8 *f, size_t n) {
    if (n < 24) return;
    u8 type = (f[0] >> 2) & 3, sub = f[0] >> 4;
    const u8 *a1 = f + 4, *a2 = f + 10;
    if (type == 0 && sub == 13 && n > 24 + 4 && f[24] == 0x7F && f[25] == 0x00 && f[26] == 0x22 && f[27] == 0xAA) {
        static LdnAdvert a;
        if (adv_decode(&keys, f + 24, n - 24, &a) != ADV_OK) return;
        if (state == SCAN) {
            adv = a;
            memcpy(host_mac, a2, 6);
            logf_(0, "scan: network from " MAC_FMT " on channel %u: local communication id %016llx, scene %u, %u of %u, "
                     "version %u, security level %u, accept policy %u, app data %u bytes", MAC_ARG(a2), a.channel,
                  (unsigned long long)a.session.local_communication_id, a.session.game_mode, a.participant_count,
                  a.max_participants, a.version, a.security_level, a.accept_policy, a.app_data_size);
            hexline("scan: server random", a.server_random, 16, 16);
            hexline("scan: auth token", a.auth_token, 8, 8);
            hexline("scan: app data", a.app_data, a.app_data_size, 160);
            for (int i = 0; i < 16; i++) snprintf(ssid_hex + 2 * i, 3, "%02x", a.session.ssid[i]);
            ldn_data_key(&keys, a.server_random, data_key);
            ncands = 0;
            cands[ncands].name = "the session id";
            memcpy(cands[ncands++].ssid, a.session.ssid, 16);
            cands[ncands].name = "the SSID's first 16 hex digits";
            memcpy(cands[ncands++].ssid, ssid_hex, 16);
            cands[ncands].name = "the server random";
            memcpy(cands[ncands++].ssid, a.server_random, 16);
            set_state(JOINING);
            join_tries = 0;
        } else if (!memcmp(a2, host_mac, 6)) {
            adv = a;
            on_adv(&a);
        }
        return;
    }
    if (state == SCAN || memcmp(a2, host_mac, 6)) return;
    if (type == 2 && (!memcmp(a1, radio.sta_mac, 6) || (a1[0] & 1))) { on_data(f, n); return; }
    if (type == 0 && (sub == 12 || sub == 10) && !memcmp(a1, radio.sta_mac, 6))
        logf_(0, "air: the host sends %s, reason %u", sub == 12 ? "deauthentication" : "disassociation",
              n >= 26 ? (unsigned)(f[24] | f[25] << 8) : 0);
}

static bool link_up;
static void on_link(const u8 bssid[6], bool up, u16 reason) {
    (void)bssid;
    link_up = up;
    if (up && state == JOINING) {
        set_state(AUTH);
        req_tries = 0;
        last_req_ms = 0;
        random_bytes(client_random, 16);
    } else if (!up && state != SCAN) {
        logf_(0, "join: link lost (reason %u) in state %d; scanning again", reason, state);
        my_ip = 0;
        set_state(SCAN);
    }
}

static void send_request(void) {
    u8 si[32] = {0};
    u64 id = adv.session.local_communication_id;
    for (int i = 0; i < 8; i++) si[i] = (u8)(id >> (8 * i));       /* little-endian, as a Switch's request */
    si[10] = (u8)adv.session.game_mode;
    si[11] = (u8)(adv.session.game_mode >> 8);
    memcpy(si + 16, adv.session.ssid, 16);
    u8 token[8], nonce[8];
    for (int i = 0; i < 8; i++) token[i] = token_raw ? adv.auth_token[i] : adv.auth_token[7 - i];
    random_bytes(nonce, 8);
    static u8 req[2048];
    u16 app_version = adv.participants[0].app_version;
    size_t k = ldn_auth_request(&keys, adv.version, si, adv.server_random, client_random, "beacon", app_version, 0,
                                token, nonce, device_id, req, sizeof req);
    LdnAuthRequest chk;
    if (!k || !ldn_auth_parse(&keys, req, k, &chk) || !chk.challenge_ok) { logf_(0, "ldn: our request does not check"); return; }
    bool ok = s3_send_eth_sta(&radio, host_mac, LDN_ETHERTYPE, req, k);
    last_req_ms = now_ms();
    req_tries++;
    logf_(0, "ldn: authentication request %d sent (%zu bytes, version %u, app version %u, token %s)%s", req_tries, k,
          adv.version, app_version, token_raw ? "as sent" : "reversed", ok ? "" : ": send FAILED");
}

int main(int argc, char **argv) {
    const char *spec = NULL, *keyfiles[8], *pcap_path = NULL, *chans = "6,1,11";
    int nkeys = 0;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i], *v = i + 1 < argc ? argv[i + 1] : NULL;
        if (!strcmp(a, "--radio") && v) spec = v, i++;
        else if (!strcmp(a, "--channels") && v) chans = v, i++;
        else if (!strcmp(a, "-k") && v && nkeys < 8) keyfiles[nkeys++] = v, i++;
        else if (!strcmp(a, "--pcap") && v) pcap_path = v, i++;
        else if (!strcmp(a, "--token") && v) token_raw = !strcmp(v, "raw"), i++;
        else {
            fprintf(stderr, "usage: ldnjoin [--radio s3[:port]] [--channels 6,1,11] [-k keyfile]... [--pcap file] "
                            "[--token raw|reversed]\n");
            return 2;
        }
    }
    if (!nkeys) { keyfiles[0] = "../keys/prod.keys"; keyfiles[1] = "../keys/ldn.txt"; nkeys = 2; }
    if (!ldn_keys_load(&keys, keyfiles, nkeys, "ldn_passphrase_scarlet_violet")) return 1;
    u8 chlist[16];
    int nch = 0;
    for (const char *p = chans; *p && nch < 16;) {
        chlist[nch++] = (u8)atoi(p);
        while (*p && *p != ',') p++;
        if (*p) p++;
    }
    random_bytes(device_id, 8);
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    char err[256];
    channel_now = chlist[0];
    if (!radio_open(&radio, spec ? spec : "s3", channel_now, false, err, sizeof err)) { logf_(0, "ldnjoin: %s", err); return 1; }
    radio.on_link = on_link;
    logf_(0, "ldnjoin: compiled %s %s; our station " MAC_FMT ", scanning channels %s", __DATE__, __TIME__,
          MAC_ARG(radio.sta_mac), chans);
    FILE *pcap = pcap_path ? fopen(pcap_path, "wb") : NULL;
    if (pcap) {
        static const u8 gh[24] = {0xD4, 0xC3, 0xB2, 0xA1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 127, 0, 0, 0};
        fwrite(gh, 1, sizeof gh, pcap);
    }
    u64 start = now_us(), last_hop = now_ms(), last_status = now_ms();
    int ch_i = 0;
    static u8 rx[4096];
    set_state(SCAN);
    while (!quit) {
        const u8 *f;
        size_t n;
        bool any = false;
        while ((n = radio_recv(&radio, rx, sizeof rx, &f))) {
            any = true;
            on_frame(f, n);
            if (pcap) {
                u64 us = now_us() - start;
                u32 len = (u32)(f - rx + n);
                u32 rh[4] = {(u32)(us / 1000000), (u32)(us % 1000000), len, len};
                fwrite(rh, 4, 4, pcap);
                fwrite(rx, 1, len, pcap);
            }
        }
        u64 t = now_ms();
        if (state == SCAN && t - last_hop >= 1500 && nch > 1) {
            ch_i = (ch_i + 1) % nch;
            channel_now = chlist[ch_i];
            if (!s3_set_channel(&radio, channel_now, err, sizeof err)) logf_(0, "ldnjoin: %s", err);
            last_hop = t;
        }
        if (state == JOINING && join_tries == 0) {
            join_tries++;
            logf_(0, "join: " MAC_FMT " SSID %s channel %u", MAC_ARG(host_mac), ssid_hex, adv.channel);
            if (!s3_join(&radio, adv.channel, host_mac, ssid_hex, data_key, err, sizeof err)) {
                logf_(0, "join: %s", err);
                set_state(SCAN);
            }
        }
        if (state == JOINING && t - state_ms > 10000) {
            logf_(0, "join: no link after 10 s; scanning again");
            s3_leave(&radio);
            set_state(SCAN);
        }
        if (state == AUTH && (last_req_ms == 0 || t - last_req_ms >= 700)) {
            if (req_tries >= 3) {
                logf_(0, "ldn: no accepted response after 3 requests; leaving, scanning again");
                s3_leave(&radio);
                set_state(SCAN);
            } else
                send_request();
        }
        if (state == JOINED && !my_ip && t - state_ms > 2000 && t - state_ms < 2100)
            logf_(0, "adv: not listed 2 s after acceptance (a console waits 1 s)");
        if (t - last_status >= 5000) {
            last_status = t;
            logf_(0, "status: state %s, channel %u, link %s; from the host: %u adverts, %u IPv4 (%u UDP, %u Pia, %u "
                     "authenticated), %u ARP, %u other", state == SCAN ? "scan" : state == JOINING ? "joining" :
                     state == AUTH ? "auth" : "in", channel_now, link_up ? "up" : "down", cnt_adv, cnt_ip, cnt_udp,
                  cnt_pia, cnt_pia_ok, cnt_arp, cnt_other);
            if (pcap) fflush(pcap);
        }
        if (!any) {
#ifdef _WIN32
            Sleep(2);
#else
            struct timespec ts = {0, 2000000};
            nanosleep(&ts, NULL);
#endif
        }
    }
    s3_leave(&radio);
    radio_close(&radio);
    if (pcap) fclose(pcap);
    return 0;
}
