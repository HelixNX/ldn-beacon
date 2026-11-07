/* ldnbeacon (Linux): joins a room, finds the network a member hosts (LDN Scan -> ScanResp) and hosts it on the air
 * as a Switch would: a beacon and the LDN advertisement every 100 ms. Stage 1: a real Switch searching for local
 * play (e.g. a raid's link code) should list the room's network; joining it is not handled yet. What the radio hears
 * that concerns us (probe requests, authentication / association to our BSSID, other consoles' advertisements) is
 * logged, as a preview of stage 2.
 *   sudo ./ldnbeacon --room host[:port] [--iface wlan0] [--channel 1|6|11] [--nick name] [--password pw]
 *                    [-k keyfile]... [--pcap file] [--no-ap] [--psk-mode 0-2] [--hostapd-log file] [--resp-flags n]
 *                    [--log 0-2]
 * Stage 2 (default): hostapd runs the network on the Wi-Fi interface (ACKs, authentication, association, WPA2; see
 * ap.h) and mon0 only injects the advertisements; --no-ap is stage 1 (beacons and probe responses injected too).
 * The WPA2 key is a guess (--psk-mode, ap.h); hostapd's debug log and --pcap capture the handshake either way.
 * --pcap saves every frame heard (radiotap, for Wireshark / analysis elsewhere).
 * Key files default to ../keys/prod.keys and ../keys/ldn.txt (run from ldn-beacon/). Ctrl+C gives Wi-Fi back. */
#include "ap.h"
#include "ccmp.h"
#include "frames.h"
#include "ldnauth.h"
#include "radio.h"
#include "room.h"
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

static volatile sig_atomic_t quit;
static void on_signal(int s) { (void)s; quit = 1; }

static struct {
    bool have;
    u8 host_ip[4];                  /* the room member hosting it */
    LdnNetworkInfo info;
    u64 seen_ms;
    HostSession session;
    u8 data_key[16];                /* the network's CCMP key (ldn_data_key) */
} net;

static LdnKeys keys;

/* the Switch that joined (one per beacon: it is one member of the room) */
static struct {
    bool active, in_room;
    u8 mac[6];
    char name[33];
    u16 version;
    u8 platform;
} sta;
static u8 own_device_id[8];
static u64 tx_pn;
static unsigned cnt_decrypted, cnt_undecryptable, cnt_auth_answered, cnt_other_data;
/* the challenge response's flags (ldnauth.h): fixed with --resp-flags, else a new value per join attempt from this
 * list, to find the one a Switch accepts in one run */
static const u32 resp_flag_tries[] = {2, 1, 0, 3};
static int resp_flags_fixed = 2, attempt;          /* run 9: 2, 1 and 0 all ended the same way */
static u32 attempt_flags;
static u64 answered_ms;

static void on_ldn(const RoomLdn *p, void *ud) {
    (void)ud;
    if ((p->type != LDN_SCAN_RESP && p->type != LDN_SYNC_NETWORK) || p->size < sizeof(LdnNetworkInfo)) {
        logf_(2, "room: ldn %s from " IP_FMT, ldn_type_name(p->type), IP_ARG(p->local_ip));
        return;
    }
    if (net.have && memcmp(net.host_ip, p->local_ip, 4)) return;   /* stay with the first host */
    LdnNetworkInfo n;
    memcpy(&n, p->data, sizeof n);
    bool changed = !net.have || memcmp(&n, &net.info, sizeof n);
    net.have = true;
    memcpy(net.host_ip, p->local_ip, 4);
    net.info = n;
    net.seen_ms = now_ms();
    if (host_session_update(&net.session, &n)) {
        ldn_data_key(&keys, net.session.server_random, net.data_key);
        sta.active = sta.in_room = false;               /* a new network: the Switch must join again */
        logf_(0, "network of " IP_FMT ": local communication id %016llx, scene %u, %u of %u nodes, %u bytes of "
                 "advertise data; on the air as 169.254.%u.0/24",
              IP_ARG(p->local_ip), (unsigned long long)n.id.intent.local_communication_id, n.id.intent.scene_id,
              n.node_count, n.node_count_max, n.advertise_size, net.session.subnet);
    } else if (changed)
        logf_(1, "network of " IP_FMT " changed: %u of %u nodes", IP_ARG(p->local_ip), n.node_count, n.node_count_max);
}

/* --- what the radio hears ---------------------------------------------------------------------------------- */

typedef struct { u8 mac[6]; } Mac;
static Mac seen_probe[64], seen_adv[64];
static int nseen_probe, nseen_adv;
static unsigned cnt_probe, cnt_probe_nn, cnt_auth, cnt_assoc, cnt_adv_other, cnt_rx, cnt_echo_beacon, cnt_echo_adv;
static Mac seen_nn_probe[64], seen_ours[64];
static int nseen_nn_probe, nseen_ours;
static unsigned cnt_probe_ours, cnt_probe_resp;

/* the air side's state, for answering probes from on_frame */
static Radio radio;
static u8 channel_now;
static bool use_ap = true;
static unsigned cnt_eapol, cnt_protected;
static u16 seq;
static u64 start_us;

#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_ARG(m) (m)[0], (m)[1], (m)[2], (m)[3], (m)[4], (m)[5]

static u32 room_ip_u32(void) {
    const u8 *ip = room_ip();
    return (u32)ip[0] << 24 | (u32)ip[1] << 16 | (u32)ip[2] << 8 | ip[3];
}

/* the Switch as the room sees it: one more station of the host's network, at the beacon's room address */
static void send_room_node(u8 type) {
    LdnNodeInfo node;
    memset(&node, 0, sizeof node);
    const u8 *ip = room_ip();
    node.ipv4 = room_ip_u32();
    node.mac[0] = 0x02;
    memcpy(node.mac + 2, ip, 4);
    node.is_connected = 1;
    memcpy(node.user_name, sta.name, 32);
    node.local_communication_version = (s16)sta.version;
    RoomLdn p = {.type = type, .data = (const u8 *)&node, .size = sizeof node};
    memcpy(p.local_ip, ip, 4);
    memcpy(p.remote_ip, net.host_ip, 4);
    room_send_ldn(&p);
}

static void station_leave(const char *why) {
    if (!sta.active) return;
    logf_(0, "station " MAC_FMT " (\"%s\") left: %s, %llu ms after our authentication response (attempt %d, "
             "response flags %u)", MAC_ARG(sta.mac), sta.name, why, (unsigned long long)(now_ms() - answered_ms),
          attempt, attempt_flags);
    if (sta.in_room && net.have) send_room_node(LDN_DISCONNECT);
    sta.active = sta.in_room = false;
}

/* an LDN frame (from the OUI on) to one station: LLC/SNAP + EtherType 0x88B7, CCMP, QoS data from the AP */
static bool send_ldn_frame(const u8 dest[6], const u8 *p, size_t n) {
    static u8 body[2048], fr[2200];
    static const u8 llc[8] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0xB7};
    if (n + 8 > sizeof body) return false;
    memcpy(body, llc, 8);
    memcpy(body + 8, p, n);
    u8 hdr[26] = {0x88, 0x02};                          /* QoS data, FromDS */
    memcpy(hdr + 4, dest, 6);
    memcpy(hdr + 10, radio.mac, 6);
    memcpy(hdr + 16, radio.mac, 6);
    u16 sc = (u16)((seq++ & 0xFFF) << 4);
    hdr[22] = (u8)sc;
    hdr[23] = (u8)(sc >> 8);
    size_t k = ccmp_encrypt(net.data_key, hdr, 26, body, n + 8, ++tx_pn, fr, sizeof fr);
    return k && radio_send_ex(&radio, fr, k, true, true);
}

static void handle_ldn(const u8 *p, size_t n, const u8 src[6]) {
    LdnAuthRequest r;
    if (!ldn_auth_parse(&keys, p, n, &r)) {
        logf_(0, "air: LDN frame from " MAC_FMT ", %zu bytes, packet type %02x%02x: not an authentication request",
              MAC_ARG(src), n, n > 4 ? p[3] : 0, n > 4 ? p[4] : 0);
        return;
    }
    u8 status = LDN_AUTH_OK;
    if (r.has_challenge && !r.challenge_ok) status = LDN_AUTH_BAD_CHALLENGE;
    bool ours = !memcmp(r.server_random, net.session.server_random, 16);
    static u64 last_req_ms;
    bool new_attempt = !last_req_ms || now_ms() - last_req_ms > 2000;   /* retries come within ~1 s */
    last_req_ms = now_ms();
    if (new_attempt) {                                  /* (the client random changes on every retry too) */
        attempt_flags = resp_flags_fixed >= 0 ? (u32)resp_flags_fixed
                                              : resp_flag_tries[attempt % (int)(sizeof resp_flag_tries / sizeof *resp_flag_tries)];
        attempt++;
    }
    static u8 resp[1024];
    size_t rn = ldn_auth_response(&keys, &r, status, own_device_id, attempt_flags, resp, sizeof resp);
    answered_ms = now_ms();
    bool sent = rn && send_ldn_frame(src, resp, rn);
    cnt_auth_answered += sent;
    logf_(0, "air: LDN authentication request from " MAC_FMT " (\"%s\", version %u, app version %u, platform %u, "
             "challenge %s%s, P %u Q %u flags %u): %s, status %u, attempt %d with response flags %u",
          MAC_ARG(src), r.user_name, r.version, r.app_version, r.platform,
          !r.has_challenge ? "none" : r.challenge_ok ? "ok" : "BAD", ours ? "" : ", other server random", r.p, r.q,
          r.flags, sent ? "answered" : "answer FAILED", status, attempt, attempt_flags);
    if (status != LDN_AUTH_OK) return;
    if (!sta.active || memcmp(sta.mac, src, 6)) {
        station_leave("another station joined");
        memset(&sta, 0, sizeof sta);
        sta.active = true;
        memcpy(sta.mac, src, 6);
        memcpy(sta.name, r.user_name, 33);
        sta.version = r.app_version;
        sta.platform = r.platform;
    }
    if (!sta.in_room) {                                 /* the room host takes it as a station: SyncNetwork follows */
        send_room_node(LDN_CONNECT);
        sta.in_room = true;
        logf_(0, "room: Connect sent to " IP_FMT " for \"%s\"", IP_ARG(net.host_ip), sta.name);
    }
}

/* a protected data frame to us: decrypt with the network's key */
static void handle_data(const u8 *f, size_t n, const u8 src[6]) {
    static u8 pl[4096];
    size_t pn_len;
    u64 pn;
    if (n > sizeof pl || (!ccmp_decrypt(net.data_key, f, n, pl, &pn_len, &pn) &&
                          !(n > 4 && ccmp_decrypt(net.data_key, f, n - 4, pl, &pn_len, &pn)))) {
        if (!cnt_undecryptable++)
            logf_(0, "air: encrypted data from " MAC_FMT " that our key does not decrypt (%zu bytes)", MAC_ARG(src), n);
        return;
    }
    if (!cnt_decrypted++) logf_(0, "air: encrypted data from " MAC_FMT " decrypts with the network's key", MAC_ARG(src));
    if (pn_len < 8 || pl[0] != 0xAA || pl[1] != 0xAA || pl[2] != 0x03) return;
    u16 et = (u16)(pl[6] << 8 | pl[7]);
    if (et == LDN_ETHERTYPE) { handle_ldn(pl + 8, pn_len - 8, src); return; }
    if (cnt_other_data++ < 10)
        logf_(0, "air: data from " MAC_FMT ": EtherType %04x, %zu bytes (not forwarded yet: stage 3)", MAC_ARG(src),
              et, pn_len - 8);
}

static bool first_time(Mac *list, int *n, const u8 *mac) {
    for (int i = 0; i < *n; i++)
        if (!memcmp(list[i].mac, mac, 6)) return false;
    if (*n < 64) memcpy(list[(*n)++].mac, mac, 6);
    return true;
}

static void on_frame(const u8 *f, size_t n, const u8 bssid[6]) {
    cnt_rx++;
    if (n < 24) return;
    u8 type = (f[0] >> 2) & 3, sub = f[0] >> 4;
    const u8 *a1 = f + 4, *a2 = f + 10;
    if (!memcmp(a2, bssid, 6)) {                            /* our own: the driver's report that it sent it */
        if (f[0] == 0x80) cnt_echo_beacon++;
        else if (f[0] == 0xD0) cnt_echo_adv++;
        return;
    }
    if (type == 2 && !memcmp(a1, bssid, 6)) {               /* data to us */
        if (f[1] & 0x40) {                                  /* protected: CCMP with the network's key */
            cnt_protected++;
            if (net.have) handle_data(f, n, a2);
            return;
        }
        size_t h = (sub & 8) ? 26 : 24;                     /* QoS data has 2 more bytes */
        if (n >= h + 8 && f[h] == 0xAA && f[h + 1] == 0xAA && f[h + 6] == 0x88 && f[h + 7] == 0x8E) {
            cnt_eapol++;
            logf_(0, "air: EAPOL (WPA2 handshake) from " MAC_FMT ", %zu bytes", MAC_ARG(a2), n);
        }
        return;
    }
    if (type != 0) return;                                  /* management only */
    if ((sub == 12 || sub == 10) && sta.active && !memcmp(a2, sta.mac, 6) && !memcmp(a1, bssid, 6)) {
        char why[64];
        snprintf(why, sizeof why, "%s, reason %u", sub == 12 ? "deauthentication" : "disassociation",
                 n >= 26 ? (unsigned)(f[24] | f[25] << 8) : 0);
        station_leave(why);
        return;
    }
    if (sub == 4) {                                         /* probe request */
        cnt_probe++;
        /* for our network by name (the SSID the advertisement's session id gives): answer at once */
        if (net.have && n >= 24 + 2 + 32 && f[24] == 0 && f[25] == 32) {
            char ssid[33];
            host_ssid(&net.session, ssid);
            if (!memcmp(f + 26, ssid, 32)) {
                cnt_probe_ours++;
                if (use_ap) {                               /* hostapd answers */
                    if (first_time(seen_ours, &nseen_ours, a2))
                        logf_(0, "air: " MAC_FMT " asks for our network by name (hostapd answers)", MAC_ARG(a2));
                    return;
                }
                u8 fr[FRAME_MAX];
                size_t k = frame_probe_resp(fr, sizeof fr, &net.session, bssid, a2, seq++ & 0xFFF,
                                            now_us() - start_us, channel_now);
                bool ok = k && radio_send(&radio, fr, k);
                cnt_probe_resp += ok;
                if (first_time(seen_ours, &nseen_ours, a2))
                    logf_(0, "air: " MAC_FMT " asks for our network by name (it read our advertisement): %s", MAC_ARG(a2),
                          ok ? "answered" : "answer FAILED");
                return;
            }
        }
        u8 ssid_len = n > 25 && f[24] == 0 ? f[25] : 0xFF;
        /* Nintendo's vendor element (00 22 aa): a console searching */
        for (size_t i = 24; i + 2 <= n && i + 2 + f[i + 1] <= n; i += 2 + (size_t)f[i + 1]) {
            if (f[i] != 221 || f[i + 1] < 3 || f[i + 2] != 0x00 || f[i + 3] != 0x22 || f[i + 4] != 0xAA) continue;
            cnt_probe_nn++;
            if (first_time(seen_nn_probe, &nseen_nn_probe, a2)) {
                char hex[2 * 255 + 1];
                for (int k = 0; k < f[i + 1]; k++) snprintf(hex + 2 * k, 3, "%02x", f[i + 2 + k]);
                hex[2 * f[i + 1]] = 0;
                logf_(0, "air: a console's probe request from " MAC_FMT " (to " MAC_FMT ", %zu bytes), Nintendo element %s",
                      MAC_ARG(a2), MAC_ARG(a1), n, hex);
            }
        }
        if (first_time(seen_probe, &nseen_probe, a2))
            logf_(1, "air: probe requests from " MAC_FMT " (SSID %s%u bytes)", MAC_ARG(a2),
                  ssid_len == 0xFF ? "? " : "", ssid_len == 0xFF ? 0 : ssid_len);
    } else if ((sub == 11 || sub == 0 || sub == 2) && !memcmp(a1, bssid, 6)) {
        /* authentication / (re)association request to us: stage 2's start */
        if (sub == 11) cnt_auth++; else cnt_assoc++;
        if (!use_ap || cnt_auth + cnt_assoc <= 20)
            logf_(0, "air: %s from " MAC_FMT " to us (%zu bytes)%s", sub == 11 ? "authentication" : "association request",
                  MAC_ARG(a2), n, use_ap ? " (hostapd answers)" : ": the Switch tries to join (not handled yet)");
    } else if (sub == 13 && n >= 24 + 6 && f[24] == 0x7F && f[25] == 0x00 && f[26] == 0x22 && f[27] == 0xAA) {
        cnt_adv_other++;
        if (first_time(seen_adv, &nseen_adv, a2))
            logf_(1, "air: Nintendo action frames from " MAC_FMT " (another console)", MAC_ARG(a2));
    }
}

/* ------------------------------------------------------------------------------------------------------------- */

int main(int argc, char **argv) {
    RoomConfig c = {.port = 24872, .nick = "beacon", .game_name = "Pokemon Violet", .game_id = 0x01008F6008C5E000ull};
    char host[256] = "";
    const char *iface = NULL, *keyfiles[8];
    const char *pcap_path = NULL, *hostapd_log = "hostapd.log", *passphrase = "ldn_passphrase_scarlet_violet";
    int psk_mode = AP_PSK_HEX_PASSPHRASE;
    int nkeys = 0, channel = 6;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i], *v = i + 1 < argc ? argv[i + 1] : NULL;
        if (!strcmp(a, "--room") && v) {
            snprintf(host, sizeof host, "%s", v);
            char *colon = strrchr(host, ':');
            if (colon) { *colon = 0; c.port = (u16)atoi(colon + 1); }
            i++;
        } else if (!strcmp(a, "--iface") && v) iface = v, i++;
        else if (!strcmp(a, "--channel") && v) channel = atoi(v), i++;
        else if (!strcmp(a, "--nick") && v) c.nick = v, i++;
        else if (!strcmp(a, "--password") && v) c.password = v, i++;
        else if (!strcmp(a, "-k") && v && nkeys < 8) keyfiles[nkeys++] = v, i++;
        else if (!strcmp(a, "--log") && v) log_level = atoi(v), i++;
        else if (!strcmp(a, "--pcap") && v) pcap_path = v, i++;
        else if (!strcmp(a, "--no-ap")) use_ap = false;
        else if (!strcmp(a, "--psk-mode") && v) psk_mode = atoi(v), i++;
        else if (!strcmp(a, "--hostapd-log") && v) hostapd_log = v, i++;
        else if (!strcmp(a, "--passphrase") && v) passphrase = v, i++;
        else if (!strcmp(a, "--resp-flags") && v) resp_flags_fixed = atoi(v), i++;
        else {
            fprintf(stderr, "usage: sudo ./ldnbeacon --room host[:port] [--iface wlan0] [--channel 1|6|11] "
                            "[--nick name] [--password pw] [-k keyfile]... [--pcap file] [--no-ap] [--psk-mode 0-2] [--hostapd-log file] [--log 0-2]\n");
            return 2;
        }
    }
    if (!*host) { fprintf(stderr, "ldnbeacon: --room host[:port] is required\n"); return 2; }
    if (channel != 1 && channel != 6 && channel != 11) { fprintf(stderr, "ldnbeacon: channel 1, 6 or 11\n"); return 2; }
    if (!nkeys) { keyfiles[0] = "../keys/prod.keys"; keyfiles[1] = "../keys/ldn.txt"; nkeys = 2; }
    random_bytes(own_device_id, sizeof own_device_id);
    random_bytes(&tx_pn, 2);                                /* any start; counts up */
    if (psk_mode < 0 || psk_mode >= AP_PSK_MODES) { fprintf(stderr, "ldnbeacon: --psk-mode 0-%d\n", AP_PSK_MODES - 1); return 2; }
    if (!ldn_keys_load(&keys, keyfiles, nkeys, use_ap ? passphrase : NULL)) return 1;
    c.host = host;

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGHUP, on_signal);
    RoomHandlers h = {.ldn = on_ldn};
    char err[256];
    if (!room_join(&c, &h, err, sizeof err)) { logf_(0, "ldnbeacon: %s", err); return 1; }
    channel_now = (u8)channel;
    if (!radio_open(&radio, iface, (u8)channel, err, sizeof err)) {
        logf_(0, "ldnbeacon: %s", err);
        room_leave();
        return 1;
    }

    int ldn_fd = use_ap ? radio_eth_socket(&radio, 0x88B7) : -1;   /* the LDN authentication, after WPA2 */
    if (use_ap && ldn_fd < 0) logf_(0, "ldnbeacon: no packet socket for EtherType 0x88B7");
    Ap ap = {0};
    u8 ap_session[16] = {0};
    bool ap_tried = false;
    FILE *pcap = NULL;
    if (pcap_path) {
        pcap = fopen(pcap_path, "wb");
        if (!pcap) logf_(0, "ldnbeacon: cannot write %s", pcap_path);
        else {
            static const u8 gh[24] = {0xD4, 0xC3, 0xB2, 0xA1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                      0xFF, 0xFF, 0, 0, 127, 0, 0, 0};   /* little-endian, radiotap */
            fwrite(gh, 1, sizeof gh, pcap);
        }
    }
    start_us = now_us();
    u64 next_tick = now_ms(), last_scan = 0, last_status = now_ms();
    unsigned sent = 0, send_fail = 0;
    bool on_air = false;
    static u8 rx[4096], fr[FRAME_MAX];
    int rc = 0;
    while (!quit) {
        u64 t = now_ms();
        int wait = next_tick > t ? (int)(next_tick - t) : 0;
        if (!room_service(wait > 5 ? 5 : wait)) { logf_(0, "ldnbeacon: left the room"); rc = 1; break; }
        const u8 *f;
        size_t n;
        while ((n = radio_recv(&radio, rx, sizeof rx, &f))) {
            on_frame(f, n, radio.mac);
            if (pcap) {
                u64 us = now_us() - start_us;
                u32 len = (u32)(f - rx + n);
                u32 rh[4] = {(u32)(us / 1000000), (u32)(us % 1000000), len, len};   /* x86: little-endian */
                fwrite(rh, 4, 4, pcap);
                fwrite(rx, 1, len, pcap);
            }
        }

        if (ldn_fd >= 0) {
            static u8 eth[2048];
            size_t k;
            while ((k = radio_eth_recv(ldn_fd, eth, sizeof eth))) {
                char hx[2 * 128 + 1];
                size_t m = k < 128 ? k : 128;
                for (size_t i = 0; i < m; i++) snprintf(hx + 2 * i, 3, "%02x", eth[i]);
                logf_(0, "ap: LDN frame (EtherType 0x88B7), %zu bytes, from " MAC_FMT ": %s%s", k, MAC_ARG(eth + 6), hx,
                      k > m ? "..." : "");
            }
        }

        t = now_ms();
        if (t - last_scan >= 1000) {                        /* ask the room who hosts */
            last_scan = t;
            RoomLdn p = {.type = LDN_SCAN, .broadcast = true};
            memcpy(p.local_ip, room_ip(), 4);
            room_send_ldn(&p);
        }
        if (net.have && t - net.seen_ms > 5000) {
            logf_(0, "network of " IP_FMT " gone (no answer for 5 s): off the air", IP_ARG(net.host_ip));
            sta.active = sta.in_room = false;
            net.have = false;
        }
        if (net.have != on_air) {
            on_air = net.have;
            if (on_air) logf_(0, "on the air: %s every 100 ms on channel %d", use_ap ? "advertisement (beacons: hostapd)" :
                              "beacon + advertisement", channel);
        }
        if (use_ap) {                                       /* one hostapd per room session */
            bool same = net.have && !memcmp(ap_session, net.session.session_id, 16);
            if (ap.pid > 0 && (!net.have || !same)) ap_stop(&ap);
            if (ap.pid > 0) ap_running(&ap);                /* exited: logged; not retried for this session */
            if (net.have && !same) {
                memcpy(ap_session, net.session.session_id, 16);
                ap_tried = false;
            }
            if (net.have && ap.pid <= 0 && !ap_tried) {
                ap_tried = true;
                char ssid[33];
                u8 key[16];
                host_ssid(&net.session, ssid);
                ldn_data_key(&keys, net.session.server_random, key);
                if (!ap_start(&ap, radio.iface, ssid, (u8)channel, key, psk_mode, hostapd_log, err, sizeof err))
                    logf_(0, "ldnbeacon: %s", err);
            }
        }
        if (t >= next_tick) {
            next_tick += 100;
            if (t > next_tick + 1000) next_tick = t + 100;  /* fell far behind: do not burst */
            if (net.have) {
                LdnAdvert a;
                host_advert(&net.session, &net.info, radio.mac, (u8)channel, &a);
                if (sta.active)                             /* the Switch: our node in the room's list */
                    for (int i = 1; i < ADV_PARTICIPANTS; i++)
                        if (net.info.nodes[i].is_connected && net.info.nodes[i].ipv4 == room_ip_u32()) {
                            memcpy(a.participants[i].mac, sta.mac, 6);
                            a.participants[i].platform = sta.platform;
                        }
                /* a new nonce whenever the content changes: a station may skip advertisements whose nonce it has
                 * already seen (run 9: the Switch left 510 ms after joining, as if it never saw itself listed) */
                {
                    static LdnAdvert last_adv;
                    static bool have_last;
                    LdnAdvert cmp = a;
                    cmp.nonce = 0;
                    if (!have_last || memcmp(&cmp, &last_adv, sizeof cmp)) {
                        if (have_last) {
                            random_bytes(&net.session.nonce, 4);
                            logf_(1, "advertisement changed: new nonce %08x", net.session.nonce);
                        }
                        last_adv = cmp;
                        have_last = true;
                    }
                    a.nonce = net.session.nonce;
                }
                /* the participant list as advertised, logged when it changes */
                static u8 last_list[ADV_PARTICIPANTS * 12 + 1];
                u8 list[ADV_PARTICIPANTS * 12 + 1];
                list[0] = a.participant_count;
                for (int i = 0; i < ADV_PARTICIPANTS; i++) {
                    const LdnAdvParticipant *q = &a.participants[i];
                    u8 *e = list + 1 + i * 12;
                    e[0] = (u8)(q->ipv4 >> 24); e[1] = (u8)(q->ipv4 >> 16); e[2] = (u8)(q->ipv4 >> 8); e[3] = (u8)q->ipv4;
                    memcpy(e + 4, q->mac, 6);
                    e[10] = q->connected;
                    e[11] = q->platform;
                }
                if (memcmp(list, last_list, sizeof list)) {
                    memcpy(last_list, list, sizeof list);
                    logf_(0, "advertising %u participant(s):", a.participant_count);
                    for (int i = 0; i < ADV_PARTICIPANTS; i++) {
                        const LdnAdvParticipant *q = &a.participants[i];
                        if (!q->connected) continue;
                        logf_(0, "  %d: %u.%u.%u.%u " MAC_FMT " \"%s\" platform %u app version %u", i, q->ipv4 >> 24,
                              (q->ipv4 >> 16) & 255, (q->ipv4 >> 8) & 255, q->ipv4 & 255, MAC_ARG(q->mac), q->user_name,
                              q->platform, q->app_version);
                    }
                }
                size_t k;
                if (!use_ap) {
                    k = frame_beacon(fr, sizeof fr, radio.mac, seq++ & 0xFFF, now_us() - start_us, (u8)channel);
                    if (k && radio_send(&radio, fr, k)) sent++; else send_fail++;
                }
                k = frame_advert(fr, sizeof fr, &keys, &a, radio.mac, seq++ & 0xFFF);
                if (k && radio_send(&radio, fr, k)) sent++; else send_fail++;
            }
        }
        if (t - last_status >= 10000) {
            last_status = t;
            logf_(1, "status: %s, %u frames sent (%u failed; reported back by the driver: %u beacons, %u advertisements); heard %u frames: "
                     "%u probe requests (%u from consoles, %u for our network, %u answered), %u authentications "
                     "and %u association requests to us, %u EAPOL and %u encrypted data frames to us (%u decrypted, %u not; %u LDN "
                     "authentications answered, %u other), %u Nintendo action frames from others; station %s",
                  on_air ? "on the air" : "no network in the room yet", sent, send_fail, cnt_echo_beacon, cnt_echo_adv, cnt_rx, cnt_probe, cnt_probe_nn, cnt_probe_ours, cnt_probe_resp, cnt_auth,
                  cnt_assoc, cnt_eapol, cnt_protected, cnt_decrypted, cnt_undecryptable, cnt_auth_answered,
                  cnt_other_data, cnt_adv_other, !sta.active ? "none" : sta.in_room ? "joined" : "authenticated");
            if (send_fail && !sent) logf_(0, "ldnbeacon: the card sends nothing (injection refused?)");
            if (pcap) fflush(pcap);
        }
    }
    if (pcap) fclose(pcap);
    ap_stop(&ap);
    if (ldn_fd >= 0) close(ldn_fd);
    radio_close(&radio);
    room_leave();
    return rc;
}
