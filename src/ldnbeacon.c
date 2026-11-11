/* ldnbeacon (Windows or Linux): joins a room, finds the network a member hosts (LDN Scan -> ScanResp) and hosts it on the air
 * as a Switch would: a beacon and the LDN advertisement every 100 ms. Stage 1: a real Switch searching for local
 * play (e.g. a raid's link code) should list the room's network; joining it is not handled yet. What the radio hears
 * that concerns us (probe requests, authentication / association to our BSSID, other consoles' advertisements) is
 * logged, as a preview of stage 2.
 *   ldnbeacon --room host[:port] [--radio s3[:port] | wifi[:iface]] [--channel 1|6|11] [--nick name]
 *                    [--password pw] [--files dir]... [--pcap file] [--no-ap] [--psk-mode 0-2] [--hostapd-log file]
 *                    [--s3-open] [--resp-flags n] [--bcast-mode 0-2] [--log 0-2]
 * The radio (radio.h): s3, an ESP32-S3 with s3/ flashed on USB (Windows and Linux; its SoftAP takes hostapd's part,
 * --s3-open makes it an open AP instead of WPA2), or wifi, the machine's own card (Linux only: mon0 + hostapd).
 * Default: the S3 when one is plugged in, else the built-in Wi-Fi. --iface x is --radio wifi:x.
 * Stage 2 (default): hostapd runs the network on the Wi-Fi interface (ACKs, authentication, association, WPA2; see
 * ap.h) and mon0 only injects the advertisements; --no-ap is stage 1 (beacons and probe responses injected too).
 * The WPA2 key is a guess (--psk-mode, ap.h); hostapd's debug log and --pcap capture the handshake either way.
 * --pcap saves every frame heard (radiotap, for Wireshark / analysis elsewhere).
 * Keys from your own prod.keys, firmware and game (ldnkeys.h; --files dir, default: ldn-beacon/ and the workspace;
 * --game scarlet_violet). Ctrl+C gives Wi-Fi back. */
#include "bridge.h"
#include "ccmp.h"
#include "frames.h"
#include "ldnauth.h"
#include "pia.h"
#include "radio.h"
#include "room.h"
#include <signal.h>
#include <stdlib.h>
#ifndef _WIN32
#include <unistd.h>
#endif

static volatile sig_atomic_t quit;
static void on_signal(int s) { (void)s; quit = 1; }

static struct {
    bool have;
    u8 host_ip[4];                  /* the room member hosting it */
    LdnNetworkInfo info;
    u64 seen_ms;
    HostSession session;
    u8 data_key[16];                /* the network's CCMP key (ldn_data_key) */
    PiaNet pia;                     /* the game's Pia session (pia.h): same key on both sides, nonces by address */
    bool have_pia;
} net;
/* Pia 6.x in LDN mode, as piatest settled it on run 14's packets: session key AES-encrypt(game key, session id),
 * nonce prefix CRC-32(session id[1..15]) XOR the source IPv4 (big-endian both), no AAD */
static const PiaVariant pia_variant = {0, 0, 0, 0};

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
/* How room broadcasts reach the Switch: 0 group frames, 1 unicast to its MAC (IP broadcast inside; one station, so
 * the same thing with ACKs and retries), 2 alternate per join attempt (odd: group, even: unicast). Run 13: the
 * Switch answered none of our group ARP probes and every unicast one (on the MT7925). With the S3 group frames have
 * reached it (S3 run 3), and a real Switch host sends its broadcasts as group frames (join run 7), so the default
 * alternates: the first join as a real host does, the next as unicast */
static int bcast_mode = 2;
static bool bcast_unicast;
/* ARP probes from the host (.1) for the Switch's address after each join: group at +500 ms, unicast at +1500 ms */
static int probes_sent;

static void on_ldn(const RoomLdn *p, void *ud) {
    (void)ud;
    /* the host tore its network down (a recomp host tells whoever scanned it): off the air at once, before a Switch
     * joins a network nobody answers for (a link-code search hosts and scans in turns) */
    if (p->type == LDN_DESTROY_NETWORK && net.have && !memcmp(net.host_ip, p->local_ip, 4)) {
        logf_(0, "network of " IP_FMT " destroyed by its host: off the air", IP_ARG(net.host_ip));
        sta.active = sta.in_room = false;
        net.have = false;
        return;
    }
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
        net.have_pia = keys.have_pia_key;
        if (net.have_pia) pia_net_init(&net.pia, keys.pia_game_key, net.session.session_id, &pia_variant);
        else logf_(0, "network: no Pia game key: Pia packets pass unchanged and fail");
        static const u8 zero16[16];
        char sr[33];
        for (int i = 0; i < 16; i++) snprintf(sr + 2 * i, 3, "%02x", net.session.server_random[i]);
        logf_(0, "network: server random = the host's security parameter, %s", memcmp(net.session.server_random,
              zero16, 16) ? sr : "zero (a recomp host leaves it so)");
        sta.active = sta.in_room = false;               /* a new network: the Switch must join again */
        logf_(0, "network of " IP_FMT ": local communication id %016llx, scene %u, %u of %u nodes, %u bytes of "
                 "advertise data, security level %u, accept policy %u (a Switch host: 1, 0); on the air as "
                 "169.254.%u.0/24",
              IP_ARG(p->local_ip), (unsigned long long)n.id.intent.local_communication_id, n.id.intent.scene_id,
              n.node_count, n.node_count_max, n.advertise_size, n.security_mode, n.accept_policy, net.session.subnet);
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
    /* the Switch's own MAC (the recomp takes the NodeInfo as it is): its Pia constant id is then the same in the
     * room as on the air, where game data carries it beyond the reach of the rewrite (S3 run 11) */
    memcpy(node.mac, sta.mac, 6);
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
    if (radio.hw_crypto) return radio_send_eth(&radio, dest, radio.mac, LDN_ETHERTYPE, p, n);
    static u8 body[2048], fr[2200];
    static const u8 llc[8] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0xB7};
    if (n + 8 > sizeof body) return false;
    memcpy(body, llc, 8);
    memcpy(body + 8, p, n);
    /* QoS data, FromDS (as on the laptop since run 8); the S3 sends only non-QoS data (kinnay's host sends that) */
    u8 hdr[26] = {radio.qos_data ? 0x88 : 0x08, 0x02};
    size_t hl = radio.qos_data ? 26 : 24;
    memcpy(hdr + 4, dest, 6);
    memcpy(hdr + 10, radio.mac, 6);
    memcpy(hdr + 16, radio.mac, 6);
    u16 sc = (u16)((seq++ & 0xFFF) << 4);
    hdr[22] = (u8)sc;
    hdr[23] = (u8)(sc >> 8);
    size_t k = ccmp_encrypt(net.data_key, hdr, hl, body, n + 8, ++tx_pn, 0, fr, sizeof fr);
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
        bcast_unicast = bcast_mode == 1 || (bcast_mode == 2 && attempt % 2 == 0);
        probes_sent = 0;
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
    if (new_attempt)
        logf_(0, "bridge: attempt %d sends the room's broadcasts %s", attempt,
              bcast_unicast ? "as unicast frames to the Switch" : "as group frames (key index 1)");
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

static void from_switch(u16 et, const u8 *p, size_t n, const u8 src_mac[6]);
static void handle_llc(const u8 *pl, size_t n, const u8 src[6]);

/* a protected data frame to us: decrypt with the network's key */
static void handle_data(const u8 *f, size_t n, const u8 src[6]) {
    static u8 pl[4096];
    size_t pn_len;
    u64 pn;
    /* the S3 holds the key and decrypts in hardware: its promiscuous frames then keep the Protected bit, the CCMP
     * header and the MIC, with the body already plain (S3 run 2, 2026-11-07: LLC/SNAP right after the CCMP header) */
    size_t h = (f[0] & 0x80) ? 26 : 24;
    if (radio.hw_crypto && n >= h + 8 + 8 + 8 && f[h + 8] == 0xAA && f[h + 9] == 0xAA && f[h + 10] == 0x03) {
        static unsigned hw;
        if (!hw++) logf_(0, "air: data from " MAC_FMT " arrives decrypted by the radio (CCMP header and MIC kept)",
                         MAC_ARG(src));
        cnt_decrypted++;
        handle_llc(f + h + 8, n - h - 8 - 8, src);
        return;
    }
    if (n > sizeof pl || (!ccmp_decrypt(net.data_key, f, n, pl, &pn_len, &pn) &&
                          !(n > 4 && ccmp_decrypt(net.data_key, f, n - 4, pl, &pn_len, &pn)))) {
        if (!cnt_undecryptable++)
            logf_(0, "air: encrypted data from " MAC_FMT " that our key does not decrypt (%zu bytes)", MAC_ARG(src), n);
        return;
    }
    if (!cnt_decrypted++) logf_(0, "air: encrypted data from " MAC_FMT " decrypts with the network's key", MAC_ARG(src));
    handle_llc(pl, pn_len, src);
}

/* a decrypted body: LLC/SNAP, EtherType, payload */
static void handle_llc(const u8 *pl, size_t n, const u8 src[6]) {
    if (n < 8 || pl[0] != 0xAA || pl[1] != 0xAA || pl[2] != 0x03) return;
    u16 et = (u16)(pl[6] << 8 | pl[7]);
    if (et == LDN_ETHERTYPE) { handle_ldn(pl + 8, n - 8, src); return; }
    if (et == ETHERTYPE_IPV4 || et == ETHERTYPE_ARP) { from_switch(et, pl + 8, n - 8, src); return; }
    cnt_other_data++;                                   /* IPv6 and the like: the console's own, not the game's */
}

/* ---- stage 3: the bridge between the room's proxy packets and IPv4 on the air ------------------------------------
 * Node i of the room network is room address nodes[i].ipv4 on one side and 169.254.X.(i + 1) with the MAC the
 * advertisement lists on the other (node 0: the host, our BSSID; our own node: the Switch). The Switch keeps static
 * neighbour entries from the advertisement (kinnay's host sends no ARP), but ARP requests are answered anyway. */
static unsigned cnt_to_air, cnt_to_room, cnt_drop_air, cnt_drop_room, cnt_arp, cnt_pia_ok, cnt_pia_bad;

/* a Pia packet crossing sides: its nonce has the sender's address, which differs between the room and the air, so
 * decrypt with the address it was sent from and encrypt with the one the receiver sees. Non-Pia payloads pass. */
static unsigned cnt_pia_rewritten, cnt_pia_noparse;
static void pia_build_map(PiaMap *m, bool to_air);

/* ... and the addresses inside its messages (run 15: the host's Net message lists the stations' StationAddresses
 * and its MAC-made constant id) become the receiver's side's; *len gets the new size */
static const u8 *pia_readdress(const u8 *p, size_t n, u32 from_ip, u32 to_ip, bool to_air, size_t *len) {
    static u8 b[2048], w[2048];
    const char *dir = to_air ? "room -> air" : "air -> room";
    *len = n;
    if (!net.have_pia || !pia_is_packet(p, n) || n > sizeof b) return p;
    memcpy(b, p, n);
    if (!pia_decrypt(&net.pia, &pia_variant, from_ip, b, n)) {
        if (cnt_pia_bad++ < 5)
            logf_(0, "pia: %s packet from %u.%u.%u.%u (%zu bytes) does not authenticate: passed unchanged", dir,
                  from_ip >> 24, from_ip >> 16 & 255, from_ip >> 8 & 255, from_ip & 255, n);
        return p;
    }
    static unsigned summarized[2];
    if (summarized[to_air]++ < 1500) {             /* S3 run 9: who acknowledges what in a raid */
        static char line[2048];
        pia_summary(b, n, line, sizeof line);
        logf_(0, "pia %s %u.%u.%u.%u %zu: %s", to_air ? "R>A" : "A>R", from_ip >> 24, from_ip >> 16 & 255,
              from_ip >> 8 & 255, from_ip & 255, n, line);
    }
    if (cnt_pia_ok++ < 5)
        logf_(0, "pia: %s packet %u.%u.%u.%u -> as from %u.%u.%u.%u, %zu bytes, protocol type %02x", dir, from_ip >> 24,
              from_ip >> 16 & 255, from_ip >> 8 & 255, from_ip & 255, to_ip >> 24, to_ip >> 16 & 255, to_ip >> 8 & 255,
              to_ip & 255, n, n > PIA_HDR + 4 ? b[PIA_HDR + 4] : 0);
    PiaMap map = {0};
    pia_build_map(&map, to_air);
    unsigned rep = 0;
    size_t wn = pia_rewrite(b, n, w, sizeof w, &map, &rep);
    if (!wn || wn > 1472) {                         /* not parsed (or too big): addresses inside stay as they are */
        if (cnt_pia_noparse++ < 5)
            logf_(0, "pia: %s packet's messages %s: only re-addressed", dir, wn ? "grew past 1472 bytes" : "do not parse");
        pia_encrypt(&net.pia, &pia_variant, to_ip, b, n);
        return b;
    }
    static unsigned summarized_after[2];
    if (rep && summarized_after[to_air]++ < 300) {  /* what the receiver gets when something was replaced */
        static char line[2048];
        pia_summary(w, wn, line, sizeof line);
        logf_(0, "pia %s after (%u replaced): %s", to_air ? "R>A" : "A>R", rep, line);
    }
    if (rep && cnt_pia_rewritten++ < 10)
        logf_(0, "pia: %s packet: %u addresses / constant ids inside replaced (%zu -> %zu bytes)", dir, rep, n, wn);
    static unsigned dumped[2];
    if (dumped[to_air]++ < 2) {                     /* the first two each way, decrypted, before and after */
        for (int k = 0; k < 2; k++) {
            const u8 *q = k ? w : b;
            size_t qn = k ? wn : n;
            logf_(0, "pia: %s packet %s (%zu bytes, footer %u):", dir, k ? "after" : "before", qn, q[0xB]);
            for (size_t i = 0; i < qn; i += 32) {
                char line[80];
                size_t o = 0;
                for (size_t j = i; j < qn && j < i + 32; j++) o += (size_t)snprintf(line + o, sizeof line - o, "%02x", q[j]);
                printf("      %s\n", line);
            }
            pia_dump(q, qn);
            fflush(stdout);
        }
    }
    pia_encrypt(&net.pia, &pia_variant, to_ip, w, wn);
    *len = wn;
    return w;
}
static u8 room_protocol = 3;                        /* UDP as the room numbers it: as the host's packets do */
static u16 ip_id;

static u32 ldn_base(void) { return 0xA9FE0000u | (u32)net.session.subnet << 8; }
static u32 ldn_ip(int node) { return ldn_base() | (u32)(node + 1); }

static int node_of_room_ip(u32 ip) {
    for (int i = 0; i < LDN_NODES; i++)
        if ((i == 0 || net.info.nodes[i].is_connected) && net.info.nodes[i].ipv4 == ip) return i;
    return -1;
}

static int node_of_ldn_ip(u32 ip) {
    if ((ip & 0xFFFFFF00u) != ldn_base()) return -1;
    int i = (int)(ip & 0xFF) - 1;
    if (i < 0 || i >= LDN_NODES || (i && !net.info.nodes[i].is_connected)) return -1;
    return i;
}

static int sta_node(void) { return sta.active ? node_of_room_ip(room_ip_u32()) : -1; }

static void node_mac(int i, u8 mac[6]) {
    if (i == 0) memcpy(mac, radio.mac, 6);
    else if (i == sta_node()) memcpy(mac, sta.mac, 6);
    else memcpy(mac, net.info.nodes[i].mac, 6);
}

/* every node's room address and MAC <-> its LDN address and the MAC the air knows (pia_readdress) */
static void pia_build_map(PiaMap *m, bool to_air) {
    for (int i = 0; i < LDN_NODES; i++) {
        if (i && !net.info.nodes[i].is_connected) continue;
        u8 air_mac[6];
        node_mac(i, air_mac);
        if (to_air) pia_map_add(m, net.info.nodes[i].ipv4, ldn_ip(i), net.info.nodes[i].mac, air_mac);
        else pia_map_add(m, ldn_ip(i), net.info.nodes[i].ipv4, air_mac, net.info.nodes[i].mac);
    }
}

/* an Ethernet-style frame to the Switch (or everyone): LLC/SNAP + ethertype, CCMP (key index 0 unicast, 1 group),
 * data from the AP (FromDS) with src as the source address */
static bool send_data_frame(const u8 dest[6], const u8 src[6], u16 ethertype, const u8 *p, size_t n) {
    if (radio.hw_crypto) return radio_send_eth(&radio, dest, src, ethertype, p, n);
    static u8 body[2048], fr[2200];
    if (n + 8 > sizeof body) return false;
    static const u8 llc[6] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00};
    memcpy(body, llc, 6);
    body[6] = (u8)(ethertype >> 8);
    body[7] = (u8)ethertype;
    memcpy(body + 8, p, n);
    u8 hdr[24] = {0x08, 0x02};                          /* data, FromDS */
    memcpy(hdr + 4, dest, 6);
    memcpy(hdr + 10, radio.mac, 6);
    memcpy(hdr + 16, src, 6);
    u16 sc = (u16)((seq++ & 0xFFF) << 4);
    hdr[22] = (u8)sc;
    hdr[23] = (u8)(sc >> 8);
    bool group = dest[0] & 1;
    size_t k = ccmp_encrypt(net.data_key, hdr, 24, body, n + 8, ++tx_pn, group ? 1 : 0, fr, sizeof fr);
    return k && radio_send_ex(&radio, fr, k, !group, true);
}

/* room -> air: a datagram for our member (the Switch) or for everyone */
static void on_proxy(const RoomProxy *p, void *ud) {
    (void)ud;
    if (p->protocol == 3 || p->protocol == 4) room_protocol = p->protocol;
    int me = sta_node();
    u32 from = (u32)p->local_ip[0] << 24 | (u32)p->local_ip[1] << 16 | (u32)p->local_ip[2] << 8 | p->local_ip[3];
    int src = net.have ? node_of_room_ip(from) : -1;
    if (me < 0 || src < 0 || src == me) {
        if (cnt_drop_room++ < 5)
            logf_(0, "room: datagram from " IP_FMT ":%u to %s" IP_FMT ":%u, %u bytes dropped (%s)", IP_ARG(p->local_ip),
                  p->local_port, p->broadcast ? "everyone, " : "", IP_ARG(p->remote_ip), p->remote_port, p->size,
                  me < 0 ? "no Switch joined" : src < 0 ? "sender not in the network" : "from ourselves");
        return;
    }
    static const u8 bcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    u32 dst = p->broadcast ? (ldn_base() | 0xFF) : ldn_ip(me);
    const u8 *dest = p->broadcast && !bcast_unicast ? bcast : sta.mac;
    static u8 pkt[2048];
    size_t plen;
    const u8 *payload = pia_readdress(p->data, p->size, from, ldn_ip(src), true, &plen);
    size_t n = ipv4_udp_build(pkt, sizeof pkt, ldn_ip(src), dst, p->local_port, p->remote_port, payload, plen,
                              ip_id++);
    u8 smac[6];
    node_mac(src, smac);
    bool ok = n && send_data_frame(dest, smac, ETHERTYPE_IPV4, pkt, n);
    cnt_to_air += ok;
    static unsigned logged_bcast, logged_unicast;
    bool log = p->broadcast ? logged_bcast++ < 5 : logged_unicast++ < 20;   /* unicast from the host: the news */
    if (log || !ok)
        logf_(0, "bridge: room " IP_FMT ":%u -> air 169.254.%u.%u:%u%s, %u bytes, %s%s", IP_ARG(p->local_ip),
              p->local_port, net.session.subnet, dst & 0xFF, p->remote_port, p->broadcast ? " (broadcast)" : "", p->size,
              dest == bcast ? "group frame" : "unicast frame", ok ? "" : ": send FAILED");
}

/* air -> room: an IPv4 or ARP frame from the Switch */
static void from_switch(u16 et, const u8 *p, size_t n, const u8 src_mac[6]) {
    int me = sta_node();
    if (me < 0 || memcmp(src_mac, sta.mac, 6)) { cnt_drop_air++; return; }
    if (et == ETHERTYPE_ARP) {
        Arp q;
        if (!arp_parse(p, n, &q)) return;
        if (q.op == 2) {                                /* an answer to our probe: that path reaches the Switch */
            logf_(0, "bridge: ARP reply from the Switch (169.254.%u.%u is " MAC_FMT "), %llu ms after our authentication "
                     "response (probes sent: group %s, unicast %s)", (q.spa >> 8) & 255, q.spa & 255, MAC_ARG(q.sha),
                  (unsigned long long)(now_ms() - answered_ms), probes_sent > 0 ? "yes" : "not yet",
                  probes_sent > 1 ? "yes" : "not yet");
            return;
        }
        if (q.op != 1) return;
        int t = node_of_ldn_ip(q.tpa);
        if (t < 0 || t == me) return;                   /* its own address (announcement) or nobody */
        Arp r = {.op = 2, .spa = q.tpa, .tpa = q.spa};
        node_mac(t, r.sha);
        memcpy(r.tha, q.sha, 6);
        u8 b[64];
        size_t k = arp_build(b, sizeof b, &r);
        bool ok = k && send_data_frame(q.sha, r.sha, ETHERTYPE_ARP, b, k);
        if (cnt_arp++ < 5)
            logf_(0, "bridge: ARP for 169.254.%u.%u answered%s", net.session.subnet, q.tpa & 0xFF, ok ? "" : " (FAILED)");
        return;
    }
    if (et != ETHERTYPE_IPV4) return;
    u32 s, d;
    u16 sp, dp;
    size_t off, len;
    IpStatus st = ipv4_udp_parse(p, n, &s, &d, &sp, &dp, &off, &len);
    if (st != IP_OK) {
        if (cnt_drop_air++ < 5)
            logf_(0, "bridge: IPv4 from the Switch not forwarded (%s)", st == IP_FRAGMENT ? "a fragment" :
                  st == IP_NOT_UDP ? "not UDP" : "malformed");
        return;
    }
    bool bcast = d == (ldn_base() | 0xFF) || d == 0xFFFFFFFFu || (d >> 28) == 0xE;
    int t = bcast ? -1 : node_of_ldn_ip(d);
    if (!bcast && (t < 0 || t == me)) {
        if (cnt_drop_air++ < 5) logf_(0, "bridge: datagram to unknown 169.254.%u.%u dropped", (d >> 8) & 255, d & 255);
        return;
    }
    u32 rip = bcast ? 0xFFFFFFFFu : net.info.nodes[t].ipv4;
    size_t plen;
    const u8 *payload = pia_readdress(p + off, len, s, room_ip_u32(), false, &plen);
    RoomProxy r = {.local_port = sp, .remote_port = dp, .protocol = room_protocol, .broadcast = bcast,
                   .data = payload, .size = (u32)plen};
    memcpy(r.local_ip, room_ip(), 4);
    r.remote_ip[0] = (u8)(rip >> 24); r.remote_ip[1] = (u8)(rip >> 16); r.remote_ip[2] = (u8)(rip >> 8); r.remote_ip[3] = (u8)rip;
    room_send_proxy(&r);
    cnt_to_room++;
    if (cnt_to_room <= 5)
        logf_(0, "bridge: air 169.254.%u.%u:%u -> room " IP_FMT ":%u%s, %zu bytes", (s >> 8) & 255, s & 255, sp,
              IP_ARG(r.remote_ip), dp, bcast ? " (broadcast)" : "", len);
}

/* who has the Switch's address, from the host (.1, our BSSID): group (key index 1) or unicast */
static void send_arp_probe(bool group) {
    int me = sta_node();
    if (me < 0) return;
    static const u8 bcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    Arp q = {.op = 1, .spa = ldn_ip(0), .tpa = ldn_ip(me)};
    memcpy(q.sha, radio.mac, 6);
    u8 b[64];
    size_t k = arp_build(b, sizeof b, &q);
    bool ok = k && send_data_frame(group ? bcast : sta.mac, radio.mac, ETHERTYPE_ARP, b, k);
    logf_(0, "bridge: ARP probe for 169.254.%u.%u sent as a %s frame%s", net.session.subnet, ldn_ip(me) & 0xFF,
          group ? "group" : "unicast", ok ? "" : ": send FAILED");
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
    /* data to us, or the joined Switch's group frames (no DS bits, to a broadcast / multicast address) */
    if (type == 2 && (!memcmp(a1, bssid, 6) || (sta.active && !memcmp(a2, sta.mac, 6) && (a1[0] & 1)))) {
        if (f[1] & 0x40) {                                  /* protected: CCMP with the network's key */
            cnt_protected++;
            if (net.have) handle_data(f, n, a2);
            return;
        }
        size_t h = (sub & 8) ? 26 : 24;                     /* QoS data has 2 more bytes */
        if (n >= h + 8 && f[h] == 0xAA && f[h + 1] == 0xAA && f[h + 6] == 0x88 && f[h + 7] == 0x8E) {
            cnt_eapol++;
            logf_(0, "air: EAPOL (WPA2 handshake) from " MAC_FMT ", %zu bytes", MAC_ARG(a2), n);
        } else if (radio.hw_crypto && net.have && n > h) {
            /* the S3 holds the key: its promiscuous receive may give the Switch's frames already decrypted */
            static unsigned plain;
            if (!plain++) logf_(0, "air: data from " MAC_FMT " arrives decrypted (the radio's key)", MAC_ARG(a2));
            handle_llc(f + h, n - h, a2);
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
                if (use_ap) {                               /* the AP answers */
                    if (first_time(seen_ours, &nseen_ours, a2))
                        logf_(0, "air: " MAC_FMT " asks for our network by name (the AP answers)", MAC_ARG(a2));
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
                  MAC_ARG(a2), n, use_ap ? " (the AP answers)" : ": the Switch tries to join (not handled yet)");
    } else if (sub == 13 && n >= 24 + 6 && f[24] == 0x7F && f[25] == 0x00 && f[26] == 0x22 && f[27] == 0xAA) {
        cnt_adv_other++;
        if (first_time(seen_adv, &nseen_adv, a2))
            logf_(1, "air: Nintendo action frames from " MAC_FMT " (another console)", MAC_ARG(a2));
    }
}

/* the S3's AP took or dropped a station (hostapd's own decisions show only in its log) */
static void on_station(const u8 mac[6], bool joined, u16 reason) {
    if (joined || !sta.active || memcmp(mac, sta.mac, 6)) return;
    char why[64];
    snprintf(why, sizeof why, "the S3's AP dropped it, reason %u", reason);
    station_leave(why);
}

/* ------------------------------------------------------------------------------------------------------------- */

int main(int argc, char **argv) {
    RoomConfig c = {.port = 24872, .nick = "beacon", .game_name = "Pokemon Violet", .game_id = 0x01008F6008C5E000ull};
    char host[256] = "";
    const char *radio_spec = NULL, *dirs[8];
    char iface_spec[48];
    bool s3_open = false;
    const char *pcap_path = NULL, *hostapd_log = "hostapd.log", *game = "scarlet_violet";
    int psk_mode = AP_PSK_HEX_PASSPHRASE;
    int ndirs = 0, channel = 6;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i], *v = i + 1 < argc ? argv[i + 1] : NULL;
        if (!strcmp(a, "--room") && v) {
            snprintf(host, sizeof host, "%s", v);
            char *colon = strrchr(host, ':');
            if (colon) { *colon = 0; c.port = (u16)atoi(colon + 1); }
            i++;
        } else if (!strcmp(a, "--iface") && v) {
            snprintf(iface_spec, sizeof iface_spec, "wifi:%s", v);
            radio_spec = iface_spec;
            i++;
        } else if (!strcmp(a, "--radio") && v) radio_spec = v, i++;
        else if (!strcmp(a, "--s3-open")) s3_open = true;
        else if (!strcmp(a, "--channel") && v) channel = atoi(v), i++;
        else if (!strcmp(a, "--nick") && v) c.nick = v, i++;
        else if (!strcmp(a, "--password") && v) c.password = v, i++;
        else if (!strcmp(a, "--files") && v && ndirs < 8) dirs[ndirs++] = v, i++;
        else if (!strcmp(a, "--log") && v) log_level = atoi(v), i++;
        else if (!strcmp(a, "--pcap") && v) pcap_path = v, i++;
        else if (!strcmp(a, "--no-ap")) use_ap = false;
        else if (!strcmp(a, "--psk-mode") && v) psk_mode = atoi(v), i++;
        else if (!strcmp(a, "--hostapd-log") && v) hostapd_log = v, i++;
        else if (!strcmp(a, "--game") && v) game = v, i++;
        else if (!strcmp(a, "--resp-flags") && v) resp_flags_fixed = atoi(v), i++;
        else if (!strcmp(a, "--bcast-mode") && v) bcast_mode = atoi(v), i++;
        else {
            fprintf(stderr, "usage: ldnbeacon --room host[:port] [--radio s3[:port] | wifi[:iface]] [--channel 1|6|11] "
                            "[--nick name] [--password pw] [--files dir]... [--pcap file] [--no-ap] [--psk-mode 0-2] [--hostapd-log file]\n"
                            "       [--s3-open] [--resp-flags n] [--bcast-mode 0-2] [--log 0-2]\n");
            return 2;
        }
    }
    if (!*host) { fprintf(stderr, "ldnbeacon: --room host[:port] is required\n"); return 2; }
    /* which code is running: run 11 ran run 10's object file (zip timestamps are local time, the laptop's clock UTC,
     * so the newer source looked older than the old build and make skipped it) */
    logf_(0, "ldnbeacon: stage 3 (room <-> air bridge, broadcast mode %d, ARP probes, high PN, the host's security parameter, Pia re-addressed, Pia messages rewritten), compiled " __DATE__
             " " __TIME__, bcast_mode);
    if (channel != 1 && channel != 6 && channel != 11) { fprintf(stderr, "ldnbeacon: channel 1, 6 or 11\n"); return 2; }
    random_bytes(own_device_id, sizeof own_device_id);
    /* our CCMP packet numbers start above any the Switch uses (it starts each join at a random 48-bit value, e.g.
     * 0x2e06668ad953, 0xeb78780e228a): a receiver with one replay counter per key would drop lower ones */
    random_bytes(&tx_pn, 4);
    tx_pn = 0xF00000000000ull | (tx_pn & 0xFFFFFFFFull);
    if (psk_mode < 0 || psk_mode >= AP_PSK_MODES) { fprintf(stderr, "ldnbeacon: --psk-mode 0-%d\n", AP_PSK_MODES - 1); return 2; }
    if (!ldn_keys_load(&keys, dirs, ndirs, use_ap ? game : NULL)) return 1;
    c.host = host;

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
#ifdef SIGHUP
    signal(SIGHUP, on_signal);
#endif
    RoomHandlers h = {.ldn = on_ldn, .proxy = on_proxy};
    char err[256];
    if (!room_join(&c, &h, err, sizeof err)) { logf_(0, "ldnbeacon: %s", err); return 1; }
    channel_now = (u8)channel;
    if (!radio_open(&radio, radio_spec, (u8)channel, pcap_path != NULL, err, sizeof err)) {
        logf_(0, "ldnbeacon: %s", err);
        room_leave();
        return 1;
    }

    radio.on_station = on_station;
    int ldn_fd = -1;
#ifdef __linux__
    if (use_ap && radio.kind == RADIO_WIFI) {                     /* the LDN authentication, after WPA2 */
        ldn_fd = radio_eth_socket(&radio, 0x88B7);
        if (ldn_fd < 0) logf_(0, "ldnbeacon: no packet socket for EtherType 0x88B7");
    }
#endif
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

#ifdef __linux__
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
#endif

        t = now_ms();
        if (t - last_scan >= 500) {                         /* ask the room who hosts */
            last_scan = t;
            RoomLdn p = {.type = LDN_SCAN, .broadcast = true};
            memcpy(p.local_ip, room_ip(), 4);
            room_send_ldn(&p);
        }
        if (sta.active && sta.in_room && probes_sent < 2 && t - answered_ms >= (probes_sent ? 1500u : 500u)) {
            send_arp_probe(probes_sent == 0);
            probes_sent++;
        }
        /* hosts that don't send DestroyNetwork (Eden, older recomps): five missed scans */
        if (net.have && t - net.seen_ms > 2500) {
            logf_(0, "network of " IP_FMT " gone (no answer for 2.5 s): off the air", IP_ARG(net.host_ip));
            sta.active = sta.in_room = false;
            net.have = false;
        }
        if (net.have != on_air) {
            on_air = net.have;
            if (on_air) logf_(0, "on the air: %s every 100 ms on channel %d", use_ap ? "advertisement (beacons: the AP)" :
                              "beacon + advertisement", channel);
        }
        if (use_ap) {                                       /* one AP per room session */
            bool same = net.have && !memcmp(ap_session, net.session.session_id, 16);
            bool ap_up = radio_ap_running(&radio);          /* hostapd exited: logged; not retried for this session */
            if (ap_up && (!net.have || !same)) { radio_ap_stop(&radio); ap_up = false; }
            if (net.have && !same) {
                memcpy(ap_session, net.session.session_id, 16);
                ap_tried = false;
            }
            if (net.have && !ap_up && !ap_tried) {
                ap_tried = true;
                ApConfig ac = {.channel = (u8)channel, .psk_mode = psk_mode, .open = s3_open, .log_path = hostapd_log};
                host_ssid(&net.session, ac.ssid);
                ldn_data_key(&keys, net.session.server_random, ac.data_key);
                /* the host's room MAC as our BSSID (S3): its Pia constant id is then the same on both sides; the
                 * raid's game data carries it inside the game's own compressed data, which the rewrite cannot reach
                 * (S3 run 11) */
                memcpy(ac.bssid, net.info.nodes[0].mac, 6);
                if (!radio_ap_start(&radio, &ac, err, sizeof err))
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
                 * already seen (run 9: the Switch left 510 ms after joining, as if it never saw itself listed). One
                 * more, as a real Switch host does (join run 7: 6e88ab97 -> 6e88ab98 when a station joined); a
                 * random one could go backwards */
                {
                    static LdnAdvert last_adv;
                    static bool have_last;
                    LdnAdvert cmp = a;
                    cmp.nonce = 0;
                    if (!have_last || memcmp(&cmp, &last_adv, sizeof cmp)) {
                        if (have_last) {
                            net.session.nonce++;
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
                     "authentications answered, %u other), %u Nintendo action frames from others; station %s; bridge: %u to the "
                     "air, %u to the room, %u ARP answered, dropped %u from the air / %u from the room; Pia %u "
                     "re-addressed (%u with addresses inside replaced, %u not parsed), %u not authenticated",
                  on_air ? "on the air" : "no network in the room yet", sent, send_fail, cnt_echo_beacon, cnt_echo_adv, cnt_rx, cnt_probe, cnt_probe_nn, cnt_probe_ours, cnt_probe_resp, cnt_auth,
                  cnt_assoc, cnt_eapol, cnt_protected, cnt_decrypted, cnt_undecryptable, cnt_auth_answered,
                  cnt_other_data, cnt_adv_other, !sta.active ? "none" : sta.in_room ? "joined" : "authenticated",
                  cnt_to_air, cnt_to_room, cnt_arp, cnt_drop_air, cnt_drop_room, cnt_pia_ok, cnt_pia_rewritten,
                  cnt_pia_noparse, cnt_pia_bad);
            if (send_fail && !sent) logf_(0, "ldnbeacon: the card sends nothing (injection refused?)");
            if (pcap) fflush(pcap);
        }
    }
    if (pcap) fclose(pcap);
    radio_ap_stop(&radio);
#ifdef __linux__
    if (ldn_fd >= 0) close(ldn_fd);
#endif
    radio_close(&radio);
    room_leave();
    return rc;
}
