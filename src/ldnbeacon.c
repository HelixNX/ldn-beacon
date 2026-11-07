/* ldnbeacon (Linux): joins a room, finds the network a member hosts (LDN Scan -> ScanResp) and hosts it on the air
 * as a Switch would: a beacon and the LDN advertisement every 100 ms. Stage 1: a real Switch searching for local
 * play (e.g. a raid's link code) should list the room's network; joining it is not handled yet. What the radio hears
 * that concerns us (probe requests, authentication / association to our BSSID, other consoles' advertisements) is
 * logged, as a preview of stage 2.
 *   sudo ./ldnbeacon --room host[:port] [--iface wlan0] [--channel 1|6|11] [--nick name] [--password pw]
 *                    [-k keyfile]... [--log 0-2]
 * Key files default to ../keys/prod.keys and ../keys/ldn.txt (run from ldn-beacon/). Ctrl+C gives Wi-Fi back. */
#include "frames.h"
#include "radio.h"
#include "room.h"
#include <signal.h>
#include <stdlib.h>

static volatile sig_atomic_t quit;
static void on_signal(int s) { (void)s; quit = 1; }

static struct {
    bool have;
    u8 host_ip[4];                  /* the room member hosting it */
    LdnNetworkInfo info;
    u64 seen_ms;
    HostSession session;
} net;

static void on_ldn(const RoomLdn *p, void *ud) {
    (void)ud;
    if (p->type != LDN_SCAN_RESP || p->size < sizeof(LdnNetworkInfo)) {
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
    if (host_session_update(&net.session, &n))
        logf_(0, "network of " IP_FMT ": local communication id %016llx, scene %u, %u of %u nodes, %u bytes of "
                 "advertise data; on the air as 169.254.%u.0/24",
              IP_ARG(p->local_ip), (unsigned long long)n.id.intent.local_communication_id, n.id.intent.scene_id,
              n.node_count, n.node_count_max, n.advertise_size, net.session.subnet);
    else if (changed)
        logf_(1, "network of " IP_FMT " changed: %u of %u nodes", IP_ARG(p->local_ip), n.node_count, n.node_count_max);
}

/* --- what the radio hears ---------------------------------------------------------------------------------- */

typedef struct { u8 mac[6]; } Mac;
static Mac seen_probe[64], seen_adv[64];
static int nseen_probe, nseen_adv;
static unsigned cnt_probe, cnt_auth, cnt_assoc, cnt_adv_other, cnt_rx;

static bool first_time(Mac *list, int *n, const u8 *mac) {
    for (int i = 0; i < *n; i++)
        if (!memcmp(list[i].mac, mac, 6)) return false;
    if (*n < 64) memcpy(list[(*n)++].mac, mac, 6);
    return true;
}

#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_ARG(m) (m)[0], (m)[1], (m)[2], (m)[3], (m)[4], (m)[5]

static void on_frame(const u8 *f, size_t n, const u8 bssid[6]) {
    cnt_rx++;
    if (n < 24) return;
    u8 type = (f[0] >> 2) & 3, sub = f[0] >> 4;
    const u8 *a1 = f + 4, *a2 = f + 10;
    if (!memcmp(a2, bssid, 6)) return;                      /* our own, echoed */
    if (type != 0) return;                                  /* management only */
    if (sub == 4) {                                         /* probe request */
        cnt_probe++;
        u8 ssid_len = n > 25 && f[24] == 0 ? f[25] : 0xFF;
        if (first_time(seen_probe, &nseen_probe, a2))
            logf_(1, "air: probe requests from " MAC_FMT " (SSID %s%u bytes)", MAC_ARG(a2),
                  ssid_len == 0xFF ? "? " : "", ssid_len == 0xFF ? 0 : ssid_len);
    } else if ((sub == 11 || sub == 0 || sub == 2) && !memcmp(a1, bssid, 6)) {
        /* authentication / (re)association request to us: stage 2's start */
        if (sub == 11) cnt_auth++; else cnt_assoc++;
        logf_(0, "air: %s from " MAC_FMT " to us (%zu bytes): the Switch tries to join (not handled yet)",
              sub == 11 ? "authentication" : "association request", MAC_ARG(a2), n);
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
        else {
            fprintf(stderr, "usage: sudo ./ldnbeacon --room host[:port] [--iface wlan0] [--channel 1|6|11] "
                            "[--nick name] [--password pw] [-k keyfile]... [--log 0-2]\n");
            return 2;
        }
    }
    if (!*host) { fprintf(stderr, "ldnbeacon: --room host[:port] is required\n"); return 2; }
    if (channel != 1 && channel != 6 && channel != 11) { fprintf(stderr, "ldnbeacon: channel 1, 6 or 11\n"); return 2; }
    if (!nkeys) { keyfiles[0] = "../keys/prod.keys"; keyfiles[1] = "../keys/ldn.txt"; nkeys = 2; }
    LdnKeys keys;
    if (!ldn_keys_load(&keys, keyfiles, nkeys, NULL)) return 1;
    c.host = host;

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGHUP, on_signal);
    RoomHandlers h = {.ldn = on_ldn};
    char err[256];
    if (!room_join(&c, &h, err, sizeof err)) { logf_(0, "ldnbeacon: %s", err); return 1; }
    Radio radio;
    if (!radio_open(&radio, iface, (u8)channel, err, sizeof err)) {
        logf_(0, "ldnbeacon: %s", err);
        room_leave();
        return 1;
    }

    u64 start_us = now_us(), next_tick = now_ms(), last_scan = 0, last_status = now_ms();
    u16 seq = 0;
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
        while ((n = radio_recv(&radio, rx, sizeof rx, &f))) on_frame(f, n, radio.mac);

        t = now_ms();
        if (t - last_scan >= 1000) {                        /* ask the room who hosts */
            last_scan = t;
            RoomLdn p = {.type = LDN_SCAN, .broadcast = true};
            memcpy(p.local_ip, room_ip(), 4);
            room_send_ldn(&p);
        }
        if (net.have && t - net.seen_ms > 5000) {
            logf_(0, "network of " IP_FMT " gone (no answer for 5 s): off the air", IP_ARG(net.host_ip));
            net.have = false;
        }
        if (net.have != on_air) {
            on_air = net.have;
            if (on_air) logf_(0, "on the air: beacon + advertisement every 100 ms on channel %d", channel);
        }
        if (t >= next_tick) {
            next_tick += 100;
            if (t > next_tick + 1000) next_tick = t + 100;  /* fell far behind: do not burst */
            if (net.have) {
                LdnAdvert a;
                host_advert(&net.session, &net.info, radio.mac, (u8)channel, &a);
                size_t k = frame_beacon(fr, sizeof fr, radio.mac, seq++ & 0xFFF, now_us() - start_us, (u8)channel);
                if (k && radio_send(&radio, fr, k)) sent++; else send_fail++;
                k = frame_advert(fr, sizeof fr, &keys, &a, radio.mac, seq++ & 0xFFF);
                if (k && radio_send(&radio, fr, k)) sent++; else send_fail++;
            }
        }
        if (t - last_status >= 10000) {
            last_status = t;
            logf_(1, "status: %s, %u frames sent (%u failed); heard %u frames: %u probe requests, %u authentications "
                     "and %u association requests to us, %u Nintendo action frames from others",
                  on_air ? "on the air" : "no network in the room yet", sent, send_fail, cnt_rx, cnt_probe, cnt_auth,
                  cnt_assoc, cnt_adv_other);
            if (send_fail && !sent) logf_(0, "ldnbeacon: the card sends nothing (injection refused?)");
        }
    }
    radio_close(&radio);
    room_leave();
    return rc;
}
