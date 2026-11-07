/* roomtest: joins a room and shows its local-play traffic, to check the room side of the beacon on any machine.
 *   roomtest --room host[:port] [--nick name] [--password pw] [--scan] [--log 0-2]
 * --scan broadcasts an LDN Scan every 2 s, as a console searching for networks would, and prints each network an
 * access point in the room answers with (a recomp or Eden instance hosting local play). Every LDN message is
 * printed; proxy datagrams are counted (log 2: each one). */
#include "ldn.h"
#include "room.h"
#include <stdlib.h>
#include <signal.h>

static volatile sig_atomic_t quit;
static void on_sigint(int s) { (void)s; quit = 1; }

static void print_network(const LdnNetworkInfo *n) {
    char ssid[34];
    u8 len = n->ssid.length < 33 ? n->ssid.length : 32;
    memcpy(ssid, n->ssid.raw, len);
    ssid[len] = 0;
    logf_(0, "  network: local communication id %016llx, scene %u, channel %d, ssid \"%s\", %u of %u nodes, "
             "advertise %u bytes, security mode %u, accept policy %u",
          (unsigned long long)n->id.intent.local_communication_id, n->id.intent.scene_id, n->channel, ssid,
          n->node_count, n->node_count_max, n->advertise_size, n->security_mode, n->accept_policy);
    for (int i = 0; i < LDN_NODES; i++) {
        const LdnNodeInfo *d = &n->nodes[i];
        if (!d->is_connected) continue;
        char name[34];
        memcpy(name, d->user_name, 33);
        name[33] = 0;
        logf_(0, "    node %d: \"%s\" %u.%u.%u.%u mac %02x:%02x:%02x:%02x:%02x:%02x version %d", d->node_id, name,
              d->ipv4 >> 24, (d->ipv4 >> 16) & 255, (d->ipv4 >> 8) & 255, d->ipv4 & 255, d->mac[0], d->mac[1],
              d->mac[2], d->mac[3], d->mac[4], d->mac[5], d->local_communication_version);
    }
}

static void on_ldn(const RoomLdn *p, void *ud) {
    (void)ud;
    logf_(0, "ldn %s from " IP_FMT " to %s" IP_FMT ", %u bytes", ldn_type_name(p->type), IP_ARG(p->local_ip),
          p->broadcast ? "everyone, " : "", IP_ARG(p->remote_ip), p->size);
    if ((p->type == LDN_SCAN_RESP || p->type == LDN_SYNC_NETWORK) && p->size >= sizeof(LdnNetworkInfo)) {
        LdnNetworkInfo n;
        memcpy(&n, p->data, sizeof n);
        print_network(&n);
    } else if ((p->type == LDN_CONNECT || p->type == LDN_DISCONNECT) && p->size >= sizeof(LdnNodeInfo)) {
        LdnNodeInfo d;
        memcpy(&d, p->data, sizeof d);
        char name[34];
        memcpy(name, d.user_name, 33);
        name[33] = 0;
        logf_(0, "  node \"%s\" version %d", name, d.local_communication_version);
    }
}

static void on_proxy(const RoomProxy *p, void *ud) {
    (void)ud;
    logf_(2, "proxy " IP_FMT ":%u -> %s" IP_FMT ":%u, protocol %u, %u bytes", IP_ARG(p->local_ip), p->local_port,
          p->broadcast ? "everyone, " : "", IP_ARG(p->remote_ip), p->remote_port, p->protocol, p->size);
}

int main(int argc, char **argv) {
    RoomConfig c = {.port = 24872, .nick = "roomtest", .game_name = "Pokemon Violet", .game_id = 0x01008F6008C5E000ull};
    char host[256] = "";
    bool scan = false;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i], *v = i + 1 < argc ? argv[i + 1] : NULL;
        if (!strcmp(a, "--room") && v) {
            snprintf(host, sizeof host, "%s", v);
            char *colon = strrchr(host, ':');
            if (colon) { *colon = 0; c.port = (u16)atoi(colon + 1); }
            i++;
        } else if (!strcmp(a, "--nick") && v) c.nick = v, i++;
        else if (!strcmp(a, "--password") && v) c.password = v, i++;
        else if (!strcmp(a, "--log") && v) log_level = atoi(v), i++;
        else if (!strcmp(a, "--scan")) scan = true;
        else {
            fprintf(stderr, "usage: roomtest --room host[:port] [--nick name] [--password pw] [--scan] [--log 0-2]\n");
            return 2;
        }
    }
    if (!*host) { fprintf(stderr, "roomtest: --room host[:port] is required\n"); return 2; }
    c.host = host;
    signal(SIGINT, on_sigint);
    RoomHandlers h = {.ldn = on_ldn, .proxy = on_proxy};
    char err[256];
    if (!room_join(&c, &h, err, sizeof err)) { logf_(0, "roomtest: %s", err); return 1; }
    u64 last_scan = 0, last_log = now_ms();
    while (!quit) {
        if (!room_service(20)) { logf_(0, "roomtest: left the room"); return 1; }
        u64 t = now_ms();
        if (scan && t - last_scan >= 2000) {
            last_scan = t;
            RoomLdn p = {.type = LDN_SCAN, .broadcast = true};
            memcpy(p.local_ip, room_ip(), 4);
            room_send_ldn(&p);
        }
        if (t - last_log >= 3000) { last_log = t; room_log_traffic(); }
    }
    room_leave();
    return 0;
}
