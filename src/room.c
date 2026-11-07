/* The room client (room.h). Adapted from nxrecomp's runtime/net/room.c (ours), made single-threaded and portable:
 * the beacon's own loop calls room_service().
 * Messages (type byte first):
 *   JoinRequest   nickname, preferred fake ip (ff ff ff ff: any), network version, password, token ("": anonymous)
 *   SetGameInfo   name, title id, version
 *   RoomInformation  name, description, slots, port, preferred game name, host username, then the members
 *                    (nickname, fake ip, game name, game id, game version, username, display name, avatar url)
 *   JoinSuccess[AsMod]  our fake ip
 *   LdnPacket     type, local ip, remote ip, broadcast, data
 *   ProxyPacket   local (domain, ip, port), remote (domain, ip, port), protocol, broadcast, data (zstd frame) */
#include "room.h"
#include <enet/enet.h>
#include <stdlib.h>
#include <zstd.h>

enum {
    ID_JOIN_REQUEST = 1, ID_JOIN_SUCCESS, ID_ROOM_INFORMATION, ID_SET_GAME_INFO, ID_PROXY_PACKET, ID_LDN_PACKET,
    ID_CHAT_MESSAGE, ID_NAME_COLLISION, ID_IP_COLLISION, ID_VERSION_MISMATCH, ID_WRONG_PASSWORD, ID_CLOSE_ROOM,
    ID_ROOM_IS_FULL, ID_STATUS_MESSAGE, ID_HOST_KICKED, ID_HOST_BANNED,
    ID_MOD_KICK, ID_MOD_BAN, ID_MOD_UNBAN, ID_MOD_GET_BAN_LIST, ID_MOD_BAN_LIST_RESPONSE, ID_MOD_PERMISSION_DENIED,
    ID_MOD_NO_SUCH_USER, ID_JOIN_SUCCESS_AS_MOD,
};
enum { STATUS_MEMBER_JOIN = 1, STATUS_MEMBER_LEAVE, STATUS_MEMBER_KICKED, STATUS_MEMBER_BANNED, STATUS_UNBANNED };
enum { NET_VERSION = 1, MAX_MEMBERS = 16, CONNECT_TIMEOUT_MS = 5000 };
#define DOMAIN_INET 1                       /* Network::Domain::INET */

/* ---------------------------------------------------------------------------------------------- packets */
typedef struct Pkt { u8 *p; u32 n, cap; } Pkt;

static void w_bytes(Pkt *k, const void *d, u32 n) {
    if (k->n + n > k->cap) {
        k->cap = (k->n + n) * 2 + 64;
        k->p = realloc(k->p, k->cap);
    }
    memcpy(k->p + k->n, d, n);
    k->n += n;
}
static void w_u8(Pkt *k, u8 v) { w_bytes(k, &v, 1); }
static void w_u16(Pkt *k, u16 v) { u8 b[2] = {(u8)(v >> 8), (u8)v}; w_bytes(k, b, 2); }
static void w_u32(Pkt *k, u32 v) { u8 b[4] = {(u8)(v >> 24), (u8)(v >> 16), (u8)(v >> 8), (u8)v}; w_bytes(k, b, 4); }
static void w_u64(Pkt *k, u64 v) { w_u32(k, (u32)(v >> 32)); w_u32(k, (u32)v); }
static void w_vec(Pkt *k, const void *d, u32 n) { w_u32(k, n); w_bytes(k, d, n); }
static void w_str(Pkt *k, const char *s) { w_vec(k, s, (u32)strlen(s)); }

typedef struct Rd { const u8 *p; u32 n, pos; bool ok; } Rd;

static bool r_take(Rd *r, void *d, u32 n) {
    if (!r->ok || r->pos + n > r->n) { r->ok = false; if (d) memset(d, 0, n); return false; }
    if (d) memcpy(d, r->p + r->pos, n);
    r->pos += n;
    return true;
}
static u8 r_u8(Rd *r) { u8 v; r_take(r, &v, 1); return v; }
static u16 r_u16(Rd *r) { u8 b[2]; r_take(r, b, 2); return (u16)(b[0] << 8 | b[1]); }
static u32 r_u32(Rd *r) { u8 b[4]; r_take(r, b, 4); return (u32)b[0] << 24 | (u32)b[1] << 16 | (u32)b[2] << 8 | b[3]; }
static u64 r_u64(Rd *r) { u64 hi = r_u32(r); return hi << 32 | r_u32(r); }
static void r_str(Rd *r, char *out, size_t n) {
    u32 len = r_u32(r);
    if (!r->ok || r->pos + len > r->n) { r->ok = false; if (n) out[0] = 0; return; }
    size_t c = len < n - 1 ? len : n - 1;
    memcpy(out, r->p + r->pos, c);
    out[c] = 0;
    r->pos += len;
}
static const u8 *r_vec(Rd *r, u32 *len) {
    *len = r_u32(r);
    const u8 *d = r->p + r->pos;
    if (!r_take(r, NULL, *len)) { *len = 0; return NULL; }
    return d;
}

/* ---------------------------------------------------------------------------------------------- state */
static ENetHost *host;
static ENetPeer *server;
static bool joined;
static u8 fake_ip[4] = {255, 255, 255, 255};
static char room_title[256];
static RoomHandlers handlers;
static RoomMember members[MAX_MEMBERS];
static int nmembers;
static unsigned long rx_count[32], tx_count[32];

static void send_pkt(Pkt *k) {
    if (k->n) tx_count[k->p[0] & 31]++;
    if (server) enet_peer_send(server, 0, enet_packet_create(k->p, k->n, ENET_PACKET_FLAG_RELIABLE));
    free(k->p);
    *k = (Pkt){0};                          /* the Pkt can be filled again */
}

const u8 *room_ip(void) { return fake_ip; }
const RoomMember *room_members(int *n) { *n = nmembers; return members; }

/* ---------------------------------------------------------------------------------------------- receiving */
static void on_room_information(Rd *r) {
    char desc[1024], game[128], host_user[64], s[256];
    r_str(r, room_title, sizeof room_title);
    r_str(r, desc, sizeof desc);
    u32 slots = r_u32(r);
    r_u16(r);                                           /* port */
    r_str(r, game, sizeof game);
    r_str(r, host_user, sizeof host_user);
    u32 n = r_u32(r);
    nmembers = 0;
    for (u32 i = 0; i < n && r->ok; i++) {
        RoomMember m = {0};
        char gver[64];
        r_str(r, m.nick, sizeof m.nick);
        r_take(r, m.ip, 4);
        r_str(r, m.game, sizeof m.game);
        m.game_id = r_u64(r);
        r_str(r, gver, sizeof gver);
        r_str(r, s, sizeof s);                          /* username */
        r_str(r, s, sizeof s);                          /* display name */
        r_str(r, s, sizeof s);                          /* avatar url */
        if (r->ok && nmembers < MAX_MEMBERS) members[nmembers++] = m;
    }
    logf_(1, "room: \"%s\", %d of %u members", room_title, nmembers, slots);
    for (int i = 0; i < nmembers; i++)
        logf_(1, "room:   %s (" IP_FMT ") %s %016llx", members[i].nick, IP_ARG(members[i].ip), members[i].game,
              (unsigned long long)members[i].game_id);
    if (handlers.members) handlers.members(members, nmembers, handlers.ud);
}

static void on_proxy(Rd *r) {
    RoomProxy p = {0};
    r_u8(r);
    r_take(r, p.local_ip, 4);
    p.local_port = r_u16(r);
    r_u8(r);
    r_take(r, p.remote_ip, 4);
    p.remote_port = r_u16(r);
    p.protocol = r_u8(r);
    p.broadcast = r_u8(r) != 0;
    u32 clen;
    const u8 *c = r_vec(r, &clen);
    if (!r->ok || !handlers.proxy) return;
    unsigned long long n = ZSTD_getFrameContentSize(c, clen);
    if (n == ZSTD_CONTENTSIZE_ERROR || n == ZSTD_CONTENTSIZE_UNKNOWN || n > 0x100000) {
        logf_(1, "room: proxy packet with a bad zstd frame (%u bytes)", clen);
        return;
    }
    u8 *d = malloc(n ? (size_t)n : 1);
    size_t got = ZSTD_decompress(d, (size_t)n, c, clen);
    if (ZSTD_isError(got) || got != n) logf_(1, "room: proxy packet that does not decompress (%u bytes)", clen);
    else {
        p.data = d;
        p.size = (u32)n;
        handlers.proxy(&p, handlers.ud);
    }
    free(d);
}

static void on_ldn(Rd *r) {
    RoomLdn p = {0};
    p.type = r_u8(r);
    r_take(r, p.local_ip, 4);
    r_take(r, p.remote_ip, 4);
    p.broadcast = r_u8(r) != 0;
    p.data = r_vec(r, &p.size);
    if (r->ok && handlers.ldn) handlers.ldn(&p, handlers.ud);
}

static void on_chat(Rd *r) {
    char nick[64], user[64], msg[600];
    r_str(r, nick, sizeof nick);
    r_str(r, user, sizeof user);
    r_str(r, msg, sizeof msg);
    logf_(0, "room chat: <%s> %s", nick, msg);
}

static void on_status(Rd *r) {
    static const char *what[] = {"?", "joined", "left", "was kicked", "was banned", "was unbanned"};
    u8 type = r_u8(r);
    char nick[64], user[64];
    r_str(r, nick, sizeof nick);
    r_str(r, user, sizeof user);
    logf_(0, "room: %s %s", nick, what[type <= STATUS_UNBANNED ? type : 0]);
}

static const char *join_error(u8 id) {
    switch (id) {
    case ID_NAME_COLLISION: return "that nickname is already in use in this room, or is not valid there";
    case ID_IP_COLLISION: return "the room gave our address to someone else";
    case ID_VERSION_MISMATCH: return "the room runs a different version of the multiplayer protocol";
    case ID_WRONG_PASSWORD: return "wrong password";
    case ID_ROOM_IS_FULL: return "the room is full";
    case ID_HOST_BANNED: return "banned from this room";
    case ID_HOST_KICKED: return "kicked from this room";
    case ID_CLOSE_ROOM: return "the room was closed";
    default: return NULL;
    }
}

/* one received packet; returns the error it reports, if any */
static const char *handle_packet(const u8 *data, size_t n) {
    if (!n) return NULL;
    rx_count[data[0] & 31]++;
    Rd r = {data, (u32)n, 1, true};
    switch (data[0]) {
    case ID_PROXY_PACKET: on_proxy(&r); break;
    case ID_LDN_PACKET: on_ldn(&r); break;
    case ID_CHAT_MESSAGE: on_chat(&r); break;
    case ID_STATUS_MESSAGE: on_status(&r); break;
    case ID_ROOM_INFORMATION: on_room_information(&r); break;
    case ID_JOIN_SUCCESS:
    case ID_JOIN_SUCCESS_AS_MOD:
        r_take(&r, fake_ip, 4);
        joined = true;
        break;
    default: return join_error(data[0]);
    }
    return NULL;
}

void room_log_traffic(void) {
    static unsigned long last;
    unsigned long sum = rx_count[ID_PROXY_PACKET] + rx_count[ID_LDN_PACKET] + tx_count[ID_PROXY_PACKET] +
                        tx_count[ID_LDN_PACKET];
    if (sum == last) return;
    last = sum;
    logf_(1, "room traffic: received %lu proxy, %lu ldn; sent %lu proxy, %lu ldn; round trip to the server %u ms",
          rx_count[ID_PROXY_PACKET], rx_count[ID_LDN_PACKET], tx_count[ID_PROXY_PACKET], tx_count[ID_LDN_PACKET],
          server ? server->roundTripTime : 0);
}

bool room_service(int timeout_ms) {
    if (!host || !server) return false;
    ENetEvent ev;
    int got = enet_host_service(host, &ev, (enet_uint32)(timeout_ms > 0 ? timeout_ms : 0));
    while (got > 0) {
        if (ev.type == ENET_EVENT_TYPE_RECEIVE) {
            const char *err = handle_packet(ev.packet->data, ev.packet->dataLength);
            enet_packet_destroy(ev.packet);
            if (err) { logf_(0, "room: %s", err); joined = false; }
        } else if (ev.type == ENET_EVENT_TYPE_DISCONNECT) {
            logf_(0, "room: lost the connection to the room server");
            server = NULL;
            joined = false;
            return false;
        }
        got = enet_host_check_events(host, &ev);
    }
    enet_host_flush(host);
    return joined;
}

/* ---------------------------------------------------------------------------------------------- joining */
static void drop_connection(void) {
    if (server) {
        enet_peer_disconnect(server, 0);
        ENetEvent ev;
        while (enet_host_service(host, &ev, 500) > 0) {
            if (ev.type == ENET_EVENT_TYPE_RECEIVE) enet_packet_destroy(ev.packet);
            else if (ev.type == ENET_EVENT_TYPE_DISCONNECT) { server = NULL; break; }
        }
        if (server) enet_peer_reset(server);
        server = NULL;
    }
    if (host) enet_host_destroy(host);
    host = NULL;
}

bool room_join(const RoomConfig *c, const RoomHandlers *h, char *err, size_t errn) {
    static bool enet_ready;
    if (!enet_ready) {
        if (enet_initialize() != 0) { snprintf(err, errn, "ENet could not start"); return false; }
        enet_ready = true;
    }
    room_leave();
    handlers = h ? *h : (RoomHandlers){0};
    host = enet_host_create(NULL, 1, 1, 0, 0);
    if (!host) { snprintf(err, errn, "could not create a network socket"); return false; }
    ENetAddress addr = {0};
    if (enet_address_set_host(&addr, c->host) != 0) {
        snprintf(err, errn, "could not resolve \"%s\"", c->host);
        drop_connection();
        return false;
    }
    addr.port = c->port ? c->port : 24872;
    server = enet_host_connect(host, &addr, 1, 0);
    ENetEvent ev;
    if (!server || enet_host_service(host, &ev, CONNECT_TIMEOUT_MS) <= 0 || ev.type != ENET_EVENT_TYPE_CONNECT) {
        snprintf(err, errn, "could not connect to %s:%u (no answer)", c->host, addr.port);
        drop_connection();
        return false;
    }
    Pkt k = {0};
    w_u8(&k, ID_JOIN_REQUEST);
    w_str(&k, c->nick);
    w_bytes(&k, (const u8[]){255, 255, 255, 255}, 4);
    w_u32(&k, NET_VERSION);
    w_str(&k, c->password ? c->password : "");
    w_str(&k, "");
    send_pkt(&k);
    w_u8(&k, ID_SET_GAME_INFO);
    w_str(&k, c->game_name ? c->game_name : "");
    w_u64(&k, c->game_id);
    w_str(&k, c->game_version ? c->game_version : "");
    send_pkt(&k);
    enet_host_flush(host);
    /* the answer: room information, then JoinSuccess or an error */
    u64 start = now_ms();
    const char *jerr = NULL;
    while (!joined && !jerr && now_ms() - start < CONNECT_TIMEOUT_MS) {
        int got = enet_host_service(host, &ev, 50);
        if (got > 0 && ev.type == ENET_EVENT_TYPE_RECEIVE) {
            jerr = handle_packet(ev.packet->data, ev.packet->dataLength);
            enet_packet_destroy(ev.packet);
        } else if (got > 0 && ev.type == ENET_EVENT_TYPE_DISCONNECT) {
            server = NULL;
            jerr = "the room server closed the connection";
        }
    }
    if (!joined) {
        snprintf(err, errn, "%s", jerr ? jerr : "the room did not answer the join request");
        drop_connection();
        return false;
    }
    logf_(0, "room: joined \"%s\" at %s:%u as %s, address " IP_FMT, room_title, c->host, addr.port, c->nick,
          IP_ARG(fake_ip));
    return true;
}

void room_leave(void) {
    drop_connection();
    joined = false;
    nmembers = 0;
    memset(fake_ip, 255, 4);
}

/* ---------------------------------------------------------------------------------------------- sending */
void room_send_ldn(const RoomLdn *p) {
    if (!joined) return;
    Pkt k = {0};
    w_u8(&k, ID_LDN_PACKET);
    w_u8(&k, p->type);
    w_bytes(&k, p->local_ip, 4);
    w_bytes(&k, p->remote_ip, 4);
    w_u8(&k, p->broadcast);
    w_vec(&k, p->data, p->size);
    send_pkt(&k);
}

void room_send_proxy(const RoomProxy *p) {
    if (!joined) return;
    size_t bound = ZSTD_compressBound(p->size);
    u8 *c = malloc(bound);
    size_t cn = ZSTD_compress(c, bound, p->data, p->size, ZSTD_CLEVEL_DEFAULT);
    if (ZSTD_isError(cn)) { free(c); return; }
    Pkt k = {0};
    w_u8(&k, ID_PROXY_PACKET);
    w_u8(&k, DOMAIN_INET);
    w_bytes(&k, p->local_ip, 4);
    w_u16(&k, p->local_port);
    w_u8(&k, DOMAIN_INET);
    w_bytes(&k, p->remote_ip, 4);
    w_u16(&k, p->remote_port);
    w_u8(&k, p->protocol);
    w_u8(&k, p->broadcast);
    w_vec(&k, c, (u32)cn);
    free(c);
    send_pkt(&k);
}
