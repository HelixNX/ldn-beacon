/* The room client: one ENet peer, the room server (the protocol Citra, yuzu and Eden rooms speak, network
 * version 1; ../room/room_server.c is ours). Single-threaded: the caller runs room_service() in its
 * own loop, and the handlers run inside it.
 * Encoding: every message is an ENet reliable packet on channel 0, type byte first; integers big-endian, strings and
 * vectors with a u32 length in front, IPv4 addresses 4 raw bytes. Members get fake addresses (192.168.1.x); LDN and
 * proxy packets name members by them, and the server relays them to the member with the remote address, or to
 * everyone else when the broadcast flag is set. Proxy payloads are zstd frames. */
#ifndef ROOM_H
#define ROOM_H

#include "common.h"

typedef struct RoomLdn {
    u8 type;                                /* LDN_* (ldn.h) */
    u8 local_ip[4], remote_ip[4];           /* sender, receiver */
    bool broadcast;
    const u8 *data;
    u32 size;
} RoomLdn;

/* a datagram on the room's network; ports in host order */
typedef struct RoomProxy {
    u8 local_ip[4], remote_ip[4];           /* sender, receiver */
    u16 local_port, remote_port;
    u8 protocol;                            /* Network::Protocol: UDP is 3 (older numbering) or 4 (newer Eden) */
    bool broadcast;
    const u8 *data;                         /* uncompressed */
    u32 size;
} RoomProxy;

typedef struct RoomMember {
    char nick[64], game[128];
    u8 ip[4];
    u64 game_id;
} RoomMember;

typedef struct RoomHandlers {
    void (*ldn)(const RoomLdn *p, void *ud);
    void (*proxy)(const RoomProxy *p, void *ud);
    void (*members)(const RoomMember *m, int n, void *ud);  /* the member list changed (us included) */
    void *ud;
} RoomHandlers;

typedef struct RoomConfig {
    const char *host;
    u16 port;                               /* 24872 by default */
    const char *nick, *password;
    const char *game_name, *game_version;
    u64 game_id;
} RoomConfig;

/* connects and joins (blocking, up to ~10 s); false with a message in err */
bool room_join(const RoomConfig *c, const RoomHandlers *h, char *err, size_t errn);
/* handles what arrived and sends what is queued, waiting up to timeout_ms for traffic; false once disconnected */
bool room_service(int timeout_ms);
void room_leave(void);

void room_send_ldn(const RoomLdn *p);
void room_send_proxy(const RoomProxy *p);

const u8 *room_ip(void);                    /* our fake address */
const RoomMember *room_members(int *n);
void room_log_traffic(void);                /* a summary line (log level 1) */

#endif
