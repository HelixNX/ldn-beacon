/* Local wireless (LDN) as the room carries it: the structures inside the room's LDN packets, in the layout Eden and
 * nxrecomp's ldn:u (runtime/services/ldn_net.c) put on the wire (the console's own structs, little-endian, sent as
 * raw bytes). The room relays them unchanged:
 *   Scan (broadcast, no data)        an access point answers ScanResp with its NetworkInfo
 *   Connect (to the host, NodeInfo)  the host takes the station into a free node and sends everyone SyncNetwork
 *   SyncNetwork (NetworkInfo)        a station's copy of the network; the first one completes its Connect
 *   Disconnect (NodeInfo), DestroyNetwork (no data)
 * Addresses are the room's fake ones: NodeInfo holds them as host-order u32s, the room's packets as network-order
 * bytes. MAC addresses are 02 00 followed by the fake address. */
#ifndef LDN_H
#define LDN_H

#include "common.h"

enum { LDN_SCAN, LDN_SCAN_RESP, LDN_CONNECT, LDN_SYNC_NETWORK, LDN_DISCONNECT, LDN_DESTROY_NETWORK };
enum { LDN_NODES = 8, LDN_ADVERTISE_MAX = 384 };

#pragma pack(push, 1)
typedef struct LdnIntentId { u64 local_communication_id; u8 r0[2]; u16 scene_id; u8 r1[4]; } LdnIntentId;
typedef struct LdnSessionId { u64 high, low; } LdnSessionId;
typedef struct LdnNetworkId { LdnIntentId intent; LdnSessionId session; } LdnNetworkId;
typedef struct LdnSsid { u8 length; char raw[33]; } LdnSsid;
typedef struct LdnNodeInfo {
    u32 ipv4;                               /* host order */
    u8 mac[6];
    s8 node_id;
    u8 is_connected;
    char user_name[33];
    u8 r0;
    s16 local_communication_version;
    u8 r1[16];
} LdnNodeInfo;
typedef struct LdnNetworkInfo {
    LdnNetworkId id;
    /* CommonNetworkInfo */
    u8 bssid[6];
    LdnSsid ssid;
    s16 channel;
    s8 link_level;
    u8 network_type;
    u8 r0[4];
    /* LdnNetworkInfo */
    u8 security_parameter[16];
    u16 security_mode;
    u8 accept_policy, has_action_frame;
    u8 r1[2];
    u8 node_count_max, node_count;
    LdnNodeInfo nodes[LDN_NODES];
    u8 r2[2];
    u16 advertise_size;
    u8 advertise[LDN_ADVERTISE_MAX];
    u8 r3[0x8c];
    u64 random_authentication_id;
} LdnNetworkInfo;
#pragma pack(pop)

_Static_assert(sizeof(LdnNodeInfo) == 0x40, "LdnNodeInfo");
_Static_assert(sizeof(LdnNetworkInfo) == 0x480, "LdnNetworkInfo");

static inline const char *ldn_type_name(u8 t) {
    static const char *n[] = {"Scan", "ScanResp", "Connect", "SyncNetwork", "Disconnect", "DestroyNetwork"};
    return t < 6 ? n[t] : "?";
}

#endif
