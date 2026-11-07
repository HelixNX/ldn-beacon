/* The LDN advertisement: the vendor action frame a host broadcasts every 100 ms (see CLAUDE.md, "Protocol").
 * adv_decode / adv_encode work on the action frame body, from its 0x7F category byte. */
#ifndef ADV_H
#define ADV_H

#include "ldn.h"
#include "ldnkeys.h"

enum {
    ADV_HEADER = 12,            /* 7f, OUI 00 22 aa, protocol 4, pad, type 0x0101, 2 zero, 2 pad */
    ADV_SESSION_INFO = 32,
    ADV_DATA_SIZE = 0x500,
    ADV_PARTICIPANTS = 8,
    ADV_FRAME_SIZE = ADV_HEADER + ADV_SESSION_INFO + 8 + 32 + ADV_DATA_SIZE,    /* 0x54C, AES-CTR / plain */
};
enum { ADV_PLAIN = 1, ADV_AES_CTR = 2, ADV_AES_GCM = 3 };

typedef struct LdnSessionInfo {
    u64 local_communication_id;
    u16 game_mode;              /* NetworkInfo's scene id */
    u8 ssid[16];                /* the session id; the network's SSID is its 32 hex digits */
} LdnSessionInfo;

typedef struct LdnAdvParticipant {
    u32 ipv4;                   /* host order */
    u8 mac[6];
    u8 connected, platform;     /* platform 0 Switch, 1 Switch 2 */
    char user_name[33];
    u16 app_version;
} LdnAdvParticipant;

typedef struct LdnAdvert {
    LdnSessionInfo session;
    u8 version, encryption;
    u32 nonce;
    u8 server_random[16];
    u16 security_level;
    u8 accept_policy;
    u8 channel, band;           /* on the wire: u16 channel | band << 10 (band 2 = 2.4 GHz) */
    u8 max_participants, participant_count;
    LdnAdvParticipant participants[ADV_PARTICIPANTS];
    u16 app_data_size;
    u8 app_data[LDN_ADVERTISE_MAX];
    u8 auth_token[8];
} LdnAdvert;

typedef enum {
    ADV_OK, ADV_NOT_ADVERT, ADV_TRUNCATED, ADV_UNSUPPORTED, ADV_BAD_HASH, ADV_BAD_FIELD
} AdvStatus;

const char *adv_status_name(AdvStatus s);
AdvStatus adv_decode(const LdnKeys *k, const u8 *frame, size_t len, LdnAdvert *out);
/* Encrypts with a->encryption (plain or AES-CTR) and a->nonce. Returns the frame's size, 0 on error. */
size_t adv_encode(const LdnKeys *k, const LdnAdvert *a, u8 *frame, size_t cap);

/* host_mac: the advertisement's sender (the network's BSSID) */
void adv_to_network_info(const LdnAdvert *a, const u8 host_mac[6], LdnNetworkInfo *n);
void adv_from_network_info(const LdnNetworkInfo *n, LdnAdvert *a);

#endif
