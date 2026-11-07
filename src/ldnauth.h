/* LDN authentication (EtherType 0x88B7, packet type 0x0102): the request a joining console sends right after
 * associating (encrypted with the network's data key, ccmp.c) and the host's response. Layout from kinnay's
 * LDN-Protocol page (behaviour only), checked against a real Switch's requests (run 7, CLAUDE.md). The frames start
 * at the OUI (after the LLC/SNAP header). */
#ifndef LDNAUTH_H
#define LDNAUTH_H

#include "ldnkeys.h"

enum {
    LDN_ETHERTYPE = 0x88B7,
    LDN_PKT_AUTH = 0x0102,
    LDN_PKT_DISCONNECT = 0x0103,
    LDN_AUTH_REQ_SIZE = 0x0E + 0x40 + 0x64 + 0x300,         /* header, session info + randoms, request, challenge */
    LDN_AUTH_RESP_SIZE = 0x0E + 0x40 + 0x84 + 0x100,
};
enum { LDN_AUTH_OK = 0, LDN_AUTH_DENIED = 1, LDN_AUTH_MALFORMED = 2, LDN_AUTH_BAD_VERSION = 4,
       LDN_AUTH_UNEXPECTED = 5, LDN_AUTH_BAD_CHALLENGE = 6 };
enum { LDN_DISCONNECT_DESTROYED = 3, LDN_DISCONNECT_DESTROYED_FORCE = 4, LDN_DISCONNECT_REJECTED = 5 };

typedef struct LdnAuthRequest {
    u8 version;
    u8 session_info[32];        /* as sent (little-endian fields) */
    u8 server_random[16], client_random[16];
    char user_name[33];
    u16 app_version;
    u8 platform;
    bool has_challenge, challenge_ok;   /* challenge_ok: its HMAC verified */
    u8 p, q, flags;
    u8 token[8], nonce[8], device_id[8], unknown[16];
} LdnAuthRequest;

/* p: from the OUI on. False if not an authentication request (r->version etc. still filled as far as read). */
bool ldn_auth_parse(const LdnKeys *k, const u8 *p, size_t n, LdnAuthRequest *r);

/* The host's response to r with status; own_device_id: the host's (any 8 bytes, the same for the whole run);
 * flags: the challenge response's 4-byte flags at 0x34 (meaning unknown; run 8 tried the request's 2 and the Switch
 * left 500 ms later). Returns the size (from the OUI on), 0 if cap is too small. */
size_t ldn_auth_response(const LdnKeys *k, const LdnAuthRequest *r, u8 status, const u8 own_device_id[8], u32 flags,
                         u8 *out, size_t cap);

/* the host's disconnect frame (from the OUI on), 0x26 bytes */
size_t ldn_disconnect(u8 reason, u8 *out, size_t cap);

#endif
