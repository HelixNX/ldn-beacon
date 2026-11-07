#include "ldnauth.h"
#include "crypto.h"
#include "rd.h"

/* header: OUI (3), packet type (2), pad (1); then version, size & 0xFF, status, 0 request / 1 response, size >> 8,
 * pad (3); session info (32), server random (16), client random (16); then the payload of `size` bytes */
enum { HDR = 0x0E, PAYLOAD = HDR + 0x40, REQ_CHALLENGE = 0x64, RESP_CHALLENGE = 0x84 };

bool ldn_auth_parse(const LdnKeys *k, const u8 *p, size_t n, LdnAuthRequest *r) {
    memset(r, 0, sizeof *r);
    Rd d = rd_init(p, n);
    u8 oui[3];
    rd_copy(&d, oui, 3);
    u16 type = rd_be16(&d);
    rd_skip(&d, 1);
    r->version = rd_u8(&d);
    u8 size_lo = rd_u8(&d), status = rd_u8(&d), is_resp = rd_u8(&d), size_hi = rd_u8(&d);
    rd_skip(&d, 3);
    rd_copy(&d, r->session_info, 32);
    rd_copy(&d, r->server_random, 16);
    rd_copy(&d, r->client_random, 16);
    if (d.err || oui[0] != 0x00 || oui[1] != 0x22 || oui[2] != 0xAA || type != LDN_PKT_AUTH || is_resp || status)
        return false;
    size_t size = (size_t)size_lo | (size_t)size_hi << 8;
    if (rd_left(&d) < size || size < 0x23) return false;
    rd_copy(&d, r->user_name, 32);
    r->user_name[32] = 0;
    r->app_version = rd_be16(&d);
    r->platform = rd_u8(&d);
    if (size >= REQ_CHALLENGE + 0x300) {
        const u8 *c = p + PAYLOAD + REQ_CHALLENGE;
        r->has_challenge = true;
        u8 mac[32];
        hmac_sha256(k->challenge_hmac, 32, c + 0x30, 0x300 - 0x30, mac);
        r->challenge_ok = ct_equal(mac, c + 4, 32);
        r->p = c[0x32];
        r->q = c[0x33];
        r->flags = c[0x34];
        memcpy(r->token, c + 0x38, 8);
        memcpy(r->nonce, c + 0x40, 8);
        memcpy(r->device_id, c + 0x48, 8);
        memcpy(r->unknown, c + 0x50, 16);
    }
    return !d.err;
}

size_t ldn_auth_response(const LdnKeys *k, const LdnAuthRequest *r, u8 status, const u8 own_device_id[8], u32 flags,
                         u8 *out, size_t cap) {
    size_t size = r->has_challenge ? RESP_CHALLENGE + 0x100 : 1;
    if (cap < PAYLOAD + size) return 0;
    memset(out, 0, PAYLOAD + size);
    Wr w = wr_init(out, cap);
    static const u8 oui[3] = {0x00, 0x22, 0xAA};
    wr_bytes(&w, oui, 3);
    wr_be16(&w, LDN_PKT_AUTH);
    wr_zero(&w, 1);
    wr_u8(&w, r->version);
    wr_u8(&w, (u8)size);
    wr_u8(&w, status);
    wr_u8(&w, 1);                                           /* response */
    wr_u8(&w, (u8)(size >> 8));
    wr_zero(&w, 3);
    wr_bytes(&w, r->session_info, 32);
    wr_bytes(&w, r->server_random, 16);
    wr_bytes(&w, r->client_random, 16);
    u8 *pl = out + PAYLOAD;
    pl[0] = 0;                                              /* platform: Switch (the host as a recomp presents it) */
    if (r->has_challenge) {
        u8 *c = pl + RESP_CHALLENGE;
        c[0x34] = (u8)(flags >> 24);                        /* 4 bytes, big-endian */
        c[0x35] = (u8)(flags >> 16);
        c[0x36] = (u8)(flags >> 8);
        c[0x37] = (u8)flags;
        memcpy(c + 0x38, r->nonce, 8);
        memcpy(c + 0x40, r->device_id, 8);
        memcpy(c + 0x48, own_device_id, 8);
        memcpy(c + 0x50, r->unknown, 16);
        hmac_sha256(k->challenge_hmac, 32, c + 0x30, 0x100 - 0x30, c + 4);
    }
    return w.err ? 0 : PAYLOAD + size;
}

size_t ldn_auth_request(const LdnKeys *k, u8 version, const u8 session_info[32], const u8 server_random[16],
                        const u8 client_random[16], const char *user_name, u16 app_version, u8 platform,
                        const u8 token[8], const u8 nonce[8], const u8 device_id[8], u8 *out, size_t cap) {
    size_t size = REQ_CHALLENGE + 0x300;
    if (cap < PAYLOAD + size) return 0;
    memset(out, 0, PAYLOAD + size);
    Wr w = wr_init(out, cap);
    static const u8 oui[3] = {0x00, 0x22, 0xAA};
    wr_bytes(&w, oui, 3);
    wr_be16(&w, LDN_PKT_AUTH);
    wr_zero(&w, 1);
    wr_u8(&w, version);
    wr_u8(&w, (u8)size);
    wr_u8(&w, 0);                                           /* status */
    wr_u8(&w, 0);                                           /* request */
    wr_u8(&w, (u8)(size >> 8));
    wr_zero(&w, 3);
    wr_bytes(&w, session_info, 32);
    wr_bytes(&w, server_random, 16);
    wr_bytes(&w, client_random, 16);
    u8 *pl = out + PAYLOAD;
    size_t nl = strlen(user_name);
    memcpy(pl, user_name, nl > 32 ? 32 : nl);
    pl[0x20] = (u8)(app_version >> 8);                      /* big-endian */
    pl[0x21] = (u8)app_version;
    pl[0x22] = platform;
    u8 *c = pl + REQ_CHALLENGE;                             /* 0x300: u32 0, HMAC, 12 pad, then the body from 0x30 */
    c[0x34] = 0;                                            /* flags; 0x32 / 0x33 (parameter counts) 0 */
    memcpy(c + 0x38, token, 8);
    memcpy(c + 0x40, nonce, 8);
    memcpy(c + 0x48, device_id, 8);
    hmac_sha256(k->challenge_hmac, 32, c + 0x30, 0x300 - 0x30, c + 4);
    return w.err ? 0 : PAYLOAD + size;
}

int ldn_auth_response_status(const u8 *p, size_t n, u8 client_random_out[16]) {
    if (n < PAYLOAD || p[0] != 0x00 || p[1] != 0x22 || p[2] != 0xAA || (p[3] << 8 | p[4]) != LDN_PKT_AUTH || p[9] != 1)
        return -1;
    if (client_random_out) memcpy(client_random_out, p + HDR + 0x30, 16);
    return p[8];
}

size_t ldn_disconnect(u8 reason, u8 *out, size_t cap) {
    if (cap < 0x26) return 0;
    memset(out, 0, 0x26);
    out[1] = 0x22;
    out[2] = 0xAA;
    out[3] = (u8)(LDN_PKT_DISCONNECT >> 8);
    out[4] = (u8)LDN_PKT_DISCONNECT;
    out[6] = reason;
    return 0x26;
}
