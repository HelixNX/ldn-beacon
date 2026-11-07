#include "adv.h"
#include "crypto.h"
#include "rd.h"

const char *adv_status_name(AdvStatus s) {
    static const char *n[] = {"ok", "not an advertisement", "truncated", "unsupported (GCM or another size)",
                              "hash mismatch (wrong key?)", "bad field"};
    return (unsigned)s < sizeof n / sizeof *n ? n[s] : "?";
}

/* hash (32) + data, decrypted in place with AES-CTR when the frame says so */
typedef struct { u8 hash[32]; u8 data[ADV_DATA_SIZE]; } AdvBody;

static void adv_crypt(const LdnKeys *k, const u8 session_info[ADV_SESSION_INFO], u32 nonce, AdvBody *b) {
    u8 key[16], iv[16] = {0};
    ldn_derive(k->adv_kek, session_info, ADV_SESSION_INFO, key);
    iv[0] = (u8)(nonce >> 24); iv[1] = (u8)(nonce >> 16); iv[2] = (u8)(nonce >> 8); iv[3] = (u8)nonce;
    Aes128 a;
    aes128_init(&a, key);
    aes128_ctr(&a, iv, (u8 *)b, sizeof *b);
}

/* SHA-256 over the payload (session info, the 8 header bytes, a zeroed hash, the data) */
static void adv_hash(const u8 pre[ADV_SESSION_INFO + 8], const u8 *data, u8 out[32]) {
    static const u8 zero[32];
    Sha256 s;
    sha256_init(&s);
    sha256_update(&s, pre, ADV_SESSION_INFO + 8);
    sha256_update(&s, zero, 32);
    sha256_update(&s, data, ADV_DATA_SIZE);
    sha256_final(&s, out);
}

AdvStatus adv_decode(const LdnKeys *k, const u8 *frame, size_t len, LdnAdvert *a) {
    memset(a, 0, sizeof *a);
    Rd r = rd_init(frame, len);
    u8 cat = rd_u8(&r);
    u8 oui[3];
    rd_copy(&r, oui, 3);
    u8 proto = rd_u8(&r);
    rd_skip(&r, 1);
    u16 type = rd_be16(&r);
    rd_skip(&r, 4);
    if (r.err) return ADV_NOT_ADVERT;
    if (cat != 0x7F || oui[0] != 0x00 || oui[1] != 0x22 || oui[2] != 0xAA || proto != 4 || type != 0x0101)
        return ADV_NOT_ADVERT;

    const u8 *pre = frame + r.off;                  /* session info + version .. nonce, hashed as sent */
    a->session.local_communication_id = rd_be64(&r);
    rd_skip(&r, 2);
    a->session.game_mode = rd_be16(&r);
    rd_skip(&r, 4);
    rd_copy(&r, a->session.ssid, 16);
    a->version = rd_u8(&r);
    a->encryption = rd_u8(&r);
    u16 size = rd_be16(&r);
    a->nonce = rd_be32(&r);
    if (r.err) return ADV_TRUNCATED;
    if (a->encryption == ADV_AES_GCM || size != ADV_DATA_SIZE) return ADV_UNSUPPORTED;
    if (a->encryption != ADV_PLAIN && a->encryption != ADV_AES_CTR) return ADV_BAD_FIELD;

    AdvBody b;
    rd_copy(&r, &b, sizeof b);
    if (r.err) return ADV_TRUNCATED;
    if (a->encryption == ADV_AES_CTR) adv_crypt(k, pre, a->nonce, &b);
    u8 h[32];
    adv_hash(pre, b.data, h);
    if (!ct_equal(h, b.hash, 32)) return ADV_BAD_HASH;

    Rd d = rd_init(b.data, sizeof b.data);
    rd_copy(&d, a->server_random, 16);
    a->security_level = rd_be16(&d);
    a->accept_policy = rd_u8(&d);
    rd_skip(&d, 1);
    u16 ch = rd_be16(&d);
    a->channel = (u8)(ch & 0x3FF);
    a->band = (u8)(ch >> 10);
    a->max_participants = rd_u8(&d);
    a->participant_count = rd_u8(&d);
    for (int i = 0; i < ADV_PARTICIPANTS; i++) {
        LdnAdvParticipant *p = &a->participants[i];
        p->ipv4 = rd_be32(&d);
        rd_copy(&d, p->mac, 6);
        p->connected = rd_u8(&d);
        p->platform = rd_u8(&d);
        rd_copy(&d, p->user_name, 32);
        p->user_name[32] = 0;
        p->app_version = rd_be16(&d);
        rd_skip(&d, 10);
    }
    rd_skip(&d, 2);
    a->app_data_size = rd_be16(&d);
    rd_copy(&d, a->app_data, LDN_ADVERTISE_MAX);
    d.off = 0x4F8;
    rd_copy(&d, a->auth_token, 8);
    if (d.err) return ADV_TRUNCATED;
    if (a->app_data_size > LDN_ADVERTISE_MAX || a->max_participants > ADV_PARTICIPANTS ||
        a->participant_count > a->max_participants)
        return ADV_BAD_FIELD;
    return ADV_OK;
}

size_t adv_encode(const LdnKeys *k, const LdnAdvert *a, u8 *frame, size_t cap) {
    if (a->encryption != ADV_PLAIN && a->encryption != ADV_AES_CTR) return 0;
    if (a->app_data_size > LDN_ADVERTISE_MAX) return 0;
    Wr w = wr_init(frame, cap);
    static const u8 hdr[ADV_HEADER] = {0x7F, 0x00, 0x22, 0xAA, 4, 0, 0x01, 0x01, 0, 0, 0, 0};
    wr_bytes(&w, hdr, sizeof hdr);
    size_t pre_off = w.off;
    wr_be64(&w, a->session.local_communication_id);
    wr_zero(&w, 2);
    wr_be16(&w, a->session.game_mode);
    wr_zero(&w, 4);
    wr_bytes(&w, a->session.ssid, 16);
    wr_u8(&w, a->version);
    wr_u8(&w, a->encryption);
    wr_be16(&w, ADV_DATA_SIZE);
    wr_be32(&w, a->nonce);
    size_t body_off = w.off;
    (void)wr_take(&w, sizeof(AdvBody));
    if (w.err) return 0;

    AdvBody b;
    memset(&b, 0, sizeof b);
    Wr d = wr_init(b.data, sizeof b.data);
    wr_bytes(&d, a->server_random, 16);
    wr_be16(&d, a->security_level);
    wr_u8(&d, a->accept_policy);
    wr_zero(&d, 1);
    wr_be16(&d, (u16)(a->channel | a->band << 10));
    wr_u8(&d, a->max_participants);
    wr_u8(&d, a->participant_count);
    for (int i = 0; i < ADV_PARTICIPANTS; i++) {
        const LdnAdvParticipant *p = &a->participants[i];
        wr_be32(&d, p->ipv4);
        wr_bytes(&d, p->mac, 6);
        wr_u8(&d, p->connected);
        wr_u8(&d, p->platform);
        char name[32] = {0};
        strncpy(name, p->user_name, sizeof name);
        wr_bytes(&d, name, 32);
        wr_be16(&d, p->app_version);
        wr_zero(&d, 10);
    }
    wr_zero(&d, 2);
    wr_be16(&d, a->app_data_size);
    wr_bytes(&d, a->app_data, LDN_ADVERTISE_MAX);
    d.off = 0x4F8;
    wr_bytes(&d, a->auth_token, 8);
    if (d.err) return 0;

    adv_hash(frame + pre_off, b.data, b.hash);
    if (a->encryption == ADV_AES_CTR) adv_crypt(k, frame + pre_off, a->nonce, &b);
    memcpy(frame + body_off, &b, sizeof b);
    return w.off;
}

void adv_to_network_info(const LdnAdvert *a, const u8 host_mac[6], LdnNetworkInfo *n) {
    static const char hex[] = "0123456789abcdef";
    memset(n, 0, sizeof *n);
    n->id.intent.local_communication_id = a->session.local_communication_id;
    n->id.intent.scene_id = a->session.game_mode;
    memcpy(&n->id.session, a->session.ssid, 16);
    memcpy(n->bssid, host_mac, 6);
    n->ssid.length = 32;
    for (int i = 0; i < 16; i++) {
        n->ssid.raw[i * 2] = hex[a->session.ssid[i] >> 4];
        n->ssid.raw[i * 2 + 1] = hex[a->session.ssid[i] & 15];
    }
    n->channel = a->channel;
    n->link_level = 3;
    n->network_type = 2;                            /* LDN */
    memcpy(n->security_parameter, a->server_random, 16);   /* assumed: the server random (kinnay) */
    n->security_mode = a->security_level;
    n->accept_policy = a->accept_policy;
    n->has_action_frame = 1;
    n->node_count_max = a->max_participants;
    n->node_count = a->participant_count;
    for (int i = 0; i < LDN_NODES; i++) {
        const LdnAdvParticipant *p = &a->participants[i];
        LdnNodeInfo *d = &n->nodes[i];
        d->ipv4 = p->ipv4;
        memcpy(d->mac, p->mac, 6);
        d->node_id = (s8)i;
        d->is_connected = p->connected;
        memcpy(d->user_name, p->user_name, 33);
        d->local_communication_version = (s16)p->app_version;
    }
    n->advertise_size = a->app_data_size;
    memcpy(n->advertise, a->app_data, LDN_ADVERTISE_MAX);
    memcpy(&n->random_authentication_id, a->auth_token, 8);  /* raw bytes; byte order unverified */
}

void adv_from_network_info(const LdnNetworkInfo *n, LdnAdvert *a) {
    memset(a, 0, sizeof *a);
    a->session.local_communication_id = n->id.intent.local_communication_id;
    a->session.game_mode = n->id.intent.scene_id;
    memcpy(a->session.ssid, &n->id.session, 16);
    a->version = 4;
    a->encryption = ADV_AES_CTR;
    memcpy(a->server_random, n->security_parameter, 16);
    a->security_level = n->security_mode;
    a->accept_policy = n->accept_policy;
    a->channel = (u8)n->channel;
    a->band = 2;
    a->max_participants = n->node_count_max > ADV_PARTICIPANTS ? ADV_PARTICIPANTS : n->node_count_max;
    a->participant_count = n->node_count > a->max_participants ? a->max_participants : n->node_count;
    for (int i = 0; i < LDN_NODES; i++) {
        const LdnNodeInfo *d = &n->nodes[i];
        LdnAdvParticipant *p = &a->participants[i];
        p->ipv4 = d->ipv4;
        memcpy(p->mac, d->mac, 6);
        p->connected = d->is_connected;
        memcpy(p->user_name, d->user_name, 32);
        p->user_name[32] = 0;
        p->app_version = (u16)d->local_communication_version;
    }
    a->app_data_size = n->advertise_size > LDN_ADVERTISE_MAX ? LDN_ADVERTISE_MAX : n->advertise_size;
    memcpy(a->app_data, n->advertise, LDN_ADVERTISE_MAX);
    memcpy(a->auth_token, &n->random_authentication_id, 8);
}
