/* Pia 6.x packets in LDN mode (kinnay's NintendoClients wiki: PIA-Protocol, Pia-Types, read 2026-11-07; behaviour
 * only). Header (version 11, Pia 6.16-6.23): magic 32 ab 98 64, u8 0x80 encrypted | version, u16 destination /
 * source variable id, u16 packet id, u8 footer size, 8-byte nonce, first 8 bytes of the AES-GCM tag (28 bytes); then
 * the messages (encrypted, padded with 0xFF to 16), then the footer (plaintext). In LDN mode the GCM nonce is
 * XOR(network id, the source's IP) + the header's nonce, the network id is CRC-32(ssid[1..15]) and the session key
 * AES(game key, ssid). So a packet is bound to its sender's address and the network's SSID: crossing between the room
 * (192.168.1.x, the recomp's SSID) and the air (169.254.X.Y, the session id) it must be decrypted and re-encrypted.
 * The details the wiki leaves open (AES direction, byte orders, AAD, the SSID's form) are PiaVariant, settled
 * against captures by piatest. */
#ifndef PIA_H
#define PIA_H

#include "crypto.h"

enum { PIA_HDR = 0x1C, PIA_TAG = 8 };

u32 crc32_ieee(const u8 *p, size_t n);

/* AES-GCM with a 12-byte nonce; the tag truncated to tag_len bytes. decrypt checks the tag first, then decrypts in
 * place; returns false on a mismatch (data unchanged). */
void gcm_encrypt(const Aes128 *a, const u8 nonce[12], const u8 *aad, size_t aad_len, u8 *data, size_t n, u8 *tag,
                 size_t tag_len);
bool gcm_decrypt(const Aes128 *a, const u8 nonce[12], const u8 *aad, size_t aad_len, u8 *data, size_t n,
                 const u8 *tag, size_t tag_len);

typedef struct PiaVariant {
    u8 key_decrypt;         /* session key: 0 AES-encrypt the SSID under the game key, 1 decrypt */
    u8 crc_le;              /* network id's bytes: 0 big-endian, 1 little-endian, XORed with the IP's bytes */
    u8 ip_le;               /* the IP's bytes: 0 network order, 1 reversed */
    u8 aad;                 /* 0 none, 1 header up to the nonce (0xC), 2 header up to the tag (0x14) */
} PiaVariant;

typedef struct PiaNet {
    Aes128 key;
    u8 session_key[16];
    u32 network_id;
} PiaNet;

/* ssid: the 16 bytes Pia takes as the network's SSID */
void pia_net_init(PiaNet *p, const u8 game_key[16], const u8 ssid[16], const PiaVariant *v);
bool pia_is_packet(const u8 *p, size_t n);          /* magic, version byte with encryption, room for header */
/* in place on a whole packet (header .. footer); src_ip host order. decrypt: false if the tag does not match. */
bool pia_decrypt(const PiaNet *net, const PiaVariant *v, u32 src_ip, u8 *p, size_t n);
void pia_encrypt(const PiaNet *net, const PiaVariant *v, u32 src_ip, u8 *p, size_t n);

#endif
