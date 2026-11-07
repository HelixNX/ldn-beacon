/* CCMP (IEEE 802.11 AES-CCM, 8-byte MIC) on whole 802.11 data frames, in software: the Switch encrypts its data
 * frames with a key it derives itself, right after association, without a WPA2 4-way handshake (run 7,
 * CLAUDE.md), so no key is ever installed in the driver and the beacon does the cipher. */
#ifndef CCMP_H
#define CCMP_H

#include "common.h"

/* frame: an 802.11 data frame with the protected bit, the CCMP header after the MAC header and the MIC at the end
 * (no FCS). On success out gets the plaintext body (from the LLC header on), *out_len its size, *pn the packet
 * number. False if not a CCMP frame or the MIC does not match. */
bool ccmp_decrypt(const u8 key[16], const u8 *frame, size_t len, u8 *out, size_t *out_len, u64 *pn);

/* hdr: a data frame's MAC header (hdr_len bytes; the protected bit gets set); body: the plaintext from the LLC header
 * on; key_id: 0 for unicast, 1 for group frames (LDN uses the same key at both indices). Writes header + CCMP header
 * + ciphertext + MIC to out (cap bytes), returns the size or 0. */
size_t ccmp_encrypt(const u8 key[16], const u8 *hdr, size_t hdr_len, const u8 *body, size_t body_len, u64 pn,
                    int key_id, u8 *out, size_t cap);

/* the MAC header's length for a data frame (QoS, four addresses), 0 if not a data frame */
size_t ccmp_hdr_len(const u8 *frame, size_t len);

#endif
