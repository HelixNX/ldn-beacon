#include "s3proto.h"
#include <string.h>

uint16_t s3_crc16(const uint8_t *p, size_t n, uint16_t crc) {
    for (size_t i = 0; i < n; i++) {
        crc ^= (uint16_t)(p[i] << 8);
        for (int b = 0; b < 8; b++) crc = (uint16_t)(crc & 0x8000 ? crc << 1 ^ 0x1021 : crc << 1);
    }
    return crc;
}

/* COBS over the logical bytes type | payload | crc (lo, hi), without copying them together first */
size_t s3_encode(uint8_t type, const void *payload, size_t n, uint8_t *out, size_t cap) {
    if (n > S3_MAX_PAYLOAD) return 0;
    const uint8_t *pl = (const uint8_t *)payload;
    uint16_t crc = s3_crc16(&type, 1, 0xFFFF);
    crc = s3_crc16(pl, n, crc);
    size_t total = 1 + n + 2, o = 1, code_at = 0;
    uint8_t code = 1;
    if (cap < total + total / 254 + 2) return 0;
    for (size_t i = 0; i < total; i++) {
        uint8_t c = i == 0 ? type : i <= n ? pl[i - 1] : i == n + 1 ? (uint8_t)crc : (uint8_t)(crc >> 8);
        if (c) {
            out[o++] = c;
            code++;
        }
        if (!c || code == 0xFF) {
            out[code_at] = code;
            code_at = o++;
            code = 1;
        }
    }
    out[code_at] = code;
    out[o++] = 0;
    return o;
}

/* decodes d->buf (one COBS frame without its zero) in place */
static bool finish(S3Dec *d, uint8_t *type, const uint8_t **payload, size_t *len) {
    size_t i = 0, o = 0;
    uint8_t *b = d->buf;
    while (i < d->n) {
        uint8_t code = b[i++];
        if (!code || i + code - 1 > d->n) return false;
        for (int k = 1; k < code; k++) b[o++] = b[i++];
        if (code != 0xFF && i < d->n) b[o++] = 0;
    }
    if (o < 3) return false;
    uint16_t crc = (uint16_t)(b[o - 2] | b[o - 1] << 8);
    if (s3_crc16(b, o - 2, 0xFFFF) != crc) return false;
    *type = b[0];
    *payload = b + 1;
    *len = o - 3;
    return true;
}

size_t s3_decode(S3Dec *d, const uint8_t *in, size_t n, uint8_t *type, const uint8_t **payload, size_t *len) {
    *len = SIZE_MAX;
    for (size_t i = 0; i < n; i++) {
        if (in[i]) {
            if (d->n < sizeof d->buf) d->buf[d->n++] = in[i];
            else d->overflow = true;
            continue;
        }
        bool ok = d->n && !d->overflow && finish(d, type, payload, len);
        if (d->n && !ok) d->bad++;
        d->n = 0;
        d->overflow = false;
        if (ok) return i + 1;
    }
    return n;
}
