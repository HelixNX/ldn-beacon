/* s3prototest: the S3 link's framing (s3proto.c): round trips of every size class (zero runs, 254-byte blocks),
 * several messages in one buffer fed in odd pieces, garbage and a damaged message in between. Any OS. */
#include "s3proto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint8_t wire[64 * S3_MAX_WIRE];

int main(void) {
    int bad = 0;
    /* the check value of CRC-16/CCITT-FALSE */
    uint16_t c = s3_crc16((const uint8_t *)"123456789", 9, 0xFFFF);
    printf("crc16 check: %04x %s\n", c, c == 0x29B1 ? "ok" : "BAD");
    bad += c != 0x29B1;

    static const size_t sizes[] = {0, 1, 2, 250, 251, 252, 253, 254, 255, 508, 1000, 1500, S3_MAX_PAYLOAD};
    enum { N = sizeof sizes / sizeof *sizes };
    static uint8_t msgs[N][S3_MAX_PAYLOAD];
    size_t w = 0;
    srand(7);
    static const char garbage[] = "ESP-ROM:esp32s3-20210327\r\nrst:0x15 (USB_UART_CHIP_RESET)";
    memcpy(wire, garbage, sizeof garbage - 1);
    w += sizeof garbage - 1;
    wire[w++] = 0;
    for (int m = 0; m < N; m++) {
        for (size_t i = 0; i < sizes[m]; i++) msgs[m][i] = (uint8_t)(m & 1 ? (rand() % 3 ? 0 : rand()) : rand());
        size_t k = s3_encode((uint8_t)(0x80 + m), msgs[m], sizes[m], wire + w, sizeof wire - w);
        if (!k) { printf("encode %zu failed\n", sizes[m]); return 1; }
        for (size_t i = 0; i + 1 < k; i++)
            if (!wire[w + i]) { printf("encode %zu: zero inside\n", sizes[m]); bad++; break; }
        w += k;
        if (m == 3) {                                       /* a damaged copy: must be dropped */
            size_t k2 = s3_encode(0x7F, msgs[m], sizes[m], wire + w, sizeof wire - w);
            wire[w + 5] ^= 0x20;
            if (!wire[w + 5]) wire[w + 5] = 1;
            w += k2;
        }
    }
    S3Dec d = {0};
    int got = 0;
    size_t pos = 0, step = 1;
    while (pos < w) {
        size_t take = step < w - pos ? step : w - pos;
        step = step * 7 % 997 + 1;
        size_t off = 0;
        while (off < take) {
            uint8_t type;
            const uint8_t *p;
            size_t len;
            off += s3_decode(&d, wire + pos + off, take - off, &type, &p, &len);
            if (len == SIZE_MAX) continue;
            if (type == 0x7F) { printf("damaged message accepted\n"); bad++; continue; }
            int m = type - 0x80;
            if (m != got || len != sizes[m] || memcmp(p, msgs[m], len)) {
                printf("message %d: type %02x, %zu bytes: BAD\n", got, type, len);
                bad++;
            }
            got++;
        }
        pos += take;
    }
    printf("%d of %d messages back, %u dropped (garbage + damaged: 2 expected)\n", got, N, d.bad);
    bad += got != N || d.bad != 2;
    printf("%s\n", bad ? "FAILED" : "all ok");
    return bad != 0;
}
