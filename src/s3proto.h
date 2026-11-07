/* The USB link between the desktop's ldnbeacon and the ESP32-S3 radio (s3/): COBS-framed messages over the S3's
 * USB-Serial-JTAG port, each [type][payload][CRC-16/CCITT-FALSE of type + payload, little-endian], ended by a zero
 * byte. Anything that does not decode or check (the ROM's boot text, a cut frame) is dropped up to the next zero.
 * Shared by both sides: plain C, no OS calls. All integers little-endian (both ends are). */
#ifndef S3PROTO_H
#define S3PROTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define S3_PROTO_VERSION 4
#define S3_MAX_PAYLOAD 2400                 /* an 802.11 frame plus our small headers */
#define S3_MAX_WIRE (S3_MAX_PAYLOAD + 3 + (S3_MAX_PAYLOAD + 3) / 254 + 2)

enum {
    /* desktop -> S3 */
    S3_HELLO_REQ = 0x01,    /* -> S3_HELLO */
    S3_OPEN = 0x02,         /* S3Open: placeholder hidden AP on the channel, promiscuous receive */
    S3_AP = 0x03,           /* S3Ap: the network's AP (SSID, auth, vendor element); -> S3_AP_DONE */
    S3_AP_OFF = 0x04,       /* back to the placeholder AP */
    S3_TX = 0x05,           /* S3TxHdr + a whole 802.11 frame (no FCS) */
    S3_FILTER = 0x06,       /* u8: 0 frames that concern our BSSID / consoles, 1 everything heard */
    S3_CLOSE = 0x07,        /* Wi-Fi stopped */
    S3_TX_ETH = 0x08,       /* S3TxHdr + an Ethernet frame (destination, source, EtherType, payload): sent as data from
                             * the AP, encrypted by the S3's hardware with the station's key (S3Ap.ldn); with
                             * S3_TX_STA from our station to the network we joined (S3_JOIN) */
    S3_JOIN = 0x09,         /* S3Join: leave AP mode and join a console's network as a station; -> S3_AP_DONE (the
                             * connect started), then S3_LINK */
    S3_LEAVE = 0x0A,        /* disconnect, back to the placeholder AP */
    /* S3 -> desktop */
    S3_HELLO = 0x81,        /* S3Hello */
    S3_RX = 0x82,           /* S3RxHdr + the frame (no FCS) */
    S3_TX_FAIL = 0x83,      /* S3TxFail */
    S3_STA = 0x84,          /* S3Sta: the AP took or lost a station */
    S3_LOG = 0x85,          /* text: the firmware's and ESP-IDF's log lines */
    S3_STATS = 0x86,        /* S3Stats, every 2 s while open */
    S3_AP_DONE = 0x87,      /* S3ApDone */
    S3_LINK = 0x88,         /* S3StaLink: our station joined (keys in) or lost the network */
};

#pragma pack(push, 1)
typedef struct S3Hello {
    uint32_t version;       /* S3_PROTO_VERSION */
    uint8_t ap_mac[6];      /* the AP interface's address: the network's BSSID */
    char build[24];         /* the firmware's compile date and time */
    char idf[24];           /* ESP-IDF version */
    uint8_t sta_mac[6];     /* the station interface's address (S3_JOIN) */
} S3Hello;

typedef struct S3Open {
    uint8_t channel;        /* 1-13 */
    uint8_t filter;         /* as S3_FILTER */
} S3Open;

enum { S3_AUTH_OPEN = 0, S3_AUTH_WPA2 = 1 };
typedef struct S3Ap {
    uint8_t channel;
    uint8_t auth;           /* S3_AUTH_* */
    uint8_t hidden;         /* 1: SSID not in beacons */
    uint8_t max_sta;
    uint8_t ssid_len;
    char ssid[32];
    uint8_t pass_len;       /* WPA2: 8-63 characters, or 64 hex digits */
    char pass[64];
    uint8_t vie_len;        /* a vendor element's body (OUI, type, data), in beacons, probe and association responses */
    uint8_t vie[32];
    /* 1: an LDN network. The Switch does no 4-way handshake (it uses the data key directly): on association the S3
     * starts none, installs ldn_key as the station's pairwise key and as the group key, and authorizes the station */
    uint8_t ldn;
    uint8_t ldn_key[16];
} S3Ap;

typedef struct S3ApDone {
    int32_t err;            /* esp_err_t, 0 ok */
} S3ApDone;

enum { S3_TX_UNICAST = 1, S3_TX_STA = 2 };
typedef struct S3TxHdr {
    uint16_t id;
    uint8_t flags;
} S3TxHdr;

typedef struct S3TxFail {
    uint16_t id;
    int32_t err;
} S3TxFail;

typedef struct S3RxHdr {
    uint32_t time_us;       /* the radio's receive time */
    int8_t rssi;
    uint8_t channel;
    uint8_t rate;
    uint8_t flags;          /* S3_RX_* */
} S3RxHdr;
/* the hardware flagged a receive error (e.g. a protected frame it could not decrypt): passed on anyway, since the
 * desktop decrypts in software and its CCMP check drops what is really damaged */
enum { S3_RX_ERROR = 1 };

typedef struct S3Sta {
    uint8_t joined;         /* 1 associated, 0 left */
    uint8_t mac[6];
    uint8_t aid;
    uint16_t reason;        /* left: the 802.11 / ESP-IDF reason */
} S3Sta;

/* join a console's LDN network: it does no 4-way handshake, so on association the S3 installs ldn_key as the
 * pairwise and group key itself and calls the handshake done */
typedef struct S3Join {
    uint8_t channel;
    uint8_t bssid[6];       /* the host console */
    uint8_t ssid_len;
    char ssid[32];          /* the session id's 32 hex digits */
    uint8_t ldn_key[16];
} S3Join;

typedef struct S3StaLink {
    uint8_t up;             /* 1 associated and keyed, 0 lost */
    uint8_t bssid[6];
    uint16_t reason;        /* lost: ESP-IDF's reason */
} S3StaLink;

typedef struct S3Stats {
    uint32_t rx_heard, rx_sent, rx_dropped;     /* dropped: the queue to USB was full */
    uint32_t tx_ok, tx_fail, usb_rx_bad;
    uint32_t heap_free;
    uint32_t rx_errors;     /* frames of ours with the hardware's receive error flag (passed on, S3_RX_ERROR) */
} S3Stats;
#pragma pack(pop)

/* CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF) */
uint16_t s3_crc16(const uint8_t *p, size_t n, uint16_t crc);
/* one message onto the wire: COBS of type + payload + CRC, then the zero byte; returns the size, 0 if out is short */
size_t s3_encode(uint8_t type, const void *payload, size_t n, uint8_t *out, size_t cap);

/* the receiving side: feed bytes, get whole messages */
typedef struct S3Dec {
    uint8_t buf[S3_MAX_WIRE];
    size_t n;
    bool overflow;
    uint32_t bad;           /* frames dropped (COBS / CRC / too long) */
} S3Dec;
/* takes bytes up to the end of one message; returns how many it used. *type / *payload / *len are set when a whole
 * valid message ended within them (*payload points into d, valid until the next call), else *len = SIZE_MAX */
size_t s3_decode(S3Dec *d, const uint8_t *in, size_t n, uint8_t *type, const uint8_t **payload, size_t *len);

#endif
