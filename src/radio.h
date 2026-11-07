/* The radio: whole 802.11 frames out and in, plus an access point that ACKs, authenticates and associates the
 * Switch (it does no 4-way handshake: the LDN data key is its CCMP key, handled in software by ccmp.c). Two kinds:
 *   s3     (radio_s3.c, Windows and Linux): an ESP32-S3 running s3/ on a serial port (its USB-Serial-JTAG):
 *          SoftAP + promiscuous receive + raw transmit. s3proto.h is the link.
 *   wifi   (radio_linux.c + ap.c, Linux only): the machine's own Wi-Fi card, a monitor interface (mon0) next to its
 *          interface for raw frames and hostapd on it for the AP. NetworkManager / wpa_supplicant / iwd stop while it
 *          runs and start again in radio_close (call it on every exit path). Needs root and iw, ip, systemctl, hostapd.
 * Spec strings: "s3[:port]" (port: COM4, /dev/ttyACM0; none: the first Espressif USB device), "wifi[:iface]".
 * No spec: the S3 when one is plugged in, else (Linux) the built-in Wi-Fi. */
#ifndef RADIO_H
#define RADIO_H

#include "common.h"

typedef enum { RADIO_WIFI, RADIO_S3 } RadioKind;

struct S3Link;

typedef struct Radio {
    RadioKind kind;
    u8 mac[6];                  /* the network's BSSID */
    bool qos_data;              /* QoS data frames can be sent (the S3 sends only non-QoS data) */
    bool hw_crypto;             /* data to stations goes as Ethernet frames (radio_send_eth), the radio encrypts them with
                                 * the network's data key (the S3: it refuses frames we protected ourselves) */
    /* a station joined / left the AP (the S3 reports them; hostapd's are only in its log) */
    void (*on_station)(const u8 mac[6], bool joined, u16 reason);
    /* wifi */
    char iface[32], mon[32], phy[32];
    char stopped[128];          /* services to start again */
    int fd;
    bool mon_added;
    int ap_pid;
    /* our station (s3, joining a console's network): its address, and the link coming up (keys in) or going */
    u8 sta_mac[6];
    void (*on_link)(const u8 bssid[6], bool up, u16 reason);
    /* s3 */
    struct S3Link *s3;
} Radio;

/* spec NULL: an S3 if one is plugged in, else the built-in Wi-Fi (Linux). filter_all: the S3 sends every frame it hears (for --pcap), not only
 * ours */
bool radio_open(Radio *r, const char *spec, u8 channel, bool filter_all, char *err, size_t errn);
void radio_close(Radio *r);
/* one 802.11 frame (no FCS) */
bool radio_send(Radio *r, const u8 *frame, size_t n);
/* unicast: the hardware waits for the ACK and retries; encrypted: the frame is already protected (ccmp.c) */
bool radio_send_ex(Radio *r, const u8 *frame, size_t n, bool unicast, bool encrypted);
/* hw_crypto: data from the AP (FromDS, src as the source address), encrypted by the radio with the data key:
 * pairwise for a unicast dest, group for broadcast */
bool radio_send_eth(Radio *r, const u8 dest[6], const u8 src[6], u16 ethertype, const u8 *p, size_t n);
/* the next received frame, or 0 when none is waiting (non-blocking). buf gets a radiotap header and the frame
 * (*frame points at it, no FCS): buf[0 .. *frame - buf + return] is a pcap record's data */
size_t radio_recv(Radio *r, u8 *buf, size_t cap, const u8 **frame);

/* How the network's 16-byte data key becomes the AP's WPA2 key (wifi: the Switch never does the handshake, so
 * any; kept for the captures): 0 the key's 32 hex digits as the passphrase, 1 PSK = key twice, 2 PSK = key + 16
 * zero bytes */
enum { AP_PSK_HEX_PASSPHRASE, AP_PSK_KEY_TWICE, AP_PSK_KEY_ZEROS, AP_PSK_MODES };
typedef struct ApConfig {
    char ssid[33];              /* hidden in beacons */
    u8 channel;
    u8 data_key[16];
    int psk_mode;
    bool open;                  /* s3: an open AP instead of WPA2 (whether the Switch associates then: to test) */
    const char *log_path;       /* wifi: hostapd's debug log */
    u8 bssid[6];                /* s3: the AP's address for this network (all zero: keep it); r->mac follows */
} ApConfig;
bool radio_ap_start(Radio *r, const ApConfig *c, char *err, size_t errn);
void radio_ap_stop(Radio *r);
/* false once the AP has gone (wifi: hostapd exited, reaped) */
bool radio_ap_running(Radio *r);

#ifdef __linux__
/* wifi: a non-blocking packet socket for one EtherType on the Wi-Fi interface (the AP's side: whole Ethernet frames,
 * decrypted); -1 on error */
int radio_eth_socket(const Radio *r, u16 ethertype);
/* the next frame on such a socket, 0 when none */
size_t radio_eth_recv(int fd, u8 *buf, size_t cap);
#endif

/* the backends (radio.c dispatches) */
bool linux_radio_open(Radio *r, const char *iface, u8 channel, char *err, size_t errn);
void linux_radio_close(Radio *r);
bool linux_radio_send_ex(Radio *r, const u8 *frame, size_t n, bool unicast, bool encrypted);
size_t linux_radio_recv(Radio *r, u8 *buf, size_t cap, const u8 **frame);
/* an ESP32-S3 (an Espressif USB serial device) is plugged in */
bool s3_radio_present(void);
bool s3_radio_open(Radio *r, const char *port, u8 channel, bool filter_all, char *err, size_t errn);
void s3_radio_close(Radio *r);
bool s3_radio_send_ex(Radio *r, const u8 *frame, size_t n, bool unicast, bool encrypted);
bool s3_radio_send_eth(Radio *r, const u8 dest[6], const u8 src[6], u16 ethertype, const u8 *p, size_t n);
size_t s3_radio_recv(Radio *r, u8 *buf, size_t cap, const u8 **frame);
bool s3_ap_start(Radio *r, const ApConfig *c, char *err, size_t errn);
/* the S3 to another channel (placeholder AP, promiscuous receive) */
bool s3_set_channel(Radio *r, u8 channel, char *err, size_t errn);
/* join a console's LDN network as a station (ssid: the session id's hex digits; key: the data key); the link comes up
 * later (on_link) */
bool s3_join(Radio *r, u8 channel, const u8 bssid[6], const char *ssid, const u8 key[16], char *err, size_t errn);
void s3_leave(Radio *r);
/* an Ethernet frame from our station, encrypted by the S3 with the data key */
bool s3_send_eth_sta(Radio *r, const u8 dest[6], u16 ethertype, const u8 *p, size_t n);
void s3_ap_stop(Radio *r);
bool s3_ap_running(Radio *r);

#endif
