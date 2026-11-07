/* The radio (Linux): a monitor interface (mon0) added next to the Wi-Fi one, as scripts/capture.sh does (the MT7925
 * receives nothing with the Wi-Fi interface itself in monitor mode), and a raw socket on it for sending and
 * receiving whole 802.11 frames. NetworkManager / wpa_supplicant / iwd are stopped while it runs and started again
 * by radio_close (call it on every exit path). Needs root (or CAP_NET_ADMIN + CAP_NET_RAW) and iw, ip, systemctl. */
#ifndef RADIO_H
#define RADIO_H

#include "common.h"

typedef struct Radio {
    char iface[32], mon[32], phy[32];
    char stopped[128];          /* services to start again */
    int fd;
    u8 mac[6];                  /* the card's address: the network's BSSID */
    bool mon_added;
} Radio;

/* iface NULL: the first Wi-Fi interface */
bool radio_open(Radio *r, const char *iface, u8 channel, char *err, size_t errn);
void radio_close(Radio *r);
/* one 802.11 frame (no FCS); a radiotap header is put in front */
bool radio_send(Radio *r, const u8 *frame, size_t n);
/* the next received frame without its radiotap header, or 0 when none is waiting (non-blocking) */
size_t radio_recv(Radio *r, u8 *buf, size_t cap, const u8 **frame);

#endif
