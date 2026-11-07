/* s3test: the ESP32-S3 radio on the bench, no room needed. Opens it (hello, Wi-Fi on a channel), listens to
 * everything for some seconds and counts what it hears (beacons by BSSID, probe requests, data), optionally starts
 * the AP with a test SSID (--ap: a phone should then see a hidden network with our BSSID) and saves a pcap.
 * --tx: twice a second, a dummy Nintendo action frame (to broadcast, wildcard BSSID: as our advertisement) and a
 * dummy protected non-QoS data frame (FromDS, to a made-up station: as our CCMP data); the S3's statistics then say
 * whether esp_wifi_80211_tx takes them.
 *   s3test [--port COM4] [--channel 6] [--seconds 10] [--ap] [--open] [--tx] [--pcap file] [--log 0-2] */
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#define nap() Sleep(1)
#else
#include <unistd.h>
#define nap() usleep(1000)
#endif
#include "radio.h"
#include <stdlib.h>

#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_ARG(m) (m)[0], (m)[1], (m)[2], (m)[3], (m)[4], (m)[5]

int main(int argc, char **argv) {
    const char *port = NULL, *pcap_path = NULL;
    int channel = 6, seconds = 10;
    bool ap = false, open_ap = false, tx = false;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i], *v = i + 1 < argc ? argv[i + 1] : NULL;
        if (!strcmp(a, "--port") && v) port = v, i++;
        else if (!strcmp(a, "--channel") && v) channel = atoi(v), i++;
        else if (!strcmp(a, "--seconds") && v) seconds = atoi(v), i++;
        else if (!strcmp(a, "--pcap") && v) pcap_path = v, i++;
        else if (!strcmp(a, "--log") && v) log_level = atoi(v), i++;
        else if (!strcmp(a, "--ap")) ap = true;
        else if (!strcmp(a, "--open")) open_ap = true;
        else if (!strcmp(a, "--tx")) tx = true;
        else {
            fprintf(stderr, "usage: s3test [--port COM4] [--channel 6] [--seconds 10] [--ap] [--open] [--tx] [--pcap file] [--log 0-2]\n");
            return 2;
        }
    }
    char spec[80], err[256];
    snprintf(spec, sizeof spec, "s3%s%s", port ? ":" : "", port ? port : "");
    Radio r;
    if (!radio_open(&r, spec, (u8)channel, true, err, sizeof err)) { fprintf(stderr, "s3test: %s\n", err); return 1; }
    if (ap) {
        ApConfig c = {.channel = (u8)channel, .open = open_ap};
        snprintf(c.ssid, sizeof c.ssid, "ldns3test%02x%02x%02x", r.mac[3], r.mac[4], r.mac[5]);
        for (int i = 0; i < 16; i++) c.data_key[i] = (u8)i;
        if (!radio_ap_start(&r, &c, err, sizeof err)) logf_(0, "s3test: %s", err);
        else logf_(0, "s3test: AP \"%s\" (hidden) up", c.ssid);
    }
    FILE *pcap = pcap_path ? fopen(pcap_path, "wb") : NULL;
    if (pcap) {
        static const u8 gh[24] = {0xD4, 0xC3, 0xB2, 0xA1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 127, 0, 0, 0};
        fwrite(gh, 1, sizeof gh, pcap);
    }
    struct { u8 mac[6]; unsigned n; int rssi; char ssid[33]; } bss[64];
    int nbss = 0;
    unsigned total = 0, beacons = 0, probes = 0, data = 0, other = 0, ours = 0;
    u64 start = now_ms(), t0 = now_us(), next_tx = start;
    unsigned tx_tried = 0, tx_queued = 0;
    static u8 buf[4096];
    while (now_ms() - start < (u64)seconds * 1000) {
        if (tx && now_ms() >= next_tx) {
            next_tx += 500;
            static const u8 bc[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, sta[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
            u8 act[24 + 40] = {0xD0, 0};                    /* action, Nintendo's OUI, junk after */
            memcpy(act + 4, bc, 6);
            memcpy(act + 10, r.mac, 6);
            memcpy(act + 16, bc, 6);
            act[24] = 0x7F; act[25] = 0x00; act[26] = 0x22; act[27] = 0xAA;
            tx_queued += radio_send(&r, act, sizeof act);
            /* data frames in four variants (ids 1-4 after the action frame's 0, mod 5): protected / plain, to a
             * made-up station / to broadcast; which ones esp_wifi_80211_tx refuses shows in the "not sent" lines */
            for (int v = 0; v < 4; v++) {
                bool prot = !(v & 1), bcast = v >= 2;
                u8 dat[24 + 8 + 40 + 8] = {0x08, (u8)(prot ? 0x42 : 0x02)};   /* data, FromDS (+ protected) */
                memcpy(dat + 4, bcast ? bc : sta, 6);
                memcpy(dat + 10, r.mac, 6);
                memcpy(dat + 16, r.mac, 6);
                if (prot) { dat[24] = 1; dat[27] = (u8)(bcast ? 0x60 : 0x20); }   /* PN 1, ExtIV, key index */
                else { dat[24] = 0xAA; dat[25] = 0xAA; dat[26] = 0x03; dat[30] = 0x08; dat[31] = 0x00; }  /* LLC: IPv4 */
                tx_queued += radio_send_ex(&r, dat, sizeof dat, !bcast, prot);
            }
            /* ids 5, 6: Ethernet frames through the S3's data path (hardware CCMP for stations with the key):
             * broadcast, and unicast to the made-up station (not associated: expected to fail) */
            static const u8 ip[20] = {0x45};
            tx_queued += radio_send_eth(&r, bc, r.mac, 0x0800, ip, sizeof ip);
            tx_queued += radio_send_eth(&r, sta, r.mac, 0x0800, ip, sizeof ip);
            tx_tried += 7;
        }
        const u8 *f;
        size_t n = radio_recv(&r, buf, sizeof buf, &f);
        if (!n) { nap(); continue; }
        total++;
        if (pcap) {
            u64 us = now_us() - t0;
            u32 len = (u32)(f - buf + n);
            u32 rh[4] = {(u32)(us / 1000000), (u32)(us % 1000000), len, len};
            fwrite(rh, 4, 4, pcap);
            fwrite(buf, 1, len, pcap);
        }
        if (n < 24) { other++; continue; }
        if (!memcmp(f + 4, r.mac, 6) || !memcmp(f + 16, r.mac, 6)) ours++;
        u8 type = (f[0] >> 2) & 3, sub = f[0] >> 4;
        if (type == 0 && sub == 8) {
            beacons++;
            int i = 0;
            while (i < nbss && memcmp(bss[i].mac, f + 16, 6)) i++;
            if (i == nbss && nbss < 64) {
                memset(&bss[i], 0, sizeof bss[i]);
                memcpy(bss[i].mac, f + 16, 6);
                if (n > 38 && f[36] == 0 && f[37] <= 32 && 38u + f[37] <= n) memcpy(bss[i].ssid, f + 38, f[37]);
                nbss++;
            }
            if (i < nbss) { bss[i].n++; bss[i].rssi = (s8)buf[14]; }
        } else if (type == 0 && sub == 4) probes++;
        else if (type == 2) data++;
        else other++;
    }
    logf_(0, "s3test: %u frames in %d s on channel %d: %u beacons from %d networks, %u probe requests, %u data, %u other, "
             "%u naming our BSSID " MAC_FMT, total, seconds, channel, beacons, nbss, probes, data, other, ours, MAC_ARG(r.mac));
    if (tx) logf_(0, "s3test: %u frames to send, %u went over USB (the S3's statistics: sent / failed)", tx_tried, tx_queued);
    for (int i = 0; i < nbss; i++)
        logf_(0, "  " MAC_FMT " %4u beacons, %d dBm  \"%s\"", MAC_ARG(bss[i].mac), bss[i].n, bss[i].rssi, bss[i].ssid);
    if (pcap) fclose(pcap);
    radio_ap_stop(&r);
    radio_close(&r);
    return total ? 0 : 1;
}
