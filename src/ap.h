/* The network's access point (Linux): hostapd on the Wi-Fi interface, so the card's firmware ACKs the Switch's frames
 * and hostapd does Open System authentication, association, the WPA2 4-way handshake and CCMP. The MT7925 has no
 * active monitor mode, so a monitor interface alone cannot answer a joining Switch (run 5, CLAUDE.md). The SSID is
 * hidden as a Switch hides it (zero bytes of the same length); Nintendo's vendor element is added. hostapd runs with
 * full debug output (keys included) into a log file, for working out the WPA2 key from a failed handshake. */
#ifndef AP_H
#define AP_H

#include "common.h"

typedef struct Ap { int pid; } Ap;

/* How the network's 16-byte data key becomes the WPA2 key (unknown yet, see CLAUDE.md):
 * 0 the key's 32 hex digits as the passphrase, 1 PSK = key twice, 2 PSK = key + 16 zero bytes */
enum { AP_PSK_HEX_PASSPHRASE, AP_PSK_KEY_TWICE, AP_PSK_KEY_ZEROS, AP_PSK_MODES };

bool ap_start(Ap *a, const char *iface, const char ssid[33], u8 channel, const u8 data_key[16], int psk_mode,
              const char *log_path, char *err, size_t errn);
void ap_stop(Ap *a);
/* false once hostapd has exited (it is reaped) */
bool ap_running(Ap *a);

#endif
