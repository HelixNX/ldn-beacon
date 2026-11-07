#define _GNU_SOURCE
#include "ap.h"
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#define CONF_PATH "/run/ldnbeacon-hostapd.conf"

static void hex(char *out, const u8 *p, size_t n) {
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[i * 2] = d[p[i] >> 4]; out[i * 2 + 1] = d[p[i] & 15]; }
    out[n * 2] = 0;
}

bool ap_start(Ap *a, const char *iface, const char ssid[33], u8 channel, const u8 data_key[16], int psk_mode,
              const char *log_path, char *err, size_t errn) {
    a->pid = 0;
    FILE *f = fopen(CONF_PATH, "w");
    if (!f) { snprintf(err, errn, "cannot write %s: %s", CONF_PATH, strerror(errno)); return false; }
    char key[65], psk[65];
    u8 raw[32];
    hex(key, data_key, 16);
    fprintf(f,
            "interface=%s\n"
            "driver=nl80211\n"
            "ssid=%s\n"
            "ignore_broadcast_ssid=2\n"         /* the SSID's length in zero bytes, as a Switch's beacon */
            "hw_mode=g\n"
            "channel=%u\n"
            "beacon_int=100\n"
            "ieee80211n=1\n"
            "wmm_enabled=1\n"
            "auth_algs=1\n"
            "wpa=2\n"
            "wpa_key_mgmt=WPA-PSK\n"
            "rsn_pairwise=CCMP\n"
            "max_num_sta=8\n"
            /* a Switch skips the 4-way handshake (it derives the key itself): keep hostapd from giving up on it and
             * disconnecting the station after the default 4 tries of message 1 */
            "wpa_pairwise_update_count=100000\n"
            "vendor_elements=dd060022aa100102\n",
            iface, ssid, channel);
    switch (psk_mode) {
    case AP_PSK_KEY_TWICE:
        memcpy(raw, data_key, 16);
        memcpy(raw + 16, data_key, 16);
        hex(psk, raw, 32);
        fprintf(f, "wpa_psk=%s\n", psk);
        break;
    case AP_PSK_KEY_ZEROS:
        memcpy(raw, data_key, 16);
        memset(raw + 16, 0, 16);
        hex(psk, raw, 32);
        fprintf(f, "wpa_psk=%s\n", psk);
        break;
    default:
        fprintf(f, "wpa_passphrase=%s\n", key);
        break;
    }
    fclose(f);

    int pid = fork();
    if (pid < 0) { snprintf(err, errn, "fork: %s", strerror(errno)); return false; }
    if (pid == 0) {
        /* -dd -K: full debug with key material (the handshake's nonces and MICs), -t: timestamps */
        execlp("hostapd", "hostapd", "-dd", "-K", "-t", "-f", log_path, CONF_PATH, (char *)NULL);
        fprintf(stderr, "hostapd: %s (sudo pacman -S hostapd)\n", strerror(errno));
        _exit(127);
    }
    a->pid = pid;
    logf_(0, "ap: hostapd on %s, channel %u, SSID %s (hidden), WPA2 key mode %d, debug log %s", iface, channel, ssid,
          psk_mode, log_path);
    logf_(1, "ap: data key %s", key);
    return true;
}

bool ap_running(Ap *a) {
    if (a->pid <= 0) return false;
    int st;
    int r = waitpid(a->pid, &st, WNOHANG);
    if (r == 0) return true;
    logf_(0, "ap: hostapd exited (%s %d): see its log", WIFEXITED(st) ? "status" : "signal",
          WIFEXITED(st) ? WEXITSTATUS(st) : WTERMSIG(st));
    a->pid = 0;
    return false;
}

void ap_stop(Ap *a) {
    if (a->pid <= 0) return;
    kill(a->pid, SIGTERM);
    for (int i = 0; i < 30; i++) {                          /* up to 3 s, then kill */
        if (waitpid(a->pid, NULL, WNOHANG) == a->pid) { a->pid = 0; break; }
        usleep(100000);
    }
    if (a->pid > 0) {
        kill(a->pid, SIGKILL);
        waitpid(a->pid, NULL, 0);
        a->pid = 0;
    }
    unlink(CONF_PATH);
    logf_(1, "ap: hostapd stopped");
}
