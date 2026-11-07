#define _GNU_SOURCE
#include "radio.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

/* runs a shell command (names were checked to be plain), logged at level 2; returns its exit status */
static int run(const char *fmt, ...) {
    char cmd[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(cmd, sizeof cmd, fmt, ap);
    va_end(ap);
    logf_(2, "radio: %s", cmd);
    int st = system(cmd);
    return st == -1 ? -1 : WEXITSTATUS(st);
}

static bool plain_name(const char *s) {
    if (!*s || strlen(s) >= 32) return false;
    for (; *s; s++)
        if (!isalnum((unsigned char)*s) && *s != '-' && *s != '_' && *s != '.') return false;
    return true;
}

static bool read_line(const char *path, char *out, size_t n) {
    FILE *f = fopen(path, "r");
    if (!f) return false;
    bool ok = fgets(out, (int)n, f) != NULL;
    fclose(f);
    if (ok) out[strcspn(out, "\r\n")] = 0;
    return ok;
}

static bool first_wifi(char *out, size_t n) {
    DIR *d = opendir("/sys/class/net");
    if (!d) return false;
    struct dirent *e;
    bool found = false;
    while (!found && (e = readdir(d))) {
        char p[300];
        snprintf(p, sizeof p, "/sys/class/net/%s/phy80211", e->d_name);
        if (e->d_name[0] != '.' && strcmp(e->d_name, "mon0") && !access(p, F_OK)) {
            snprintf(out, n, "%.31s", e->d_name);
            found = true;
        }
    }
    closedir(d);
    return found;
}

bool radio_open(Radio *r, const char *iface, u8 channel, char *err, size_t errn) {
    memset(r, 0, sizeof *r);
    r->fd = -1;
    if (geteuid() != 0) { snprintf(err, errn, "needs root: run it with sudo"); return false; }
    if (iface) snprintf(r->iface, sizeof r->iface, "%s", iface);
    else if (!first_wifi(r->iface, sizeof r->iface)) { snprintf(err, errn, "no Wi-Fi interface found"); return false; }
    if (!plain_name(r->iface)) { snprintf(err, errn, "odd interface name"); return false; }
    snprintf(r->mon, sizeof r->mon, "mon0");

    char path[300], line[64];
    snprintf(path, sizeof path, "/sys/class/net/%s/phy80211/name", r->iface);
    if (!read_line(path, r->phy, sizeof r->phy) || !plain_name(r->phy)) {
        snprintf(err, errn, "%s is not a Wi-Fi interface", r->iface);
        return false;
    }
    snprintf(path, sizeof path, "/sys/class/net/%s/address", r->iface);
    unsigned m[6];
    if (!read_line(path, line, sizeof line) ||
        sscanf(line, "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6) {
        snprintf(err, errn, "cannot read %s's address", r->iface);
        return false;
    }
    for (int i = 0; i < 6; i++) r->mac[i] = (u8)m[i];

    /* as airmon-ng's "check kill": these keep scanning and reconfiguring the card */
    static const char *svc[] = {"NetworkManager", "wpa_supplicant", "iwd"};
    for (int i = 0; i < 3; i++)
        if (run("systemctl is-active --quiet %s 2>/dev/null", svc[i]) == 0 && run("systemctl stop %s", svc[i]) == 0) {
            strcat(r->stopped, " ");
            strcat(r->stopped, svc[i]);
        }
    if (r->stopped[0]) logf_(1, "radio: stopped while running:%s", r->stopped);
    run("pkill -x wpa_supplicant 2>/dev/null");
    run("rfkill unblock wifi 2>/dev/null");
    run("ip addr flush dev %s", r->iface);
    run("ip link set %s down", r->iface);
    run("iw dev %s del 2>/dev/null", r->mon);
    if (run("iw phy %s interface add %s type monitor flags otherbss control", r->phy, r->mon) != 0 &&
        run("iw phy %s interface add %s type monitor", r->phy, r->mon) != 0) {
        snprintf(err, errn, "could not add a monitor interface on %s", r->phy);
        radio_close(r);
        return false;
    }
    r->mon_added = true;
    if (run("ip link set %s up", r->mon) != 0 || run("iw dev %s set channel %u", r->mon, channel) != 0) {
        snprintf(err, errn, "could not bring %s up on channel %u", r->mon, channel);
        radio_close(r);
        return false;
    }

    r->fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (r->fd < 0) { snprintf(err, errn, "raw socket: %s", strerror(errno)); radio_close(r); return false; }
    struct sockaddr_ll sll = {0};
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = (int)if_nametoindex(r->mon);
    if (!sll.sll_ifindex || bind(r->fd, (struct sockaddr *)&sll, sizeof sll) < 0) {
        snprintf(err, errn, "bind to %s: %s", r->mon, strerror(errno));
        radio_close(r);
        return false;
    }
    fcntl(r->fd, F_SETFL, fcntl(r->fd, F_GETFL) | O_NONBLOCK);
    logf_(1, "radio: %s (%s) monitor %s on channel %u, BSSID %02x:%02x:%02x:%02x:%02x:%02x", r->iface, r->phy,
          r->mon, channel, r->mac[0], r->mac[1], r->mac[2], r->mac[3], r->mac[4], r->mac[5]);
    return true;
}

void radio_close(Radio *r) {
    if (r->fd >= 0) close(r->fd);
    r->fd = -1;
    if (r->mon_added) run("iw dev %s del 2>/dev/null", r->mon);
    r->mon_added = false;
    if (r->iface[0]) {                                      /* hostapd may have left it in AP mode */
        run("ip link set %s down 2>/dev/null", r->iface);
        run("iw dev %s set type managed 2>/dev/null", r->iface);
        run("ip link set %s up 2>/dev/null", r->iface);
    }
    char *save, *s = strtok_r(r->stopped, " ", &save);
    for (; s; s = strtok_r(NULL, " ", &save)) run("systemctl start %s", s);
    r->stopped[0] = 0;
    logf_(1, "radio: Wi-Fi given back");
}

bool radio_send(Radio *r, const u8 *frame, size_t n) { return radio_send_ex(r, frame, n, false, false); }

bool radio_send_ex(Radio *r, const u8 *frame, size_t n, bool unicast, bool encrypted) {
    /* radiotap: version 0, length 12, present = flags + TX flags. Flags 0x04: already encrypted (mac80211 leaves it
     * alone); TX flags 0x0008: no ACK expected (broadcast); unicast frames get the hardware's ACK wait and retries */
    u8 buf[4096];
    u8 rt[] = {0x00, 0x00, 0x0C, 0x00, 0x02, 0x80, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00};
    if (encrypted) rt[8] = 0x04;
    if (unicast) rt[10] = 0x00;
    if (n + sizeof rt > sizeof buf) return false;
    memcpy(buf, rt, sizeof rt);
    memcpy(buf + sizeof rt, frame, n);
    ssize_t k = send(r->fd, buf, n + sizeof rt, 0);
    return k == (ssize_t)(n + sizeof rt);
}

int radio_eth_socket(const Radio *r, u16 ethertype) {
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ethertype));
    if (fd < 0) return -1;
    struct sockaddr_ll sll = {0};
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ethertype);
    sll.sll_ifindex = (int)if_nametoindex(r->iface);
    if (!sll.sll_ifindex || bind(fd, (struct sockaddr *)&sll, sizeof sll) < 0) { close(fd); return -1; }
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    return fd;
}

size_t radio_eth_recv(int fd, u8 *buf, size_t cap) {
    ssize_t k = recv(fd, buf, cap, 0);
    return k > 0 ? (size_t)k : 0;
}

size_t radio_recv(Radio *r, u8 *buf, size_t cap, const u8 **frame) {
    ssize_t k = recv(r->fd, buf, cap, 0);
    if (k < 4) return 0;
    size_t rl = (size_t)(buf[2] | buf[3] << 8);
    if (rl >= (size_t)k) return 0;
    *frame = buf + rl;
    return (size_t)k - rl;
}
