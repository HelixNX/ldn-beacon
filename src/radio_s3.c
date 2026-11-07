/* radio.h's s3 kind: an ESP32-S3 running s3/ on a serial port (the S3's own USB, USB-Serial-JTAG), s3proto.h's
 * messages. Windows and POSIX. The S3 keeps a placeholder AP from radio_open on (hidden, random SSID), so its MAC is
 * the BSSID from the start; radio_ap_start gives it the network's SSID and Nintendo's element. */
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <setupapi.h>
#include <devguid.h>
#else
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>
#endif
#include "radio.h"
#include "s3proto.h"
#include <stdlib.h>

struct S3Link {
#ifdef _WIN32
    HANDLE h;
#else
    int fd;
#endif
    char port[64];
    S3Dec dec;
    u8 in[8192];
    size_t in_off, in_n;
    S3Hello hello;
    bool ap_up;
    u16 tx_id;
    unsigned tx_fail, rx_count;
    S3Stats stats;
    u64 last_stats_log;
    u8 last_type;               /* the message s3_wait got, its payload in wait_buf */
    u8 wait_buf[S3_MAX_PAYLOAD];
    size_t wait_len;
};

/* ---- the serial port ------------------------------------------------------------------------------------------ */
#ifdef _WIN32
/* the first USB device with Espressif's vendor id (303A) that has a COM port */
static bool find_port(char *out, size_t n) {
    HDEVINFO di = SetupDiGetClassDevsA(&GUID_DEVCLASS_PORTS, NULL, NULL, DIGCF_PRESENT);
    if (di == INVALID_HANDLE_VALUE) return false;
    bool found = false;
    SP_DEVINFO_DATA d = {.cbSize = sizeof d};
    for (DWORD i = 0; !found && SetupDiEnumDeviceInfo(di, i, &d); i++) {
        char hw[512] = "";
        if (!SetupDiGetDeviceRegistryPropertyA(di, &d, SPDRP_HARDWAREID, NULL, (BYTE *)hw, sizeof hw - 1, NULL)) continue;
        if (!strstr(hw, "VID_303A")) continue;
        HKEY k = SetupDiOpenDevRegKey(di, &d, DICS_FLAG_GLOBAL, 0, DIREG_DEV, KEY_READ);
        if (k == INVALID_HANDLE_VALUE) continue;
        char name[32] = "";
        DWORD len = sizeof name - 1, type = 0;
        if (RegQueryValueExA(k, "PortName", NULL, &type, (BYTE *)name, &len) == ERROR_SUCCESS && type == REG_SZ &&
            !strncmp(name, "COM", 3)) {
            snprintf(out, n, "%s", name);
            found = true;
        }
        RegCloseKey(k);
    }
    SetupDiDestroyDeviceInfoList(di);
    return found;
}

static bool port_open(struct S3Link *l, char *err, size_t errn) {
    char path[80];
    snprintf(path, sizeof path, "\\\\.\\%s", l->port);
    l->h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (l->h == INVALID_HANDLE_VALUE) {
        snprintf(err, errn, "cannot open %s (error %lu; in use by idf.py monitor?)", l->port, GetLastError());
        return false;
    }
    DCB dcb = {.DCBlength = sizeof dcb};
    GetCommState(l->h, &dcb);
    dcb.BaudRate = 921600;      /* USB: ignored */
    dcb.ByteSize = 8;
    dcb.Parity = NOPARITY;
    dcb.StopBits = ONESTOPBIT;
    dcb.fBinary = TRUE;
    dcb.fOutxCtsFlow = dcb.fOutxDsrFlow = FALSE;
    dcb.fOutX = dcb.fInX = FALSE;
    /* DTR and RTS drive the S3's reset and boot pins over USB-Serial-JTAG: leave both off (no reset) */
    dcb.fDtrControl = DTR_CONTROL_DISABLE;
    dcb.fRtsControl = RTS_CONTROL_DISABLE;
    SetCommState(l->h, &dcb);
    COMMTIMEOUTS t = {.ReadIntervalTimeout = MAXDWORD, .WriteTotalTimeoutConstant = 200};   /* reads never wait */
    SetCommTimeouts(l->h, &t);
    SetupComm(l->h, 1 << 16, 1 << 16);
    PurgeComm(l->h, PURGE_RXCLEAR | PURGE_TXCLEAR);
    return true;
}

static void port_close(struct S3Link *l) {
    if (l->h && l->h != INVALID_HANDLE_VALUE) CloseHandle(l->h);
    l->h = NULL;
}

static long port_read(struct S3Link *l, u8 *p, size_t n) {
    DWORD k = 0;
    if (!ReadFile(l->h, p, (DWORD)n, &k, NULL)) return -1;
    return (long)k;
}

static bool port_write(struct S3Link *l, const u8 *p, size_t n) {
    DWORD k = 0;
    return WriteFile(l->h, p, (DWORD)n, &k, NULL) && k == n;
}

static void sleep_ms(int ms) { Sleep((DWORD)ms); }
#else
static bool find_port(char *out, size_t n) {
    DIR *d = opendir("/dev/serial/by-id");
    if (!d) return false;
    struct dirent *e;
    bool found = false;
    while (!found && (e = readdir(d)))
        if (strstr(e->d_name, "Espressif")) {
            snprintf(out, n, "/dev/serial/by-id/%.40s", e->d_name);
            found = true;
        }
    closedir(d);
    return found;
}

static bool port_open(struct S3Link *l, char *err, size_t errn) {
    l->fd = open(l->port, O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (l->fd < 0) { snprintf(err, errn, "cannot open %s: %s", l->port, strerror(errno)); return false; }
    struct termios t;
    if (!tcgetattr(l->fd, &t)) {
        cfmakeraw(&t);
        t.c_cflag &= ~(tcflag_t)HUPCL;      /* closing must not drop DTR (a reset) */
        tcsetattr(l->fd, TCSANOW, &t);
    }
    tcflush(l->fd, TCIOFLUSH);
    return true;
}

static void port_close(struct S3Link *l) {
    if (l->fd >= 0) close(l->fd);
    l->fd = -1;
}

static long port_read(struct S3Link *l, u8 *p, size_t n) {
    ssize_t k = read(l->fd, p, n);
    if (k < 0) return errno == EAGAIN || errno == EWOULDBLOCK ? 0 : -1;
    return (long)k;
}

static bool port_write(struct S3Link *l, const u8 *p, size_t n) {
    size_t off = 0;
    for (int tries = 0; off < n && tries < 200; tries++) {
        ssize_t k = write(l->fd, p + off, n - off);
        if (k > 0) off += (size_t)k;
        else if (k < 0 && errno != EAGAIN) return false;
        else usleep(1000);
    }
    return off == n;
}

static void sleep_ms(int ms) { usleep((useconds_t)ms * 1000); }
#endif

bool s3_radio_present(void) {
    char port[64];
    return find_port(port, sizeof port);
}

/* ---- messages ----------------------------------------------------------------------------------------------- */
static bool s3_send(struct S3Link *l, u8 type, const void *p, size_t n) {
    static u8 wire[S3_MAX_WIRE];
    size_t k = s3_encode(type, p, n, wire, sizeof wire);
    return k && port_write(l, wire, k);
}

#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_ARG(m) (m)[0], (m)[1], (m)[2], (m)[3], (m)[4], (m)[5]

/* the next whole message from the port: 1 got one, 0 none waiting, -1 the port failed */
static int next_msg(struct S3Link *l, u8 *type, const u8 **p, size_t *len) {
    for (;;) {
        while (l->in_off < l->in_n) {
            l->in_off += s3_decode(&l->dec, l->in + l->in_off, l->in_n - l->in_off, type, p, len);
            if (*len != SIZE_MAX) return 1;
        }
        long k = port_read(l, l->in, sizeof l->in);
        if (k < 0) return -1;
        l->in_off = 0;
        l->in_n = (size_t)k;
        if (!k) return 0;
    }
}

/* everything but received frames: logged / passed on here. Returns true if it was handled */
static bool handle_other(Radio *r, u8 type, const u8 *p, size_t n) {
    struct S3Link *l = r->s3;
    switch (type) {
    case S3_LOG:                /* one or more lines, '\n' between them */
        for (size_t i = 0; i < n;) {
            size_t e = i;
            while (e < n && p[e] != '\n') e++;
            if (e > i) logf_(1, "s3: %.*s", (int)(e - i), (const char *)p + i);
            i = e + 1;
        }
        return true;
    case S3_STA:
        if (n >= sizeof(S3Sta)) {
            S3Sta s;
            memcpy(&s, p, sizeof s);
            if (s.joined) logf_(0, "s3: the AP took station " MAC_FMT " (aid %u)", MAC_ARG(s.mac), s.aid);
            else logf_(0, "s3: the AP dropped station " MAC_FMT " (aid %u, reason %u)", MAC_ARG(s.mac), s.aid, s.reason);
            if (r->on_station) r->on_station(s.mac, s.joined, s.reason);
        }
        return true;
    case S3_TX_FAIL:
        if (n >= sizeof(S3TxFail)) {
            S3TxFail f;
            memcpy(&f, p, sizeof f);
            if (l->tx_fail++ < 10) logf_(0, "s3: frame %u not sent (esp_err 0x%x)", f.id, (unsigned)f.err);
        }
        return true;
    case S3_STATS:
        if (n >= sizeof(S3Stats)) {
            memcpy(&l->stats, p, sizeof l->stats);
            u64 t = now_ms();
            if (t - l->last_stats_log >= 10000) {
                l->last_stats_log = t;
                logf_(1, "s3: heard %u frames, %u to us (%u dropped: USB queue full; %u with a receive error), sent "
                         "%u (%u failed), %u bad messages from us, heap %u", l->stats.rx_heard, l->stats.rx_sent,
                      l->stats.rx_dropped, l->stats.rx_errors, l->stats.tx_ok, l->stats.tx_fail, l->stats.usb_rx_bad,
                      l->stats.heap_free);
            }
        }
        return true;
    case S3_LINK:
        if (n >= sizeof(S3StaLink)) {
            S3StaLink k;
            memcpy(&k, p, sizeof k);
            if (k.up) logf_(0, "s3: our station is in " MAC_FMT "'s network (keys in)", MAC_ARG(k.bssid));
            else logf_(0, "s3: our station lost " MAC_FMT " (reason %u)", MAC_ARG(k.bssid), k.reason);
            if (r->on_link) r->on_link(k.bssid, k.up, k.reason);
        }
        return true;
    case S3_HELLO:
        if (n >= sizeof(S3Hello)) memcpy(&l->hello, p, sizeof l->hello);
        logf_(0, "s3: the radio restarted (hello again): its AP is gone until the beacon reopens");
        l->ap_up = false;
        return true;
    default:
        return false;
    }
}

/* waits for one message of a type (others handled, received frames dropped); its payload in l->wait_buf */
static bool s3_wait(Radio *r, u8 want, int timeout_ms) {
    struct S3Link *l = r->s3;
    u64 end = now_ms() + (u64)timeout_ms;
    while (now_ms() < end) {
        u8 type;
        const u8 *p;
        size_t len;
        int got = next_msg(l, &type, &p, &len);
        if (got < 0) return false;
        if (!got) { sleep_ms(2); continue; }
        if (type == want) {
            l->wait_len = len < sizeof l->wait_buf ? len : sizeof l->wait_buf;
            memcpy(l->wait_buf, p, l->wait_len);
            return true;
        }
        if (type != S3_RX && type != S3_HELLO) handle_other(r, type, p, len);
    }
    return false;
}

bool s3_radio_open(Radio *r, const char *port, u8 channel, bool filter_all, char *err, size_t errn) {
    struct S3Link *l = calloc(1, sizeof *l);
    if (!l) { snprintf(err, errn, "out of memory"); return false; }
#ifndef _WIN32
    l->fd = -1;
#endif
    r->s3 = l;
    r->qos_data = false;
    r->hw_crypto = true;
    if (port) snprintf(l->port, sizeof l->port, "%s", port);
    else if (!find_port(l->port, sizeof l->port)) {
        snprintf(err, errn, "no ESP32-S3 found (an Espressif USB serial port): plug it in, or --radio s3:<port>");
        s3_radio_close(r);
        return false;
    }
    if (!port_open(l, err, errn)) { s3_radio_close(r); return false; }
    bool hello = false;
    for (int i = 0; i < 3 && !hello; i++) {
        s3_send(l, S3_HELLO_REQ, NULL, 0);
        hello = s3_wait(r, S3_HELLO, 700);
    }
    if (!hello || l->wait_len < sizeof(S3Hello)) {
        snprintf(err, errn, "%s: no answer from the S3 firmware (flashed with s3/? in download mode?)", l->port);
        s3_radio_close(r);
        return false;
    }
    memcpy(&l->hello, l->wait_buf, sizeof l->hello);
    if (l->hello.version != S3_PROTO_VERSION) {
        snprintf(err, errn, "%s: S3 firmware speaks version %u, we %u: flash s3/ again", l->port, l->hello.version,
                 S3_PROTO_VERSION);
        s3_radio_close(r);
        return false;
    }
    memcpy(r->mac, l->hello.ap_mac, 6);
    memcpy(r->sta_mac, l->hello.sta_mac, 6);
    S3Open o = {.channel = channel, .filter = filter_all};
    S3ApDone d = {-1};
    if (!s3_send(l, S3_OPEN, &o, sizeof o) || !s3_wait(r, S3_AP_DONE, 5000) || l->wait_len < sizeof d ||
        (memcpy(&d, l->wait_buf, sizeof d), d.err)) {
        snprintf(err, errn, "%s: the S3 did not start Wi-Fi on channel %u (esp_err 0x%x)", l->port, channel, (unsigned)d.err);
        s3_radio_close(r);
        return false;
    }
    logf_(0, "radio: ESP32-S3 on %s (firmware %.24s, ESP-IDF %.24s), channel %u, BSSID " MAC_FMT ", %s", l->port,
          l->hello.build, l->hello.idf, channel, MAC_ARG(r->mac), filter_all ? "every frame heard" : "frames for us");
    return true;
}

void s3_radio_close(Radio *r) {
    struct S3Link *l = r->s3;
    if (!l) return;
#ifdef _WIN32
    bool open = l->h && l->h != INVALID_HANDLE_VALUE;
#else
    bool open = l->fd >= 0;
#endif
    if (open) {
        s3_send(l, S3_CLOSE, NULL, 0);
        port_close(l);
        logf_(1, "radio: S3 Wi-Fi stopped");
    }
    free(l);
    r->s3 = NULL;
}

bool s3_radio_send_ex(Radio *r, const u8 *frame, size_t n, bool unicast, bool encrypted) {
    (void)encrypted;            /* always as given: the S3 encrypts nothing itself */
    static u8 msg[S3_MAX_PAYLOAD];
    struct S3Link *l = r->s3;
    if (!l || n + sizeof(S3TxHdr) > sizeof msg) return false;
    S3TxHdr h = {.id = l->tx_id++, .flags = unicast ? S3_TX_UNICAST : 0};
    memcpy(msg, &h, sizeof h);
    memcpy(msg + sizeof h, frame, n);
    return s3_send(l, S3_TX, msg, sizeof h + n);
}

bool s3_radio_send_eth(Radio *r, const u8 dest[6], const u8 src[6], u16 ethertype, const u8 *p, size_t n) {
    static u8 msg[S3_MAX_PAYLOAD];
    struct S3Link *l = r->s3;
    if (!l || sizeof(S3TxHdr) + 14 + n > sizeof msg) return false;
    S3TxHdr h = {.id = l->tx_id++, .flags = dest[0] & 1 ? 0 : S3_TX_UNICAST};
    memcpy(msg, &h, sizeof h);
    u8 *e = msg + sizeof h;
    memcpy(e, dest, 6);
    memcpy(e + 6, src, 6);
    e[12] = (u8)(ethertype >> 8);
    e[13] = (u8)ethertype;
    memcpy(e + 14, p, n);
    return s3_send(l, S3_TX_ETH, msg, sizeof h + 14 + n);
}

size_t s3_radio_recv(Radio *r, u8 *buf, size_t cap, const u8 **frame) {
    struct S3Link *l = r->s3;
    if (!l) return 0;
    for (;;) {
        u8 type;
        const u8 *p;
        size_t len;
        int got = next_msg(l, &type, &p, &len);
        if (got <= 0) {
            static bool told;
            if (got < 0 && !told) { told = true; logf_(0, "radio: the S3's port failed (unplugged?)"); }
            return 0;
        }
        if (type != S3_RX) {
            if (!handle_other(r, type, p, len)) logf_(2, "s3: message %02x, %zu bytes", type, len);
            continue;
        }
        if (len < sizeof(S3RxHdr)) continue;
        S3RxHdr h;
        memcpy(&h, p, sizeof h);
        if (h.flags & S3_RX_ERROR) {
            static unsigned logged;
            if (logged++ < 5 && len >= sizeof h + 16)
                logf_(0, "s3: frame %02x%02x from " MAC_FMT " with the hardware's receive error flag (passed on)",
                      p[sizeof h], p[sizeof h + 1], MAC_ARG(p + sizeof h + 10));
        }
        size_t n = len - sizeof h;
        enum { RT = 16 };
        if (n + RT > cap) continue;
        /* radiotap: flags, channel, dBm signal (present bits 1, 3, 5) */
        u16 freq = h.channel == 14 ? 2484 : (u16)(2407 + 5 * h.channel);
        u8 rt[RT] = {0, 0, RT, 0, 0x2A, 0, 0, 0, 0, 0, (u8)freq, (u8)(freq >> 8), 0x80, 0x00, (u8)h.rssi, 0};
        memcpy(buf, rt, RT);
        memcpy(buf + RT, p + sizeof h, n);
        *frame = buf + RT;
        l->rx_count++;
        return n;
    }
}

bool s3_ap_start(Radio *r, const ApConfig *c, char *err, size_t errn) {
    struct S3Link *l = r->s3;
    static const char hex[] = "0123456789abcdef";
    S3Ap a = {.channel = c->channel, .auth = c->open ? S3_AUTH_OPEN : S3_AUTH_WPA2, .hidden = 1, .max_sta = 8,
              .ssid_len = (u8)strlen(c->ssid)};
    memcpy(a.ssid, c->ssid, a.ssid_len);
    /* WPA2: the key's 32 hex digits as the passphrase (the Switch never does the handshake: any will do) */
    for (int i = 0; i < 16; i++) {
        a.pass[2 * i] = hex[c->data_key[i] >> 4];
        a.pass[2 * i + 1] = hex[c->data_key[i] & 15];
    }
    a.pass_len = 32;
    static const u8 nintendo[] = {0x00, 0x22, 0xAA, 0x10, 0x01, 0x02};     /* as a Switch's beacon carries it */
    memcpy(a.vie, nintendo, sizeof nintendo);
    a.vie_len = sizeof nintendo;
    a.ldn = 1;                  /* no 4-way handshake; the data key into the hardware for each station */
    memcpy(a.ldn_key, c->data_key, 16);
    S3ApDone d = {-1};
    if (!s3_send(l, S3_AP, &a, sizeof a) || !s3_wait(r, S3_AP_DONE, 5000) || l->wait_len < sizeof d ||
        (memcpy(&d, l->wait_buf, sizeof d), d.err)) {
        snprintf(err, errn, "S3 AP for %s not started (esp_err 0x%x)", c->ssid, (unsigned)d.err);
        return false;
    }
    l->ap_up = true;
    logf_(0, "ap: S3 SoftAP, channel %u, SSID %s (hidden), %s, %s", c->channel, c->ssid,
          c->open ? "open (no RSN element)" : "WPA2", "no 4-way handshake: the data key in its hardware");
    return true;
}

void s3_ap_stop(Radio *r) {
    struct S3Link *l = r->s3;
    if (!l || !l->ap_up) return;
    s3_send(l, S3_AP_OFF, NULL, 0);
    l->ap_up = false;
    logf_(1, "ap: S3 back to its placeholder AP");
}

bool s3_ap_running(Radio *r) { return r->s3 && r->s3->ap_up; }

bool s3_set_channel(Radio *r, u8 channel, char *err, size_t errn) {
    struct S3Link *l = r->s3;
    S3Open o = {.channel = channel, .filter = 0};
    S3ApDone d = {-1};
    if (!l || !s3_send(l, S3_OPEN, &o, sizeof o) || !s3_wait(r, S3_AP_DONE, 5000) || l->wait_len < sizeof d ||
        (memcpy(&d, l->wait_buf, sizeof d), d.err)) {
        snprintf(err, errn, "the S3 did not move to channel %u (esp_err 0x%x)", channel, (unsigned)d.err);
        return false;
    }
    return true;
}

bool s3_join(Radio *r, u8 channel, const u8 bssid[6], const char *ssid, const u8 key[16], char *err, size_t errn) {
    struct S3Link *l = r->s3;
    S3Join j = {.channel = channel, .ssid_len = (u8)strlen(ssid)};
    memcpy(j.bssid, bssid, 6);
    memcpy(j.ssid, ssid, j.ssid_len > 32 ? 32 : j.ssid_len);
    memcpy(j.ldn_key, key, 16);
    S3ApDone d = {-1};
    if (!l || !s3_send(l, S3_JOIN, &j, sizeof j) || !s3_wait(r, S3_AP_DONE, 5000) || l->wait_len < sizeof d ||
        (memcpy(&d, l->wait_buf, sizeof d), d.err)) {
        snprintf(err, errn, "the S3 did not start joining " MAC_FMT " (esp_err 0x%x)", MAC_ARG(bssid), (unsigned)d.err);
        return false;
    }
    l->ap_up = false;
    return true;
}

void s3_leave(Radio *r) {
    if (r->s3) s3_send(r->s3, S3_LEAVE, NULL, 0);
}

bool s3_send_eth_sta(Radio *r, const u8 dest[6], u16 ethertype, const u8 *p, size_t n) {
    static u8 msg[S3_MAX_PAYLOAD];
    struct S3Link *l = r->s3;
    if (!l || sizeof(S3TxHdr) + 14 + n > sizeof msg) return false;
    S3TxHdr h = {.id = l->tx_id++, .flags = (u8)(S3_TX_STA | (dest[0] & 1 ? 0 : S3_TX_UNICAST))};
    memcpy(msg, &h, sizeof h);
    u8 *e = msg + sizeof h;
    memcpy(e, dest, 6);
    memcpy(e + 6, r->sta_mac, 6);
    e[12] = (u8)(ethertype >> 8);
    e[13] = (u8)ethertype;
    memcpy(e + 14, p, n);
    return s3_send(l, S3_TX_ETH, msg, sizeof h + 14 + n);
}
