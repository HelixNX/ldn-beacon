/* radio.h's dispatch to the backend in use */
#include "radio.h"
#ifdef __linux__
#include "ap.h"
#endif

bool radio_open(Radio *r, const char *spec, u8 channel, bool filter_all, char *err, size_t errn) {
    memset(r, 0, sizeof *r);
    r->fd = -1;
#ifdef __linux__
    if (!spec) spec = s3_radio_present() ? "s3" : "wifi";
#else
    if (!spec) spec = "s3";
#endif
    const char *colon = strchr(spec, ':');
    size_t kn = colon ? (size_t)(colon - spec) : strlen(spec);
    const char *arg = colon && colon[1] ? colon + 1 : NULL;
    if (kn == 2 && !memcmp(spec, "s3", 2)) {
        r->kind = RADIO_S3;
        return s3_radio_open(r, arg, channel, filter_all, err, errn);
    }
    if (kn == 4 && !memcmp(spec, "wifi", 4)) {
#ifdef __linux__
        r->kind = RADIO_WIFI;
        r->qos_data = true;
        return linux_radio_open(r, arg, channel, err, errn);
#else
        snprintf(err, errn, "the built-in Wi-Fi radio is Linux only: on Windows plug in the ESP32-S3 (--radio s3)");
        return false;
#endif
    }
    snprintf(err, errn, "unknown radio \"%s\" (s3[:port] or wifi[:iface])", spec);
    return false;
}

void radio_close(Radio *r) {
    if (r->kind == RADIO_S3) s3_radio_close(r);
#ifdef __linux__
    else linux_radio_close(r);
#endif
}

bool radio_send(Radio *r, const u8 *frame, size_t n) { return radio_send_ex(r, frame, n, false, false); }

bool radio_send_ex(Radio *r, const u8 *frame, size_t n, bool unicast, bool encrypted) {
    if (r->kind == RADIO_S3) return s3_radio_send_ex(r, frame, n, unicast, encrypted);
#ifdef __linux__
    return linux_radio_send_ex(r, frame, n, unicast, encrypted);
#else
    return false;
#endif
}

bool radio_send_eth(Radio *r, const u8 dest[6], const u8 src[6], u16 ethertype, const u8 *p, size_t n) {
    return r->kind == RADIO_S3 && s3_radio_send_eth(r, dest, src, ethertype, p, n);
}

size_t radio_recv(Radio *r, u8 *buf, size_t cap, const u8 **frame) {
    if (r->kind == RADIO_S3) return s3_radio_recv(r, buf, cap, frame);
#ifdef __linux__
    return linux_radio_recv(r, buf, cap, frame);
#else
    return 0;
#endif
}

bool radio_ap_start(Radio *r, const ApConfig *c, char *err, size_t errn) {
    if (r->kind == RADIO_S3) return s3_ap_start(r, c, err, errn);
#ifdef __linux__
    Ap a = {0};
    bool ok = ap_start(&a, r->iface, c->ssid, c->channel, c->data_key, c->psk_mode, c->log_path, err, errn);
    r->ap_pid = a.pid;
    return ok;
#else
    snprintf(err, errn, "no AP on this radio");
    return false;
#endif
}

void radio_ap_stop(Radio *r) {
    if (r->kind == RADIO_S3) { s3_ap_stop(r); return; }
#ifdef __linux__
    Ap a = {r->ap_pid};
    ap_stop(&a);
    r->ap_pid = a.pid;
#endif
}

bool radio_ap_running(Radio *r) {
    if (r->kind == RADIO_S3) return s3_ap_running(r);
#ifdef __linux__
    Ap a = {r->ap_pid};
    bool ok = ap_running(&a);
    r->ap_pid = a.pid;
    return ok;
#else
    return false;
#endif
}
