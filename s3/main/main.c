/* ldns3: the beacon's radio on an ESP32-S3. A dumb antenna for the desktop's ldnbeacon (src/radio_s3.c), over the
 * S3's own USB port (USB-Serial-JTAG) with the messages of src/s3proto.h:
 *   - a SoftAP gives what the beacon cannot do from the desktop: the hardware's ACKs and retries, Open System
 *     authentication and association (as hostapd did on the laptop). Until the desktop names the network it is a
 *     placeholder (hidden, random SSID and password) so the interface and its MAC (the BSSID) exist from the start;
 *   - promiscuous receive on its channel: every frame for our BSSID, probe requests and Nintendo action frames go to
 *     the desktop raw (still CCMP-encrypted: the Switch uses the LDN data key directly, no 4-way handshake, and the
 *     desktop decrypts it in software);
 *   - raw transmit (esp_wifi_80211_tx): the advertisements, and data frames the desktop has already encrypted.
 * ESP-IDF's log lines go to UART0 and to the desktop (S3_LOG), so the AP's own decisions show in ldnbeacon's log. */
#include "esp_event.h"
#include "esp_idf_version.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_random.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "driver/usb_serial_jtag.h"
#include "nvs_flash.h"
#include "s3proto.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static const char *TAG = "ldns3";

/* ---- messages to the desktop: one queue, one writer task -------------------------------------------------- */
typedef struct Msg {
    uint8_t type;
    uint16_t len;
    uint8_t data[];
} Msg;

static QueueHandle_t outq;
static volatile uint32_t rx_heard, rx_sent, rx_dropped, tx_ok, tx_fail, rx_errors;
static uint32_t usb_rx_bad;

/* never blocks (the Wi-Fi task calls it): a full queue drops the message and counts it */
static bool post2(uint8_t type, const void *a, size_t an, const void *b, size_t bn) {
    if (an + bn > S3_MAX_PAYLOAD) return false;
    Msg *m = malloc(sizeof *m + an + bn);
    if (!m) return false;
    m->type = type;
    m->len = (uint16_t)(an + bn);
    if (an) memcpy(m->data, a, an);
    if (bn) memcpy(m->data + an, b, bn);
    if (xQueueSend(outq, &m, 0) != pdTRUE) {
        free(m);
        return false;
    }
    return true;
}
static bool post(uint8_t type, const void *p, size_t n) { return post2(type, p, n, NULL, 0); }

static void writer_task(void *arg) {
    (void)arg;
    static uint8_t wire[S3_MAX_WIRE];
    for (;;) {
        Msg *m;
        if (xQueueReceive(outq, &m, portMAX_DELAY) != pdTRUE) continue;
        size_t k = s3_encode(m->type, m->data, m->len, wire, sizeof wire);
        free(m);
        /* no desktop reading: the USB FIFO stays full and writes time out; the queue then fills and drops */
        if (k) usb_serial_jtag_write_bytes(wire, k, pdMS_TO_TICKS(50));
    }
}

/* ESP-IDF's log, also to the desktop: the Wi-Fi library writes a line in pieces ("wifi:", then the text), so pieces
 * collect until a newline (one buffer for all tasks: lines from two tasks at once could mix, rarely) */
static vprintf_like_t uart_vprintf;
static portMUX_TYPE log_mux = portMUX_INITIALIZER_UNLOCKED;
static char log_line[240];
static size_t log_len;
static int log_vprintf(const char *fmt, va_list ap) {
    char piece[200];
    va_list ap2;
    va_copy(ap2, ap);
    int n = vsnprintf(piece, sizeof piece, fmt, ap2);
    va_end(ap2);
    if (n > 0 && outq) {
        size_t k = (size_t)n < sizeof piece ? (size_t)n : sizeof piece - 1;
        char out[sizeof piece + sizeof log_line + 8];    /* whole lines, '\n' between them (the desktop splits) */
        size_t out_len = 0;
        taskENTER_CRITICAL(&log_mux);
        for (size_t i = 0; i < k; i++) {
            char c = piece[i];
            if (c == '\r') continue;
            if (c == '\n' || log_len == sizeof log_line) {
                if (log_len && out_len + 1 + log_len <= sizeof out) {
                    if (out_len) out[out_len++] = '\n';
                    memcpy(out + out_len, log_line, log_len);
                    out_len += log_len;
                }
                log_len = 0;
                if (c == '\n') continue;
            }
            log_line[log_len++] = c;
        }
        taskEXIT_CRITICAL(&log_mux);
        if (out_len) post(S3_LOG, out, out_len);
    }
    return uart_vprintf ? uart_vprintf(fmt, ap) : n;
}

static void logline(const char *fmt, ...) {
    char line[200];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    if (n > 0) post(S3_LOG, line, (size_t)n < sizeof line ? (size_t)n : sizeof line - 1);
}

/* ---- LDN stations: no 4-way handshake, the data key in the hardware --------------------------------------------
 * A Switch associates and at once uses the network's data key as its CCMP key (pairwise and group). ESP-IDF's AP
 * authenticator (wpa_supplicant/src/ap/wpa_auth.c, built from source) would send 4-way message 1 four times and then
 * deauthenticate it; and esp_wifi_80211_tx refuses frames with the Protected bit (bench, 2026-11-07: ESP_ERR_INVALID_ARG),
 * so the desktop cannot send frames it encrypted itself. So in LDN mode the link wraps two of its functions
 * (main/CMakeLists.txt: -Wl,--wrap): no 4-way handshake is started, and when the station has associated the data key
 * goes into the hardware for it (index 0) and for the group (index 1) and the station is authorized; the desktop then
 * sends plain Ethernet frames (S3_TX_ETH) through the normal data path and the hardware encrypts them. Receiving is
 * unchanged: promiscuous frames, decrypted on the desktop. */
#include "esp_private/wifi.h"
struct sta_info;
struct wpa_authenticator;
struct wpa_state_machine;
extern int esp_wifi_set_ap_key_internal(int alg, const uint8_t *addr, int idx, uint8_t *key, size_t key_len);
extern bool esp_wifi_wpa_ptk_init_done_internal(uint8_t *mac);
#define ALG_CCMP 3                                  /* esp_wifi_driver.h's WIFI_WPA_ALG_CCMP */

static volatile bool ldn_mode;
static uint8_t ldn_key[16];

int __real_wpa_auth_sta_associated(struct wpa_authenticator *wpa_auth, struct wpa_state_machine *sm);
int __wrap_wpa_auth_sta_associated(struct wpa_authenticator *wpa_auth, struct wpa_state_machine *sm) {
    if (ldn_mode) return 0;                         /* no 4-way handshake: the keys go in from key_task */
    return __real_wpa_auth_sta_associated(wpa_auth, sm);
}

/* With WPA2, ESP-IDF sends WIFI_EVENT_AP_STACONNECTED only once the 4-way handshake is done, so with none it never
 * comes (first Switch run, 2026-11-07: associated, no event, no key, its frames failed decryption in the hardware and
 * it left after 1.07 s). So the association itself (hostap_new_assoc_sta: `bssid` is the station's address) hands
 * the station to key_task, which installs the keys shortly after (the association response first). */
static QueueHandle_t keyq;
bool __real_hostap_new_assoc_sta(struct sta_info *sta, uint8_t *bssid, uint8_t *wpa_ie, uint8_t wpa_ie_len,
                                 uint8_t *rsnxe, uint16_t rsnxe_len, bool *pmf_enable, int subtype,
                                 uint8_t *pairwise_cipher, uint8_t *reason);
bool __wrap_hostap_new_assoc_sta(struct sta_info *sta, uint8_t *bssid, uint8_t *wpa_ie, uint8_t wpa_ie_len,
                                 uint8_t *rsnxe, uint16_t rsnxe_len, bool *pmf_enable, int subtype,
                                 uint8_t *pairwise_cipher, uint8_t *reason) {
    bool ok = __real_hostap_new_assoc_sta(sta, bssid, wpa_ie, wpa_ie_len, rsnxe, rsnxe_len, pmf_enable, subtype,
                                          pairwise_cipher, reason);
    if (ok && ldn_mode && bssid && keyq) {
        uint8_t mac[6];
        memcpy(mac, bssid, 6);
        xQueueSend(keyq, mac, 0);
    }
    return ok;
}

static void ldn_station_keys(const uint8_t mac[6]);
static void key_task(void *arg) {
    (void)arg;
    for (;;) {
        uint8_t mac[6];
        if (xQueueReceive(keyq, mac, portMAX_DELAY) != pdTRUE) continue;
        vTaskDelay(pdMS_TO_TICKS(10));
        ldn_station_keys(mac);
    }
}

static void ldn_station_keys(const uint8_t mac[6]) {
    static const uint8_t bcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t m[6], k1[16], k2[16];
    memcpy(m, mac, 6);
    memcpy(k1, ldn_key, 16);
    memcpy(k2, ldn_key, 16);
    int e1 = esp_wifi_set_ap_key_internal(ALG_CCMP, m, 0, k1, 16);
    int e2 = esp_wifi_set_ap_key_internal(ALG_CCMP, bcast, 1, k2, 16);
    bool ok = esp_wifi_wpa_ptk_init_done_internal(m);
    ESP_LOGI(TAG, "ldn: station " MACSTR ": data key installed (pairwise %d, group %d), authorized %d", MAC2STR(mac), e1, e2, ok);
    S3Sta s = {.joined = 1};                        /* the desktop's "joined": no STACONNECTED event comes */
    memcpy(s.mac, mac, 6);
    post(S3_STA, &s, sizeof s);
}

/* ---- the radio ---------------------------------------------------------------------------------------------- */
static uint8_t bssid[6];
static volatile uint8_t filter_all;
static bool wifi_on;
static uint8_t cur_channel = 6;
static uint8_t vie_buf[2 + 32];

/* frames the desktop wants (S3_FILTER 0): anything naming our BSSID, probe requests, Nintendo action frames */
static bool wanted(const uint8_t *f, size_t n) {
    if (filter_all) return true;
    if (n < 24) return false;
    uint8_t type = (f[0] >> 2) & 3, sub = f[0] >> 4;
    if (!memcmp(f + 4, bssid, 6) || !memcmp(f + 16, bssid, 6) || !memcmp(f + 10, bssid, 6)) return true;
    if (type == 0 && sub == 4) return true;
    if (type == 0 && sub == 13 && n >= 28 && f[24] == 0x7F && f[25] == 0x00 && f[26] == 0x22 && f[27] == 0xAA) return true;
    return false;
}

static void promisc_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;
    const wifi_promiscuous_pkt_t *p = buf;
    rx_heard++;
    size_t n = p->rx_ctrl.sig_len;
    if (n < 4 + 10) return;
    n -= 4;                                                 /* the FCS */
    if (!wanted(p->payload, n)) return;
    if (p->rx_ctrl.rx_state) rx_errors++;                   /* receive error: passed on, flagged */
    S3RxHdr h = {.time_us = p->rx_ctrl.timestamp, .rssi = (int8_t)p->rx_ctrl.rssi, .channel = p->rx_ctrl.channel,
                 .rate = p->rx_ctrl.rate, .flags = p->rx_ctrl.rx_state ? S3_RX_ERROR : 0};
    if (post2(S3_RX, &h, sizeof h, p->payload, n)) rx_sent++;
    else rx_dropped++;
}

static void on_wifi_event(void *arg, esp_event_base_t base, int32_t id, void *data) {
    (void)arg;
    (void)base;
    S3Sta s = {0};
    if (id == WIFI_EVENT_AP_STACONNECTED) {
        const wifi_event_ap_staconnected_t *e = data;
        s.joined = 1;
        memcpy(s.mac, e->mac, 6);
        s.aid = e->aid;
    } else if (id == WIFI_EVENT_AP_STADISCONNECTED) {
        const wifi_event_ap_stadisconnected_t *e = data;
        memcpy(s.mac, e->mac, 6);
        s.aid = e->aid;
        s.reason = e->reason;
    } else
        return;
    post(S3_STA, &s, sizeof s);
}

static esp_err_t set_vendor_ie(const uint8_t *body, size_t n) {
    static const wifi_vendor_ie_type_t types[] = {WIFI_VND_IE_TYPE_BEACON, WIFI_VND_IE_TYPE_PROBE_RESP,
                                                  WIFI_VND_IE_TYPE_ASSOC_RESP};
    static bool set;
    esp_err_t err = ESP_OK;
    if (set)
        for (int i = 0; i < 3; i++) esp_wifi_set_vendor_ie(false, types[i], WIFI_VND_IE_ID_0, vie_buf);
    set = false;
    if (!n) return ESP_OK;
    if (n < 4 || n > 32) return ESP_ERR_INVALID_ARG;
    vie_buf[0] = 0xDD;                                      /* vendor_ie_data_t: id, length, OUI, OUI type, data */
    vie_buf[1] = (uint8_t)n;
    memcpy(vie_buf + 2, body, n);
    for (int i = 0; i < 3 && err == ESP_OK; i++) err = esp_wifi_set_vendor_ie(true, types[i], WIFI_VND_IE_ID_0, vie_buf);
    set = err == ESP_OK;
    return err;
}

static esp_err_t ap_config(const S3Ap *a) {
    wifi_config_t c = {0};
    memcpy(c.ap.ssid, a->ssid, a->ssid_len > 32 ? 32 : a->ssid_len);
    c.ap.ssid_len = a->ssid_len > 32 ? 32 : a->ssid_len;
    c.ap.channel = a->channel;
    c.ap.ssid_hidden = a->hidden;
    c.ap.max_connection = a->max_sta ? (a->max_sta > 10 ? 10 : a->max_sta) : 4;
    c.ap.beacon_interval = 100;
    if (a->auth == S3_AUTH_WPA2) {
        c.ap.authmode = WIFI_AUTH_WPA2_PSK;
        c.ap.pairwise_cipher = WIFI_CIPHER_TYPE_CCMP;
        memcpy(c.ap.password, a->pass, a->pass_len > 64 ? 64 : a->pass_len);
    } else
        c.ap.authmode = WIFI_AUTH_OPEN;
    c.ap.pmf_cfg.required = false;
    ldn_mode = a->ldn;
    memcpy(ldn_key, a->ldn_key, 16);
    esp_err_t err = esp_wifi_set_config(WIFI_IF_AP, &c);
    if (err == ESP_OK) err = set_vendor_ie(a->vie, a->vie_len);
    if (err == ESP_OK) cur_channel = a->channel;
    return err;
}

static esp_err_t placeholder(uint8_t channel) {
    S3Ap a = {.channel = channel, .auth = S3_AUTH_WPA2, .hidden = 1, .max_sta = 1, .ssid_len = 32, .pass_len = 32};
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        a.ssid[i] = hex[esp_random() & 15];
        a.pass[i] = hex[esp_random() & 15];
    }
    return ap_config(&a);
}

static esp_err_t wifi_open(const S3Open *o) {
    filter_all = o->filter;
    esp_err_t err = ESP_OK;
    if (!wifi_on) {
        err = esp_wifi_set_mode(WIFI_MODE_AP);
        if (err == ESP_OK) err = placeholder(o->channel);
        if (err == ESP_OK) err = esp_wifi_start();
        if (err != ESP_OK) return err;
        esp_wifi_set_ps(WIFI_PS_NONE);
        wifi_promiscuous_filter_t f = {.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA};
        esp_wifi_set_promiscuous_filter(&f);
        esp_wifi_set_promiscuous_rx_cb(promisc_cb);
        err = esp_wifi_set_promiscuous(true);
        wifi_on = err == ESP_OK;
    } else
        err = placeholder(o->channel);
    logline("open: channel %u, filter %s: %s", o->channel, o->filter ? "everything" : "ours", esp_err_to_name(err));
    return err;
}

static void wifi_close(void) {
    if (!wifi_on) return;
    esp_wifi_set_promiscuous(false);
    set_vendor_ie(NULL, 0);
    esp_wifi_stop();
    wifi_on = false;
    logline("closed");
}

static void send_hello(void) {
    S3Hello h = {.version = S3_PROTO_VERSION};
    memcpy(h.ap_mac, bssid, 6);
    snprintf(h.build, sizeof h.build, "%s %s", __DATE__, __TIME__);
    snprintf(h.idf, sizeof h.idf, "%s", esp_get_idf_version());
    post(S3_HELLO, &h, sizeof h);
}

static void handle(uint8_t type, const uint8_t *p, size_t n) {
    switch (type) {
    case S3_HELLO_REQ:
        send_hello();
        break;
    case S3_OPEN:
        if (n >= sizeof(S3Open)) {
            S3Open o;
            memcpy(&o, p, sizeof o);
            esp_err_t err = wifi_open(&o);
            S3ApDone d = {err};
            post(S3_AP_DONE, &d, sizeof d);
        }
        break;
    case S3_AP:
        if (n >= sizeof(S3Ap)) {
            S3Ap a;
            memcpy(&a, p, sizeof a);
            esp_err_t err = wifi_on ? ap_config(&a) : ESP_ERR_WIFI_NOT_STARTED;
            logline("ap: \"%.*s\" channel %u, %s%s%s, vendor element %u bytes: %s", a.ssid_len, a.ssid, a.channel,
                    a.auth == S3_AUTH_WPA2 ? "WPA2" : "open", a.hidden ? ", hidden" : "",
                    a.ldn ? ", LDN (no 4-way handshake, data key in hardware)" : "", a.vie_len, esp_err_to_name(err));
            S3ApDone d = {err};
            post(S3_AP_DONE, &d, sizeof d);
        }
        break;
    case S3_AP_OFF:
        if (wifi_on) placeholder(cur_channel);
        break;
    case S3_TX:
        if (n > sizeof(S3TxHdr) && wifi_on) {
            S3TxHdr h;
            memcpy(&h, p, sizeof h);
            esp_err_t err = esp_wifi_80211_tx(WIFI_IF_AP, p + sizeof h, (int)(n - sizeof h), true);
            if (err == ESP_OK) tx_ok++;
            else {
                tx_fail++;
                S3TxFail f = {h.id, err};
                post(S3_TX_FAIL, &f, sizeof f);
            }
        }
        break;
    case S3_TX_ETH:
        if (n >= sizeof(S3TxHdr) + 14 && wifi_on) {
            S3TxHdr h;
            memcpy(&h, p, sizeof h);
            static uint8_t eth[S3_MAX_PAYLOAD];
            memcpy(eth, p + sizeof h, n - sizeof h);
            int err = esp_wifi_internal_tx(WIFI_IF_AP, eth, (uint16_t)(n - sizeof h));
            if (err == ESP_OK) tx_ok++;
            else {
                tx_fail++;
                S3TxFail f = {h.id, err};
                post(S3_TX_FAIL, &f, sizeof f);
            }
        }
        break;
    case S3_FILTER:
        if (n >= 1) filter_all = p[0];
        break;
    case S3_CLOSE:
        wifi_close();
        break;
    default:
        logline("unknown message %02x (%u bytes)", type, (unsigned)n);
    }
}

static void reader_task(void *arg) {
    (void)arg;
    static S3Dec dec;
    static uint8_t in[512];
    for (;;) {
        int k = usb_serial_jtag_read_bytes(in, sizeof in, pdMS_TO_TICKS(20));
        size_t off = 0;
        while (k > 0 && off < (size_t)k) {
            uint8_t type;
            const uint8_t *p;
            size_t len;
            off += s3_decode(&dec, in + off, (size_t)k - off, &type, &p, &len);
            if (len != SIZE_MAX) handle(type, p, len);
        }
        usb_rx_bad = dec.bad;
    }
}

static void stats_task(void *arg) {
    (void)arg;
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(2000));
        if (!wifi_on) continue;
        S3Stats s = {rx_heard, rx_sent, rx_dropped, tx_ok, tx_fail, usb_rx_bad, esp_get_free_heap_size(), rx_errors};
        post(S3_STATS, &s, sizeof s);
    }
}

void app_main(void) {
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }
    usb_serial_jtag_driver_config_t uc = {.tx_buffer_size = 16384, .rx_buffer_size = 8192};
    ESP_ERROR_CHECK(usb_serial_jtag_driver_install(&uc));
    outq = xQueueCreate(48, sizeof(Msg *));
    keyq = xQueueCreate(8, 6);
    xTaskCreatePinnedToCore(key_task, "ldn_keys", 3072, NULL, 4, NULL, 1);
    uart_vprintf = esp_log_set_vprintf(log_vprintf);
    xTaskCreatePinnedToCore(writer_task, "usb_tx", 4096, NULL, 5, NULL, 1);

    ESP_ERROR_CHECK(esp_event_loop_create_default());
    wifi_init_config_t wc = WIFI_INIT_CONFIG_DEFAULT();
    wc.nvs_enable = 0;
    ESP_ERROR_CHECK(esp_wifi_init(&wc));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, on_wifi_event, NULL));
    esp_read_mac(bssid, ESP_MAC_WIFI_SOFTAP);

    xTaskCreatePinnedToCore(reader_task, "usb_rx", 4096, NULL, 6, NULL, 1);
    xTaskCreatePinnedToCore(stats_task, "stats", 3072, NULL, 3, NULL, 1);
    ESP_LOGI(TAG, "ldns3 up, BSSID " MACSTR ", ESP-IDF %s", MAC2STR(bssid), esp_get_idf_version());
    send_hello();
}
