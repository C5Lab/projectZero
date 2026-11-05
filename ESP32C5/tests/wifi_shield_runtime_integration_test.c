#include "wifi_security_runtime.h"
#include "csa_detector_core.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

/* DETECTOR ENUM */
typedef enum { WIFI_PKT_MGMT, WIFI_PKT_DATA, WIFI_PKT_MISC } wifi_promiscuous_pkt_type_t;
typedef struct {
    uint16_t sig_len;
    int8_t rssi;
    uint8_t channel;
    uint32_t timestamp;
    uint16_t dump_len;
    uint32_t rx_state;
} rx_ctrl_t;
typedef struct { rx_ctrl_t rx_ctrl; uint8_t payload[1604]; } wifi_promiscuous_pkt_t;
static struct {
    wifi_security_runtime_t *runtime;
    struct { wifi_security_session_config_t config; } session;
    uint32_t callback_generation;
    bool worker_stop;
} security_platform;
static unsigned notifications, lock_depth, full_calls, compact_calls;
static bool in_callback, stop_from_consumer;
static uint16_t last_length;
static uint64_t last_full_timestamp;
static wifi_shield_compact_event_t last_event;
static wifi_shield_compact_kind_t compact_order[64];
static char lane_order[100];
static unsigned lane_calls;
static size_t expected_auth_offset, expected_auth_length;
static int64_t monotonic_time_us = 123;
int64_t esp_timer_get_time(void) { return monotonic_time_us; }
static void security_enter(void *ctx) { (void)ctx; assert(lock_depth++ == 0); }
static void security_leave(void *ctx) { (void)ctx; assert(--lock_depth == 0); }
static void security_notify(void *ctx) { (void)ctx; assert(lock_depth == 0); ++notifications; }
/* EXTRACTED CALLBACK */

static bool full_consume(void *ctx, const wifi_security_frame_slot_t *slot,
                         const wifi_security_decoded_t *decoded)
{
    (void)ctx;
    assert(!in_callback && lock_depth == 0);
    assert(slot->generation == security_platform.callback_generation);
    if (expected_auth_offset != 0) {
        assert(decoded->kind == WIFI_SEC_FRAME_AUTH);
        assert(decoded->body == slot->bytes + expected_auth_offset);
        assert(decoded->body_len == expected_auth_length);
        assert(decoded->body[0] == 3 && decoded->body[1] == 0);
    }
    last_length = slot->captured_len;
    last_full_timestamp = slot->timestamp_us;
    lane_order[lane_calls++] = 'F';
    ++full_calls;
    return true;
}
static bool compact_consume(void *ctx, const wifi_shield_compact_event_t *event)
{
    (void)ctx;
    assert(!in_callback && lock_depth == 0);
    assert(event->generation == security_platform.callback_generation);
    last_event = *event;
    compact_order[compact_calls] = event->kind;
    lane_order[lane_calls++] = 'C';
    ++compact_calls;
    if (stop_from_consumer) {
        wifi_security_runtime_request_stop(security_platform.runtime);
        assert(!wifi_security_runtime_finish(security_platform.runtime));
        assert(wifi_security_runtime_drain(security_platform.runtime) == 0);
    }
    return true;
}
static void send_frame(uint8_t fc, uint16_t length, uint16_t algorithm, bool csa)
{
    wifi_promiscuous_pkt_t p = {.rx_ctrl = {length + 4, -42, 6, 123}};
    p.payload[0] = fc;
    p.payload[4] = 4; /* Distinct station; addr2/addr3 identify the AP. */
    p.payload[10] = p.payload[16] = 2;
    p.payload[24] = (uint8_t)algorithm;
    p.payload[25] = (uint8_t)(algorithm >> 8);
    if (csa) {
        unsigned offset = fc == 0xd0 ? 26 : (length > 64 ? 80 : 36);
        if (fc == 0xd0) { p.payload[24] = 0; p.payload[25] = 4; }
        /* Long beacon: vendor IE before CSA, never truncate it into evidence. */
        if (offset == 80) { p.payload[36] = 221; p.payload[37] = 42; }
        p.payload[offset] = 37; p.payload[offset + 1] = 3;
        p.payload[offset + 2] = 1; p.payload[offset + 3] = 11;
        p.payload[offset + 4] = 2;
    }
    in_callback = true;
    wifi_security_promiscuous_callback(&p, (fc & 12) == 8 ? WIFI_PKT_DATA : WIFI_PKT_MGMT);
    in_callback = false;
    memset(&p, 0, sizeof(p));
}
static void send_eapol_frame(void)
{
    static const uint8_t snap[] = {
        0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e
    };
    wifi_promiscuous_pkt_t p = {.rx_ctrl = {84, -42, 6, 123}};
    p.payload[0] = 0x08;
    p.payload[4] = 4;
    p.payload[10] = p.payload[16] = 2;
    memcpy(p.payload + 24, snap, sizeof(snap));
    in_callback = true;
    wifi_security_promiscuous_callback(&p, WIFI_PKT_DATA);
    in_callback = false;
    memset(&p, 0, sizeof(p));
}
static wifi_security_runtime_status_t snapshot(void)
{
    wifi_security_runtime_status_t s;
    wifi_security_runtime_get_status(security_platform.runtime, &s);
    return s;
}
int main(int argc, char **argv)
{
    wifi_security_runtime_t runtime;
    wifi_shield_compact_event_t storage[24];
    wifi_security_runtime_hooks_t hooks = {NULL, security_enter, security_leave, security_notify};
    assert(wifi_security_runtime_init(&runtime, &hooks, 8));
    assert(wifi_security_runtime_bind_compact(&runtime, storage, compact_consume, NULL));
    wifi_security_runtime_config_t config = {WIFI_SECURITY_MODULE_SHIELD, 7, NULL, full_consume};
    assert(wifi_security_runtime_start(&runtime, &config));
    security_platform.runtime = &runtime;
    security_platform.callback_generation = 7;
    assert(!wifi_security_runtime_bind_compact(&runtime, storage, compact_consume, NULL));

    if (argc == 2 && strcmp(argv[1], "clock-domain") == 0) {
        monotonic_time_us = 5000000;
        send_frame(0xc0, 26, 0, false);
        send_eapol_frame();
        assert(wifi_security_runtime_drain(&runtime) == 2);
        /* A raw driver timestamp can wrap and is not comparable with the
         * monotonic Defence clock used after TX. */
        assert(last_event.rx_us == 5000000);
        assert(last_full_timestamp == 5000000);
        wifi_security_runtime_request_stop(&runtime);
        assert(wifi_security_runtime_finish(&runtime));
        puts("PASS: Shield two bounded RX lanes");
        return 0;
    }

    if (argc == 2) {
        bool ht_control = strcmp(argv[1], "ht-sae") == 0;
        expected_auth_offset = ht_control ? 28 : 24;
        /* Both algorithm bytes suffice for SAE evidence: an incomplete
         * transaction/status body must reach the worker's anomaly parser. */
        for (unsigned body_length = 2; body_length <= 6; ++body_length) {
            wifi_promiscuous_pkt_t p = {
                .rx_ctrl = {(uint16_t)(expected_auth_offset + body_length + 4), -42, 6, 123}
            };
            p.payload[0] = 0xb0;
            p.payload[1] = ht_control ? 0x80 : 0;
            p.payload[4] = 4;
            p.payload[10] = p.payload[16] = 2;
            p.payload[expected_auth_offset] = 3;
            expected_auth_length = body_length;
            unsigned before_calls = full_calls;
            in_callback = true;
            wifi_security_promiscuous_callback(&p, WIFI_PKT_MGMT);
            in_callback = false;
            assert(runtime.queue_count == 1 && runtime.compact_count == 0);
            assert(full_calls == before_calls);
            assert(wifi_security_runtime_drain(&runtime) == 1);
            assert(full_calls == before_calls + 1 && compact_calls == 0);
        }
        /* Bytes in the HT-Control field are not the authentication algorithm. */
        if (ht_control) {
            wifi_promiscuous_pkt_t p = {.rx_ctrl = {38, -42, 6, 123}};
            p.payload[0] = 0xb0;
            p.payload[1] = 0x80;
            p.payload[4] = 4;
            p.payload[10] = p.payload[16] = 2;
            p.payload[24] = 3;
            in_callback = true;
            wifi_security_promiscuous_callback(&p, WIFI_PKT_MGMT);
            in_callback = false;
            assert(runtime.queue_count == 0 && runtime.compact_count == 1);
            assert(wifi_security_runtime_drain(&runtime) == 1);
            assert(last_event.kind == WIFI_SHIELD_COMPACT_AUTH);
        }
        wifi_security_runtime_request_stop(&runtime);
        assert(wifi_security_runtime_finish(&runtime));
        puts("PASS: Shield two bounded RX lanes");
        return 0;
    }

    /* Ordinary channel traffic must not consume the eight full-frame slots or
     * become RX_DROPS. Only an EAPOL candidate belongs in Shield's DATA lane. */
    for (unsigned i = 0; i < 128; ++i)
        send_frame(0x08, 80, 0, false);
    assert(runtime.queue_count == 0 && snapshot().rx_drops == 0);
    send_eapol_frame();
    assert(runtime.queue_count == 1 && snapshot().rx_drops == 0);
    assert(wifi_security_runtime_drain(&runtime) == 1 && full_calls == 1);
    full_calls = compact_calls = lane_calls = notifications = 0;
    memset(lane_order, 0, sizeof(lane_order));

    /* Each frame has one owner; SAE auth has full-frame priority. */
    send_frame(0xc0, 26, 0, false);
    send_frame(0xa0, 26, 0, false);
    send_frame(0xb0, 30, 0, false);
    send_frame(0x00, 28, 0, false);
    send_frame(0x20, 34, 0, false);
    send_frame(0xd0, 31, 0, true);
    send_frame(0x80, 41, 0, true);
    assert(runtime.compact_count == 7 && runtime.queue_count == 0);
    send_frame(0xb0, 40, 3, false); /* SAE */
    send_eapol_frame(); /* WPS/EAPOL candidate */
    send_frame(0x80, 36, 0, false); /* Trust/WPS beacon */
    send_frame(0x50, 36, 0, false); /* Trust/WPS probe */
    send_frame(0x80, 85, 0, true); /* CSA IE outside compact prefix */
    assert(runtime.compact_count == 7 && runtime.queue_count == 5);
    assert(full_calls == 0 && compact_calls == 0 && notifications == 1);
    assert(wifi_security_runtime_drain(&runtime) == 12);
    assert(full_calls == 5 && compact_calls == 7 && last_length == 85);
    const wifi_shield_compact_kind_t expected[] = {
        WIFI_SHIELD_COMPACT_DEAUTH, WIFI_SHIELD_COMPACT_DISASSOC,
        WIFI_SHIELD_COMPACT_AUTH, WIFI_SHIELD_COMPACT_ASSOC,
        WIFI_SHIELD_COMPACT_REASSOC, WIFI_SHIELD_COMPACT_CSA, WIFI_SHIELD_COMPACT_CSA
    };
    assert(memcmp(compact_order, expected, sizeof(expected)) == 0);
    assert(memcmp(lane_order, "CFCFCFCFCFCC", 12) == 0);
    assert(last_event.kind == WIFI_SHIELD_COMPACT_CSA && last_event.length == 41);
    assert(last_event.rx_us == 123 && last_event.rssi == -42 && last_event.channel == 6);
    assert(last_event.bssid[0] == 2 && last_event.station[0] == 4);
    csa_event_t csa;
    assert(csa_parse(last_event.bytes, last_event.length, 6, -42, &csa));
    assert(csa.target_channel == 11);

    /* Deauth-family cap leaves 8 entries even with full-frame exhaustion. */
    for (unsigned i = 0; i < 16; ++i) send_frame(i & 1 ? 0xa0 : 0xc0, 26, 0, false);
    send_frame(0xc0, 26, 0, false);
    assert(runtime.compact_count == 16 && snapshot().rx_drops == 1);
    for (unsigned i = 0; i < 8; ++i) send_eapol_frame();
    send_eapol_frame();
    assert(runtime.compact_count == 16 && snapshot().dropped_pool == 1 && snapshot().rx_drops == 2);
    for (unsigned i = 0; i < 8; ++i) send_frame(0xb0, 30, 0, false);
    send_frame(0x00, 28, 0, false);
    assert(runtime.compact_count == 24 && snapshot().rx_drops == 3);
    unsigned before = notifications;
    security_worker_stop(NULL);
    assert(security_platform.worker_stop && notifications == before + 1);
    wifi_security_runtime_request_stop(&runtime);
    assert(!wifi_security_runtime_finish(&runtime));
    stop_from_consumer = true;
    assert(wifi_security_runtime_drain(&runtime) == 32);
    assert(wifi_security_runtime_finish(&runtime));
    for (size_t i = 0; i < sizeof(storage); ++i) assert(((unsigned char *)storage)[i] == 0);

    assert(wifi_security_runtime_bind_compact(&runtime, storage, compact_consume, NULL));
    config.generation = 8;
    assert(wifi_security_runtime_start(&runtime, &config));
    send_frame(0xc0, 26, 0, false);
    send_eapol_frame();
    assert(runtime.compact_count == 0 && runtime.queue_count == 0);
    assert(snapshot().stale_generation == 2);
    security_platform.callback_generation = 8;
    wifi_security_runtime_close_callbacks(&runtime);
    send_frame(0xc0, 26, 0, false);
    send_eapol_frame();
    assert(runtime.compact_count == 0 && runtime.queue_count == 0);
    wifi_security_runtime_request_stop(&runtime);
    assert(wifi_security_runtime_finish(&runtime));

    /* Existing identities still receive all MGMT/DATA bytes unchanged. */
    stop_from_consumer = false;
    for (unsigned module = 1; module <= 3; ++module) {
        config.module = (wifi_security_module_t)module;
        config.generation = 8 + module;
        security_platform.callback_generation = config.generation;
        assert(wifi_security_runtime_start(&runtime, &config));
        send_frame(0xc0, 26, 0, false);
        send_frame(0x08, 1600, 0, false);
        assert(runtime.queue_count == 2 && runtime.compact_count == 0);
        assert(wifi_security_runtime_drain(&runtime) == 2 && last_length == 1536);
        assert(snapshot().truncated == 1);
        wifi_security_runtime_request_stop(&runtime);
        assert(wifi_security_runtime_finish(&runtime));
    }
    /* Missing caller storage is a visible bounded drop, never fallback allocation. */
    config.module = WIFI_SECURITY_MODULE_SHIELD;
    config.generation = 12;
    security_platform.callback_generation = 12;
    assert(wifi_security_runtime_start(&runtime, &config));
    send_frame(0xc0, 26, 0, false);
    assert(runtime.compact_count == 0 && snapshot().rx_drops == 1);
    runtime.status.rx_drops = UINT32_MAX;
    send_frame(0xc0, 26, 0, false);
    assert(snapshot().rx_drops == UINT32_MAX);
    send_eapol_frame();
    assert(wifi_security_runtime_drain(&runtime) == 1);
    wifi_security_runtime_request_stop(&runtime);
    assert(wifi_security_runtime_finish(&runtime));
    puts("PASS: Shield two bounded RX lanes");
    return 0;
}
