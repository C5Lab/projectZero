"""Build and execute the portable runtime with the real bounded decoder."""
from pathlib import Path
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from test_sniffer_extended import function

ROOT = Path(__file__).resolve().parents[1]


def wsl_path(path):
    path = Path(path).resolve()
    return f"/mnt/{path.drive.rstrip(':').lower()}/{path.relative_to(path.anchor).as_posix()}"


class WifiSecurityRuntimeTest(unittest.TestCase):
    def test_runtime_sanitizer_builders_are_fatal(self):
        source = Path(__file__).read_text(encoding="utf-8")
        blocks = re.findall(
            r'if os\.environ\.get\("JANOS_TEST_SANITIZERS"\):\s*'
            r'flags \+= \[(.*?)\]', source, flags=re.S)
        self.assertEqual(len(blocks), 2)
        self.assertTrue(all('"-fno-sanitize-recover=all"' in block
                            for block in blocks))

    def test_shield_runtime_identity_exists(self):
        header = (ROOT / "main/wifi_security_runtime.h").read_text(encoding="utf-8")
        self.assertTrue("WIFI_SECURITY_MODULE_SHIELD" in header,
                      "missing Shield runtime identity for generation isolation")

    def test_documented_security_runtime_contract(self):
        path = ROOT / "docs/wifi-security-runtime.md"
        self.assertTrue(path.is_file(), "missing passive security runtime contract")
        document = " ".join(path.read_text(encoding="utf-8").split())
        for required in (
            "SECURITY_MONITOR", "eight slots", "1536 bytes",
            "No decoding, printing, allocation, channel changes, raw TX, or persistence",
            "QUARANTINED", "retry", "No terminal success under uncertainty",
            "Host tests do not prove firmware compilation", "FreeRTOS scheduling",
            "driver callback fence", "RF reception", "hardware cleanup",
            "channel restore on device", "SD durability",
        ):
            with self.subTest(required=required):
                self.assertIn(required, document)
        self.assertIn(
            "close callback admission -> unregister callback -> disable promiscuous RX "
            "-> request core stop and lease cancellation -> signal worker stop "
            "-> join worker -> restore saved promiscuous filter -> restore saved channel "
            "-> finish core -> begin lease cleanup "
            "-> finish verified cleanup and release owner/generation -> wipe module context",
            document,
            "documented Stop sequence must include every cleanup stage in order",
        )
        lease = (ROOT / "docs/janos-radio-lease.md").read_text(encoding="utf-8")
        self.assertIn("`SECURITY_MONITOR`", lease)
        self.assertIn("wifi-security-runtime.md", lease)
        normalized_lease = " ".join(lease.split())
        self.assertIn(
            "finishes/wipes the core, completes exact lease cleanup and "
            "verified release, and only then wipes module context",
            normalized_lease,
        )
        self.assertNotIn(
            "wipes module context and then releases verified cleanup",
            normalized_lease,
        )
        self.assertNotIn("validated frame/IE/EAPOL slices", document)
        self.assertIn("bounded MAC-body", document)
        self.assertIn("consumers validate IE/EAPOL structures", document)

    def adapter_interleaving(self, scenario):
        source = (ROOT / "main/main.c").read_text(encoding="utf-8")
        adapter = source.split("/* Security monitor platform state", 1)[1].split(
            "static atomic_bool ota_boot_ready", 1)[0]
        adapter = "/* Security monitor platform state" + adapter
        enum_start = source.index("typedef enum {\n    DETECTOR_EVENT_DEAUTH")
        enum_end = source.index("} detector_event_kind_t;", enum_start)
        adapter = ('#include "csa_detector_core.h"\n' +
                   source[enum_start:enum_end + len("} detector_event_kind_t;")] + "\n" + adapter)
        return self.compile_adapter(r'''
#include "wifi_security_runtime.h"
#include "janos_radio_lease.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdatomic.h>
typedef int portMUX_TYPE;
static unsigned critical_depth;
static bool pending_stop;
static void after_unlock(void);
static void before_lock(portMUX_TYPE *lock);
#define portMUX_INITIALIZER_UNLOCKED 0
#define portENTER_CRITICAL(lock) do { before_lock(lock); assert(*(lock) == 0); ++*(lock); ++critical_depth; } while (0)
#define portEXIT_CRITICAL(lock) do { assert(*(lock) == 1); --*(lock); --critical_depth; after_unlock(); } while (0)
typedef struct { bool mutex, held; } StaticSemaphore_t;
typedef StaticSemaphore_t *SemaphoreHandle_t;
typedef unsigned char StackType_t;
typedef int StaticTask_t;
typedef void *TaskHandle_t;
typedef unsigned TickType_t;
enum { pdTRUE = 1, portMAX_DELAY = 0x7fffffff, ESP_OK = 0 };
#define pdMS_TO_TICKS(ms) (ms)
typedef enum { WIFI_PKT_MGMT, WIFI_PKT_DATA, WIFI_PKT_MISC } wifi_promiscuous_pkt_type_t;
typedef struct {
    uint16_t sig_len, dump_len;
    uint32_t rx_state;
    int8_t rssi;
    uint8_t channel;
    uint32_t timestamp;
} rx_ctrl_t;
typedef struct { rx_ctrl_t rx_ctrl; uint8_t payload[1600]; } wifi_promiscuous_pkt_t;
typedef int wifi_second_chan_t;
typedef void (*wifi_promiscuous_cb_t)(void *, wifi_promiscuous_pkt_type_t);
typedef struct { uint32_t filter_mask; } wifi_promiscuous_filter_t;
enum { WIFI_PROMIS_FILTER_MASK_MGMT = 1, WIFI_PROMIS_FILTER_MASK_DATA = 4 };
static uint32_t filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
static wifi_promiscuous_cb_t registered_callback;
static unsigned radio_operations;
static janos_radio_lease_t janos_radio_lease;
static int scenario, injections, worker_token;
static unsigned cleanup_failures;
static unsigned wipes;
static unsigned telemetry_calls;
static unsigned borrowed_calls, worker_poll_calls;
static int telemetry_identity;
static bool registered, enabled;
static bool legacy_active;
static const char *busy_reason_override;
static janos_radio_owner_t expected_owner = JANOS_RADIO_OWNER_SECURITY_MONITOR;
bool wifi_security_runtime_stop(uint32_t timeout_ms);
static void wifi_shield_worker_poll(void) {}
static const char *analyzer_host_busy_reason(void) {
    assert(janos_radio_lease_snapshot(&janos_radio_lease).owner == expected_owner);
    if (busy_reason_override) { ++injections; return busy_reason_override; }
    if (legacy_active) { ++injections; return "sniffer"; }
    return NULL;
}
int esp_wifi_get_promiscuous_filter(wifi_promiscuous_filter_t *filter) {
    ++radio_operations;
    if (scenario == 11 && injections == 0) { ++injections; return -1; }
    filter->filter_mask = filter_mask; return ESP_OK;
}
int esp_wifi_set_promiscuous_filter(const wifi_promiscuous_filter_t *filter) {
    ++radio_operations;
    if (scenario == 14 && injections == 0 && filter->filter_mask == WIFI_PROMIS_FILTER_MASK_MGMT) {
        ++injections; return -1;
    }
    filter_mask = filter->filter_mask;
    if (scenario == 12 && injections == 0) { ++injections; return -1; }
    if (scenario == 13 && injections == 0) { ++injections; assert(!wifi_security_runtime_stop(0)); }
    return ESP_OK;
}
static wifi_security_runtime_t *worker_runtime;
bool wifi_security_runtime_stop(uint32_t timeout_ms);
static bool core_is_open(void);
static void after_unlock(void) {
    if (pending_stop && critical_depth == 0) {
        pending_stop = false; ++injections;
        assert(!wifi_security_runtime_stop(0));
    }
}
static int xSemaphoreTake(SemaphoreHandle_t semaphore, unsigned timeout) {
    (void)timeout;
    if (semaphore->mutex) {
        if (semaphore->held) return 0;
        semaphore->held = true;
        if (scenario == 4 && injections == 0) {
            /* Schedule Stop at the mutex-acquired/phase-publication boundary.
             * A critical section defers it until that publication is complete. */
            pending_stop = true; after_unlock();
        }
        return pdTRUE;
    }
    if (timeout != 0 && worker_runtime != NULL) {
        (void)wifi_security_runtime_drain(worker_runtime);
        return pdTRUE;
    }
    return 0;
}
static void xSemaphoreGive(SemaphoreHandle_t semaphore) { semaphore->held = false; }
static SemaphoreHandle_t xSemaphoreCreateMutexStatic(StaticSemaphore_t *storage) {
    storage->mutex = true; return storage;
}
static SemaphoreHandle_t xSemaphoreCreateBinaryStatic(StaticSemaphore_t *storage) { return storage; }
static TaskHandle_t xTaskCreateStatic(void (*run)(void *), const char *name,
    unsigned depth, void *context, unsigned priority, StackType_t *stack, StaticTask_t *storage) {
    assert(run != NULL && name != NULL && depth == 5120 / sizeof(StackType_t) && priority == 5);
    ++radio_operations;
    assert(stack != NULL && storage != NULL); worker_runtime = context; return &worker_token;
}
static void xTaskNotifyGive(TaskHandle_t task) { assert(task == &worker_token); }
static void vTaskDelete(TaskHandle_t task) { assert(task == &worker_token); worker_runtime = NULL; }
static void vTaskSuspend(void *task) { (void)task; assert(!"worker is simulated by fake join"); }
static unsigned ulTaskNotifyTake(bool clear, unsigned ticks) { (void)clear; (void)ticks; return 0; }
void vTaskDelay(unsigned ticks) { assert(ticks != 0); }
static int esp_wifi_get_channel(uint8_t *primary, wifi_second_chan_t *secondary) { ++radio_operations; *primary = 6; *secondary = 0; return ESP_OK; }
static int esp_wifi_set_channel(uint8_t primary, wifi_second_chan_t secondary) {
    assert(primary == 6 && secondary == 0);
    ++radio_operations;
    if (scenario == 6 && injections == 0) { ++injections; return -1; }
    return ESP_OK;
}
static int esp_wifi_set_promiscuous(bool enable) { ++radio_operations; enabled = enable; return ESP_OK; }
static int64_t esp_timer_get_time(void) { return 1000; }
static bool observed_cancel_requested(const janos_radio_lease_t *lease,
    janos_radio_owner_t owner, uint32_t generation) {
    bool observed = janos_radio_lease_cancel_requested(lease, owner, generation);
    if (scenario == 3 && injections == 0 &&
        janos_radio_lease_snapshot(lease).state == JANOS_RADIO_LEASE_RUNNING) {
        /* The final check already read false. Schedule Stop before returning
         * that observed value to the real session's final-open handoff. */
        assert(!observed); ++injections;
        assert(!wifi_security_runtime_stop(0));
    }
    return observed;
}
#define janos_radio_lease_cancel_requested observed_cancel_requested
static bool observed_finish_cleanup(janos_radio_lease_t *lease,
    janos_radio_owner_t owner, uint32_t generation, bool restored) {
    if ((scenario == 16 || scenario == 20) && cleanup_failures == 0 && restored) {
        ++cleanup_failures;
        return false;
    }
    return janos_radio_lease_finish_cleanup(lease, owner, generation, restored);
}
#define janos_radio_lease_finish_cleanup observed_finish_cleanup
static int esp_wifi_set_promiscuous_rx_cb(wifi_promiscuous_cb_t callback) {
    ++radio_operations;
    if (callback == NULL && scenario == 2 && injections == 0) {
        assert(registered);
        assert(!janos_radio_lease_snapshot(&janos_radio_lease).cancel_requested);
        ++injections;
        assert(!wifi_security_runtime_stop(0));
        /* Stop B must not insert cancellation after Stop A closes core but
         * before this driver unregister operation completes. */
        assert(!janos_radio_lease_snapshot(&janos_radio_lease).cancel_requested);
    }
    registered = callback != NULL; registered_callback = callback; return ESP_OK;
}
''' + adapter + r'''
static bool core_is_open(void) { return security_platform.runtime->callbacks_open; }
static void before_lock(portMUX_TYPE *lock) {
    if (scenario == 5 && injections == 0 && lock == &security_platform.lock &&
        atomic_load(&security_platform.phase) == SECURITY_PHASE_OPEN_COMMITTED) {
        /* CAS won, but core start has not acquired its lock or opened yet. */
        assert(!core_is_open()); ++injections;
        assert(!wifi_security_runtime_stop(0));
        assert(!core_is_open());
        assert(!janos_radio_lease_snapshot(&janos_radio_lease).cancel_requested);
    }
}
static bool validate(void *context) {
    (void)context;
    assert(security_platform.lifecycle->held);
    if (scenario == 1 && injections == 0) {
        assert(janos_radio_lease_snapshot(&janos_radio_lease).owner == JANOS_RADIO_OWNER_NONE);
        ++injections;
        assert(!wifi_security_runtime_stop(0));
    }
    if (scenario == 9 && injections == 0) {
        uint32_t generation;
        ++injections;
        assert(janos_radio_lease_acquire(&janos_radio_lease, JANOS_RADIO_OWNER_LEGACY,
            &generation) == JANOS_RADIO_LEASE_OK);
    }
    if ((scenario == 19 || scenario == 20) && injections == 0) {
        ++injections;
        /* Deterministic Stop after Shield scan reservation and before the
         * reserved session validates/adopts the generation. */
        assert(!wifi_security_runtime_stop(0));
        return false;
    }
    return true;
}
static void wipe(void *context) { (void)context; ++wipes; }
static bool borrowed_receive(void *context, uint32_t generation,
                             const wifi_security_rx_view_t *view) {
    (void)context;
    assert(generation != 0U && view != NULL && view->bytes != NULL);
    assert(view->packet_class == WIFI_SECURITY_RECEIVE_MGMT);
    assert(view->signal_length == 51U && view->dump_length == 47U);
    assert(view->captured_length == 47U && view->rx_state == 0U);
    assert(view->channel == 6U && view->rssi == -42);
    ++borrowed_calls;
    return true;
}
static void worker_poll(void *context) { (void)context; ++worker_poll_calls; }
static void feature_uncertainty(void *context, wifi_security_session_result_t result, bool owned) {
    assert(context == &telemetry_identity && critical_depth == 0);
    /* BUSY is the simulated competing caller, which does not own the mutex.
     * Serialized cleanup failures must emit only after releasing its mutex. */
    if (result != WIFI_SECURITY_SESSION_BUSY) assert(!security_platform.lifecycle->held);
    assert(owned == (janos_radio_lease_snapshot(&janos_radio_lease).owner == expected_owner));
    ++telemetry_calls;
    printf("[WPS_GUARD/1] ownership=%s\n", owned ? "retained" : "none");
}
int main(int argc, char **argv) {
    assert(argc == 2); scenario = atoi(argv[1]);
    (void)wifi_security_runtime_platform_quiesce;
    (void)wifi_security_runtime_platform_finish_cleanup;
    janos_radio_lease_init(&janos_radio_lease);
    security_platform.runtime = calloc(1U, sizeof(*security_platform.runtime));
    security_platform.worker_stack = calloc(
        SECURITY_WORKER_STACK_DEPTH, sizeof(*security_platform.worker_stack));
    assert(security_platform.runtime != NULL && security_platform.worker_stack != NULL);
    assert(wifi_security_platform_init());
    (void)analyzer_host_busy_reason;
    legacy_active = scenario == 8;
    if (scenario == 7) {
        security_platform.runtime->last_generation = 1;
        ++injections; /* Reject first core open; lease retry supplies generation 2. */
    }
    wifi_security_session_config_t config = {
        .module = WIFI_SECURITY_MODULE_WPS_GUARD, .validate = validate, .wipe = wipe,
        .uncertainty = feature_uncertainty, .telemetry_context = &telemetry_identity
    };
    if (scenario == 21) {
        config.module = WIFI_SECURITY_MODULE_DEAUTH_V2;
        config.receive_policy = WIFI_SECURITY_RECEIVE_MGMT;
        config.borrowed_receive = borrowed_receive;
        config.worker_poll = worker_poll;
    }
    if (scenario == 22) {
        config.module = WIFI_SECURITY_MODULE_DEAUTH_V2;
        config.receive_policy = WIFI_SECURITY_RECEIVE_MGMT;
        config.borrowed_receive = borrowed_receive;
        config.worker_poll = worker_poll;
        busy_reason_override = "wifi_connected";
        assert(wifi_security_platform_reserve_scan_module(
            WIFI_SECURITY_MODULE_DEAUTH_V2));
        assert(wifi_security_runtime_platform_start(&config) ==
               WIFI_SECURITY_SESSION_OK);
        assert(wifi_security_runtime_stop(5000));
        assert(wifi_security_runtime_platform_start(&config) ==
               WIFI_SECURITY_SESSION_OK);
        assert(wifi_security_runtime_stop(5000));
        return 0;
    }
    if (scenario == 23) {
        expected_owner = JANOS_RADIO_OWNER_SHIELD;
        busy_reason_override = "wifi_connected";
        assert(!wifi_security_platform_reserve_scan_module(
            WIFI_SECURITY_MODULE_SHIELD));
        assert(janos_radio_lease_snapshot(&janos_radio_lease).owner ==
               JANOS_RADIO_OWNER_NONE);
        return 0;
    }
    if (scenario == 24) {
        config.module = WIFI_SECURITY_MODULE_DEAUTH_V2;
        busy_reason_override = "sniffer";
        assert(!wifi_security_platform_reserve_scan_module(
            WIFI_SECURITY_MODULE_DEAUTH_V2));
        assert(janos_radio_lease_snapshot(&janos_radio_lease).owner ==
               JANOS_RADIO_OWNER_NONE);
        return 0;
    }
    if (scenario == 16) {
        expected_owner = JANOS_RADIO_OWNER_SHIELD;
        legacy_active = true;
        assert(!wifi_security_platform_reserve_shield_scan());
        janos_radio_lease_snapshot_t retained =
            janos_radio_lease_snapshot(&janos_radio_lease);
        assert(retained.owner == JANOS_RADIO_OWNER_SHIELD);
        assert(retained.state == JANOS_RADIO_LEASE_QUARANTINED);
        assert(security_platform.owner == JANOS_RADIO_OWNER_SHIELD);
        assert(security_platform.shield_scan_reserved);
        assert(security_platform.shield_scan_generation == retained.generation);
        assert(atomic_load(&security_platform.phase) == SECURITY_PHASE_STOPPING);
        legacy_active = false;
        assert(wifi_security_platform_abort_shield_scan(5000));
        assert(!security_platform.shield_scan_reserved);
        assert(security_platform.owner == JANOS_RADIO_OWNER_NONE);
        assert(atomic_load(&security_platform.phase) == SECURITY_PHASE_IDLE);
        assert(janos_radio_lease_snapshot(&janos_radio_lease).owner ==
               JANOS_RADIO_OWNER_NONE);
        return 0;
    }
    if (scenario == 18) {
        expected_owner = JANOS_RADIO_OWNER_SHIELD;
        assert(wifi_security_platform_reserve_shield_scan());
        janos_radio_lease_snapshot_t before =
            janos_radio_lease_snapshot(&janos_radio_lease);
        assert(before.owner == JANOS_RADIO_OWNER_SHIELD);
        assert(wifi_security_runtime_platform_start(&config) ==
               WIFI_SECURITY_SESSION_BUSY);
        janos_radio_lease_snapshot_t after =
            janos_radio_lease_snapshot(&janos_radio_lease);
        assert(after.owner == before.owner &&
               after.generation == before.generation);
        assert(security_platform.shield_scan_reserved);
        assert(atomic_load(&security_platform.phase) == SECURITY_PHASE_STOPPING);
        assert(wifi_security_platform_abort_shield_scan(5000));
        return 0;
    }
    if (scenario == 19) {
        expected_owner = JANOS_RADIO_OWNER_SHIELD;
        assert(wifi_security_platform_reserve_shield_scan());
        janos_radio_lease_snapshot_t before =
            janos_radio_lease_snapshot(&janos_radio_lease);
        assert(before.owner == JANOS_RADIO_OWNER_SHIELD);
        config.module = WIFI_SECURITY_MODULE_SHIELD;
        security_platform.shield_staged_channel = 6U;
        assert(wifi_security_runtime_platform_start(&config) !=
               WIFI_SECURITY_SESSION_OK);
        janos_radio_lease_snapshot_t after =
            janos_radio_lease_snapshot(&janos_radio_lease);
        assert(after.owner == JANOS_RADIO_OWNER_NONE);
        assert(after.generation == 0U && after.state == JANOS_RADIO_LEASE_IDLE);
        assert(!security_platform.shield_scan_reserved);
        assert(security_platform.shield_scan_generation == 0U);
        assert(security_platform.owner == JANOS_RADIO_OWNER_NONE);
        assert(!security_platform.session.active);
        return 0;
    }
    if (scenario == 20) {
        expected_owner = JANOS_RADIO_OWNER_SHIELD;
        assert(wifi_security_platform_reserve_shield_scan());
        janos_radio_lease_snapshot_t before =
            janos_radio_lease_snapshot(&janos_radio_lease);
        assert(before.owner == JANOS_RADIO_OWNER_SHIELD);
        config.module = WIFI_SECURITY_MODULE_SHIELD;
        security_platform.shield_staged_channel = 6U;
        assert(wifi_security_runtime_platform_start(&config) ==
               WIFI_SECURITY_SESSION_CLEANUP_FAILED);
        janos_radio_lease_snapshot_t retained =
            janos_radio_lease_snapshot(&janos_radio_lease);
        assert(retained.owner == before.owner &&
               retained.generation == before.generation);
        assert(retained.state == JANOS_RADIO_LEASE_QUARANTINED);
        assert(security_platform.shield_scan_reserved);
        assert(security_platform.shield_scan_generation == before.generation);
        assert(security_platform.owner == JANOS_RADIO_OWNER_SHIELD);
        assert(atomic_load(&security_platform.phase) == SECURITY_PHASE_STOPPING);
        assert(!security_platform.session.active);
        assert(wifi_security_platform_abort_shield_scan(5000));
        assert(!security_platform.shield_scan_reserved);
        assert(security_platform.owner == JANOS_RADIO_OWNER_NONE);
        assert(janos_radio_lease_snapshot(&janos_radio_lease).owner ==
               JANOS_RADIO_OWNER_NONE);
        return 0;
    }
    wifi_security_session_config_t silent = config;
    silent.uncertainty = NULL;
    assert(wifi_security_runtime_platform_start(&silent) == WIFI_SECURITY_SESSION_INVALID);
    assert(radio_operations == 0 && wipes == 0);
    wifi_security_session_result_t result = wifi_security_runtime_platform_start(&config);
    if (scenario == 8 || scenario == 9) {
        assert(result != WIFI_SECURITY_SESSION_OK);
        assert(radio_operations == 0 && wipes == 0);
        if (scenario == 9) {
            janos_radio_lease_snapshot_t lease = janos_radio_lease_snapshot(&janos_radio_lease);
            assert(lease.owner == JANOS_RADIO_OWNER_LEGACY);
            assert(janos_radio_lease_begin_cleanup(&janos_radio_lease, lease.owner, lease.generation));
            assert(janos_radio_lease_finish_cleanup(&janos_radio_lease, lease.owner, lease.generation, true));
        }
    } else if (scenario == 2 || scenario == 5 || scenario == 6 || scenario == 10 ||
               scenario == 21 ||
               scenario == 14 || scenario == 17) {
        assert(result == WIFI_SECURITY_SESSION_OK);
        assert(atomic_load(&security_platform.phase) == SECURITY_PHASE_OPEN_COMMITTED);
        if (scenario == 17) {
            ++injections;
            assert(!wifi_security_platform_reserve_shield_scan());
            assert(security_platform.session.active);
            assert(security_platform.owner == JANOS_RADIO_OWNER_SECURITY_MONITOR);
            assert(atomic_load(&security_platform.phase) ==
                   SECURITY_PHASE_OPEN_COMMITTED);
        }
        if (scenario == 10) {
            wifi_promiscuous_pkt_t packet = {
                .rx_ctrl = {.sig_len = 36, .dump_len = 32,
                            .rssi = -42, .channel = 6, .timestamp = 123}
            };
            packet.payload[0] = 0x08;
            packet.payload[4] = packet.payload[10] = packet.payload[16] = 2;
            ++injections;
            if (filter_mask & WIFI_PROMIS_FILTER_MASK_DATA)
                registered_callback(&packet, WIFI_PKT_DATA);
            wifi_security_runtime_status_t status;
            wifi_security_runtime_get_status(security_platform.runtime, &status);
            assert(status.queued == 1);
            assert(filter_mask == (WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA));
        }
        if (scenario == 21) {
            assert(filter_mask == WIFI_PROMIS_FILTER_MASK_MGMT);
            wifi_promiscuous_pkt_t packet = {
                .rx_ctrl = {.sig_len = 51, .dump_len = 47,
                            .rssi = -42, .channel = 6, .timestamp = 123}
            };
            registered_callback(&packet, WIFI_PKT_DATA);
            assert(borrowed_calls == 0U);
            registered_callback(&packet, WIFI_PKT_MGMT);
            assert(borrowed_calls == 1U);
        }
        if (scenario == 6 || scenario == 14) {
            assert(!wifi_security_runtime_stop(5000));
            assert(wipes == 0 && telemetry_calls == 1);
            assert(atomic_load(&security_platform.phase) == SECURITY_PHASE_STOPPING);
            assert(janos_radio_lease_snapshot(&janos_radio_lease).state == JANOS_RADIO_LEASE_QUARANTINED);
            assert(wifi_security_runtime_platform_start(&config) == WIFI_SECURITY_SESSION_BUSY);
            assert(atomic_load(&security_platform.phase) == SECURITY_PHASE_STOPPING);
        }
        assert(wifi_security_runtime_stop(5000));
    } else {
        wifi_security_session_result_t want = scenario == 7 ? WIFI_SECURITY_SESSION_INVALID :
            scenario == 11 ? WIFI_SECURITY_SESSION_FILTER_SNAPSHOT_FAILED :
            scenario == 12 ? WIFI_SECURITY_SESSION_FILTER_APPLY_FAILED : WIFI_SECURITY_SESSION_CANCELLED;
        assert(result == want);
        assert(!security_platform.runtime->callbacks_open);
    }
    assert(atomic_load(&security_platform.phase) == SECURITY_PHASE_IDLE);
    assert(injections == (scenario == 21 ? 0 : 1) &&
           !security_platform.lifecycle->held);
    assert(janos_radio_lease_snapshot(&janos_radio_lease).owner == JANOS_RADIO_OWNER_NONE);
    assert(!registered && !enabled && worker_runtime == NULL);
    assert(filter_mask == WIFI_PROMIS_FILTER_MASK_MGMT);
    /* Retry starts normally and completes cleanup, proving no stale latch. */
    scenario = 0; legacy_active = false;
    assert(wifi_security_runtime_platform_start(&config) == WIFI_SECURITY_SESSION_OK);
    assert(wifi_security_runtime_stop(5000));
    assert(!security_platform.lifecycle->held);
    return 0;
}
''', link_runtime=True, arguments=[str(scenario)])

    def test_adapter_retains_stop_before_lease_acquisition(self):
        output = self.adapter_interleaving(1)
        self.assertIn("ownership=none", output)
        self.assertNotIn("ownership=retained", output)

    def test_adapter_checks_legacy_host_after_reserving_lease(self):
        for scenario in (8, 9):
            with self.subTest(scenario=scenario):
                self.adapter_interleaving(scenario)

    def test_shield_reserve_retains_uncertain_baseline_cleanup_for_abort_retry(self):
        self.adapter_interleaving(16)

    def test_shield_reserve_rejection_preserves_active_legacy_phase(self):
        self.adapter_interleaving(17)

    def test_legacy_start_rejection_preserves_shield_preparing_phase(self):
        self.adapter_interleaving(18)

    def test_stop_between_scan_and_adopt_releases_exact_reserved_generation(self):
        self.adapter_interleaving(19)

    def test_uncertain_reserved_abort_retains_exact_generation_for_retry(self):
        self.adapter_interleaving(20)

    def test_adapter_installs_data_filter_and_restores_mgmt_baseline(self):
        self.adapter_interleaving(10)

    def test_adapter_deauth_profile_uses_mgmt_borrowed_lane(self):
        self.adapter_interleaving(21)

    def test_deauth_connected_sta_exception_is_module_scoped(self):
        self.adapter_interleaving(22)
        self.adapter_interleaving(23)
        self.adapter_interleaving(24)

    def test_adapter_emits_no_unversioned_foundation_record(self):
        output = self.adapter_interleaving(1)
        self.assertIn("[WPS_GUARD/1] ownership=none", output)
        self.assertNotIn("[WIFI_SECURITY]", output)

    def test_adapter_filter_failures_cancel_and_retry(self):
        for scenario in (11, 12, 13, 14):
            with self.subTest(scenario=scenario):
                self.adapter_interleaving(scenario)

    def test_adapter_competing_stops_preserve_close_unregister_order(self):
        self.adapter_interleaving(2)

    def test_adapter_cancel_at_final_check_prevents_generation_open(self):
        self.adapter_interleaving(3)

    def test_adapter_mutex_acquisition_publishes_start_phase_atomically(self):
        self.adapter_interleaving(4)

    def test_adapter_open_commit_wins_and_cleanup_controls_idle_phase(self):
        for scenario in (5, 6, 7):
            with self.subTest(scenario=scenario):
                self.adapter_interleaving(scenario)

    def compile_adapter(self, source, link_runtime=False, arguments=()):
        with tempfile.TemporaryDirectory(prefix="janos-security-adapter-") as directory:
            source_path = Path(directory) / "adapter.c"
            source_path.write_text(source, encoding="utf-8")
            executable = Path(directory) / "adapter"
            compiler = next((shutil.which(name) for name in ("cc", "gcc", "clang")
                             if shutil.which(name)), None)
            flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic"]
            sources = [source_path]
            includes = []
            if link_runtime:
                sources += [ROOT / "main/wifi_security_runtime.c",
                            ROOT / "main/wifi_security_frame.c",
                            ROOT / "main/csa_detector_core.c",
                            ROOT / "components/janos_wps/janos_radio_lease.c"]
                includes = [ROOT / "main", ROOT / "components/janos_wps/include"]
            if os.environ.get("JANOS_TEST_SANITIZERS"):
                flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                          "-fno-sanitize-recover=all"]
            if compiler:
                command = [compiler, *flags, *[arg for path in includes for arg in ("-I", str(path))],
                           *map(str, sources), "-o", str(executable)]
                run = [str(executable)]
            else:
                self.assertTrue(shutil.which("wsl.exe"), "host C compiler required")
                command = ["wsl.exe", "cc", *flags, *[arg for path in includes for arg in ("-I", wsl_path(path))],
                           *map(wsl_path, sources), "-o", wsl_path(executable)]
                run = ["wsl.exe", wsl_path(executable)]
            built = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            result = subprocess.run([*run, *arguments], cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return result.stdout

    def test_main_callback_only_submits_metadata_and_borrowed_bytes(self):
        source = (ROOT / "main/main.c").read_text(encoding="utf-8")
        try:
            callback = function(source, "wifi_security_promiscuous_callback")
        except ValueError:
            self.fail("security bounded-copy callback is not wired in main.c")
        # Compile the real callback against a deliberately narrow interface:
        # decode, print, alloc, channel and persistence APIs are unavailable.
        self.compile_adapter(r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
typedef enum { WIFI_PKT_MGMT, WIFI_PKT_DATA, WIFI_PKT_MISC } wifi_promiscuous_pkt_type_t;
typedef enum {
    WIFI_SECURITY_RECEIVE_DEFAULT = 0,
    WIFI_SECURITY_RECEIVE_MGMT = 1U << 0,
    WIFI_SECURITY_RECEIVE_DATA = 1U << 1
} wifi_security_receive_policy_t;
typedef struct {
    const uint8_t *bytes; uint16_t captured_length, signal_length, dump_length;
    uint32_t rx_state; uint64_t timestamp_us; int8_t rssi; uint8_t channel;
    wifi_security_receive_policy_t packet_class;
} wifi_security_rx_view_t;
typedef struct {
    wifi_security_receive_policy_t receive_policy;
    bool (*borrowed_receive)(void *, uint32_t, const wifi_security_rx_view_t *);
    void (*worker_poll)(void *); void *context;
} callback_config_t;
typedef callback_config_t wifi_security_session_config_t;
typedef struct { callback_config_t config; } callback_session_t;
typedef struct {
    uint16_t sig_len, dump_len; uint32_t rx_state;
    int8_t rssi; uint8_t channel; uint32_t timestamp;
} rx_ctrl_t;
typedef struct { rx_ctrl_t rx_ctrl; uint8_t payload[1600]; } wifi_promiscuous_pkt_t;
static int runtime_token;
static struct {
    int *runtime; uint32_t callback_generation; callback_session_t session;
} security_platform;
static unsigned calls;
static const uint8_t *expected_bytes;
static int64_t esp_timer_get_time(void) { return 5000000; }
static bool security_shield_submit(int *runtime, uint32_t generation,
    const uint8_t *bytes, uint16_t length, uint64_t timestamp, int8_t rssi, uint8_t channel)
{
    assert(runtime == security_platform.runtime && generation == 17);
    assert(bytes == expected_bytes && length == 1596);
    assert(timestamp == 5000000 && rssi == -42 && channel == 6);
    ++calls;
    return true;
}
''' + callback + r'''
int main(void) {
    wifi_promiscuous_pkt_t packet = {
        .rx_ctrl = {.sig_len = 1600, .dump_len = 1596,
                    .rssi = -42, .channel = 6, .timestamp = 123}
    };
    security_platform.runtime = &runtime_token;
    security_platform.callback_generation = 17;
    expected_bytes = packet.payload;
    wifi_security_promiscuous_callback(&packet, WIFI_PKT_MGMT);
    wifi_security_promiscuous_callback(&packet, WIFI_PKT_DATA);
    assert(calls == 2);
    wifi_security_promiscuous_callback(NULL, WIFI_PKT_DATA);
    wifi_security_promiscuous_callback(&packet, WIFI_PKT_MISC);
    packet.rx_ctrl.sig_len = 4;
    wifi_security_promiscuous_callback(&packet, WIFI_PKT_DATA);
    packet.rx_ctrl.sig_len = 3;
    wifi_security_promiscuous_callback(&packet, WIFI_PKT_DATA);
    assert(calls == 2);
    return 0;
}
''')

    def test_global_stop_gates_legacy_reset_and_preserves_idle_output(self):
        source = (ROOT / "main/main.c").read_text(encoding="utf-8")
        prefix = function(source, "cmd_stop").split(
            '    MY_LOG_INFO(TAG, "Stop command received')[0]
        output = self.compile_adapter(r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
static char calls[16];
static unsigned used;
static bool shield_ok = true;
static bool security_ok = true;
static bool sae_ok = true;
static bool trust_ok = true;
static int detector_event_lock;
static void *detector_v2_context;
#define portENTER_CRITICAL(lock) ((void)(lock))
#define portEXIT_CRITICAL(lock) ((void)(lock))
static bool wifi_shield_deauth_profile_pending(void) { return false; }
static bool wifi_shield_stop(unsigned ms) { assert(ms == 5000); calls[used++] = 'Q'; return shield_ok; }
static bool janos_wps_runtime_stop(unsigned ms) { assert(ms == 5000); calls[used++] = 'W'; return true; }
static bool wifi_analyzer_stop(unsigned ms) { assert(ms == 5000); calls[used++] = 'A'; return true; }
static bool wps_guard_stop(unsigned ms) { assert(ms == 5000); calls[used++] = 'G'; return true; }
static bool sae_guard_stop(unsigned ms) { assert(ms == 5000); calls[used++] = 'H'; return sae_ok; }
static bool wifi_trust_stop(unsigned ms) { assert(ms == 5000); calls[used++] = 'T'; return trust_ok; }
static bool deauth_detector_stop_v2_profile(unsigned ms) { assert(ms == 5000); calls[used++] = 'D'; return true; }
bool wifi_security_runtime_stop(uint32_t ms) { assert(ms == 5000); calls[used++] = 'S'; return security_ok; }
''' + prefix + r'''
    calls[used++] = 'L';
    puts("LEGACY");
    return 0;
}
int main(void) {
    assert(cmd_stop(0, NULL) == 0);
    assert(!strcmp(calls, "QWAGHTDSL"));
    memset(calls, 0, sizeof(calls)); used = 0; shield_ok = false;
    assert(cmd_stop(0, NULL) == 1);
    assert(!strcmp(calls, "Q"));
    memset(calls, 0, sizeof(calls)); used = 0; shield_ok = true; sae_ok = false;
    assert(cmd_stop(0, NULL) == 1);
    assert(!strcmp(calls, "QWAGH"));
    memset(calls, 0, sizeof(calls)); used = 0; sae_ok = true; trust_ok = false;
    assert(cmd_stop(0, NULL) == 1);
    assert(!strcmp(calls, "QWAGHT"));
    memset(calls, 0, sizeof(calls)); used = 0; trust_ok = true;
    security_ok = false;
    assert(cmd_stop(0, NULL) == 1);
    assert(!strcmp(calls, "QWAGHTDS"));
    return 0;
}
''')
        self.assertEqual(output, "LEGACY\n")

    def test_global_stop_skips_legacy_radio_teardown_for_shared_v2_only(self):
        source = (ROOT / "main/main.c").read_text(encoding="utf-8")
        begin = source.index("    // Stop deauth_detector if active")
        end = source.index("    // Stop GPS raw task if running", begin)
        deauth_tail = source[begin:end]
        output = self.compile_adapter(r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
typedef void *TaskHandle_t;
typedef int esp_err_t;
enum { ESP_OK = 0, WIFI_SECOND_CHAN_NONE = 0,
       JANOS_RADIO_OWNER_DEFENCE = 5 };
#define pdMS_TO_TICKS(ms) (ms)
#define TAG "test"
static bool deauth_detector_active;
static TaskHandle_t deauth_detector_task_handle;
static struct { bool started; } detector_defence_runtime;
static uint32_t detector_defence_lease_generation;
static uint32_t detector_dropped_total;
static int detector_event_lock;
static bool detector_defence_restore_valid;
static uint8_t detector_defence_restore_channel;
static int detector_defence_restore_secondary;
static int deauth_detector_channel_index;
static int deauth_detector_current_channel;
static int64_t deauth_detector_last_channel_hop;
static bool deauth_detector_selected_mode;
static int deauth_detector_selected_channels_count;
static int deauth_detector_selected_channels[64];
static int dual_band_channels[] = {1, 6, 11};
static int janos_radio_lease;
static char trace[64];
static size_t trace_used;
static char logs[256];
static size_t logs_used;
static void mark(char value) { trace[trace_used++] = value; trace[trace_used] = 0; }
static void test_log(const char *format, ...) {
    va_list arguments;
    va_start(arguments, format);
    int written = vsnprintf(logs + logs_used, sizeof(logs) - logs_used,
                            format, arguments);
    va_end(arguments);
    assert(written >= 0 && (size_t)written < sizeof(logs) - logs_used);
    logs_used += (size_t)written;
    logs[logs_used++] = '\n'; logs[logs_used] = 0;
}
#define MY_LOG_INFO(tag, ...) test_log(__VA_ARGS__)
#define portENTER_CRITICAL(lock) ((void)(lock))
#define portEXIT_CRITICAL(lock) ((void)(lock))
static void deauth_detector_close_events(void) { mark('C'); }
static bool janos_radio_lease_request_cancel(int *lease, int owner,
                                             uint32_t generation) {
    (void)lease; (void)owner; (void)generation; mark('R'); return true;
}
static void deauth_defence_runtime_request_stop(void *runtime) {
    (void)runtime; mark('S');
}
static void xTaskNotifyGive(TaskHandle_t task) { assert(task); mark('N'); }
static esp_err_t esp_wifi_set_promiscuous(bool enabled) {
    assert(!enabled); mark('P'); return ESP_OK;
}
static esp_err_t esp_wifi_set_promiscuous_rx_cb(void *callback) {
    assert(callback == NULL); mark('B'); return ESP_OK;
}
static void vTaskDelay(int ticks) {
    assert(ticks == 50); mark('W'); deauth_detector_task_handle = NULL;
}
static void vTaskDelete(TaskHandle_t task) { assert(task); mark('X'); }
static esp_err_t esp_wifi_set_channel(uint8_t channel, int secondary) {
    (void)channel; assert(secondary == WIFI_SECOND_CHAN_NONE); mark('T');
    return ESP_OK;
}
static bool deauth_detector_stop_defence_session(uint32_t dropped,
                                                 bool restored) {
    (void)dropped; (void)restored; mark('F'); return true;
}
static int run_deauth_tail(bool deauth_v2_was_active) {
    (void)deauth_v2_was_active;
''' + deauth_tail + r'''
    return 0;
}
static void reset(bool active, bool task) {
    deauth_detector_active = active;
    deauth_detector_task_handle = task ? (TaskHandle_t)1 : NULL;
    detector_defence_runtime.started = false;
    detector_defence_lease_generation = 0U;
    detector_defence_restore_valid = false;
    trace_used = logs_used = 0U;
    trace[0] = logs[0] = 0;
}
int main(void) {
    reset(false, false);
    assert(run_deauth_tail(true) == 0);
    assert(!strcmp(trace, ""));
    assert(!strcmp(logs, ""));

    reset(true, false);
    assert(run_deauth_tail(true) == 0);
    assert(!strcmp(trace, "C"));
    assert(!strcmp(logs,
        "Stopping Deauth Detector task...\nDeauth Detector stopped.\n"));
    assert(!deauth_detector_active && !deauth_detector_selected_mode &&
           deauth_detector_selected_channels_count == 0);

    reset(true, true);
    assert(run_deauth_tail(false) == 0);
    assert(!strcmp(trace, "CNPBWP"));
    assert(!strcmp(logs,
        "Stopping Deauth Detector task...\nDeauth Detector stopped.\n"));
    assert(!deauth_detector_active && deauth_detector_task_handle == NULL);
    puts("stop ownership PASS");
    return 0;
}
''')
        self.assertEqual(output, "stop ownership PASS\n")

    def test_runtime_behavior(self):
        with tempfile.TemporaryDirectory(prefix="janos-security-runtime-") as directory:
            executable = Path(directory) / "wifi_security_runtime_test"
            requested = os.environ.get("CC", "")
            compiler = shutil.which(requested) if requested else None
            if compiler is None:
                compiler = next((shutil.which(name) for name in
                                 ("cc", "gcc", "clang") if shutil.which(name)), None)
            flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic"]
            if os.environ.get("JANOS_TEST_SANITIZERS"):
                flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                          "-fno-sanitize-recover=all"]
            sources = [ROOT / "tests/wifi_security_runtime_test.c",
                       ROOT / "main/wifi_security_runtime.c",
                       ROOT / "main/wifi_security_frame.c",
                       ROOT / "components/janos_wps/janos_radio_lease.c"]
            includes = [ROOT / "main", ROOT / "components/janos_wps/include"]
            if compiler:
                command = [compiler, *flags, *[arg for path in includes for arg in ("-I", str(path))],
                           *map(str, sources), "-o", str(executable)]
                run = [str(executable)]
            elif shutil.which("wsl.exe"):
                command = ["wsl.exe", "cc", *flags, *[arg for path in includes for arg in ("-I", wsl_path(path))],
                           *map(wsl_path, sources), "-o", wsl_path(executable)]
                run = ["wsl.exe", wsl_path(executable)]
            else:
                self.fail("host C compiler required (native or WSL)")
            built = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            result = subprocess.run(run, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout.strip(), "PASS: fixed Wi-Fi security runtime")


if __name__ == "__main__":
    unittest.main()
