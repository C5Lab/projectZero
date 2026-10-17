#include "lab_platform.h"
#include "lab_radio.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char trace[512];
    size_t trace_length;
    char fail_code;
    bool fail_once;
    unsigned factory_reads;
    unsigned entropy_reads;
    unsigned mac_reads;
    unsigned mounts;
    unsigned unmounts;
    unsigned allocations;
    unsigned frees;
    unsigned reboots;
    uint8_t current_mac[6];
    uint8_t stored[STA_MAC_POLICY_RECORD_SIZE];
    bool stored_present;
    bool wrong_readback;
    bool cancel_pending;
    unsigned cancel_polls;
} fixture_t;

static int event(fixture_t *fixture, char code)
{
    fixture->trace[fixture->trace_length++] = code;
    fixture->trace[fixture->trace_length] = '\0';
    if (fixture->fail_code == code) {
        if (fixture->fail_once) fixture->fail_code = 0;
        return -1;
    }
    return 0;
}

static int sd_mount(void *context) { ((fixture_t *)context)->mounts++; return 0; }
static int sd_unmount(void *context) { ((fixture_t *)context)->unmounts++; return 0; }
static int factory_mac(void *context, uint8_t out[6])
{
    fixture_t *fixture = context;
    const uint8_t value[6] = {0x3c, 0xdc, 0x75, 0x85, 0xfd, 0x80};
    fixture->factory_reads++;
    memcpy(out, value, sizeof(value));
    return 0;
}
static int entropy(void *context, uint8_t *out, size_t length)
{
    fixture_t *fixture = context;
    const uint8_t value[6] = {0xff, 1, 2, 3, 4, 5};
    fixture->entropy_reads++;
    assert(length == sizeof(value));
    memcpy(out, value, sizeof(value));
    return 0;
}
static int read_mac(void *context, uint8_t out[6])
{
    fixture_t *fixture = context;
    fixture->mac_reads++;
    memcpy(out, fixture->current_mac, 6);
    if (fixture->wrong_readback) out[5] ^= 1;
    return 0;
}
static void *psram_alloc(void *context, size_t size)
{
    ((fixture_t *)context)->allocations++;
    return malloc(size);
}
static void psram_free(void *context, void *memory)
{
    ((fixture_t *)context)->frees++;
    free(memory);
}
static uint64_t now_ms(void *context) { (void)context; return 4242; }
static void reboot(void *context) { ((fixture_t *)context)->reboots++; }
static bool poll_cancel(void *context)
{
    fixture_t *fixture = context;
    fixture->cancel_polls++;
    return fixture->cancel_pending;
}

static sta_mac_io_status_t store_open(void *context, sta_mac_store_access_t access,
                                      void **handle)
{
    (void)access;
    *handle = context;
    return STA_MAC_IO_OK;
}
static sta_mac_io_status_t store_read(void *handle, uint8_t *out, size_t capacity,
                                      size_t *actual_length)
{
    fixture_t *fixture = handle;
    if (!fixture->stored_present) return STA_MAC_IO_MISSING;
    *actual_length = sizeof(fixture->stored);
    if (capacity < sizeof(fixture->stored)) return STA_MAC_IO_BUFFER_TOO_SMALL;
    memcpy(out, fixture->stored, sizeof(fixture->stored));
    return STA_MAC_IO_OK;
}
static sta_mac_io_status_t store_write(void *handle, const uint8_t *data, size_t length)
{
    fixture_t *fixture = handle;
    assert(length == sizeof(fixture->stored));
    memcpy(fixture->stored, data, length);
    fixture->stored_present = true;
    return STA_MAC_IO_OK;
}
static sta_mac_io_status_t store_commit(void *handle) { (void)handle; return STA_MAC_IO_OK; }
static void store_close(void *handle) { (void)handle; }

static const lab_platform_ops_t platform_ops = {
    .sd_mount = sd_mount, .sd_unmount = sd_unmount,
    .factory_mac = factory_mac, .entropy = entropy,
    .read_sta_mac = read_mac, .psram_alloc = psram_alloc,
    .psram_free = psram_free, .monotonic_ms = now_ms,
    .reboot = reboot, .poll_cancel = poll_cancel,
};

static sta_mac_policy_store_t make_store(fixture_t *fixture)
{
    const sta_mac_policy_store_t store = {
        fixture, store_open, store_read, store_write, store_commit, store_close,
    };
    return store;
}

static void platform_contract(void)
{
    fixture_t fixture = {0};
    sta_mac_policy_store_t store = make_store(&fixture);
    lab_platform_t platform;
    lab_platform_init(&platform, &platform_ops, &fixture, &store);

    uint8_t first[6] = {0};
    uint8_t second[6] = {0};
    sta_mac_policy_record_t policy = {0};
    assert(lab_platform_resolve_boot_mac(&platform, first, &policy) == LAB_PLATFORM_OK);
    assert(policy.mode == STA_MAC_MODE_FACTORY);
    assert(first[0] == 0x3c && first[5] == 0x80);
    assert(lab_platform_resolve_boot_mac(&platform, second, NULL) == LAB_PLATFORM_OK);
    assert(memcmp(first, second, 6) == 0 && fixture.factory_reads == 1);

    assert(lab_platform_sd_mount(&platform) == LAB_PLATFORM_OK);
    assert(lab_platform_sd_mount(&platform) == LAB_PLATFORM_OK);
    assert(fixture.mounts == 1);
    assert(lab_platform_sd_unmount(&platform) == LAB_PLATFORM_OK);
    assert(fixture.unmounts == 1);

    void *scratch = lab_platform_psram_alloc(&platform, 32);
    assert(scratch != NULL && fixture.allocations == 1);
    lab_platform_psram_free(&platform, scratch);
    assert(fixture.frees == 1);
    assert(lab_platform_now_ms(&platform) == 4242);
    lab_platform_reboot(&platform);
    assert(fixture.reboots == 1);
    assert(!lab_platform_poll_cancel(&platform));
    fixture.cancel_pending = true;
    assert(lab_platform_poll_cancel(&platform));
    assert(fixture.cancel_polls == 2);

    sta_mac_policy_record_t fixed = {
        STA_MAC_POLICY_VERSION, STA_MAC_MODE_FIXED, {0x02, 1, 2, 3, 4, 5},
    };
    assert(lab_platform_policy_save(&platform, &fixed) == LAB_PLATFORM_OK);
    sta_mac_policy_record_t loaded = {0};
    assert(lab_platform_policy_load(&platform, &loaded) == LAB_PLATFORM_OK);
    assert(loaded.mode == STA_MAC_MODE_FIXED && memcmp(loaded.mac, fixed.mac, 6) == 0);

    fixture_t random_fixture = {0};
    sta_mac_policy_store_t random_store = make_store(&random_fixture);
    sta_mac_policy_record_t random = {
        STA_MAC_POLICY_VERSION, STA_MAC_MODE_RANDOM_PER_BOOT, {0},
    };
    assert(sta_mac_policy_encode(&random, random_fixture.stored,
                                 sizeof(random_fixture.stored)) == STA_MAC_POLICY_OK);
    random_fixture.stored_present = true;
    lab_platform_t random_platform;
    lab_platform_init(&random_platform, &platform_ops, &random_fixture, &random_store);
    assert(lab_platform_resolve_boot_mac(&random_platform, first, NULL) == LAB_PLATFORM_OK);
    assert((first[0] & 3) == 2 && random_fixture.entropy_reads == 1);
    assert(lab_platform_resolve_boot_mac(&random_platform, second, NULL) == LAB_PLATFORM_OK);
    assert(memcmp(first, second, 6) == 0 && random_fixture.entropy_reads == 1);
}

static int transport_init(void *context) { return event(context, 'I'); }
static int transport_start(void *context) { return event(context, 'S'); }
static int transport_stop(void *context) { return event(context, 's'); }
static int transport_deinit(void *context) { return event(context, 'i'); }
static int transport_mac(void *context, const uint8_t mac[6])
{
    fixture_t *fixture = context;
    char code = mac[0] == 0x02 ? 'M' : 'm';
    int result = event(fixture, code);
    if (result == 0) memcpy(fixture->current_mac, mac, 6);
    return result;
}
static int transport_callbacks(void *context, bool enabled)
{ return event(context, enabled ? 'C' : 'c'); }
static int transport_appie(void *context, bool enabled)
{ return event(context, enabled ? 'A' : 'a'); }
static int transport_wps(void *context, bool enabled)
{ return event(context, enabled ? 'W' : 'w'); }
static int transport_disconnect(void *context) { return event(context, 'D'); }

static const wps_transport_ops_t transport_ops = {
    transport_init, transport_start, transport_stop, transport_deinit,
    transport_mac, transport_callbacks, transport_appie, transport_wps,
    transport_disconnect,
};

static void radio_clean_cycle_and_late_callbacks(void)
{
    fixture_t fixture = {0};
    sta_mac_policy_store_t store = make_store(&fixture);
    lab_platform_t platform;
    lab_platform_init(&platform, &platform_ops, &fixture, &store);
    uint8_t boot_mac[6];
    assert(lab_platform_resolve_boot_mac(&platform, boot_mac, NULL) == LAB_PLATFORM_OK);
    memcpy(fixture.current_mac, boot_mac, 6);

    lab_radio_t radio;
    lab_radio_init(&radio, &platform, &transport_ops, &fixture, boot_mac);
    const uint8_t session[6] = {0x02, 6, 7, 8, 9, 10};
    uint32_t token = 0;
    assert(lab_radio_acquire(&radio, session, 48, &token));
    assert(token != 0 && !lab_radio_accept_callback(&radio, token));
    assert(!lab_radio_acquire(&radio, session, 0, &token));
    assert(lab_radio_mark_running(&radio, token));
    assert(lab_radio_accept_callback(&radio, token));
    assert(!lab_radio_accept_callback(&radio, token + 1));
    lab_radio_cancel(&radio, token);
    assert(!lab_radio_accept_callback(&radio, token));
    lab_radio_result_t result = lab_radio_release(&radio, -77);
    assert(result.workflow_result == -77 && result.cleanup_ok && !result.quarantined);
    assert(!lab_radio_accept_callback(&radio, token));
    assert(strcmp(fixture.trace, "IMSCAWwDacsmi") == 0);
    assert(fixture.allocations == 1 && fixture.frees == 1);
    assert(fixture.mac_reads == 1);
}

static void acquire_failures_cleanup_or_quarantine(void)
{
    const char setup_failures[] = "IMSCAW";
    const uint8_t session[6] = {0x02, 6, 7, 8, 9, 10};
    const uint8_t boot_mac[6] = {0x3c, 0xdc, 0x75, 0x85, 0xfd, 0x80};
    for (size_t index = 0; index < sizeof(setup_failures) - 1; index++) {
        fixture_t fixture = {0};
        memcpy(fixture.current_mac, boot_mac, 6);
        lab_platform_t platform;
        lab_platform_init(&platform, &platform_ops, &fixture, NULL);
        lab_radio_t radio;
        lab_radio_init(&radio, &platform, &transport_ops, &fixture, boot_mac);
        fixture.fail_code = setup_failures[index];
        uint32_t token = 0;
        assert(!lab_radio_acquire(&radio, session, 16, &token));
        assert(!lab_radio_accept_callback(&radio, token));
        assert(lab_radio_is_quarantined(&radio) == wps_transport_cleanup_pending(&radio.transport));
    }
}

static void cleanup_failures_quarantine_and_retry(void)
{
    const char failures[] = "wDacsmi";
    const uint8_t session[6] = {0x02, 6, 7, 8, 9, 10};
    const uint8_t boot_mac[6] = {0x3c, 0xdc, 0x75, 0x85, 0xfd, 0x80};
    for (size_t index = 0; index < sizeof(failures) - 1; index++) {
        fixture_t fixture = {0};
        memcpy(fixture.current_mac, boot_mac, 6);
        lab_platform_t platform;
        lab_platform_init(&platform, &platform_ops, &fixture, NULL);
        lab_radio_t radio;
        lab_radio_init(&radio, &platform, &transport_ops, &fixture, boot_mac);
        uint32_t token = 0;
        assert(lab_radio_acquire(&radio, session, 16, &token));
        assert(lab_radio_mark_running(&radio, token));
        fixture.fail_code = failures[index];
        lab_radio_result_t result = lab_radio_release(&radio, 13);
        assert(result.workflow_result == 13 && !result.cleanup_ok && result.quarantined);
        assert(lab_radio_is_quarantined(&radio));
        assert(!lab_radio_acquire(&radio, session, 0, &token));
        fixture.fail_code = 0;
        result = lab_radio_release(&radio, 13);
        assert(result.cleanup_ok && !result.quarantined);
        assert(!lab_radio_is_quarantined(&radio));
    }
}

static void wrong_mac_readback_quarantines(void)
{
    fixture_t fixture = {.wrong_readback = true};
    const uint8_t boot_mac[6] = {0x3c, 0xdc, 0x75, 0x85, 0xfd, 0x80};
    memcpy(fixture.current_mac, boot_mac, 6);
    lab_platform_t platform;
    lab_platform_init(&platform, &platform_ops, &fixture, NULL);
    lab_radio_t radio;
    lab_radio_init(&radio, &platform, &transport_ops, &fixture, boot_mac);
    const uint8_t session[6] = {0x02, 6, 7, 8, 9, 10};
    uint32_t token = 0;
    assert(lab_radio_acquire(&radio, session, 8, &token));
    lab_radio_result_t result = lab_radio_release(&radio, 0);
    assert(!result.cleanup_ok && result.quarantined);
    assert(!wps_transport_cleanup_pending(&radio.transport));
}

static void adapter_cleanup_failure_forces_quarantine(void)
{
    lab_radio_t radio;
    memset(&radio, 0, sizeof(radio));
    radio.phase = LAB_RADIO_IDLE;

    lab_radio_quarantine(&radio);

    assert(lab_radio_is_quarantined(&radio));
}

int main(void)
{
    platform_contract();
    radio_clean_cycle_and_late_callbacks();
    acquire_failures_cleanup_or_quarantine();
    cleanup_failures_quarantine_and_retry();
    wrong_mac_readback_quarantines();
    adapter_cleanup_failure_forces_quarantine();
    puts("PASS: WPS lab radio owner");
    return 0;
}
