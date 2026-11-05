#include "wifi_trust_wire.h"

#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define STATUS_FIELDS \
    " MODE=monitor SCOPE=current_channel CHANNEL=6" \
    " BASELINE_LOADED=1 BASELINE_COUNT=2 BOOT=0001020304050607" \
    " CREATED_UNIX=1793650000 STORE=recovered_retry" \
    " RECOVERY=restored_backup RECEIVED=1 FILTERED=2 UNRELATED=3" \
    " ACCEPTED=4 INVALID=5 PROFILES=6 CONFLICTS=7 EVENTS_INFO=8" \
    " EVENTS_WARN=9 EVENTS_ALERT=10 CAPACITY_DROPS=11 RX_DROPS=12" \
    " OUTPUT_FAILURES=13 STORAGE_FAILURES=14 RUNNING=1 STOPPING=0\r\n"

static void untouched(const char *bytes, size_t size)
{
    for (size_t i = 0; i < size; ++i)
        assert((unsigned char)bytes[i] == 0xa5U);
}

static void privacy(const char *line)
{
    static const char *const forbidden[] = {
        "evil_twin", "attacker", "compromised", "safe", "exploit",
        "attribution", "credential", "password", "PIN=", "KEY=",
        "raw_frame", "raw frame"
    };
    for (size_t i = 0; i < sizeof(forbidden) / sizeof(forbidden[0]); ++i)
        assert(strstr(line, forbidden[i]) == NULL);
    const size_t length = strlen(line);
    assert(length >= 2U && line[length - 2U] == '\r' &&
           line[length - 1U] == '\n');
    for (size_t i = 0; i + 2U < length; ++i)
        assert(line[i] != '\r' && line[i] != '\n');
}

static void exact(int result, const char *line, const char *want)
{
    if (result != (int)strlen(want) || strcmp(line, want) != 0) {
        fprintf(stderr, "record mismatch result=%d want=%zu\nactual: %s\nexpect: %s\n",
                result, strlen(want), line, want);
    }
    assert(result == (int)strlen(want));
    assert(strcmp(line, want) == 0);
    privacy(line);
}

static void fill_selector(uint8_t out[4], uint8_t type)
{
    out[0] = 0x00U;
    out[1] = 0x0fU;
    out[2] = 0xacU;
    out[3] = type;
}

static wifi_trust_profile_t profile_fixture(void)
{
    wifi_trust_profile_t profile;
    memset(&profile, 0, sizeof(profile));
    const uint8_t bssid[6] = {0x02U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U};
    memcpy(profile.bssid, bssid, sizeof(bssid));
    profile.ssid_status = SX_VALID;
    profile.ssid_len = 4U;
    profile.ssid[0] = 'A';
    profile.ssid[1] = 0x00U;
    profile.ssid[2] = 0xffU;
    profile.ssid[3] = 0x55U;
    profile.source = SX_PROBE_RESP;
    profile.privacy = 1;
    profile.rsn.status = SX_VALID;
    profile.rsn.group_present = true;
    fill_selector(profile.rsn.group, 4U);
    profile.rsn.pairwise_known = true;
    profile.rsn.pairwise_count = 2U;
    fill_selector(profile.rsn.pairwise[0], 4U);
    fill_selector(profile.rsn.pairwise[1], 8U);
    profile.rsn.akm_known = true;
    profile.rsn.akm_count = 2U;
    fill_selector(profile.rsn.akm[0], 8U);
    fill_selector(profile.rsn.akm[1], 2U);
    profile.rsn.capabilities_present = true;
    profile.rsn.pmf_capable = true;
    profile.rsn.pmf_required = true;
    profile.rsn.management_present = true;
    fill_selector(profile.rsn.management, 6U);
    profile.wpa.status = SX_ABSENT;
    profile.rsnxe.status = SX_VALID;
    profile.rsnxe.present = true;
    profile.rsnxe.len = 2U;
    profile.rsnxe.bytes[0] = 0x21U;
    profile.rsnxe.bytes[1] = 0x55U;
    profile.wps.status = SX_VALID;
    profile.wps.present = true;
    profile.wps.state = 2;
    profile.wps.config_methods = 128;
    profile.wps.setup_locked = 0;
    profile.wps.selected_registrar = 1;
    profile.wps.manufacturer.present = true;
    profile.wps.manufacturer.len = 3U;
    memcpy(profile.wps.manufacturer.bytes, "LAB", 3U);
    profile.wps.model_name.present = true;
    profile.wps.model_name.len = 2U;
    profile.wps.model_name.bytes[1] = 0x55U;
    profile.country.status = SX_VALID;
    memcpy(profile.country.code, "PL ", 3U);
    profile.channel = 6U;
    profile.observed_us = UINT64_C(123456874);
    assert(wifi_trust_profile_valid(&profile));
    return profile;
}

static wifi_trust_store_meta_t meta_fixture(void)
{
    wifi_trust_store_meta_t meta = {0};
    for (size_t i = 0; i < sizeof(meta.boot_id); ++i)
        meta.boot_id[i] = (uint8_t)i;
    meta.created_unix_known = true;
    meta.created_unix = UINT64_C(1793650000);
    meta.created_monotonic_us = UINT64_C(987654321);
    return meta;
}

static wifi_trust_event_t event_identity(wifi_trust_reason_t reason,
                                         wifi_trust_field_t field)
{
    wifi_trust_event_t event;
    memset(&event, 0, sizeof(event));
    event.reason = reason;
    event.field = field;
    const uint8_t bssid[6] = {0x02U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U};
    memcpy(event.bssid, bssid, sizeof(bssid));
    event.ssid_status = SX_VALID;
    event.ssid_len = 4U;
    event.ssid[0] = 'A';
    event.ssid[1] = 0x00U;
    event.ssid[2] = 0xffU;
    event.ssid[3] = 0x55U;
    event.source = SX_PROBE_RESP;
    event.channel = 6U;
    event.timestamp_us = UINT64_C(123456874);
    return event;
}

static void bytes_value(wifi_trust_event_value_t *value,
                        const uint8_t *bytes, size_t length)
{
    memset(value, 0, sizeof(*value));
    assert(length <= sizeof(value->bytes));
    value->status = SX_VALID;
    value->len = (uint8_t)length;
    memcpy(value->bytes, bytes, length);
}

static void scalar_value(wifi_trust_event_value_t *value, int32_t number)
{
    memset(value, 0, sizeof(*value));
    value->status = SX_VALID;
    value->number = number;
}

static void values_for_field(wifi_trust_event_t *event)
{
    static const uint8_t aa[2] = {0x41U, 0x41U};
    static const uint8_t bb[2] = {0x42U, 0x42U};
    wifi_trust_profile_t baseline = profile_fixture();
    wifi_trust_profile_t current = baseline;
    switch (event->field) {
    case WIFI_TRUST_FIELD_NONE:
        event->baseline.status = SX_UNKNOWN;
        event->current.status = SX_UNKNOWN;
        break;
    case WIFI_TRUST_FIELD_ADVERTISEMENT:
        event->baseline.status = SX_UNKNOWN;
        event->current.status = SX_INVALID;
        break;
    case WIFI_TRUST_FIELD_SSID:
    case WIFI_TRUST_FIELD_RSNXE:
    case WIFI_TRUST_FIELD_WPS_MANUFACTURER:
    case WIFI_TRUST_FIELD_WPS_MODEL_NAME:
    case WIFI_TRUST_FIELD_WPS_MODEL_NUMBER:
    case WIFI_TRUST_FIELD_WPS_DEVICE_NAME:
        bytes_value(&event->baseline, aa, sizeof(aa));
        bytes_value(&event->current, bb, sizeof(bb));
        break;
    case WIFI_TRUST_FIELD_PRIVACY:
        scalar_value(&event->baseline, 1);
        scalar_value(&event->current, 0);
        break;
    case WIFI_TRUST_FIELD_AKM:
        current.rsn.akm[1][3] = 3U;
        assert(wifi_trust_value_from_profile(&baseline, event->field,
                                             &event->baseline));
        assert(wifi_trust_value_from_profile(&current, event->field,
                                             &event->current));
        break;
    case WIFI_TRUST_FIELD_CIPHER:
        current.rsn.pairwise[1][3] = 9U;
        assert(wifi_trust_value_from_profile(&baseline, event->field,
                                             &event->baseline));
        assert(wifi_trust_value_from_profile(&current, event->field,
                                             &event->current));
        break;
    case WIFI_TRUST_FIELD_PMF:
        scalar_value(&event->baseline, 2);
        scalar_value(&event->current, 1);
        break;
    case WIFI_TRUST_FIELD_WPS:
        event->baseline.status = SX_ABSENT;
        scalar_value(&event->current, 1);
        break;
    case WIFI_TRUST_FIELD_WPS_STATE:
        scalar_value(&event->baseline, 1);
        scalar_value(&event->current, 2);
        break;
    case WIFI_TRUST_FIELD_WPS_CONFIG_METHODS:
        scalar_value(&event->baseline, 128);
        scalar_value(&event->current, 256);
        break;
    case WIFI_TRUST_FIELD_WPS_LOCK:
    case WIFI_TRUST_FIELD_WPS_SELECTED_REGISTRAR:
        scalar_value(&event->baseline, 1);
        scalar_value(&event->current, 0);
        break;
    case WIFI_TRUST_FIELD_COUNTRY:
        bytes_value(&event->baseline, (const uint8_t *)"PL ", 3U);
        bytes_value(&event->current, (const uint8_t *)"USI", 3U);
        break;
    case WIFI_TRUST_FIELD_CHANNEL:
        scalar_value(&event->baseline, 6);
        scalar_value(&event->current, 11);
        break;
    default:
        assert(false);
    }
}

static void test_exact_reason_records(void)
{
    static const struct {
        wifi_trust_reason_t reason;
        wifi_trust_field_t field;
        const char *middle;
    } cases[] = {
        {WIFI_TRUST_NEW_BSSID, WIFI_TRUST_FIELD_NONE,
         "FIELD=bssid BASE=absent CURRENT=observed REASON=new_bssid SEVERITY=info"},
        {WIFI_TRUST_SSID_CHANGED, WIFI_TRUST_FIELD_SSID,
         "FIELD=ssid BASE=hex:4141 CURRENT=hex:4242 REASON=ssid_changed SEVERITY=warn"},
        {WIFI_TRUST_AKM_CHANGED, WIFI_TRUST_FIELD_AKM,
         "FIELD=akm BASE=hex:020102000FAC08000FAC02010000 CURRENT=hex:020102000FAC08000FAC03010000 REASON=akm_changed SEVERITY=warn"},
        {WIFI_TRUST_CIPHER_CHANGED, WIFI_TRUST_FIELD_PRIVACY,
         "FIELD=privacy BASE=num:1 CURRENT=num:0 REASON=cipher_changed SEVERITY=warn"},
        {WIFI_TRUST_PMF_DOWNGRADE, WIFI_TRUST_FIELD_PMF,
         "FIELD=pmf BASE=num:2 CURRENT=num:1 REASON=pmf_downgrade SEVERITY=alert"},
        {WIFI_TRUST_RSNXE_CHANGED, WIFI_TRUST_FIELD_RSNXE,
         "FIELD=rsnxe BASE=hex:4141 CURRENT=hex:4242 REASON=rsnxe_changed SEVERITY=warn"},
        {WIFI_TRUST_WPS_ENABLED, WIFI_TRUST_FIELD_WPS,
         "FIELD=wps BASE=absent CURRENT=num:1 REASON=wps_enabled SEVERITY=warn"},
        {WIFI_TRUST_WPS_LOCK_CHANGED, WIFI_TRUST_FIELD_WPS_LOCK,
         "FIELD=wps_lock BASE=num:1 CURRENT=num:0 REASON=wps_lock_changed SEVERITY=warn"},
        {WIFI_TRUST_COUNTRY_CHANGED, WIFI_TRUST_FIELD_COUNTRY,
         "FIELD=country BASE=hex:504C20 CURRENT=hex:555349 REASON=country_changed SEVERITY=info"},
        {WIFI_TRUST_CHANNEL_CHANGED, WIFI_TRUST_FIELD_CHANNEL,
         "FIELD=channel BASE=num:6 CURRENT=num:11 REASON=channel_changed SEVERITY=info"},
        {WIFI_TRUST_ADVERTISEMENT_CONFLICT, WIFI_TRUST_FIELD_WPS_STATE,
         "FIELD=wps_state BASE=num:1 CURRENT=num:2 REASON=advertisement_conflict SEVERITY=warn"},
        {WIFI_TRUST_MALFORMED_OBSERVATION, WIFI_TRUST_FIELD_ADVERTISEMENT,
         "FIELD=advertisement BASE=unknown CURRENT=invalid REASON=malformed_observation SEVERITY=warn"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        wifi_trust_event_t event = event_identity(cases[i].reason,
                                                  cases[i].field);
        values_for_field(&event);
        if (event.reason == WIFI_TRUST_MALFORMED_OBSERVATION) {
            memset(event.bssid, 0, sizeof(event.bssid));
            event.ssid_status = SX_INVALID;
            event.ssid_len = 0U;
            memset(event.ssid, 0, sizeof(event.ssid));
            event.source = SX_NONE;
            event.channel = 0U;
        }
        char want[WIFI_TRUST_LINE_MAX];
        const char *identity = event.reason == WIFI_TRUST_MALFORMED_OBSERVATION ?
            "[WIFI_TRUST/1] EVENT BSSID=00:00:00:00:00:00 SSID=invalid CHANNEL=unknown SOURCE=unknown " :
            "[WIFI_TRUST/1] EVENT BSSID=02:11:22:33:44:55 SSID=hex:4100FF55 CHANNEL=6 SOURCE=probe_response ";
        const int want_length = snprintf(
            want, sizeof(want), "%s%s CONFIDENCE=observation TS_US=123456874\r\n",
            identity, cases[i].middle);
        assert(want_length > 0 && (size_t)want_length < sizeof(want));
        char out[WIFI_TRUST_LINE_MAX];
        exact(wifi_trust_format_event(out, sizeof(out), &event), out, want);
    }
}

static void test_all_field_tokens_and_invalid_pairs(void)
{
    static const char *const tokens[WIFI_TRUST_FIELD_COUNT] = {
        [WIFI_TRUST_FIELD_NONE] = "bssid",
        [WIFI_TRUST_FIELD_ADVERTISEMENT] = "advertisement",
        [WIFI_TRUST_FIELD_SSID] = "ssid",
        [WIFI_TRUST_FIELD_PRIVACY] = "privacy",
        [WIFI_TRUST_FIELD_AKM] = "akm",
        [WIFI_TRUST_FIELD_CIPHER] = "cipher",
        [WIFI_TRUST_FIELD_PMF] = "pmf",
        [WIFI_TRUST_FIELD_RSNXE] = "rsnxe",
        [WIFI_TRUST_FIELD_WPS] = "wps",
        [WIFI_TRUST_FIELD_WPS_STATE] = "wps_state",
        [WIFI_TRUST_FIELD_WPS_CONFIG_METHODS] = "wps_config_methods",
        [WIFI_TRUST_FIELD_WPS_LOCK] = "wps_lock",
        [WIFI_TRUST_FIELD_WPS_SELECTED_REGISTRAR] = "wps_selected_registrar",
        [WIFI_TRUST_FIELD_WPS_MANUFACTURER] = "wps_manufacturer",
        [WIFI_TRUST_FIELD_WPS_MODEL_NAME] = "wps_model_name",
        [WIFI_TRUST_FIELD_WPS_MODEL_NUMBER] = "wps_model_number",
        [WIFI_TRUST_FIELD_WPS_DEVICE_NAME] = "wps_device_name",
        [WIFI_TRUST_FIELD_COUNTRY] = "country",
        [WIFI_TRUST_FIELD_CHANNEL] = "channel",
    };
    char out[WIFI_TRUST_LINE_MAX];
    for (wifi_trust_field_t field = WIFI_TRUST_FIELD_SSID;
         field < WIFI_TRUST_FIELD_COUNT; ++field) {
        wifi_trust_event_t event = event_identity(
            WIFI_TRUST_ADVERTISEMENT_CONFLICT, field);
        values_for_field(&event);
        assert(wifi_trust_format_event(out, sizeof(out), &event) > 0);
        char needle[48];
        const int length = snprintf(needle, sizeof(needle), " FIELD=%s ",
                                    tokens[field]);
        assert(length > 0 && (size_t)length < sizeof(needle));
        assert(strstr(out, needle) != NULL);
        privacy(out);
    }

    wifi_trust_event_t event = event_identity(WIFI_TRUST_NO_CHANGE,
                                              WIFI_TRUST_FIELD_SSID);
    values_for_field(&event);
    memset(out, 0xa5, sizeof(out));
    assert(wifi_trust_format_event(out, sizeof(out), &event) == -1);
    untouched(out, sizeof(out));
    event.reason = WIFI_TRUST_REASON_COUNT;
    assert(wifi_trust_format_event(out, sizeof(out), &event) == -1);
    event.reason = (wifi_trust_reason_t)-1;
    assert(wifi_trust_format_event(out, sizeof(out), &event) == -1);
    event.reason = WIFI_TRUST_SSID_CHANGED;
    event.field = WIFI_TRUST_FIELD_COUNTRY;
    assert(wifi_trust_format_event(out, sizeof(out), &event) == -1);
    event.reason = WIFI_TRUST_ADVERTISEMENT_CONFLICT;
    event.field = WIFI_TRUST_FIELD_ADVERTISEMENT;
    assert(wifi_trust_format_event(out, sizeof(out), &event) == -1);
    event.field = WIFI_TRUST_FIELD_COUNT;
    assert(wifi_trust_format_event(out, sizeof(out), &event) == -1);
    untouched(out, sizeof(out));
}

static void test_event_uncertainty_and_validation(void)
{
    char out[WIFI_TRUST_LINE_MAX];
    wifi_trust_event_t event = event_identity(WIFI_TRUST_SSID_CHANGED,
                                              WIFI_TRUST_FIELD_SSID);
    values_for_field(&event);
    event.ssid_status = SX_VALID;
    event.ssid_len = 0U;
    memset(event.ssid, 0, sizeof(event.ssid));
    assert(wifi_trust_format_event(out, sizeof(out), &event) > 0);
    assert(strstr(out, " SSID=hex: ") != NULL);
    event.ssid_status = SX_ABSENT;
    assert(wifi_trust_format_event(out, sizeof(out), &event) > 0);
    assert(strstr(out, " SSID=absent ") != NULL);
    event.ssid_status = SX_UNKNOWN;
    assert(wifi_trust_format_event(out, sizeof(out), &event) > 0);
    assert(strstr(out, " SSID=unknown ") != NULL);

    event = event_identity(WIFI_TRUST_MALFORMED_OBSERVATION,
                           WIFI_TRUST_FIELD_ADVERTISEMENT);
    values_for_field(&event);
    event.source = SX_NONE;
    event.channel = 0U;
    event.current.number = 0;
    assert(wifi_trust_format_event(out, sizeof(out), &event) > 0);
    event.current.number = 6;
    event.channel = 6U;
    assert(wifi_trust_format_event(out, sizeof(out), &event) > 0);

    event = event_identity(WIFI_TRUST_SSID_CHANGED, WIFI_TRUST_FIELD_SSID);
    values_for_field(&event);
    const wifi_trust_event_t valid = event;
    const struct { int kind; int value; } corruptions[] = {
        {0, SX_NONE}, {0, SX_ASSOC_REQ}, {1, 234}, {2, SX_INVALID},
        {3, 33}, {4, SX_INVALID}, {5, WIFI_TRUST_EVENT_VALUE_BYTES + 1},
        {6, 1}, {7, 1}
    };
    for (size_t i = 0; i < sizeof(corruptions) / sizeof(corruptions[0]); ++i) {
        event = valid;
        switch (corruptions[i].kind) {
        case 0: event.source = (sx_source_t)corruptions[i].value; break;
        case 1: event.channel = (uint8_t)corruptions[i].value; break;
        case 2: event.ssid_status = (sx_status_t)corruptions[i].value; break;
        case 3: event.ssid_len = (uint8_t)corruptions[i].value; break;
        case 4: event.baseline.status = (sx_status_t)corruptions[i].value; break;
        case 5: event.baseline.len = (uint8_t)corruptions[i].value; break;
        case 6: event.baseline.bytes[event.baseline.len] = 1U; break;
        case 7: event.baseline.number = corruptions[i].value; break;
        default: assert(false);
        }
        memset(out, 0xa5, sizeof(out));
        assert(wifi_trust_format_event(out, sizeof(out), &event) == -1);
        untouched(out, sizeof(out));
    }
    event = valid;
    event.current = event.baseline;
    memset(out, 0xa5, sizeof(out));
    assert(wifi_trust_format_event(out, sizeof(out), &event) == -1);
    untouched(out, sizeof(out));
    assert(wifi_trust_format_event(NULL, sizeof(out), &valid) == -1);
    assert(wifi_trust_format_event(out, sizeof(out), NULL) == -1);
}

static void unknown_value(wifi_trust_event_value_t *value,
                          wifi_trust_field_t field)
{
    memset(value, 0, sizeof(*value));
    value->status = SX_UNKNOWN;
    if (field == WIFI_TRUST_FIELD_PRIVACY ||
        field == WIFI_TRUST_FIELD_WPS_STATE ||
        field == WIFI_TRUST_FIELD_WPS_CONFIG_METHODS ||
        field == WIFI_TRUST_FIELD_WPS_LOCK ||
        field == WIFI_TRUST_FIELD_WPS_SELECTED_REGISTRAR)
        value->number = -1;
}

static void reject_event_untouched(const wifi_trust_event_t *event)
{
    char out[WIFI_TRUST_LINE_MAX];
    memset(out, 0xa5, sizeof(out));
    assert(wifi_trust_format_event(out, sizeof(out), event) == -1);
    untouched(out, sizeof(out));
}

static void swap_four(uint8_t *left, uint8_t *right)
{
    uint8_t temporary[4];
    memcpy(temporary, left, sizeof(temporary));
    memcpy(left, right, sizeof(temporary));
    memcpy(right, temporary, sizeof(temporary));
}

static void test_reason_semantics_reject_unreachable_events(void)
{
    wifi_trust_event_t event = event_identity(WIFI_TRUST_NEW_BSSID,
                                              WIFI_TRUST_FIELD_NONE);
    values_for_field(&event);
    scalar_value(&event.current, 1);
    reject_event_untouched(&event);

    event = event_identity(WIFI_TRUST_SSID_CHANGED, WIFI_TRUST_FIELD_SSID);
    values_for_field(&event);
    unknown_value(&event.baseline, event.field);
    reject_event_untouched(&event);

    event = event_identity(WIFI_TRUST_AKM_CHANGED, WIFI_TRUST_FIELD_AKM);
    values_for_field(&event);
    event.current = event.baseline;
    swap_four(event.current.bytes + 3U, event.current.bytes + 7U);
    reject_event_untouched(&event);

    event = event_identity(WIFI_TRUST_CIPHER_CHANGED,
                           WIFI_TRUST_FIELD_PRIVACY);
    values_for_field(&event);
    unknown_value(&event.baseline, event.field);
    reject_event_untouched(&event);
    event.field = WIFI_TRUST_FIELD_CIPHER;
    values_for_field(&event);
    event.current = event.baseline;
    swap_four(event.current.bytes + 7U, event.current.bytes + 11U);
    reject_event_untouched(&event);

    event = event_identity(WIFI_TRUST_PMF_DOWNGRADE, WIFI_TRUST_FIELD_PMF);
    scalar_value(&event.baseline, 0);
    scalar_value(&event.current, 1);
    reject_event_untouched(&event);
    scalar_value(&event.baseline, 1);
    scalar_value(&event.current, 2);
    reject_event_untouched(&event);

    event = event_identity(WIFI_TRUST_RSNXE_CHANGED,
                           WIFI_TRUST_FIELD_RSNXE);
    values_for_field(&event);
    unknown_value(&event.current, event.field);
    reject_event_untouched(&event);

    event = event_identity(WIFI_TRUST_WPS_ENABLED, WIFI_TRUST_FIELD_WPS);
    values_for_field(&event);
    unknown_value(&event.baseline, event.field);
    reject_event_untouched(&event);
    scalar_value(&event.baseline, 1);
    memset(&event.current, 0, sizeof(event.current));
    event.current.status = SX_ABSENT;
    reject_event_untouched(&event);

    event = event_identity(WIFI_TRUST_WPS_LOCK_CHANGED,
                           WIFI_TRUST_FIELD_WPS_LOCK);
    values_for_field(&event);
    unknown_value(&event.current, event.field);
    reject_event_untouched(&event);

    event = event_identity(WIFI_TRUST_COUNTRY_CHANGED,
                           WIFI_TRUST_FIELD_COUNTRY);
    values_for_field(&event);
    unknown_value(&event.baseline, event.field);
    reject_event_untouched(&event);

    event = event_identity(WIFI_TRUST_CHANNEL_CHANGED,
                           WIFI_TRUST_FIELD_CHANNEL);
    values_for_field(&event);
    unknown_value(&event.baseline, event.field);
    reject_event_untouched(&event);

    event = event_identity(WIFI_TRUST_ADVERTISEMENT_CONFLICT,
                           WIFI_TRUST_FIELD_WPS_STATE);
    values_for_field(&event);
    event.source = SX_BEACON;
    reject_event_untouched(&event);
    event.source = SX_PROBE_RESP;
    unknown_value(&event.current, event.field);
    reject_event_untouched(&event);

    event = event_identity(WIFI_TRUST_MALFORMED_OBSERVATION,
                           WIFI_TRUST_FIELD_ADVERTISEMENT);
    values_for_field(&event);
    event.baseline.status = SX_VALID;
    event.current.status = SX_VALID;
    reject_event_untouched(&event);
    event.baseline.status = SX_UNKNOWN;
    event.current.status = SX_UNKNOWN;
    reject_event_untouched(&event);
    event.baseline.status = SX_INVALID;
    event.current.status = SX_INVALID;
    char out[WIFI_TRUST_LINE_MAX];
    assert(wifi_trust_format_event(out, sizeof(out), &event) > 0);
    assert(strstr(out, " BASE=invalid CURRENT=invalid ") != NULL);
    privacy(out);
    event.current.number = event.channel;
    reject_event_untouched(&event);

    static const struct {
        sx_status_t baseline;
        sx_status_t current;
    } malformed_pairs[] = {
        {SX_UNKNOWN, SX_INVALID},
        {SX_INVALID, SX_VALID},
        {SX_VALID, SX_INVALID},
        {SX_INVALID, SX_INVALID},
    };
    for (size_t i = 0;
         i < sizeof(malformed_pairs) / sizeof(malformed_pairs[0]); ++i) {
        event = event_identity(WIFI_TRUST_MALFORMED_OBSERVATION,
                               WIFI_TRUST_FIELD_ADVERTISEMENT);
        values_for_field(&event);
        event.baseline.status = malformed_pairs[i].baseline;
        event.current.status = malformed_pairs[i].current;
        assert(wifi_trust_format_event(out, sizeof(out), &event) > 0);
        privacy(out);
    }

    static const struct {
        sx_status_t current_status;
        int32_t baseline_mode;
        int32_t current_mode;
    } pmf_edges[] = {
        {SX_VALID, 2, 1}, {SX_VALID, 2, 0}, {SX_ABSENT, 2, 0},
        {SX_VALID, 1, 0}, {SX_ABSENT, 1, 0},
    };
    for (size_t i = 0; i < sizeof(pmf_edges) / sizeof(pmf_edges[0]); ++i) {
        event = event_identity(WIFI_TRUST_PMF_DOWNGRADE,
                               WIFI_TRUST_FIELD_PMF);
        scalar_value(&event.baseline, pmf_edges[i].baseline_mode);
        if (pmf_edges[i].current_status == SX_VALID) {
            scalar_value(&event.current, pmf_edges[i].current_mode);
        } else {
            memset(&event.current, 0, sizeof(event.current));
            event.current.status = pmf_edges[i].current_status;
        }
        assert(wifi_trust_format_event(out, sizeof(out), &event) > 0);
        privacy(out);
    }
}

static void test_exact_baseline(void)
{
    const wifi_trust_profile_t profile = profile_fixture();
    const wifi_trust_store_meta_t meta = meta_fixture();
    static const char want[] =
        "[WIFI_TRUST/1] BASELINE BSSID=02:11:22:33:44:55"
        " SSID=hex:4100FF55 CHANNEL=6 SOURCE=probe_response PRIVACY=num:1"
        " AKM=hex:020102000FAC08000FAC02010000"
        " CIPHER=hex:020102000FAC04000FAC04000FAC0801000FAC0601000000"
        " PMF=num:2 RSNXE=hex:2155 WPS=num:1 WPS_STATE=num:2"
        " WPS_CONFIG_METHODS=num:128 WPS_LOCK=num:0"
        " WPS_SELECTED_REGISTRAR=num:1 COUNTRY=hex:504C20"
        " OBSERVED_US=123456874 BOOT=0001020304050607\r\n";
    char out[WIFI_TRUST_LINE_MAX];
    exact(wifi_trust_format_baseline(out, sizeof(out), &profile, &meta),
          out, want);

    wifi_trust_profile_t invalid = profile;
    invalid.source = SX_ASSOC_REQ;
    memset(out, 0xa5, sizeof(out));
    assert(wifi_trust_format_baseline(out, sizeof(out), &invalid, &meta) == -1);
    untouched(out, sizeof(out));
    wifi_trust_store_meta_t bad_meta = meta;
    bad_meta.created_unix_known = false;
    assert(wifi_trust_format_baseline(out, sizeof(out), &profile,
                                      &bad_meta) == -1);
    untouched(out, sizeof(out));
    bad_meta.created_unix = 0U;
    exact(wifi_trust_format_baseline(out, sizeof(out), &profile, &bad_meta),
          out, want);
    assert(wifi_trust_format_baseline(NULL, sizeof(out), &profile, &meta) == -1);
    assert(wifi_trust_format_baseline(out, sizeof(out), NULL, &meta) == -1);
    assert(wifi_trust_format_baseline(out, sizeof(out), &profile, NULL) == -1);
}

static void test_baseline_preserves_canonical_unknown_and_absent(void)
{
    wifi_trust_profile_t profile;
    memset(&profile, 0, sizeof(profile));
    profile.bssid[0] = 0x02U;
    profile.bssid[5] = 0x01U;
    profile.ssid_status = SX_ABSENT;
    profile.source = SX_BEACON;
    profile.privacy = -1;
    profile.rsn.status = SX_UNKNOWN;
    profile.wpa.status = SX_UNKNOWN;
    profile.rsnxe.status = SX_ABSENT;
    profile.wps.status = SX_ABSENT;
    profile.wps.state = -1;
    profile.wps.config_methods = -1;
    profile.wps.setup_locked = -1;
    profile.wps.selected_registrar = -1;
    profile.country.status = SX_ABSENT;
    assert(wifi_trust_profile_valid(&profile));
    wifi_trust_store_meta_t meta = meta_fixture();
    meta.created_unix_known = false;
    meta.created_unix = 0U;
    char out[WIFI_TRUST_LINE_MAX];
    const int length = wifi_trust_format_baseline(out, sizeof(out), &profile,
                                                   &meta);
    assert(length > 0);
    assert(strstr(out, " SSID=absent CHANNEL=unknown SOURCE=beacon") != NULL);
    assert(strstr(out, " PRIVACY=unknown") != NULL);
    assert(strstr(out, " PMF=unknown RSNXE=absent WPS=absent") != NULL);
    assert(strstr(out, " WPS_STATE=unknown WPS_CONFIG_METHODS=unknown") != NULL);
    assert(strstr(out, " WPS_LOCK=unknown WPS_SELECTED_REGISTRAR=unknown") != NULL);
    assert(strstr(out, " COUNTRY=absent OBSERVED_US=0") != NULL);
    privacy(out);
}

static wifi_trust_status_t status_fixture(void)
{
    wifi_trust_status_t status;
    memset(&status, 0, sizeof(status));
    status.mode = WIFI_TRUST_MODE_MONITOR;
    status.channel = 6U;
    status.baseline_loaded = 1U;
    status.baseline_count = 2U;
    status.boot_known = 1U;
    for (size_t i = 0; i < sizeof(status.boot_id); ++i)
        status.boot_id[i] = (uint8_t)i;
    status.created_unix_known = 1U;
    status.created_unix = UINT64_C(1793650000);
    status.store = WIFI_TRUST_STORE_RECOVERED_RETRY;
    status.recovery = WIFI_TRUST_RECOVERY_RESTORED_BACKUP;
    status.received = 1U;
    status.filtered = 2U;
    status.unrelated = 3U;
    status.accepted = 4U;
    status.invalid = 5U;
    status.profiles = 6U;
    status.conflicts = 7U;
    status.events_info = 8U;
    status.events_warn = 9U;
    status.events_alert = 10U;
    status.capacity_drops = 11U;
    status.rx_drops = 12U;
    status.output_failures = 13U;
    status.storage_failures = 14U;
    status.running = 1U;
    return status;
}

static void test_exact_status_terminal_and_all_tokens(void)
{
    wifi_trust_status_t status = status_fixture();
    char out[WIFI_TRUST_LINE_MAX];
    exact(wifi_trust_format_status(out, sizeof(out), &status), out,
          "[WIFI_TRUST/1] STATUS" STATUS_FIELDS);
    static const char *const outcomes[] = {
        "ok", "stopped", "busy", "invalid", "timeout", "queue_overflow",
        "restore_failed", "storage_failed", "storage_uncertain",
        "output_failed"
    };
    for (size_t i = 0; i < sizeof(outcomes) / sizeof(outcomes[0]); ++i) {
        char want[WIFI_TRUST_LINE_MAX];
        const int length = snprintf(want, sizeof(want),
            "[WIFI_TRUST/1] TERMINAL OUTCOME=%s%s", outcomes[i],
            STATUS_FIELDS);
        assert(length > 0 && (size_t)length < sizeof(want));
        exact(wifi_trust_format_terminal(out, sizeof(out), &status,
                                         outcomes[i]), out, want);
    }

    static const char *const store_tokens[] = {
        "ok", "ok_backup_pending", "published_uncertain", "recovered_retry",
        "not_found", "io", "format", "capacity", "publish", "recovery"
    };
    for (int value = WIFI_TRUST_STORE_OK;
         value <= WIFI_TRUST_STORE_RECOVERY; ++value) {
        status.store = (wifi_trust_store_result_t)value;
        assert(wifi_trust_format_status(out, sizeof(out), &status) > 0);
        char needle[48];
        const int length = snprintf(needle, sizeof(needle), " STORE=%s ",
                                    store_tokens[value]);
        assert(length > 0 && (size_t)length < sizeof(needle));
        assert(strstr(out, needle) != NULL);
    }
    static const char *const recovery_tokens[] = {
        "none", "cleared_stage", "restored_backup", "kept_target"
    };
    for (int value = WIFI_TRUST_RECOVERY_NONE;
         value <= WIFI_TRUST_RECOVERY_KEPT_TARGET; ++value) {
        status.recovery = (wifi_trust_recovery_action_t)value;
        assert(wifi_trust_format_status(out, sizeof(out), &status) > 0);
        char needle[48];
        const int length = snprintf(needle, sizeof(needle), " RECOVERY=%s ",
                                    recovery_tokens[value]);
        assert(length > 0 && (size_t)length < sizeof(needle));
        assert(strstr(out, needle) != NULL);
    }
    static const char *const mode_tokens[] = {"idle", "capture", "monitor"};
    for (int value = WIFI_TRUST_MODE_IDLE;
         value < WIFI_TRUST_MODE_COUNT; ++value) {
        status.mode = (wifi_trust_mode_t)value;
        if (status.mode == WIFI_TRUST_MODE_IDLE) status.running = 0U;
        assert(wifi_trust_format_status(out, sizeof(out), &status) > 0);
        char needle[32];
        const int length = snprintf(needle, sizeof(needle), " MODE=%s ",
                                    mode_tokens[value]);
        assert(length > 0 && (size_t)length < sizeof(needle));
        assert(strstr(out, needle) != NULL);
    }
}

static void test_status_validation_and_unknown_meta(void)
{
    char out[WIFI_TRUST_LINE_MAX];
    wifi_trust_status_t status = {0};
    status.mode = WIFI_TRUST_MODE_IDLE;
    status.store = WIFI_TRUST_STORE_NOT_FOUND;
    status.recovery = WIFI_TRUST_RECOVERY_NONE;
    exact(wifi_trust_format_status(out, sizeof(out), &status), out,
          "[WIFI_TRUST/1] STATUS MODE=idle SCOPE=current_channel"
          " CHANNEL=unknown BASELINE_LOADED=0 BASELINE_COUNT=0 BOOT=unknown"
          " CREATED_UNIX=unknown STORE=not_found RECOVERY=none RECEIVED=0"
          " FILTERED=0 UNRELATED=0 ACCEPTED=0 INVALID=0 PROFILES=0"
          " CONFLICTS=0 EVENTS_INFO=0 EVENTS_WARN=0 EVENTS_ALERT=0"
          " CAPACITY_DROPS=0 RX_DROPS=0 OUTPUT_FAILURES=0"
          " STORAGE_FAILURES=0 RUNNING=0 STOPPING=0\r\n");

    const wifi_trust_status_t valid = status_fixture();
    for (unsigned kind = 0; kind < 14U; ++kind) {
        status = valid;
        switch (kind) {
        case 0: status.mode = WIFI_TRUST_MODE_COUNT; break;
        case 1: status.channel = 234U; break;
        case 2: status.baseline_loaded = 2U; break;
        case 3: status.baseline_count = WIFI_TRUST_MAX_PROFILES + 1U; break;
        case 4: status.boot_known = 2U; break;
        case 5: status.created_unix_known = 2U; break;
        case 6: status.store = (wifi_trust_store_result_t)99; break;
        case 7: status.recovery = (wifi_trust_recovery_action_t)99; break;
        case 8: status.profiles = WIFI_TRUST_MAX_PROFILES + 1U; break;
        case 9: status.running = 2U; break;
        case 10: status.stopping = 2U; break;
        case 11: status.boot_known = 0U; break;
        case 12: status.baseline_loaded = 0U; break;
        case 13:
            status.mode = WIFI_TRUST_MODE_IDLE;
            status.running = 0U;
            status.stopping = 1U;
            break;
        default: assert(false);
        }
        memset(out, 0xa5, sizeof(out));
        assert(wifi_trust_format_status(out, sizeof(out), &status) == -1);
        untouched(out, sizeof(out));
    }
    status = (wifi_trust_status_t){0};
    status.mode = WIFI_TRUST_MODE_IDLE;
    status.store = WIFI_TRUST_STORE_OK;
    status.recovery = WIFI_TRUST_RECOVERY_NONE;
    status.boot_id[7] = 1U;
    memset(out, 0xa5, sizeof(out));
    assert(wifi_trust_format_status(out, sizeof(out), &status) == -1);
    untouched(out, sizeof(out));
    status.boot_id[7] = 0U;
    status.created_unix = 1U;
    assert(wifi_trust_format_status(out, sizeof(out), &status) == -1);
    untouched(out, sizeof(out));

    status = valid;
    status.running = 0U;
    status.stopping = 1U;
    assert(wifi_trust_format_status(out, sizeof(out), &status) > 0);
    assert(strstr(out, " RUNNING=0 STOPPING=1\r\n") != NULL);

    static const char *const invalid_outcomes[] = {
        NULL, "", "OK", "ok ", " ok", "ok\n", "start_failed",
        "restore_failed ", "storage_failed\r\n[WIFI_TRUST/1]", "safe"
    };
    for (size_t i = 0;
         i < sizeof(invalid_outcomes) / sizeof(invalid_outcomes[0]); ++i) {
        memset(out, 0xa5, sizeof(out));
        assert(wifi_trust_format_terminal(out, sizeof(out), &valid,
                                          invalid_outcomes[i]) == -1);
        untouched(out, sizeof(out));
    }
    assert(wifi_trust_format_status(NULL, sizeof(out), &valid) == -1);
    assert(wifi_trust_format_status(out, sizeof(out), NULL) == -1);
    assert(wifi_trust_format_terminal(NULL, sizeof(out), &valid, "ok") == -1);
    assert(wifi_trust_format_terminal(out, sizeof(out), NULL, "ok") == -1);
}

static wifi_trust_profile_t maximum_profile(void)
{
    wifi_trust_profile_t profile = profile_fixture();
    profile.bssid[0] = 0xfeU;
    memset(profile.bssid + 1, 0xff, sizeof(profile.bssid) - 1U);
    profile.ssid_len = sizeof(profile.ssid);
    memset(profile.ssid, 0xff, sizeof(profile.ssid));
    profile.privacy = -1;
    sx_security_t *security[] = {&profile.rsn, &profile.wpa};
    for (size_t which = 0; which < 2U; ++which) {
        memset(security[which], 0, sizeof(*security[which]));
        security[which]->status = SX_VALID;
        security[which]->group_present = true;
        security[which]->management_present = true;
        fill_selector(security[which]->group, (uint8_t)(1U + which));
        fill_selector(security[which]->management, (uint8_t)(6U + which));
        security[which]->pairwise_known = true;
        security[which]->akm_known = true;
        security[which]->pairwise_count = SX_SELECTORS;
        security[which]->akm_count = SX_SELECTORS;
        for (size_t i = 0; i < SX_SELECTORS; ++i) {
            fill_selector(security[which]->pairwise[i],
                          (uint8_t)(1U + i + which * 16U));
            fill_selector(security[which]->akm[i],
                          (uint8_t)(9U + i + which * 16U));
        }
    }
    profile.rsn.capabilities_present = false;
    profile.rsn.pmf_capable = false;
    profile.rsn.pmf_required = false;
    profile.rsnxe.len = SX_RSNXE_BYTES;
    memset(profile.rsnxe.bytes, 0xff, sizeof(profile.rsnxe.bytes));
    profile.wps.state = -1;
    profile.wps.config_methods = UINT16_MAX;
    profile.wps.setup_locked = -1;
    profile.wps.selected_registrar = -1;
    sx_text_t *texts[] = {&profile.wps.manufacturer, &profile.wps.model_name,
        &profile.wps.model_number, &profile.wps.device_name};
    for (size_t i = 0; i < sizeof(texts) / sizeof(texts[0]); ++i) {
        texts[i]->present = true;
        texts[i]->len = SX_TEXT_BYTES;
        memset(texts[i]->bytes, 0xff, SX_TEXT_BYTES);
    }
    memcpy(profile.country.code, "ZZO", 3U);
    profile.channel = 0U;
    profile.observed_us = UINT64_MAX;
    assert(wifi_trust_profile_valid(&profile));
    return profile;
}

typedef int (*format_thunk_t)(char *, size_t, const void *);

static int event_thunk(char *out, size_t capacity, const void *value)
{
    return wifi_trust_format_event(out, capacity, value);
}

typedef struct {
    const wifi_trust_profile_t *profile;
    const wifi_trust_store_meta_t *meta;
} baseline_args_t;

static int baseline_thunk(char *out, size_t capacity, const void *value)
{
    const baseline_args_t *args = value;
    return wifi_trust_format_baseline(out, capacity, args->profile, args->meta);
}

static int status_thunk(char *out, size_t capacity, const void *value)
{
    return wifi_trust_format_status(out, capacity, value);
}

typedef struct {
    const wifi_trust_status_t *status;
    const char *outcome;
} terminal_args_t;

static int terminal_thunk(char *out, size_t capacity, const void *value)
{
    const terminal_args_t *args = value;
    return wifi_trust_format_terminal(out, capacity, args->status,
                                      args->outcome);
}

static int capacity_contract(format_thunk_t formatter, const void *value)
{
    char out[WIFI_TRUST_LINE_MAX + 16U];
    memset(out, 0xa5, sizeof(out));
    const int length = formatter(out, WIFI_TRUST_LINE_MAX, value);
    assert(length > 0 && length <= (int)WIFI_TRUST_LINE_MAX - 1);
    assert((size_t)length == strlen(out));
    privacy(out);
    for (size_t capacity = 0; capacity <= (size_t)length; ++capacity) {
        memset(out, 0xa5, sizeof(out));
        assert(formatter(out, capacity, value) == -1);
        untouched(out, sizeof(out));
    }
    memset(out, 0xa5, sizeof(out));
    assert(formatter(out, (size_t)length + 1U, value) == length);
    privacy(out);
    untouched(out + (size_t)length + 1U,
              sizeof(out) - (size_t)length - 1U);
    return length;
}

static void test_real_maxima_and_atomic_capacity(int lengths[4])
{
    wifi_trust_profile_t baseline_profile = maximum_profile();
    wifi_trust_profile_t current_profile = baseline_profile;
    current_profile.rsn.pairwise[7][3] ^= 1U;
    current_profile.wpa.pairwise[7][3] ^= 1U;
    wifi_trust_event_t event = event_identity(
        WIFI_TRUST_ADVERTISEMENT_CONFLICT, WIFI_TRUST_FIELD_CIPHER);
    memcpy(event.bssid, baseline_profile.bssid, sizeof(event.bssid));
    event.ssid_status = SX_VALID;
    event.ssid_len = sizeof(event.ssid);
    memset(event.ssid, 0xff, sizeof(event.ssid));
    event.channel = 0U;
    event.timestamp_us = UINT64_MAX;
    assert(wifi_trust_value_from_profile(&baseline_profile, event.field,
                                         &event.baseline));
    assert(wifi_trust_value_from_profile(&current_profile, event.field,
                                         &event.current));
    lengths[0] = capacity_contract(event_thunk, &event);

    wifi_trust_store_meta_t meta = meta_fixture();
    memset(meta.boot_id, 0xff, sizeof(meta.boot_id));
    meta.created_unix = UINT64_MAX;
    meta.created_monotonic_us = UINT64_MAX;
    baseline_args_t baseline = {&baseline_profile, &meta};
    lengths[1] = capacity_contract(baseline_thunk, &baseline);

    wifi_trust_status_t status = status_fixture();
    status.channel = 0U;
    status.baseline_count = WIFI_TRUST_MAX_PROFILES;
    memset(status.boot_id, 0xff, sizeof(status.boot_id));
    status.created_unix = UINT64_MAX;
    status.store = WIFI_TRUST_STORE_PUBLISHED_UNCERTAIN;
    status.recovery = WIFI_TRUST_RECOVERY_RESTORED_BACKUP;
    status.received = status.filtered = status.unrelated = UINT32_MAX;
    status.accepted = status.invalid = status.conflicts = UINT32_MAX;
    status.events_info = status.events_warn = status.events_alert = UINT32_MAX;
    status.capacity_drops = status.rx_drops = UINT32_MAX;
    status.output_failures = status.storage_failures = UINT32_MAX;
    status.profiles = WIFI_TRUST_MAX_PROFILES;
    status.stopping = 1U;
    lengths[2] = capacity_contract(status_thunk, &status);
    terminal_args_t terminal = {&status, "storage_uncertain"};
    lengths[3] = capacity_contract(terminal_thunk, &terminal);
    assert(lengths[0] == 640);
    assert(lengths[1] == 780);
    assert(lengths[2] == 544);
    assert(lengths[3] == 572);
}

int main(void)
{
    test_exact_reason_records();
    test_all_field_tokens_and_invalid_pairs();
    test_event_uncertainty_and_validation();
    test_reason_semantics_reject_unreachable_events();
    test_exact_baseline();
    test_baseline_preserves_canonical_unknown_and_absent();
    test_exact_status_terminal_and_all_tokens();
    test_status_validation_and_unknown_meta();
    int lengths[4];
    test_real_maxima_and_atomic_capacity(lengths);
    printf("PASS: Wi-Fi Trust exact wire records, validation, privacy, capacity; "
           "max lengths event=%d baseline=%d status=%d terminal=%d\n",
           lengths[0], lengths[1], lengths[2], lengths[3]);
    return 0;
}
