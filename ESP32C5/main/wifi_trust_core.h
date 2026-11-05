#ifndef WIFI_TRUST_CORE_H
#define WIFI_TRUST_CORE_H

#include "sniffer_extended.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define WIFI_TRUST_MAX_PROFILES 128U
#define WIFI_TRUST_EVENT_VALUE_BYTES 96U

typedef struct {
    uint8_t bssid[6];
    sx_status_t ssid_status;
    uint8_t ssid[32];
    uint8_t ssid_len;
    sx_source_t source;
    int8_t privacy;
    sx_security_t rsn;
    sx_security_t wpa;
    sx_rsnxe_t rsnxe;
    sx_wps_t wps;
    sx_country_t country;
    uint8_t channel; /* Zero means unknown. */
    uint64_t observed_us;
} wifi_trust_profile_t;

typedef enum {
    WIFI_TRUST_NO_CHANGE = 0,
    WIFI_TRUST_NEW_BSSID,
    WIFI_TRUST_SSID_CHANGED,
    WIFI_TRUST_AKM_CHANGED,
    WIFI_TRUST_CIPHER_CHANGED,
    WIFI_TRUST_PMF_DOWNGRADE,
    WIFI_TRUST_RSNXE_CHANGED,
    WIFI_TRUST_WPS_ENABLED,
    WIFI_TRUST_WPS_LOCK_CHANGED,
    WIFI_TRUST_COUNTRY_CHANGED,
    WIFI_TRUST_CHANNEL_CHANGED,
    WIFI_TRUST_ADVERTISEMENT_CONFLICT,
    WIFI_TRUST_MALFORMED_OBSERVATION,
    WIFI_TRUST_REASON_COUNT
} wifi_trust_reason_t;

typedef enum {
    WIFI_TRUST_FIELD_NONE = 0,
    WIFI_TRUST_FIELD_ADVERTISEMENT,
    WIFI_TRUST_FIELD_SSID,
    WIFI_TRUST_FIELD_PRIVACY,
    WIFI_TRUST_FIELD_AKM,
    WIFI_TRUST_FIELD_CIPHER,
    WIFI_TRUST_FIELD_PMF,
    WIFI_TRUST_FIELD_RSNXE,
    WIFI_TRUST_FIELD_WPS,
    WIFI_TRUST_FIELD_WPS_STATE,
    WIFI_TRUST_FIELD_WPS_CONFIG_METHODS,
    WIFI_TRUST_FIELD_WPS_LOCK,
    WIFI_TRUST_FIELD_WPS_SELECTED_REGISTRAR,
    WIFI_TRUST_FIELD_WPS_MANUFACTURER,
    WIFI_TRUST_FIELD_WPS_MODEL_NAME,
    WIFI_TRUST_FIELD_WPS_MODEL_NUMBER,
    WIFI_TRUST_FIELD_WPS_DEVICE_NAME,
    WIFI_TRUST_FIELD_COUNTRY,
    WIFI_TRUST_FIELD_CHANNEL,
    WIFI_TRUST_FIELD_COUNT
} wifi_trust_field_t;

typedef uint32_t wifi_trust_field_mask_t;
#define WIFI_TRUST_FIELD_MASK(field) \
    (UINT32_C(1) << (uint32_t)(field))

/* A bounded, wire-ready field snapshot. status distinguishes unknown, absent,
 * valid and invalid. bytes retain exact evidence order; number carries scalar
 * values such as PMF mode, WPS lock, privacy and channel. */
typedef struct {
    sx_status_t status;
    uint8_t bytes[WIFI_TRUST_EVENT_VALUE_BYTES];
    uint8_t len;
    int32_t number;
} wifi_trust_event_value_t;

typedef struct {
    wifi_trust_reason_t reason;
    wifi_trust_field_t field;
    uint8_t bssid[6];
    sx_status_t ssid_status;
    uint8_t ssid[32];
    uint8_t ssid_len;
    sx_source_t source;
    uint8_t channel; /* Zero means unknown. */
    wifi_trust_event_value_t baseline;
    wifi_trust_event_value_t current;
    uint64_t timestamp_us;
} wifi_trust_event_t;

typedef enum {
    WIFI_TRUST_INGEST_ACCEPTED = 0,
    WIFI_TRUST_INGEST_UNRELATED,
    WIFI_TRUST_INGEST_MALFORMED,
    WIFI_TRUST_INGEST_CONFLICT,
    WIFI_TRUST_INGEST_CAPACITY
} wifi_trust_ingest_result_t;

typedef struct {
    bool used;
    uint8_t bssid[6];
    bool have_beacon;
    bool have_probe;
    wifi_trust_profile_t beacon;
    wifi_trust_profile_t probe;
    wifi_trust_field_mask_t conflict_mask;
} wifi_trust_builder_t;

typedef struct {
    wifi_trust_builder_t entries[WIFI_TRUST_MAX_PROFILES];
    size_t active;
    uint32_t capacity_drops;
} wifi_trust_table_t;

/* Caller-owned transactional scratch. Shield stores this in its PSRAM arena so
 * its 4096-byte worker stack never carries a profile plus builder copy. The
 * legacy observe APIs retain their public behavior by supplying local scratch. */
typedef struct {
    wifi_trust_profile_t incoming;
    wifi_trust_builder_t updated;
} wifi_trust_observe_workspace_t;

/* Rejects malformed or unrelated observations and clears out on every
 * failure. A present zero-length SSID is valid; missing SSID is absent. */
bool wifi_trust_profile_from_observation(const sx_observation_t *observation,
                                         uint8_t channel,
                                         uint64_t observed_us,
                                         wifi_trust_profile_t *out);
/* Shared canonical validator for storage/wire adapters. */
bool wifi_trust_profile_valid(const wifi_trust_profile_t *profile);
/* Deterministic bounded field encoder shared by drift and wire adapters.
 * Failure leaves out unchanged. */
bool wifi_trust_value_from_profile(const wifi_trust_profile_t *profile,
                                   wifi_trust_field_t field,
                                   wifi_trust_event_value_t *out);

void wifi_trust_table_init(wifi_trust_table_t *table);

/* Invalid input never mutates builder. Backwards source time is unrelated.
 * Unknown subfields preserve prior confirmed evidence in that source slot.
 * new_conflicts receives only newly raised field bits. */
wifi_trust_ingest_result_t wifi_trust_builder_observe(
    wifi_trust_builder_t *builder,
    const sx_observation_t *observation,
    uint8_t channel, uint64_t observed_us,
    wifi_trust_field_mask_t *new_conflicts);

wifi_trust_ingest_result_t wifi_trust_table_observe(
    wifi_trust_table_t *table,
    const sx_observation_t *observation,
    uint8_t channel, uint64_t observed_us,
    wifi_trust_builder_t **builder,
    wifi_trust_field_mask_t *new_conflicts);

/* Same result/output/table semantics as wifi_trust_table_observe. Workspace is
 * required, must not overlap table/observation/output storage, and is borrowed
 * only for this call. Invalid input never mutates the table. */
wifi_trust_ingest_result_t wifi_trust_table_observe_with_workspace(
    wifi_trust_table_t *table,
    const sx_observation_t *observation,
    uint8_t channel, uint64_t observed_us,
    wifi_trust_builder_t **builder,
    wifi_trust_field_mask_t *new_conflicts,
    wifi_trust_observe_workspace_t *workspace);

/* Snapshot succeeds with one source or two non-conflicting sources. With two
 * agreeing sources the newest profile wins, with Beacon as the stable tie. */
bool wifi_trust_builder_snapshot(const wifi_trust_builder_t *builder,
                                 wifi_trust_profile_t *out);

/* All batch APIs return the required count. If capacity is insufficient they
 * leave the entire destination unchanged. NULL with zero capacity is a size
 * query. Event order is deterministic and inputs are never mutated. */
size_t wifi_trust_diff(const wifi_trust_profile_t *baseline,
                       const wifi_trust_profile_t *current,
                       wifi_trust_event_t *events, size_t capacity);
size_t wifi_trust_builder_conflict_events(
    const wifi_trust_builder_t *builder,
    wifi_trust_event_t *events, size_t capacity);
size_t wifi_trust_malformed_events(const sx_observation_t *observation,
                                   uint8_t channel, uint64_t observed_us,
                                   wifi_trust_event_t *events,
                                   size_t capacity);

#endif
