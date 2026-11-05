#ifndef SAE_GUARD_CORE_H
#define SAE_GUARD_CORE_H

#include "sae_guard_parser.h"

#define SAE_GUARD_TRACKED_PAIRS 32U
#define SAE_GUARD_TRACKED_MALFORMED_BSSIDS 32U
#define SAE_GUARD_WINDOW_US UINT64_C(10000000)
#define SAE_GUARD_MALFORMED_THRESHOLD 3U
#define SAE_GUARD_UNCONFIRMED_THRESHOLD 8U
#define SAE_GUARD_GROUP_CHURN_THRESHOLD 3U

typedef enum {
    SAE_GUARD_EVENT_NONE = 0,
    SAE_GUARD_EVENT_MALFORMED,
    SAE_GUARD_EVENT_UNCONFIRMED_COMMITS,
    SAE_GUARD_EVENT_GROUP_CHURN,
    SAE_GUARD_EVENT_ANTI_CLOGGING,
    SAE_GUARD_EVENT_STATUS_FAILURE,
    SAE_GUARD_EVENT_CAPACITY,
    SAE_GUARD_EVENT_REASON_COUNT
} sae_guard_event_reason_t;

#define SAE_GUARD_EVENT_MASK(reason) (UINT32_C(1) << (uint32_t)(reason))

/* Metadata-only snapshot for the strict Task 3 formatter. */
typedef struct {
    sae_guard_observation_t observation;
    sae_guard_event_reason_t reason; /* Primary reason for single-reason wire APIs. */
    uint32_t reason_mask; /* All reasons crossed by this observation. */
    uint32_t commits;
    uint32_t confirms;
    uint32_t retries;
    uint32_t malformed;
    uint32_t distinct_groups;
    uint32_t window_ms;
} sae_guard_event_t;

typedef struct {
    uint32_t observations; /* Valid inputs accepted with a non-NULL event buffer. */
    uint32_t commits; /* Unique Commit observations admitted to a pair window. */
    uint32_t confirms; /* Successfully correlated Confirm observations. */
    uint32_t retries;
    uint32_t malformed;
    uint32_t anti_clogging;
    uint32_t status_failures;
    uint32_t capacity_drops;
    uint32_t pair_capacity_drops;
    uint32_t malformed_capacity_drops;
    uint32_t reason_counts[SAE_GUARD_EVENT_REASON_COUNT];
    uint32_t active_pairs;
    uint32_t active_malformed_bssids;
    /* Adapter-owned saturated fields. Core observe/expire never changes them. */
    uint32_t received;
    uint32_t filtered;
    uint32_t unrelated;
    uint32_t rx_drops;
    uint32_t output_failures;
    bool running;
    bool stopping;
} sae_guard_status_t;

/* One correlation window is exactly BSSID, station and direction. Group is the
 * latest unique Commit's group because Confirm does not carry a group field.
 * A matching Confirm clears attempt counts but retains threshold cooldowns
 * until the fixed window expires; awaiting_confirm distinguishes that state.
 * distinct_groups is deliberately capped at the threshold; all cumulative
 * counters saturate at UINT32_MAX. */
typedef struct {
    uint8_t bssid[6];
    uint8_t station[6];
    uint16_t current_group;
    uint16_t last_commit_sequence;
    uint16_t last_commit_group;
    uint16_t groups[SAE_GUARD_GROUP_CHURN_THRESHOLD];
    uint64_t window_start_us;
    uint64_t last_seen_us;
    uint32_t commits;
    uint32_t confirms;
    uint32_t retries;
    uint32_t distinct_groups;
    bool from_ap;
    bool active;
    bool awaiting_confirm;
    bool have_last_commit;
    bool unconfirmed_reported;
    bool group_churn_reported;
} sae_guard_pair_t;

/* Malformed thresholds are per BSSID across stations and directions. This
 * independent fixed table prevents pair-table pressure from erasing malformed
 * evidence (and vice versa). Its capacity loss is reported, never evicted. */
typedef struct {
    uint8_t bssid[6];
    uint64_t window_start_us;
    uint64_t last_seen_us;
    uint32_t malformed;
    bool active;
    bool reported;
} sae_guard_malformed_bssid_t;

typedef struct {
    sae_guard_pair_t pairs[SAE_GUARD_TRACKED_PAIRS];
    sae_guard_malformed_bssid_t
        malformed_bssids[SAE_GUARD_TRACKED_MALFORMED_BSSIDS];
    sae_guard_status_t status;
} sae_guard_core_t;

void sae_guard_core_init(sae_guard_core_t *core);
void sae_guard_reset(sae_guard_core_t *core);
void sae_guard_get_status(const sae_guard_core_t *core,
                          sae_guard_status_t *status);

/* event is required; NULL rejects the observation without state mutation.
 * Returns true only when event is populated. Anti-clogging and failure-status
 * records are informational observations. Threshold events do not claim an
 * attack, attribution, password compromise or vulnerable implementation.
 * An identical sequence/group retry increments only retry telemetry. A
 * first-seen or changed sequence/group retry counts once as a unique Commit.
 * Equal timestamps are monotonic; a backwards timestamp cannot mutate a live
 * row. Expired rows are cleared before lookup/capacity checks. */
bool sae_guard_observe(sae_guard_core_t *core,
                       const sae_guard_observation_t *observation,
                       sae_guard_event_t *event);

/* Fixed half-open windows expire when now reaches ten seconds after
 * window_start. Backwards time never underflows. The return is the number of
 * pair plus malformed-BSSID rows removed, bounded by 64. */
size_t sae_guard_expire(sae_guard_core_t *core, uint64_t now_us);

#endif
