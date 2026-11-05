#ifndef WIFI_SHIELD_WIRE_H
#define WIFI_SHIELD_WIRE_H

#include "wifi_shield_core.h"
#include "wifi_shield_journal.h"

#define WIFI_SHIELD_LINE_MAX 512U
#define WIFI_SHIELD_V2_LINE_MAX WIFI_SHIELD_LINE_MAX

/* Returns bytes excluding NUL, including CRLF; -1 leaves all output unchanged.
 * Output must not overlap inputs. Channel IDs are platform-validated snapshots:
 * this portable layer rejects zero identities, not regulatory availability.
 * Idle status/terminal use zero targets/channels/current channel and none coverage.
 * MODE is passive or active; explicit PMKID opt-in does not change the mode.
 */
int wifi_shield_format_armed(char *out, size_t capacity,
                            const wifi_shield_status_t *status);
int wifi_shield_format_target(char *out, size_t capacity,
                             const wifi_shield_target_t *target,
                             size_t ordinal, size_t total);
int wifi_shield_format_event(char *out, size_t capacity,
                            const wifi_shield_event_t *event);
int wifi_shield_format_status(char *out, size_t capacity,
                             const wifi_shield_status_t *status);
int wifi_shield_format_terminal(char *out, size_t capacity,
                               const wifi_shield_status_t *status,
                               const char *outcome);

/* V2 lines have CRLF and transactional failure within the actual 512-byte
 * UART/output-record capacity. JSONL retains its separate 1024-byte bound.
 * AP BSSID is selected observed evidence, supplied separately from metrics.
 * Storage notice returns 0 unchanged when pending is false (owner clears it). */
int wifi_shield_format_campaign_report(char *, size_t,
    const wifi_shield_campaign_snapshot_t *);
int wifi_shield_format_ap_health(char *, size_t, const uint8_t bssid[6],
    const wifi_shield_ap_health_snapshot_t *);
int wifi_shield_format_recommendation(char *, size_t,
    const uint8_t bssid[6],
    const wifi_shield_ap_recommendation_detail_t *);
int wifi_shield_format_log_status(char *, size_t,
    const wifi_shield_journal_status_t *);
int wifi_shield_format_storage_degraded(char *, size_t,
    const wifi_shield_journal_status_t *);

#endif
