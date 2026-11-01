#pragma once

#include "pmkid_parser.h"

/* One session spans all selected targets or the complete D-UCB run.
 * The owner must quiesce RX/event handlers before stop; stop drains the writer. */
bool pmkid_capture_start(bool (*excluded)(const uint8_t bssid[6]));
void pmkid_capture_stop(void);

/* Owner-task diagnostics for one AP observation window. end drains preceding
 * writes before reporting a result; never call it while holding the RX lock.
 * client may be NULL for a selected AP. failure_reason is NULL on normal end. */
void pmkid_capture_attempt_begin(const uint8_t bssid[6], const uint8_t *client,
                                 unsigned active_ordinal);
void pmkid_capture_attempt_end(const char *failure_reason);

/* Nonblocking, bounded copies only. target_bssid may be NULL in scan-all mode.
 * Caller-provided SSID is a fallback; actual beacon/probe bytes are preserved. */
void pmkid_capture_observe(const uint8_t *frame, size_t length, uint32_t timestamp,
                           const uint8_t *target_bssid, const char *ssid);
