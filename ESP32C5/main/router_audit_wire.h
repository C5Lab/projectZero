#ifndef ROUTER_AUDIT_WIRE_H
#define ROUTER_AUDIT_WIRE_H

#include "router_cve_db.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ROUTER_AUDIT_LINE_MAX 1536U

typedef enum {
    ROUTER_AUDIT_WIRE_SCAN_PASSIVE = 0,
    ROUTER_AUDIT_WIRE_SCAN_STANDARD_OWNED,
    ROUTER_AUDIT_WIRE_STATUS,
    ROUTER_AUDIT_WIRE_DB_STATUS,
    ROUTER_AUDIT_WIRE_DB_VERIFY,
    ROUTER_AUDIT_WIRE_DB_INSTALL
} router_audit_wire_mode_t;

typedef enum {
    ROUTER_AUDIT_OUTCOME_EXACT_FIRMWARE_MATCH = 0,
    ROUTER_AUDIT_OUTCOME_CANDIDATE_MANUAL_CHECK,
    ROUTER_AUDIT_OUTCOME_NO_CATALOG_MATCH,
    ROUTER_AUDIT_OUTCOME_IDENTITY_UNKNOWN,
    ROUTER_AUDIT_OUTCOME_CATALOG_UNAVAILABLE,
    ROUTER_AUDIT_OUTCOME_OK,
    ROUTER_AUDIT_OUTCOME_PARTIAL,
    ROUTER_AUDIT_OUTCOME_CANCELLED,
    ROUTER_AUDIT_OUTCOME_INVALID,
    ROUTER_AUDIT_OUTCOME_BUSY,
    ROUTER_AUDIT_OUTCOME_PRECONDITION_FAILED,
    ROUTER_AUDIT_OUTCOME_INCOMPLETE_STAGE,
    ROUTER_AUDIT_OUTCOME_BAD_FORMAT,
    ROUTER_AUDIT_OUTCOME_BAD_HASH,
    ROUTER_AUDIT_OUTCOME_BAD_SIGNATURE,
    ROUTER_AUDIT_OUTCOME_UNKNOWN_KEY,
    ROUTER_AUDIT_OUTCOME_NOT_YET_VALID,
    ROUTER_AUDIT_OUTCOME_STALE,
    ROUTER_AUDIT_OUTCOME_TIME_UNKNOWN,
    ROUTER_AUDIT_OUTCOME_ROLLBACK,
    ROUTER_AUDIT_OUTCOME_IO_FAILED,
    ROUTER_AUDIT_OUTCOME_CAPACITY_FAILED,
    ROUTER_AUDIT_OUTCOME_PUBLISH_FAILED,
    ROUTER_AUDIT_OUTCOME_PUBLISHED_UNCERTAIN,
    ROUTER_AUDIT_OUTCOME_RECOVERY_FAILED,
    ROUTER_AUDIT_OUTCOME_OUTPUT_FAILED
} router_audit_outcome_t;

typedef struct {
    bool busy;
    bool available;
    uint64_t serial;
    bool stale;
    bool time_unknown;
    router_audit_outcome_t db_outcome;
    router_audit_outcome_t outcome;
} router_audit_status_record_t;

typedef struct {
    router_audit_wire_mode_t mode;
    uint32_t requests;
    uint32_t errors;
    uint32_t evidence;
    router_confidence_t confidence;
    uint32_t candidates;
    uint32_t exact;
    router_audit_outcome_t outcome;
} router_audit_terminal_t;

bool router_audit_wire_evidence(char *output, size_t capacity,
                                const router_evidence_t *evidence,
                                const char *field, const char *value,
                                bool truncated);
bool router_audit_wire_identity(char *output, size_t capacity,
                                const router_fingerprint_t *identity);
bool router_audit_wire_cve(char *output, size_t capacity,
                           const router_cve_result_t *cve,
                           uint64_t catalog_serial,
                           uint64_t catalog_age_seconds,
                           bool stale, bool time_unknown);
bool router_audit_wire_status(char *output, size_t capacity,
                              const router_audit_status_record_t *status);
bool router_audit_wire_terminal(char *output, size_t capacity,
                                const router_audit_terminal_t *terminal);

const char *router_audit_outcome_name(router_audit_outcome_t outcome);

#ifdef __cplusplus
}
#endif

#endif
