#include "router_audit_wire.h"

#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    char bytes[ROUTER_AUDIT_LINE_MAX];
    size_t used;
    bool ok;
} line_builder_t;

static bool appendf(line_builder_t *builder, const char *format, ...)
{
    if (builder == NULL || !builder->ok || format == NULL ||
        builder->used >= sizeof(builder->bytes)) return false;
    va_list args;
    va_start(args, format);
    int written = vsnprintf(builder->bytes + builder->used,
                            sizeof(builder->bytes) - builder->used,
                            format, args);
    va_end(args);
    if (written < 0 || (size_t)written >= sizeof(builder->bytes) - builder->used) {
        builder->ok = false;
        return false;
    }
    builder->used += (size_t)written;
    return true;
}

static bool safe_byte(unsigned char value)
{
    return (value >= 'a' && value <= 'z') ||
           (value >= 'A' && value <= 'Z') ||
           (value >= '0' && value <= '9') || value == '.' || value == '_' ||
           value == '~' || value == '-' || value == '/' || value == ':' ||
           value == '@';
}

static bool terminated(const char *value, size_t capacity)
{
    return value != NULL && memchr(value, '\0', capacity) != NULL;
}

static bool append_escaped(line_builder_t *builder, const char *value)
{
    static const char hex[] = "0123456789ABCDEF";
    if (builder == NULL || value == NULL) return false;
    const unsigned char *cursor = (const unsigned char *)value;
    while (*cursor != 0U) {
        if (safe_byte(*cursor)) {
            if (builder->used + 1U >= sizeof(builder->bytes)) {
                builder->ok = false;
                return false;
            }
            builder->bytes[builder->used++] = (char)*cursor;
            builder->bytes[builder->used] = '\0';
        } else {
            if (builder->used + 3U >= sizeof(builder->bytes)) {
                builder->ok = false;
                return false;
            }
            builder->bytes[builder->used++] = '%';
            builder->bytes[builder->used++] = hex[*cursor >> 4U];
            builder->bytes[builder->used++] = hex[*cursor & 0x0FU];
            builder->bytes[builder->used] = '\0';
        }
        ++cursor;
    }
    return true;
}

static bool publish(char *output, size_t capacity, line_builder_t *builder)
{
    if (output == NULL || builder == NULL || !builder->ok ||
        builder->used + 1U > capacity) return false;
    memcpy(output, builder->bytes, builder->used + 1U);
    return true;
}

static const char *source_name(router_evidence_source_t source)
{
    switch (source) {
    case ROUTER_EVIDENCE_OUI: return "oui";
    case ROUTER_EVIDENCE_DHCP: return "dhcp";
    case ROUTER_EVIDENCE_SSDP_SERVER: return "ssdp_server";
    case ROUTER_EVIDENCE_UPNP_STRUCTURED: return "upnp_structured";
    case ROUTER_EVIDENCE_HTTP_SERVER: return "http_server";
    case ROUTER_EVIDENCE_HTTP_TITLE: return "http_title";
    default: return NULL;
    }
}

static const char *confidence_name(router_confidence_t confidence)
{
    switch (confidence) {
    case ROUTER_CONFIDENCE_UNKNOWN: return "unknown";
    case ROUTER_CONFIDENCE_PROBABLE: return "probable";
    case ROUTER_CONFIDENCE_CONFIRMED: return "confirmed";
    default: return NULL;
    }
}

static const char *match_name(router_cve_match_t match)
{
    switch (match) {
    case ROUTER_CVE_EXACT_FIRMWARE: return "exact_firmware_match";
    case ROUTER_CVE_MODEL_CANDIDATE: return "candidate_manual_check";
    default: return NULL;
    }
}

static const char *mode_name(router_audit_wire_mode_t mode)
{
    switch (mode) {
    case ROUTER_AUDIT_WIRE_SCAN_PASSIVE: return "passive";
    case ROUTER_AUDIT_WIRE_SCAN_STANDARD_OWNED: return "standard";
    case ROUTER_AUDIT_WIRE_STATUS: return "status";
    case ROUTER_AUDIT_WIRE_DB_STATUS: return "db_status";
    case ROUTER_AUDIT_WIRE_DB_VERIFY: return "db_verify";
    case ROUTER_AUDIT_WIRE_DB_INSTALL: return "db_install";
    default: return NULL;
    }
}

const char *router_audit_outcome_name(router_audit_outcome_t outcome)
{
    static const char * const names[] = {
        "exact_firmware_match", "candidate_manual_check", "no_catalog_match",
        "identity_unknown", "catalog_unavailable", "ok", "partial",
        "cancelled", "invalid", "busy", "precondition_failed",
        "incomplete_stage", "bad_format", "bad_hash", "bad_signature",
        "unknown_key", "not_yet_valid", "stale", "time_unknown", "rollback",
        "io_failed", "capacity_failed", "publish_failed",
        "published_uncertain", "recovery_failed", "output_failed"
    };
    size_t index = (size_t)outcome;
    return index < sizeof(names) / sizeof(names[0]) ? names[index] : NULL;
}

bool router_audit_wire_evidence(char *output, size_t capacity,
                                const router_evidence_t *evidence,
                                const char *field, const char *value,
                                bool truncated)
{
    const char *source = evidence != NULL ? source_name(evidence->source) : NULL;
    if (source == NULL || field == NULL ||
        !terminated(value, ROUTER_EVIDENCE_TEXT_MAX + 1U) ||
        (strcmp(field, "vendor") != 0 && strcmp(field, "model") != 0 &&
         strcmp(field, "firmware") != 0)) return false;
    line_builder_t builder = {.ok = true};
    (void)appendf(&builder, "[ROUTER_AUDIT/1] EVIDENCE SOURCE=%s STATUS=valid FIELD=%s VALUE=",
                  source, field);
    (void)append_escaped(&builder, value);
    (void)appendf(&builder, " TRUNCATED=%u\r\n", truncated ? 1U : 0U);
    return publish(output, capacity, &builder);
}

bool router_audit_wire_identity(char *output, size_t capacity,
                                const router_fingerprint_t *identity)
{
    const char *confidence = identity != NULL ?
        confidence_name(identity->confidence) : NULL;
    if (confidence == NULL ||
        !terminated(identity->vendor, sizeof(identity->vendor)) ||
        !terminated(identity->model, sizeof(identity->model)) ||
        !terminated(identity->firmware, sizeof(identity->firmware))) return false;
    line_builder_t builder = {.ok = true};
    (void)appendf(&builder, "[ROUTER_AUDIT/1] IDENTITY VENDOR=");
    (void)append_escaped(&builder, identity->vendor[0] ? identity->vendor : "-");
    (void)appendf(&builder, " MODEL=");
    (void)append_escaped(&builder, identity->model[0] ? identity->model : "-");
    (void)appendf(&builder, " FIRMWARE=");
    (void)append_escaped(&builder, identity->firmware[0] ? identity->firmware : "-");
    (void)appendf(&builder, " CONFIDENCE=%s CONFLICT=%u TRUNCATED=%u\r\n",
                  confidence, identity->conflict ? 1U : 0U,
                  identity->truncated ? 1U : 0U);
    return publish(output, capacity, &builder);
}

bool router_audit_wire_cve(char *output, size_t capacity,
                           const router_cve_result_t *cve,
                           uint64_t catalog_serial,
                           uint64_t catalog_age_seconds,
                           bool stale, bool time_unknown)
{
    const char *match = cve != NULL ? match_name(cve->match) : NULL;
    if (match == NULL ||
        !terminated(cve->cve, sizeof(cve->cve)) ||
        !terminated(cve->advisory_url, sizeof(cve->advisory_url)) ||
        !terminated(cve->severity, sizeof(cve->severity)) ||
        !terminated(cve->kev_date, sizeof(cve->kev_date)) ||
        !terminated(cve->fixed_version, sizeof(cve->fixed_version)) ||
        !terminated(cve->source_id, sizeof(cve->source_id)) ||
        cve->cve[0] == '\0' || cve->advisory_url[0] == '\0')
        return false;
    line_builder_t builder = {.ok = true};
    (void)appendf(&builder, "[ROUTER_AUDIT/1] CVE ID=");
    (void)append_escaped(&builder, cve->cve);
    (void)appendf(&builder, " MATCH=%s SEVERITY=", match);
    (void)append_escaped(&builder, cve->severity[0] ? cve->severity : "unknown");
    (void)appendf(&builder, " EOL=%u KEV=%u KEV_DATE=", cve->eol ? 1U : 0U,
                  cve->kev ? 1U : 0U);
    (void)append_escaped(&builder, cve->kev_date[0] ? cve->kev_date : "none");
    (void)appendf(&builder, " FIXED=");
    (void)append_escaped(&builder, cve->fixed_version[0] ? cve->fixed_version : "none");
    (void)appendf(&builder, " URL=");
    (void)append_escaped(&builder, cve->advisory_url);
    (void)appendf(&builder,
        " CATALOG_SERIAL=%" PRIu64 " CATALOG_AGE_S=%" PRIu64
        " STALE=%u TIME_UNKNOWN=%u SOURCE=",
        catalog_serial, catalog_age_seconds, stale ? 1U : 0U,
        time_unknown ? 1U : 0U);
    (void)append_escaped(&builder, cve->source_id[0] ? cve->source_id : "-");
    (void)appendf(&builder, "\r\n");
    return publish(output, capacity, &builder);
}

bool router_audit_wire_status(char *output, size_t capacity,
                              const router_audit_status_record_t *status)
{
    const char *outcome = status != NULL ?
        router_audit_outcome_name(status->outcome) : NULL;
    const char *db_outcome = status != NULL ?
        router_audit_outcome_name(status->db_outcome) : NULL;
    if (outcome == NULL || db_outcome == NULL) return false;
    line_builder_t builder = {.ok = true};
    (void)appendf(&builder,
        "[ROUTER_AUDIT/1] STATUS BUSY=%u DB_AVAILABLE=%u SERIAL=%" PRIu64
        " STALE=%u TIME_UNKNOWN=%u DB_OUTCOME=%s OUTCOME=%s\r\n",
        status->busy ? 1U : 0U, status->available ? 1U : 0U, status->serial,
        status->stale ? 1U : 0U, status->time_unknown ? 1U : 0U,
        db_outcome, outcome);
    return publish(output, capacity, &builder);
}

bool router_audit_wire_terminal(char *output, size_t capacity,
                                const router_audit_terminal_t *terminal)
{
    const char *mode = terminal != NULL ? mode_name(terminal->mode) : NULL;
    const char *confidence = terminal != NULL ?
        confidence_name(terminal->confidence) : NULL;
    const char *outcome = terminal != NULL ?
        router_audit_outcome_name(terminal->outcome) : NULL;
    if (mode == NULL || confidence == NULL || outcome == NULL) return false;
    line_builder_t builder = {.ok = true};
    (void)appendf(&builder,
        "[ROUTER_AUDIT/1] END MODE=%s REQUESTS=%" PRIu32
        " ERRORS=%" PRIu32 " EVIDENCE=%" PRIu32
        " CONFIDENCE=%s CANDIDATES=%" PRIu32 " EXACT=%" PRIu32
        " OUTCOME=%s\r\n",
        mode, terminal->requests, terminal->errors, terminal->evidence,
        confidence, terminal->candidates, terminal->exact, outcome);
    return publish(output, capacity, &builder);
}
