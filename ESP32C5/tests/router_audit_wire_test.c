#include "router_audit_wire.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void unchanged_on_failure(void)
{
    char line[32];
    memset(line, 'Q', sizeof(line));
    char before[32];
    memcpy(before, line, sizeof(line));
    router_evidence_t evidence = {0};
    evidence.source = ROUTER_EVIDENCE_HTTP_TITLE;
    strcpy(evidence.model, "a control\nvalue");
    assert(!router_audit_wire_evidence(line, sizeof(line), &evidence,
                                       "model", evidence.model, false));
    assert(memcmp(line, before, sizeof(line)) == 0);
}

int main(void)
{
    char line[ROUTER_AUDIT_LINE_MAX];
    router_evidence_t evidence = {0};
    evidence.source = ROUTER_EVIDENCE_HTTP_TITLE;
    assert(router_audit_wire_evidence(line, sizeof(line), &evidence,
                                      "model", "Lab Router\r\nCookie: secret", true));
    assert(strcmp(line,
        "[ROUTER_AUDIT/1] EVIDENCE SOURCE=http_title STATUS=valid FIELD=model "
        "VALUE=Lab%20Router%0D%0ACookie:%20secret TRUNCATED=1\r\n") == 0);
    assert(strstr(line, "\r\nCookie") == NULL);

    router_fingerprint_t identity = {0};
    strcpy(identity.vendor, "lab vendor");
    strcpy(identity.model, "router-one");
    strcpy(identity.firmware, "1.2.3");
    identity.confidence = ROUTER_CONFIDENCE_CONFIRMED;
    assert(router_audit_wire_identity(line, sizeof(line), &identity));
    assert(strcmp(line,
        "[ROUTER_AUDIT/1] IDENTITY VENDOR=lab%20vendor MODEL=router-one "
        "FIRMWARE=1.2.3 CONFIDENCE=confirmed CONFLICT=0 TRUNCATED=0\r\n") == 0);

    router_cve_result_t cve = {0};
    cve.match = ROUTER_CVE_EXACT_FIRMWARE;
    strcpy(cve.cve, "CVE-2099-0001");
    strcpy(cve.severity, "high");
    strcpy(cve.fixed_version, "1.2.4");
    strcpy(cve.advisory_url, "https://security.example.invalid/a@b");
    assert(router_audit_wire_cve(line, sizeof(line), &cve, 7U, 3600U,
                                 false, false));
    assert(strcmp(line,
        "[ROUTER_AUDIT/1] CVE ID=CVE-2099-0001 MATCH=exact_firmware_match "
        "SEVERITY=high EOL=0 KEV=0 KEV_DATE=none FIXED=1.2.4 "
        "URL=https://security.example.invalid/a@b CATALOG_SERIAL=7 CATALOG_AGE_S=3600 "
        "STALE=0 TIME_UNKNOWN=0 SOURCE=-\r\n") == 0);
    assert(strstr(line, "vulnerable") == NULL);
    assert(strstr(line, "exploitable") == NULL);

    char exact[ROUTER_AUDIT_LINE_MAX];
    memset(exact, 'X', sizeof(exact));
    size_t exact_length = strlen(line);
    assert(!router_audit_wire_cve(exact, exact_length, &cve, 7U, 3600U,
                                  false, false));
    assert(exact[0] == 'X');

    router_audit_status_record_t status = {
        .busy = false, .available = true, .serial = 7U,
        .stale = false, .time_unknown = true,
        .db_outcome = ROUTER_AUDIT_OUTCOME_TIME_UNKNOWN,
        .outcome = ROUTER_AUDIT_OUTCOME_EXACT_FIRMWARE_MATCH,
    };
    assert(router_audit_wire_status(line, sizeof(line), &status));
    assert(strcmp(line,
        "[ROUTER_AUDIT/1] STATUS BUSY=0 DB_AVAILABLE=1 SERIAL=7 STALE=0 "
        "TIME_UNKNOWN=1 DB_OUTCOME=time_unknown "
        "OUTCOME=exact_firmware_match\r\n") == 0);

    router_audit_terminal_t terminal = {
        .mode = ROUTER_AUDIT_WIRE_SCAN_PASSIVE,
        .requests = 0U, .errors = 0U, .evidence = 2U,
        .confidence = ROUTER_CONFIDENCE_CONFIRMED,
        .candidates = 0U, .exact = 1U,
        .outcome = ROUTER_AUDIT_OUTCOME_EXACT_FIRMWARE_MATCH,
    };
    assert(router_audit_wire_terminal(line, sizeof(line), &terminal));
    assert(strcmp(line,
        "[ROUTER_AUDIT/1] END MODE=passive REQUESTS=0 ERRORS=0 EVIDENCE=2 "
        "CONFIDENCE=confirmed CANDIDATES=0 EXACT=1 "
        "OUTCOME=exact_firmware_match\r\n") == 0);

    terminal.mode = ROUTER_AUDIT_WIRE_SCAN_STANDARD_OWNED;
    assert(router_audit_wire_terminal(line, sizeof(line), &terminal));
    assert(strstr(line, "MODE=standard ") != NULL);
    assert(strstr(line, "owned") == NULL);

    router_cve_result_t hostile;
    memset(&hostile, 'A', sizeof(hostile));
    hostile.match = ROUTER_CVE_EXACT_FIRMWARE;
    memset(exact, 'Z', sizeof(exact));
    assert(!router_audit_wire_cve(exact, sizeof(exact), &hostile,
                                  0U, 0U, false, false));
    assert(exact[0] == 'Z');

    unchanged_on_failure();
    puts("PASS: bounded Router Audit wire records");
    return 0;
}
