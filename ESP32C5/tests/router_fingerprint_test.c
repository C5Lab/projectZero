#include "router_fingerprint.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static router_evidence_t evidence(router_evidence_source_t source,
                                  const char *vendor,
                                  const char *model,
                                  const char *firmware)
{
    router_evidence_t item;
    memset(&item, 0, sizeof(item));
    item.source = source;
    if (vendor != NULL) {
        assert(strlen(vendor) <= ROUTER_EVIDENCE_TEXT_MAX);
        memcpy(item.vendor, vendor, strlen(vendor) + 1U);
    }
    if (model != NULL) {
        assert(strlen(model) <= ROUTER_EVIDENCE_TEXT_MAX);
        memcpy(item.model, model, strlen(model) + 1U);
    }
    if (firmware != NULL) {
        assert(strlen(firmware) <= ROUTER_EVIDENCE_TEXT_MAX);
        memcpy(item.firmware, firmware, strlen(firmware) + 1U);
    }
    return item;
}

static void test_structured_confirmation_and_normalization(void)
{
    router_evidence_t items[2] = {
        evidence(ROUTER_EVIDENCE_UPNP_STRUCTURED,
                 "  TP-LINK__Technologies  ", " Archer\tAX-55 ",
                 " V1.2.3-build_7 "),
        evidence(ROUTER_EVIDENCE_OUI, "tp link technologies", NULL, NULL),
    };
    router_fingerprint_t out;

    assert(router_fingerprint_normalize(items, 2U, &out));
    assert(strcmp(out.vendor, "tp link technologies") == 0);
    assert(strcmp(out.model, "archer ax 55") == 0);
    assert(strcmp(out.firmware, "v1 2 3 build 7") == 0);
    assert(out.confidence == ROUTER_CONFIDENCE_CONFIRMED);
    assert(!out.conflict);
    assert(!out.truncated);
}

static void test_weak_and_anti_inference_sources(void)
{
    router_fingerprint_t out;
    router_evidence_t weak = evidence(ROUTER_EVIDENCE_HTTP_TITLE,
                                      "Acme", "Gateway Pro 7", "9.9.9");
    assert(router_fingerprint_normalize(&weak, 1U, &out));
    assert(strcmp(out.vendor, "acme") == 0);
    assert(strcmp(out.model, "gateway pro 7") == 0);
    assert(out.firmware[0] == '\0');
    assert(out.confidence == ROUTER_CONFIDENCE_PROBABLE);

    router_evidence_t server = evidence(ROUTER_EVIDENCE_HTTP_SERVER,
                                        "nginx", "router 9000", "1.2.3");
    assert(router_fingerprint_normalize(&server, 1U, &out));
    assert(out.vendor[0] == '\0');
    assert(strcmp(out.model, "router 9000") == 0);
    assert(out.firmware[0] == '\0');
    assert(out.confidence == ROUTER_CONFIDENCE_PROBABLE);

    server = evidence(ROUTER_EVIDENCE_SSDP_SERVER,
                      "Acme", "Router Family 8", "build 4");
    assert(router_fingerprint_normalize(&server, 1U, &out));
    assert(strcmp(out.model, "router family 8") == 0);
    assert(out.firmware[0] == '\0');
    assert(out.confidence == ROUTER_CONFIDENCE_PROBABLE);

    router_evidence_t oui = evidence(ROUTER_EVIDENCE_OUI, "Acme", "X1", "4");
    assert(router_fingerprint_normalize(&oui, 1U, &out));
    assert(strcmp(out.vendor, "acme") == 0);
    assert(out.model[0] == '\0');
    assert(out.firmware[0] == '\0');
    assert(out.confidence == ROUTER_CONFIDENCE_UNKNOWN);

    oui.locally_administered_mac = true;
    assert(router_fingerprint_normalize(&oui, 1U, &out));
    assert(out.vendor[0] == '\0');
    assert(out.model[0] == '\0');
    assert(out.confidence == ROUTER_CONFIDENCE_UNKNOWN);
}

static void test_structured_identity_may_use_separate_vendor_evidence(void)
{
    router_evidence_t items[2] = {
        evidence(ROUTER_EVIDENCE_UPNP_STRUCTURED, NULL, "Router X", "3.1"),
        evidence(ROUTER_EVIDENCE_OUI, "Acme", NULL, NULL),
    };
    router_fingerprint_t out;

    assert(router_fingerprint_normalize(items, 2U, &out));
    assert(strcmp(out.vendor, "acme") == 0);
    assert(strcmp(out.model, "router x") == 0);
    assert(strcmp(out.firmware, "3 1") == 0);
    assert(out.confidence == ROUTER_CONFIDENCE_CONFIRMED);

    items[1].locally_administered_mac = true;
    assert(router_fingerprint_normalize(items, 2U, &out));
    assert(out.vendor[0] == '\0');
    assert(out.confidence == ROUTER_CONFIDENCE_UNKNOWN);

    items[0] = evidence(ROUTER_EVIDENCE_UPNP_STRUCTURED,
                        "Acme", "Router X", "3.1");
    items[1] = evidence(ROUTER_EVIDENCE_HTTP_SERVER,
                        "nginx", "router x", NULL);
    assert(router_fingerprint_normalize(items, 2U, &out));
    assert(strcmp(out.vendor, "acme") == 0);
    assert(!out.conflict);
    assert(out.confidence == ROUTER_CONFIDENCE_CONFIRMED);
}

static void test_conflict_duplicates_and_order_are_deterministic(void)
{
    router_evidence_t items[4] = {
        evidence(ROUTER_EVIDENCE_UPNP_STRUCTURED, "Acme", "Model-B", "2.0"),
        evidence(ROUTER_EVIDENCE_HTTP_TITLE, "acme", "Model A", NULL),
        evidence(ROUTER_EVIDENCE_UPNP_STRUCTURED, "ACME", "Model-B", "2.0"),
        evidence(ROUTER_EVIDENCE_DHCP, "Acme", "model a", NULL),
    };
    router_evidence_t reversed[4] = {items[3], items[2], items[1], items[0]};
    router_fingerprint_t first;
    router_fingerprint_t second;

    assert(router_fingerprint_normalize(items, 4U, &first));
    assert(router_fingerprint_normalize(reversed, 4U, &second));
    assert(first.conflict);
    assert(first.confidence == ROUTER_CONFIDENCE_UNKNOWN);
    assert(memcmp(&first, &second, sizeof(first)) == 0);
    assert(strcmp(first.model, "model a") == 0);
    assert(strcmp(first.firmware, "2 0") == 0);

    items[1] = evidence(ROUTER_EVIDENCE_HTTP_TITLE, "acme", "model b", NULL);
    items[3] = evidence(ROUTER_EVIDENCE_DHCP, "acme", "model b", NULL);
    assert(router_fingerprint_normalize(items, 4U, &first));
    assert(!first.conflict);
    assert(first.confidence == ROUTER_CONFIDENCE_CONFIRMED);
}

static void test_utf8_truncation_and_invalid_inputs_are_atomic(void)
{
    router_evidence_t maximum[ROUTER_EVIDENCE_MAX];
    router_evidence_t item = evidence(ROUTER_EVIDENCE_HTTP_TITLE, NULL, NULL, NULL);
    router_fingerprint_t out;
    router_fingerprint_t sentinel;
    size_t index;

    for (index = 0U; index < ROUTER_EVIDENCE_MAX; ++index) {
        maximum[index] = evidence(ROUTER_EVIDENCE_OUI, "Acme", NULL, NULL);
    }
    assert(router_fingerprint_normalize(maximum, ROUTER_EVIDENCE_MAX, &out));
    assert(strcmp(out.vendor, "acme") == 0);

    memset(item.model, 'A', 95U);
    item.model[95] = (char)0xC3;
    item.model[96] = (char)0xA9;
    item.model[97] = '\0';
    assert(router_fingerprint_normalize(&item, 1U, &out));
    assert(strlen(out.model) == 95U);
    assert(out.model[94] == 'a');
    assert(out.truncated);
    assert(out.confidence == ROUTER_CONFIDENCE_PROBABLE);

    item = evidence(ROUTER_EVIDENCE_UPNP_STRUCTURED, "Acme", NULL, "1.0");
    memset(item.model, 'M', 97U);
    item.model[97] = '\0';
    assert(router_fingerprint_normalize(&item, 1U, &out));
    assert(out.truncated);
    assert(out.confidence == ROUTER_CONFIDENCE_UNKNOWN);

    memset(&sentinel, 0xA5, sizeof(sentinel));
    out = sentinel;
    assert(!router_fingerprint_normalize(&item, ROUTER_EVIDENCE_MAX + 1U, &out));
    assert(memcmp(&out, &sentinel, sizeof(out)) == 0);

    item.source = (router_evidence_source_t)99;
    assert(!router_fingerprint_normalize(&item, 1U, &out));
    assert(memcmp(&out, &sentinel, sizeof(out)) == 0);

    item = evidence(ROUTER_EVIDENCE_HTTP_TITLE, NULL, NULL, NULL);
    item.model[0] = (char)0xC3;
    item.model[1] = '(';
    item.model[2] = '\0';
    assert(!router_fingerprint_normalize(&item, 1U, &out));
    assert(memcmp(&out, &sentinel, sizeof(out)) == 0);

    item = evidence(ROUTER_EVIDENCE_HTTP_TITLE, NULL, NULL, NULL);
    memset(item.model, 'x', sizeof(item.model));
    assert(!router_fingerprint_normalize(&item, 1U, &out));
    assert(memcmp(&out, &sentinel, sizeof(out)) == 0);

    assert(router_fingerprint_normalize(NULL, 0U, &out));
    assert(out.confidence == ROUTER_CONFIDENCE_UNKNOWN);
    assert(out.vendor[0] == '\0' && out.model[0] == '\0' && out.firmware[0] == '\0');
    assert(!out.conflict && !out.truncated);
    assert(!router_fingerprint_normalize(NULL, 1U, &out));
    assert(!router_fingerprint_normalize(&item, 1U, NULL));
}

static void test_vendor_and_firmware_conflicts_force_unknown(void)
{
    router_evidence_t items[2] = {
        evidence(ROUTER_EVIDENCE_UPNP_STRUCTURED, "Acme", "R1", "1.0"),
        evidence(ROUTER_EVIDENCE_UPNP_STRUCTURED, "Other", "R1", "2.0"),
    };
    router_fingerprint_t out;
    assert(router_fingerprint_normalize(items, 2U, &out));
    assert(out.conflict);
    assert(out.confidence == ROUTER_CONFIDENCE_UNKNOWN);
    assert(strcmp(out.vendor, "acme") == 0);
    assert(strcmp(out.model, "r1") == 0);
    assert(strcmp(out.firmware, "1 0") == 0);
}

int main(void)
{
    test_structured_confirmation_and_normalization();
    test_weak_and_anti_inference_sources();
    test_structured_identity_may_use_separate_vendor_evidence();
    test_conflict_duplicates_and_order_are_deterministic();
    test_utf8_truncation_and_invalid_inputs_are_atomic();
    test_vendor_and_firmware_conflicts_force_unknown();
    puts("PASS: bounded router fingerprint normalization and confidence");
    return 0;
}
