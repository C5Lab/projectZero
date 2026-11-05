#include "sae_guard_parser.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t ap[6] = {0x02, 0x10, 0x20, 0x30, 0x40, 0x50};
static const uint8_t sta[6] = {0x04, 0x11, 0x21, 0x31, 0x41, 0x51};
static const uint8_t other[6] = {0x06, 0x12, 0x22, 0x32, 0x42, 0x52};
static const uint8_t multicast[6] = {0x01, 0x00, 0x5e, 0, 0, 1};

static void le16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
}

static void auth_body(uint8_t *bytes, uint16_t transaction, uint16_t status)
{
    le16(bytes, 3);
    le16(bytes + 2, transaction);
    le16(bytes + 4, status);
}

static wifi_security_decoded_t auth_view(uint8_t *body, size_t body_len,
                                         bool from_ap)
{
    wifi_security_decoded_t frame = {0};
    frame.kind = WIFI_SEC_FRAME_AUTH;
    frame.subtype = 11;
    frame.sequence = 0x321;
    frame.retry = true;
    frame.body = body;
    frame.body_len = body_len;
    memcpy(frame.bssid, ap, sizeof(ap));
    memcpy(frame.station, sta, sizeof(sta));
    memcpy(frame.addr3, ap, sizeof(ap));
    if (from_ap) {
        memcpy(frame.addr1, sta, sizeof(sta));
        memcpy(frame.addr2, ap, sizeof(ap));
    } else {
        memcpy(frame.addr1, ap, sizeof(ap));
        memcpy(frame.addr2, sta, sizeof(sta));
    }
    return frame;
}

static void assert_cleared(const sae_guard_observation_t *observation)
{
    const sae_guard_observation_t cleared = {0};
    assert(memcmp(observation, &cleared, sizeof(cleared)) == 0);
}

static void assert_unrelated(const wifi_security_decoded_t *frame,
                             bool input_truncated)
{
    sae_guard_observation_t observation;
    memset(&observation, 0xa5, sizeof(observation));
    assert(!sae_guard_parse(frame, input_truncated, UINT64_C(123456),
                            &observation));
    assert_cleared(&observation);
}

static void assert_metadata(const sae_guard_observation_t *observation,
                            size_t body_len, bool from_ap,
                            uint64_t timestamp_us)
{
    assert(memcmp(observation->bssid, ap, sizeof(ap)) == 0);
    assert(memcmp(observation->station, sta, sizeof(sta)) == 0);
    assert(observation->from_ap == from_ap);
    assert(observation->retry);
    assert(observation->sequence == 0x321);
    assert(observation->body_len == body_len);
    assert(observation->timestamp_us == timestamp_us);
    /* The runtime adapter fills copied-slot radio metadata after parsing. */
    assert(observation->channel == 0);
    assert(observation->rssi == 0);
}

/* Catches classifying unrelated auth algorithms or ambiguous identities as SAE. */
static void test_unrelated_direction_and_identity(void)
{
    uint8_t body[8] = {0};
    auth_body(body, 1, 1);
    wifi_security_decoded_t frame = auth_view(body, 6, true);
    sae_guard_observation_t observation;

    memset(&observation, 0xa5, sizeof(observation));
    assert(!sae_guard_parse(NULL, false, 1, &observation));
    assert_cleared(&observation);
    assert(!sae_guard_parse(&frame, false, 1, NULL));

    frame.kind = WIFI_SEC_FRAME_MGMT;
    assert_unrelated(&frame, true);
    frame = auth_view(body, 6, true);
    le16(body, 0); /* Open System. */
    assert_unrelated(&frame, true);
    le16(body, 3);

    assert(sae_guard_parse(&frame, false, UINT64_C(123456), &observation));
    assert(observation.kind == SAE_GUARD_STATUS_ONLY);
    assert(observation.reason == SAE_GUARD_PARSE_OK);
    assert(observation.transaction == 1 && observation.status == 1);
    assert_metadata(&observation, 6, true, UINT64_C(123456));

    frame = auth_view(body, 6, false);
    frame.retry = false;
    assert(sae_guard_parse(&frame, false, 7, &observation));
    assert(observation.kind == SAE_GUARD_STATUS_ONLY && !observation.from_ap);
    assert(!observation.retry && observation.sequence == 0x321);

    frame = auth_view(body, 6, true);
    memset(frame.bssid, 0, sizeof(frame.bssid));
    assert_unrelated(&frame, false);
    frame = auth_view(body, 6, true);
    memcpy(frame.bssid, multicast, sizeof(multicast));
    assert_unrelated(&frame, false);
    frame = auth_view(body, 6, true);
    memset(frame.station, 0, sizeof(frame.station));
    assert_unrelated(&frame, false);
    frame = auth_view(body, 6, true);
    memcpy(frame.station, multicast, sizeof(multicast));
    assert_unrelated(&frame, false);
    frame = auth_view(body, 6, true);
    memcpy(frame.station, ap, sizeof(ap));
    assert_unrelated(&frame, false);

    frame = auth_view(body, 6, true);
    memcpy(frame.addr3, other, sizeof(other));
    assert_unrelated(&frame, false);
    frame = auth_view(body, 6, true);
    memcpy(frame.addr1, other, sizeof(other));
    assert_unrelated(&frame, false);
    frame = auth_view(body, 6, true);
    memcpy(frame.addr2, other, sizeof(other));
    assert_unrelated(&frame, false);
    frame = auth_view(body, 6, true);
    frame.to_ds = true;
    assert_unrelated(&frame, false);
    frame = auth_view(body, 6, true);
    frame.from_ds = true;
    assert_unrelated(&frame, false);
}

/* Exact allocations make ASan prove that no absent Authentication byte is read. */
static void test_short_protected_and_truncation_precedence(void)
{
    static const uint8_t header[6] = {3, 0, 1, 0, 0, 0};
    sae_guard_observation_t observation;
    for (size_t length = 0; length <= sizeof(header); ++length) {
        uint8_t *body = malloc(length == 0 ? 1 : length);
        assert(body != NULL);
        if (length != 0) memcpy(body, header, length);
        wifi_security_decoded_t frame = auth_view(body, length, true);
        if (length < 2) {
            assert_unrelated(&frame, false);
        } else {
            assert(sae_guard_parse(&frame, false, 9, &observation));
            assert(observation.kind == SAE_GUARD_MALFORMED);
            assert(observation.reason == (length < 6 ?
                   SAE_GUARD_SHORT_AUTH_BODY : SAE_GUARD_SHORT_GROUP));
            assert_metadata(&observation, length, true, 9);
        }
        free(body);
    }

    uint8_t open_system[6] = {0};
    wifi_security_decoded_t frame = auth_view(open_system, sizeof(open_system), true);
    assert_unrelated(&frame, true); /* Truncation cannot invent SAE identity. */

    frame = auth_view(NULL, 0, true);
    frame.protected_frame = true;
    assert_unrelated(&frame, false);
    assert_unrelated(&frame, true);

    uint8_t malformed[8] = {0};
    auth_body(malformed, 9, 0);
    le16(malformed + 6, 19);
    frame = auth_view(malformed, sizeof(malformed), true);
    assert(sae_guard_parse(&frame, true, 12, &observation));
    assert(observation.kind == SAE_GUARD_MALFORMED);
    assert(observation.reason == SAE_GUARD_INPUT_TRUNCATED);
    assert(observation.transaction == 9 && observation.group == 0);

    frame = auth_view(NULL, 2, true);
    assert_unrelated(&frame, false);
}

/* Catches parser-only role assumptions that disagree with the real decoder. */
static void test_decoded_authentication_views(void)
{
    uint8_t raw[32] = {0xb0, 0x08, 0, 0};
    memcpy(raw + 4, sta, sizeof(sta));
    memcpy(raw + 10, ap, sizeof(ap));
    memcpy(raw + 16, ap, sizeof(ap));
    raw[22] = 0x10;
    raw[23] = 0x32;
    auth_body(raw + 24, 1, 9);

    wifi_security_decoded_t decoded;
    sae_guard_observation_t observation;
    assert(wifi_security_decode(raw, 30, &decoded));
    assert(decoded.kind == WIFI_SEC_FRAME_AUTH && decoded.body == raw + 24);
    assert(sae_guard_parse(&decoded, false, 400, &observation));
    assert(observation.kind == SAE_GUARD_STATUS_ONLY && observation.from_ap);
    assert_metadata(&observation, 6, true, 400);

    memcpy(raw + 4, ap, sizeof(ap));
    memcpy(raw + 10, sta, sizeof(sta));
    assert(wifi_security_decode(raw, 30, &decoded));
    assert(sae_guard_parse(&decoded, false, 401, &observation));
    assert(observation.kind == SAE_GUARD_STATUS_ONLY && !observation.from_ap);
    assert_metadata(&observation, 6, false, 401);

    raw[1] = 0x48; /* Protected body is intentionally hidden by the decoder. */
    assert(wifi_security_decode(raw, 24, &decoded));
    assert(decoded.kind == WIFI_SEC_FRAME_AUTH && decoded.protected_frame);
    assert(decoded.body == NULL && decoded.body_len == 0);
    assert_unrelated(&decoded, false);
    assert_unrelated(&decoded, true);
}

/* Catches conflating status outcomes, bad transactions, and raw Confirm minima. */
static void test_transactions_statuses_and_unknown_groups(void)
{
    uint8_t body[96] = {0};
    sae_guard_observation_t observation;

    auth_body(body, 1, 0);
    le16(body + 6, 0x1234); /* Unknown groups remain observations, not size claims. */
    wifi_security_decoded_t frame = auth_view(body, 8, true);
    assert(sae_guard_parse(&frame, false, 20, &observation));
    assert(observation.kind == SAE_GUARD_COMMIT);
    assert(observation.reason == SAE_GUARD_PARSE_OK);
    assert(observation.group == 0x1234);

    for (uint16_t transaction = 0; transaction <= 3; transaction += 3) {
        auth_body(body, transaction, 0);
        frame = auth_view(body, sizeof(body), true);
        assert(sae_guard_parse(&frame, false, 21, &observation));
        assert(observation.kind == SAE_GUARD_MALFORMED);
        assert(observation.reason == SAE_GUARD_BAD_TRANSACTION);
        assert(observation.transaction == transaction);
    }

    auth_body(body, 1, 9);
    frame = auth_view(body, 6, true);
    assert(sae_guard_parse(&frame, false, 22, &observation));
    assert(observation.kind == SAE_GUARD_STATUS_ONLY);
    assert(observation.status == 9 && observation.group == 0);

    uint8_t status76_header[8] = {0};
    auth_body(status76_header, 1, 76);
    le16(status76_header + 6, 19);
    for (size_t length = 6; length <= 7; ++length) {
        uint8_t *short_body = malloc(length);
        assert(short_body != NULL);
        memcpy(short_body, status76_header, length);
        frame = auth_view(short_body, length, true);
        assert(sae_guard_parse(&frame, false, 23, &observation));
        assert(observation.kind == SAE_GUARD_MALFORMED);
        assert(observation.reason == SAE_GUARD_SHORT_GROUP);
        assert(observation.status == 76 && observation.group == 0);
        free(short_body);
    }

    frame = auth_view(status76_header, sizeof(status76_header), true);
    assert(sae_guard_parse(&frame, false, 24, &observation));
    assert(observation.kind == SAE_GUARD_ANTI_CLOGGING);
    assert(observation.reason == SAE_GUARD_PARSE_OK);
    assert(observation.status == 76 && observation.group == 19);
    auth_body(body, 1, 76);
    le16(body + 6, 0x1234);
    frame = auth_view(body, sizeof(body), true); /* Opaque token/trailing bytes. */
    assert(sae_guard_parse(&frame, false, 25, &observation));
    assert(observation.kind == SAE_GUARD_ANTI_CLOGGING);
    assert(observation.group == 0x1234);

    auth_body(body, 1, 77);
    le16(body + 6, 20);
    frame = auth_view(body, 6, false);
    assert(sae_guard_parse(&frame, false, 26, &observation));
    assert(observation.kind == SAE_GUARD_UNSUPPORTED_GROUP);
    assert(observation.status == 77 && observation.group == 0);
    frame.body_len = 8; /* A trailing rejected-group value is not interpreted. */
    assert(sae_guard_parse(&frame, false, 27, &observation));
    assert(observation.kind == SAE_GUARD_UNSUPPORTED_GROUP);
    assert(observation.group == 0);

    static const uint16_t transaction_two_statuses[] = {9, 76, 77, 126, 127};
    for (size_t i = 0; i < sizeof(transaction_two_statuses) /
                           sizeof(transaction_two_statuses[0]); ++i) {
        auth_body(body, 2, transaction_two_statuses[i]);
        le16(body + 6, 19);
        frame = auth_view(body, 8, true);
        assert(sae_guard_parse(&frame, false, 28 + i, &observation));
        assert(observation.kind == SAE_GUARD_STATUS_ONLY);
        assert(observation.reason == SAE_GUARD_PARSE_OK);
        assert(observation.status == transaction_two_statuses[i]);
        assert(observation.group == 0);
    }

    auth_body(body, 2, 0);
    frame = auth_view(body, 39, true);
    assert(sae_guard_parse(&frame, false, 40, &observation));
    assert(observation.kind == SAE_GUARD_MALFORMED);
    assert(observation.reason == SAE_GUARD_CONFIRM_UNDERSIZE);
    frame.body_len = 40; /* 6-byte header + send-confirm 2 + raw confirm 32. */
    assert(sae_guard_parse(&frame, false, 41, &observation));
    assert(observation.kind == SAE_GUARD_CONFIRM);
    assert(observation.reason == SAE_GUARD_PARSE_OK && observation.group == 0);
    frame.body_len = sizeof(body);
    assert(sae_guard_parse(&frame, false, 42, &observation));
    assert(observation.kind == SAE_GUARD_CONFIRM);
}

/* Catches off-by-one group minima or rejecting bounded optional Commit fields. */
static void test_known_group_minimums(void)
{
    static const struct {
        uint16_t group;
        size_t scalar_and_element;
    } cases[] = {
        {19, 32 + 64},
        {20, 48 + 96},
        {21, 66 + 132},
    };
    sae_guard_observation_t observation;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        const size_t minimum = 8 + cases[i].scalar_and_element;
        for (size_t extra = 0; extra <= 17; extra += 17) {
            const size_t length = minimum + extra;
            uint8_t *body = malloc(length);
            assert(body != NULL);
            memset(body, 0x6d, length);
            auth_body(body, 1, 0);
            le16(body + 6, cases[i].group);
            wifi_security_decoded_t frame = auth_view(body, length, i != 1);
            assert(sae_guard_parse(&frame, false, 100 + i, &observation));
            assert(observation.kind == SAE_GUARD_COMMIT);
            assert(observation.reason == SAE_GUARD_PARSE_OK);
            assert(observation.group == cases[i].group);
            assert_metadata(&observation, length, i != 1, 100 + i);
            free(body);
        }

        uint8_t *short_body = malloc(minimum - 1);
        assert(short_body != NULL);
        memset(short_body, 0x7e, minimum - 1);
        auth_body(short_body, 1, 0);
        le16(short_body + 6, cases[i].group);
        wifi_security_decoded_t frame = auth_view(short_body, minimum - 1, true);
        assert(sae_guard_parse(&frame, false, 200 + i, &observation));
        assert(observation.kind == SAE_GUARD_MALFORMED);
        assert(observation.reason == SAE_GUARD_KNOWN_GROUP_UNDERSIZE);
        assert(observation.group == cases[i].group);
        free(short_body);
    }
}

/* Catches reducing H2E/SAE-PK Commit variants to generic status records. */
static void test_commit_bearing_status_minimums(void)
{
    static const uint16_t statuses[] = {126, 127};
    static const struct {
        uint16_t group;
        size_t scalar_and_element;
    } groups[] = {
        {19, 32 + 64},
        {20, 48 + 96},
        {21, 66 + 132},
    };
    sae_guard_observation_t observation;
    for (size_t s = 0; s < sizeof(statuses) / sizeof(statuses[0]); ++s) {
        for (size_t g = 0; g < sizeof(groups) / sizeof(groups[0]); ++g) {
            const size_t minimum = 8 + groups[g].scalar_and_element;
            for (size_t extra = 0; extra <= 11; extra += 11) {
                const size_t length = minimum + extra;
                uint8_t *body = malloc(length);
                assert(body != NULL);
                memset(body, 0x5c, length);
                auth_body(body, 1, statuses[s]);
                le16(body + 6, groups[g].group);
                wifi_security_decoded_t frame = auth_view(body, length, true);
                assert(sae_guard_parse(&frame, false, 500 + s * 10 + g,
                                       &observation));
                assert(observation.kind == SAE_GUARD_COMMIT);
                assert(observation.reason == SAE_GUARD_PARSE_OK);
                assert(observation.status == statuses[s]);
                assert(observation.group == groups[g].group);
                free(body);
            }

            uint8_t *short_body = malloc(minimum - 1);
            assert(short_body != NULL);
            memset(short_body, 0x4b, minimum - 1);
            auth_body(short_body, 1, statuses[s]);
            le16(short_body + 6, groups[g].group);
            wifi_security_decoded_t frame = auth_view(short_body, minimum - 1,
                                                       false);
            assert(sae_guard_parse(&frame, false, 600 + s * 10 + g,
                                   &observation));
            assert(observation.kind == SAE_GUARD_MALFORMED);
            assert(observation.reason == SAE_GUARD_KNOWN_GROUP_UNDERSIZE);
            assert(observation.status == statuses[s]);
            assert(observation.group == groups[g].group);
            free(short_body);
        }

        uint8_t unknown[8] = {0};
        auth_body(unknown, 1, statuses[s]);
        le16(unknown + 6, 0x1234);
        wifi_security_decoded_t frame = auth_view(unknown, sizeof(unknown), true);
        assert(sae_guard_parse(&frame, false, 700 + s, &observation));
        assert(observation.kind == SAE_GUARD_COMMIT);
        assert(observation.reason == SAE_GUARD_PARSE_OK);
        assert(observation.status == statuses[s]);
        assert(observation.group == 0x1234);
    }
}

static bool contains_bytes(const uint8_t *haystack, size_t haystack_len,
                           const uint8_t *needle, size_t needle_len)
{
    if (needle_len == 0 || needle_len > haystack_len) return false;
    for (size_t i = 0; i <= haystack_len - needle_len; ++i) {
        if (memcmp(haystack + i, needle, needle_len) == 0) return true;
    }
    return false;
}

/* Catches retaining scalar, element, token, or any body slice in observations. */
static void test_secret_marker_hygiene(void)
{
    static const uint8_t marker[] = {
        0xde, 0xad, 0xbe, 0xef, 0xc0, 0xff, 0xee, 0x42,
        0x53, 0x41, 0x45, 0x2d, 0x53, 0x45, 0x43, 0x52
    };
    uint8_t body[128];
    for (size_t i = 0; i < sizeof(body); ++i) body[i] = marker[i % sizeof(marker)];
    auth_body(body, 1, 0);
    le16(body + 6, 19);
    wifi_security_decoded_t frame = auth_view(body, 104, true);
    sae_guard_observation_t observation;
    assert(sae_guard_parse(&frame, false, 300, &observation));
    assert(observation.kind == SAE_GUARD_COMMIT);
    assert(!contains_bytes((const uint8_t *)&observation, sizeof(observation),
                           marker, sizeof(marker)));

    auth_body(body, 1, 76);
    le16(body + 6, 19);
    frame = auth_view(body, sizeof(body), false);
    assert(sae_guard_parse(&frame, false, 301, &observation));
    assert(observation.kind == SAE_GUARD_ANTI_CLOGGING);
    assert(observation.group == 19);
    assert(!contains_bytes((const uint8_t *)&observation, sizeof(observation),
                           marker, sizeof(marker)));
}

int main(void)
{
    test_unrelated_direction_and_identity();
    test_short_protected_and_truncation_precedence();
    test_decoded_authentication_views();
    test_transactions_statuses_and_unknown_groups();
    test_known_group_minimums();
    test_commit_bearing_status_minimums();
    test_secret_marker_hygiene();
    puts("PASS: bounded passive SAE Authentication parser");
    return 0;
}
