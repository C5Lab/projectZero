#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include "pmkid_parser.h"
#include "pmkid_fixtures.h"

static unsigned visited;
static void visit(const pmkid_identity_t *id, const uint8_t pmkid[16], void *ctx)
{
    (void)ctx;
    assert(!memcmp(id->bssid, test_ap, 6));
    assert(!memcmp(id->client, test_sta, 6));
    assert(pmkid[0] != 0);
    ++visited;
}

int main(void)
{
    uint8_t f[512];
    for (unsigned qos = 0; qos < 2; ++qos) {
        size_t n = make_key(f, qos, 2);
        visited = 0;
        assert(pmkid_parse_frame(f, n, visit, NULL) == 2 && visited == 2);
        for (size_t length = 0; length < n; ++length) {
            uint8_t *short_frame = malloc(length ? length : 1);
            memcpy(short_frame, f, length);
            assert(pmkid_parse_frame(short_frame, length, NULL, NULL) == 0);
            free(short_frame);
        }
        size_t key = (qos ? 26 : 24) + 12;
        f[key + 1] |= 0x10;
        assert(!pmkid_parse_frame(f, n, NULL, NULL));
        f[key + 1] &= ~0x10;
        f[key + 95 + 2] = 1; /* Wrong KDE OUI. */
        assert(pmkid_parse_frame(f, n, NULL, NULL) == 1);
        f[key + 95 + 2] = 0;
        memset(f + key + 101, 0, 16);
        assert(pmkid_parse_frame(f, n, NULL, NULL) == 1);
        f[key + 95 + 22 + 1] = 255;
        assert(!pmkid_parse_frame(f, n, NULL, NULL));
    }
    const unsigned kinds[] = {0, 0x10, 0x20, 0x30};
    for (size_t k = 0; k < 4; ++k) {
        size_t n = make_assoc(f, kinds[k], 2);
        visited = 0;
        assert(pmkid_parse_frame(f, n, visit, NULL) == 2 && visited == 2);
        memset(f + n, 0xff, 4);
        assert(pmkid_parse_frame(f, n + 4, visit, NULL) == 2); /* FCS. */
        for (size_t length = 0; length < n; ++length) {
            uint8_t *short_frame = malloc(length ? length : 1);
            memcpy(short_frame, f, length);
            assert(!pmkid_parse_frame(short_frame, length, NULL, NULL));
            free(short_frame);
        }
        f[n - 33] = 255; /* Invalid PMKID count (high byte). */
        assert(!pmkid_parse_frame(f, n, NULL, NULL));
        n = make_assoc(f, kinds[k], 0);
        assert(!pmkid_parse_frame(f, n, NULL, NULL));
    }
    size_t n = make_key(f, 1, 1);
    memmove(f + 30, f + 26, n - 26); /* QoS + HT control. */
    memset(f + 26, 0, 4);
    f[1] |= 0x80;
    assert(pmkid_parse_frame(f, n + 4, visit, NULL) == 1);
    n = make_key(f, 0, 1);
    f[1] = 1; /* Reverse direction: STA -> AP. */
    memcpy(f + 4, test_ap, 6); memcpy(f + 10, test_sta, 6);
    assert(pmkid_parse_frame(f, n, visit, NULL) == 1);
    f[1] = 3;
    assert(!pmkid_parse_frame(f, n, NULL, NULL));
    f[1] = 0x42;
    assert(!pmkid_parse_frame(f, n, NULL, NULL));
    n = make_key(f, 0, 0); /* Initial M1 with no PMKID. */
    assert(!pmkid_parse_frame(f, n, NULL, NULL));
    n = make_key(f, 0, 1); /* A later M1 can carry a PMKID. */
    assert(pmkid_parse_frame(f, n, visit, NULL) == 1);
    assert(pmkid_is_capture_filename("lab_030405_123_pmkid.pcap"));
    assert(!pmkid_is_capture_filename("lab_030405_123.pcap"));
    assert(!pmkid_is_capture_filename("x_pmkid.pcap.part"));
    assert(!pmkid_is_capture_filename(NULL));
    assert(!pmkid_parse_frame(NULL, 0, NULL, NULL));
    assert(make_beacon(f) == 41);
    /* Deterministic random byte inputs exercise all length gates under ASan. */
    uint32_t state = 123;
    for (size_t length = 0; length <= sizeof(f); ++length) {
        for (unsigned sample = 0; sample < 40; ++sample) {
            uint8_t *p = malloc(length ? length : 1);
            for (size_t i = 0; i < length; ++i) {
                state = state * 1664525U + 1013904223U;
                p[i] = state >> 24;
            }
            pmkid_parse_frame(p, length, NULL, NULL);
            free(p);
        }
    }
    return 0;
}
