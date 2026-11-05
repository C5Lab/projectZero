#include "wifi_shield_wps.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static const uint8_t m1[] = {0x10, 0x22, 0, 1, 4};
static const uint8_t m2[] = {0x10, 0x22, 0, 1, 5};

static wps_guard_fragment_t fragment(uint8_t id, uint8_t flags, uint16_t total,
                                      const uint8_t *data, size_t length)
{
    wps_guard_fragment_t f = {0};
    const uint8_t ap[] = {2, 1, 2, 3, 4, 5}, sta[] = {4, 6, 7, 8, 9, 10};
    memcpy(f.bssid, ap, 6);
    memcpy(f.station, sta, 6);
    f.direction = WPS_GUARD_DIR_AP_TO_STA;
    f.eap_id = id;
    f.opcode = 4;
    f.flags = flags;
    f.length_present = (flags & 2U) != 0;
    f.more_fragments = (flags & 1U) != 0;
    f.declared_total = total;
    f.payload_len = (uint16_t)length;
    f.payload_hash = UINT32_C(2166136261);
    for (size_t i = 0; i < length; ++i) {
        f.payload_hash ^= data[i];
        f.payload_hash *= UINT32_C(16777619);
    }
    f.timestamp_us = 100;
    return f;
}

static size_t active(const wifi_shield_wps_table_t *table)
{
    size_t count = 0;
    for (size_t i = 0; i < WIFI_SHIELD_WPS_FLOW_CAPACITY; ++i)
        if (table->flows[i].active) ++count;
    return count;
}

static bool contains(const void *memory, size_t length, const void *marker, size_t size)
{
    const uint8_t *p = memory;
    for (size_t i = 0; i + size <= length; ++i)
        if (memcmp(p + i, marker, size) == 0) return true;
    return false;
}

static void test_message_values_and_standalone_replay(void)
{
    const struct { uint8_t value; wifi_shield_wps_message_t want; } cases[] = {
        {4, WIFI_SHIELD_WPS_M1}, {5, WIFI_SHIELD_WPS_M2},
        {7, WIFI_SHIELD_WPS_M3}, {8, WIFI_SHIELD_WPS_M4},
        {9, WIFI_SHIELD_WPS_M5}, {10, WIFI_SHIELD_WPS_M6},
        {11, WIFI_SHIELD_WPS_M7}, {12, WIFI_SHIELD_WPS_M8},
        {13, WIFI_SHIELD_WPS_ACK}, {14, WIFI_SHIELD_WPS_NACK},
        {15, WIFI_SHIELD_WPS_DONE}, {0, WIFI_SHIELD_WPS_UNKNOWN},
        {6, WIFI_SHIELD_WPS_UNKNOWN}, {255, WIFI_SHIELD_WPS_UNKNOWN}
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        wifi_shield_wps_table_t table = {0};
        uint8_t data[] = {0x10, 0x22, 0, 1, cases[i].value};
        wps_guard_fragment_t f = fragment(37, 0, 0, data, sizeof(data));
        assert(wifi_shield_wps_observe(&table, &f, data, sizeof(data)) == cases[i].want);
        f.timestamp_us = 1000;
        assert(wifi_shield_wps_observe(&table, &f, data, sizeof(data)) == cases[i].want);
        for (size_t split = 1; split < sizeof(data); ++split) {
            wifi_shield_wps_reset(&table);
            f = fragment(1, 3, sizeof(data), data, split);
            assert(wifi_shield_wps_observe(&table, &f, data, split) == WIFI_SHIELD_WPS_UNKNOWN);
            f = fragment(2, 0, 0, data + split, sizeof(data) - split);
            assert(wifi_shield_wps_observe(&table, &f, data + split, sizeof(data) - split) == cases[i].want);
        }
    }
}

static void test_every_split_and_bytewise_fragments(void)
{
    /* Unrelated values contain fake TLVs; only top-level 0x1022 is evidence. */
    const uint8_t data[] = {0x10, 0x49, 0, 5, 0x10, 0x22, 0, 1, 14,
                           0x10, 0x22, 0, 1, 4, 0x10, 0x50, 0, 2, 0xaa, 0xbb};
    for (size_t split = 1; split < sizeof(data); ++split) {
        wifi_shield_wps_table_t table = {0};
        wps_guard_fragment_t first = fragment(1, 3, sizeof(data), data, split);
        assert(wifi_shield_wps_observe(&table, &first, data, split) == WIFI_SHIELD_WPS_UNKNOWN);
        first.timestamp_us = 200;
        assert(wifi_shield_wps_observe(&table, &first, data, split) == WIFI_SHIELD_WPS_UNKNOWN);
        wps_guard_fragment_t last = fragment(2, 0, 0, data + split, sizeof(data) - split);
        assert(wifi_shield_wps_observe(&table, &last, data + split, sizeof(data) - split) == WIFI_SHIELD_WPS_M1);
        /* Replayed terminal bytes must not be appended as another TLV. */
        assert(wifi_shield_wps_observe(&table, &last, data + split, sizeof(data) - split) == WIFI_SHIELD_WPS_M1);
    }
    wifi_shield_wps_table_t table = {0};
    for (size_t i = 0; i < sizeof(data); ++i) {
        uint8_t flags = i == 0 ? 3 : (i + 1 == sizeof(data) ? 0 : 1);
        wps_guard_fragment_t f = fragment((uint8_t)i, flags, i == 0 ? sizeof(data) : 0, data + i, 1);
        wifi_shield_wps_message_t want = i + 1 == sizeof(data) ? WIFI_SHIELD_WPS_M1 : WIFI_SHIELD_WPS_UNKNOWN;
        assert(wifi_shield_wps_observe(&table, &f, data + i, 1) == want);
        assert(wifi_shield_wps_observe(&table, &f, data + i, 1) == want);
    }
    /* Every three-part partition exercises split header and split value together. */
    for (size_t a = 1; a < sizeof(data) - 1; ++a) {
        for (size_t b = a + 1; b < sizeof(data); ++b) {
            wifi_shield_wps_reset(&table);
            wps_guard_fragment_t f = fragment(1, 3, sizeof(data), data, a);
            assert(wifi_shield_wps_observe(&table, &f, data, a) == WIFI_SHIELD_WPS_UNKNOWN);
            f = fragment(2, 1, 0, data + a, b - a);
            assert(wifi_shield_wps_observe(&table, &f, data + a, b - a) == WIFI_SHIELD_WPS_UNKNOWN);
            f = fragment(3, 0, 0, data + b, sizeof(data) - b);
            assert(wifi_shield_wps_observe(&table, &f, data + b, sizeof(data) - b) == WIFI_SHIELD_WPS_M1);
        }
    }
}

static void test_malformed_incomplete_and_duplicates(void)
{
    const uint8_t inputs[][12] = {
        {0x10, 0x22, 0, 0}, {0x10, 0x22, 0, 2, 4, 4},
        {0x10, 0x22, 0, 1, 4, 0x10, 0x22, 0, 1, 4},
        {0x10, 0x22, 0, 1, 4, 0x10, 0x22, 0, 1, 5},
        {0x10, 0x22, 0, 1, 4, 0x10}, {0x10, 0x49, 0xff, 0xff},
        {0x10, 0x49, 0, 1, 4}, {0x10, 0x49, 0, 0},
        {0x10, 0x22, 0, 1, 4, 0x10, 0x49, 0, 2, 7}
    };
    const size_t sizes[] = {4, 6, 10, 10, 6, 4, 5, 4, 10};
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); ++i) {
        wifi_shield_wps_table_t table = {0};
        wps_guard_fragment_t f = fragment(1, 0, 0, inputs[i], sizes[i]);
        assert(wifi_shield_wps_observe(&table, &f, inputs[i], sizes[i]) == WIFI_SHIELD_WPS_UNKNOWN);
    }
    for (size_t size = 0; size < sizeof(m1); ++size) {
        wifi_shield_wps_table_t table = {0};
        wps_guard_fragment_t f = fragment(1, 0, 0, m1, size);
        assert(wifi_shield_wps_observe(&table, &f, m1, size) == WIFI_SHIELD_WPS_UNKNOWN);
    }
    /* Duplicate/invalid Message Type after an early match invalidates the message. */
    const uint8_t duplicate[] = {0x10, 0x22, 0, 1, 4, 0x10, 0x22, 0, 1, 5};
    for (size_t split = 1; split < sizeof(duplicate); ++split) {
        wifi_shield_wps_table_t table = {0};
        wps_guard_fragment_t f = fragment(1, 3, sizeof(duplicate), duplicate, split);
        assert(wifi_shield_wps_observe(&table, &f, duplicate, split) == WIFI_SHIELD_WPS_UNKNOWN);
        f = fragment(2, 0, 0, duplicate + split, sizeof(duplicate) - split);
        assert(wifi_shield_wps_observe(&table, &f, duplicate + split, sizeof(duplicate) - split) == WIFI_SHIELD_WPS_UNKNOWN);
    }
}

static void test_flow_key_and_interleaving(void)
{
    wifi_shield_wps_table_t table = {0};
    wps_guard_fragment_t first[4], last[4];
    for (size_t i = 0; i < 4; ++i) {
        const uint8_t *data = i & 1U ? m2 : m1;
        first[i] = fragment(37, 3, 5, data, 4);
        first[i].direction = i & 1U ? WPS_GUARD_DIR_STA_TO_AP : WPS_GUARD_DIR_AP_TO_STA;
        if (i == 2) first[i].station[5]++;
        if (i == 3) first[i].bssid[5]++;
        last[i] = fragment(38, 0, 0, data + 4, 1);
        memcpy(last[i].bssid, first[i].bssid, 6);
        memcpy(last[i].station, first[i].station, 6);
        last[i].direction = first[i].direction;
        assert(wifi_shield_wps_observe(&table, &first[i], data, 4) == WIFI_SHIELD_WPS_UNKNOWN);
    }
    assert(active(&table) == 4);
    for (size_t i = 4; i-- > 0;) {
        const uint8_t *data = i & 1U ? m2 : m1;
        assert(wifi_shield_wps_observe(&table, &last[i], data + 4, 1) ==
               (i & 1U ? WIFI_SHIELD_WPS_M2 : WIFI_SHIELD_WPS_M1));
    }
}

static void test_capacity_no_eviction_and_saturation(void)
{
    wifi_shield_wps_table_t table = {0};
    for (size_t i = 0; i < WIFI_SHIELD_WPS_FLOW_CAPACITY; ++i) {
        wps_guard_fragment_t f = fragment(1, 3, 5, m1, 4);
        f.station[5] = (uint8_t)(20 + i);
        assert(wifi_shield_wps_observe(&table, &f, m1, 4) == WIFI_SHIELD_WPS_UNKNOWN);
    }
    assert(active(&table) == 32);
    wifi_shield_wps_table_t before = table;
    wps_guard_fragment_t extra = fragment(1, 3, 5, m1, 4);
    extra.station[5] = 100;
    assert(wifi_shield_wps_observe(&table, &extra, m1, 4) == WIFI_SHIELD_WPS_UNKNOWN);
    assert(table.capacity_drops == 1 && memcmp(table.flows, before.flows, sizeof(table.flows)) == 0);
    table.capacity_drops = UINT32_MAX - 1;
    for (size_t i = 0; i < 3; ++i)
        assert(wifi_shield_wps_observe(&table, &extra, m1, 4) == WIFI_SHIELD_WPS_UNKNOWN);
    assert(table.capacity_drops == UINT32_MAX);
    for (size_t i = 0; i < WIFI_SHIELD_WPS_FLOW_CAPACITY; ++i) {
        wps_guard_fragment_t f = fragment(2, 0, 0, m1 + 4, 1);
        f.station[5] = (uint8_t)(20 + i);
        assert(wifi_shield_wps_observe(&table, &f, m1 + 4, 1) == WIFI_SHIELD_WPS_M1);
    }
}

static void test_expiry_backwards_time_and_reset_wipe(void)
{
    wifi_shield_wps_table_t table = {0};
    wps_guard_fragment_t f = fragment(1, 3, 5, m1, 4);
    assert(wifi_shield_wps_observe(&table, &f, m1, 4) == WIFI_SHIELD_WPS_UNKNOWN);
    f.timestamp_us = 900;
    assert(wifi_shield_wps_observe(&table, &f, m1, 4) == WIFI_SHIELD_WPS_UNKNOWN);
    f.timestamp_us = 200;
    assert(wifi_shield_wps_observe(&table, &f, m1, 4) == WIFI_SHIELD_WPS_UNKNOWN);
    assert(wifi_shield_wps_expire(&table, 1) == 0);
    assert(wifi_shield_wps_expire(&table, 5000900) == 0);
    assert(wifi_shield_wps_expire(&table, 5000901) == 1);
    wifi_shield_wps_table_t zero = {0};
    assert(memcmp(&table, &zero, sizeof(table)) == 0);
    /* Observe expires before lookup, so an expired continuation cannot complete. */
    f.timestamp_us = 100;
    assert(wifi_shield_wps_observe(&table, &f, m1, 4) == WIFI_SHIELD_WPS_UNKNOWN);
    f = fragment(2, 0, 0, m1 + 4, 1);
    f.timestamp_us = 5000101;
    assert(wifi_shield_wps_observe(&table, &f, m1 + 4, 1) == WIFI_SHIELD_WPS_UNKNOWN);
    memset(&table, 0xa5, sizeof(table));
    wifi_shield_wps_reset(&table);
    assert(memcmp(&table, &zero, sizeof(table)) == 0);
    assert(wifi_shield_wps_expire(NULL, UINT64_MAX) == 0);
    wifi_shield_wps_reset(NULL);
}

static void test_invalid_envelope_and_sequence_fail_closed(void)
{
    for (size_t change = 0; change < 14; ++change) {
        wifi_shield_wps_table_t table = {0};
        wps_guard_fragment_t f = fragment(1, 3, 5, m1, 4);
        assert(wifi_shield_wps_observe(&table, &f, m1, 4) == WIFI_SHIELD_WPS_UNKNOWN);
        f = fragment(2, 0, 0, m1 + 4, 1);
        switch (change) {
        case 0: f.input_truncated = true; break;
        case 1: f.envelope_reason = WPS_GUARD_INVALID_ENVELOPE; break;
        case 2: f.opcode = 3; break;
        case 3: f.eap_id = 1; break;
        case 4: f.flags = 2; f.length_present = true; f.declared_total = 5; break;
        case 5: f.payload_len = 2; break;
        case 6: f.flags = 4; break;
        case 7: f.more_fragments = true; break;
        case 8: f.length_present = true; break;
        case 9: f.declared_total = 1; break;
        case 10: f.direction = (wps_guard_direction_t)2; break;
        case 11: f.bssid[0] = 3; break;
        case 12: f.station[0] = 5; break;
        default: memcpy(f.station, f.bssid, 6); break;
        }
        assert(wifi_shield_wps_observe(&table, &f, m1 + 4, 1) == WIFI_SHIELD_WPS_UNKNOWN);
    }
    /* Missing first LF, invalid declared lengths, and early/late terminal. */
    const uint16_t totals[] = {0, 4, 5, 4097};
    for (size_t i = 0; i < sizeof(totals) / sizeof(totals[0]); ++i) {
        wifi_shield_wps_table_t table = {0};
        wps_guard_fragment_t f = fragment(1, totals[i] == 0 ? 1 : 3, totals[i], m1, 5);
        assert(wifi_shield_wps_observe(&table, &f, m1, 5) == WIFI_SHIELD_WPS_UNKNOWN);
    }
    wifi_shield_wps_table_t table = {0};
    wps_guard_fragment_t f = fragment(1, 3, 6, m1, 4);
    assert(wifi_shield_wps_observe(&table, &f, m1, 4) == WIFI_SHIELD_WPS_UNKNOWN);
    f = fragment(2, 0, 0, m1 + 4, 1);
    assert(wifi_shield_wps_observe(&table, &f, m1 + 4, 1) == WIFI_SHIELD_WPS_UNKNOWN);
    wifi_shield_wps_reset(&table);
    f = fragment(1, 3, 5, m1, 4);
    assert(wifi_shield_wps_observe(&table, &f, m1, 4) == WIFI_SHIELD_WPS_UNKNOWN);
    const uint8_t too_long[] = {4, 0};
    f = fragment(2, 0, 0, too_long, 2);
    assert(wifi_shield_wps_observe(&table, &f, too_long, 2) == WIFI_SHIELD_WPS_UNKNOWN);
    f = fragment(1, 0, 0, m1, sizeof(m1));
    assert(wifi_shield_wps_observe(NULL, &f, m1, sizeof(m1)) == WIFI_SHIELD_WPS_UNKNOWN);
    assert(wifi_shield_wps_observe(&table, NULL, m1, sizeof(m1)) == WIFI_SHIELD_WPS_UNKNOWN);
    assert(wifi_shield_wps_observe(&table, &f, NULL, sizeof(m1)) == WIFI_SHIELD_WPS_UNKNOWN);
}

static void test_payload_and_pointer_are_never_retained(void)
{
    wifi_shield_wps_table_t table = {0};
    uint8_t data[73] = {0x10, 0x49, 0, 64};
    for (size_t i = 0; i < 64; ++i) data[4 + i] = (uint8_t)(31 + 3 * i);
    memcpy(data + 68, m1, 5);
    const uint8_t *borrowed = data;
    wps_guard_fragment_t f = fragment(1, 3, sizeof(data), data, 36);
    assert(wifi_shield_wps_observe(&table, &f, borrowed, 36) == WIFI_SHIELD_WPS_UNKNOWN);
    assert(!contains(&table, sizeof(table), data + 4, 24));
    assert(!contains(&table, sizeof(table), &borrowed, sizeof(borrowed)));
    memset(data, 0, 36); /* The first borrowed input is dead before continuation. */
    f = fragment(2, 0, 0, data + 36, sizeof(data) - 36);
    assert(wifi_shield_wps_observe(&table, &f, data + 36, sizeof(data) - 36) == WIFI_SHIELD_WPS_M1);
    assert(!contains(&table, sizeof(table), data + 36, 24));
    assert(!contains(&table, sizeof(table), &borrowed, sizeof(borrowed)));
    wifi_shield_wps_reset(&table);
    const uint8_t *bytes = (const uint8_t *)&table;
    for (size_t i = 0; i < sizeof(table); ++i) assert(bytes[i] == 0);
}

static void test_next_message_reuses_identity_without_stale_classification(void)
{
    wifi_shield_wps_table_t table = {0};
    wps_guard_fragment_t f = fragment(1, 0, 0, m1, sizeof(m1));
    assert(wifi_shield_wps_observe(&table, &f, m1, sizeof(m1)) == WIFI_SHIELD_WPS_M1);
    f = fragment(2, 3, 5, m2, 4);
    assert(wifi_shield_wps_observe(&table, &f, m2, 4) == WIFI_SHIELD_WPS_UNKNOWN);
    f = fragment(3, 0, 0, m2 + 4, 1);
    assert(wifi_shield_wps_observe(&table, &f, m2 + 4, 1) == WIFI_SHIELD_WPS_M2);
    assert(active(&table) == 1);
    f = fragment(4, 0, 0, NULL, 0);
    assert(wifi_shield_wps_observe(&table, &f, NULL, 0) == WIFI_SHIELD_WPS_UNKNOWN);
    /* Transport opcode by itself must not synthesize ACK/NACK/DONE. */
    for (uint8_t opcode = 1; opcode <= 6; ++opcode) {
        f.opcode = opcode;
        assert(wifi_shield_wps_observe(&table, &f, NULL, 0) == WIFI_SHIELD_WPS_UNKNOWN);
    }
}

static void test_large_values_and_short_mutated_inputs_are_bounded(void)
{
    wifi_shield_wps_table_t table = {0};
    uint8_t large[4096] = {0x10, 0x49, 0x0f, 0xf7}; /* 4087 unrelated bytes. */
    memset(large + 4, 0xa5, 4087);
    memcpy(large + 4091, m2, 5);
    wps_guard_fragment_t f = fragment(1, 3, 4096, large, 2048);
    assert(wifi_shield_wps_observe(&table, &f, large, 2048) == WIFI_SHIELD_WPS_UNKNOWN);
    f = fragment(2, 0, 0, large + 2048, 2048);
    assert(wifi_shield_wps_observe(&table, &f, large + 2048, 2048) == WIFI_SHIELD_WPS_M2);
    uint32_t random = UINT32_C(0x37f12821);
    uint8_t bytes[96];
    for (size_t iteration = 0; iteration < 20000; ++iteration) {
        const size_t length = iteration % (sizeof(bytes) + 1);
        uint8_t *p = bytes + sizeof(bytes) - length;
        for (size_t i = 0; i < length; ++i) {
            random = random * UINT32_C(1664525) + UINT32_C(1013904223);
            p[i] = (uint8_t)(random >> 24);
        }
        wifi_shield_wps_reset(&table);
        f = fragment(1, 0, 0, p, length);
        (void)wifi_shield_wps_observe(&table, &f, p, length);
        /* Declared streaming input may stop inside any random header/value. */
        wifi_shield_wps_reset(&table);
        f = fragment(1, 3, 128, p, length);
        (void)wifi_shield_wps_observe(&table, &f, p, length);
        f = fragment(2, 0, 0, p, length);
        (void)wifi_shield_wps_observe(&table, &f, p, length);
    }
}

int main(void)
{
    test_message_values_and_standalone_replay();
    test_every_split_and_bytewise_fragments();
    test_malformed_incomplete_and_duplicates();
    test_flow_key_and_interleaving();
    test_capacity_no_eviction_and_saturation();
    test_expiry_backwards_time_and_reset_wipe();
    test_invalid_envelope_and_sequence_fail_closed();
    test_payload_and_pointer_are_never_retained();
    test_next_message_reuses_identity_without_stale_classification();
    test_large_values_and_short_mutated_inputs_are_bounded();
    puts("wifi shield wps: PASS");
    return 0;
}
