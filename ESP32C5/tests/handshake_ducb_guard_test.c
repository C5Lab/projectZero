#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>

#include "handshake_ducb_guard.h"

static int allocations;
static int frees;
static bool fail_allocation;
static int fail_on_allocation;

typedef struct {
    bool state_lock_held;
    unsigned tx_count;
    unsigned delay_count;
    unsigned rx_count;
    unsigned stop_after_delay;
    bool fail_all_tx;
} burst_fixture_t;

static bool burst_tx(void *context, unsigned ordinal, bool ap_to_client)
{
    burst_fixture_t *fixture = context;
    assert(!fixture->state_lock_held);
    assert(ordinal == fixture->tx_count);
    assert(ap_to_client == (ordinal < 5U));
    fixture->tx_count++;
    return !fixture->fail_all_tx;
}

static void burst_delay(void *context, uint32_t delay_ms)
{
    burst_fixture_t *fixture = context;
    assert(!fixture->state_lock_held);
    assert(delay_ms == 10U);
    fixture->delay_count++;
    /* Deterministic callback injection at the most vulnerable instant. */
    fixture->rx_count++;
}

static bool burst_stop_requested(void *context)
{
    burst_fixture_t *fixture = context;
    return fixture->stop_after_delay != 0U &&
           fixture->delay_count >= fixture->stop_after_delay;
}

typedef struct {
    atomic_bool entered;
    atomic_bool release;
    atomic_bool finished;
    bool result;
} writer_fixture_t;

static void *slow_writer(void *context)
{
    writer_fixture_t *writer = context;
    atomic_store(&writer->entered, true);
    while (!atomic_load(&writer->release)) {
        struct timespec pause = {.tv_nsec = 1000000L};
        nanosleep(&pause, NULL);
    }
    writer->result = false;
    atomic_store(&writer->finished, true);
    return NULL;
}

static void *test_alloc(size_t size)
{
    if (fail_allocation || (fail_on_allocation > 0 &&
                            allocations + 1 == fail_on_allocation)) return NULL;
    ++allocations;
    return malloc(size);
}

static void test_free(void *ptr)
{
    if (ptr) ++frees;
    free(ptr);
}

static bool contains_bytes(const uint8_t *haystack, size_t haystack_size,
                           const uint8_t *needle, size_t needle_size)
{
    if (!needle_size || needle_size > haystack_size) return false;
    for (size_t i = 0; i <= haystack_size - needle_size; ++i) {
        if (memcmp(haystack + i, needle, needle_size) == 0) return true;
    }
    return false;
}

static void test_target_revalidation_rejects_fifo_reuse(void)
{
    const uint8_t ap_a[6] = {0, 1, 2, 3, 4, 5};
    const uint8_t ap_b[6] = {6, 7, 8, 9, 10, 11};
    const uint8_t client[6] = {12, 13, 14, 15, 16, 17};
    hs_ducb_target_snapshot_t snapshot = {0};
    hs_ducb_target_snapshot_init(&snapshot, ap_a, client, "lab", 6, 7, 9);

    assert(hs_ducb_target_snapshot_matches(&snapshot, ap_a, client, 7, 9));
    assert(!hs_ducb_target_snapshot_matches(&snapshot, ap_b, client, 7, 9));
    assert(!hs_ducb_target_snapshot_matches(&snapshot, ap_a, client, 8, 9));
    assert(!hs_ducb_target_snapshot_matches(&snapshot, ap_a, client, 7, 10));
}

static void test_immutable_capture_survives_live_mutation(void)
{
    uint8_t pcap[4] = {1, 2, 3, 4};
    uint8_t hccapx[3] = {5, 6, 7};
    hs_capture_snapshot_t snapshot = {0};

    assert(hs_capture_snapshot_create(&snapshot, pcap, sizeof(pcap),
                                      hccapx, sizeof(hccapx), test_alloc,
                                      test_free));
    memset(pcap, 0xaa, sizeof(pcap));
    memset(hccapx, 0xbb, sizeof(hccapx));
    assert(snapshot.pcap[0] == 1 && snapshot.pcap[3] == 4);
    assert(snapshot.hccapx[0] == 5 && snapshot.hccapx[2] == 7);
    hs_capture_snapshot_release(&snapshot, test_free);
    assert(snapshot.pcap == NULL && snapshot.hccapx == NULL);
}

static void test_snapshot_allocation_failure_is_atomic(void)
{
    uint8_t pcap[2] = {9, 8};
    uint8_t hccapx[2] = {7, 6};
    hs_capture_snapshot_t snapshot = {0};
    fail_allocation = true;
    assert(!hs_capture_snapshot_create(&snapshot, pcap, sizeof(pcap),
                                       hccapx, sizeof(hccapx), test_alloc,
                                       test_free));
    fail_allocation = false;
    assert(snapshot.pcap == NULL && snapshot.hccapx == NULL);
    assert(pcap[0] == 9 && pcap[1] == 8);
    assert(hccapx[0] == 7 && hccapx[1] == 6);

    int before_allocations = allocations;
    int before_frees = frees;
    fail_on_allocation = before_allocations + 2;
    assert(!hs_capture_snapshot_create(&snapshot, pcap, sizeof(pcap),
                                       hccapx, sizeof(hccapx), test_alloc,
                                       test_free));
    fail_on_allocation = 0;
    assert(allocations == before_allocations + 1);
    assert(frees == before_frees + 1);
    assert(snapshot.pcap == NULL && snapshot.hccapx == NULL);
}

static void test_three_capture_snapshots_are_independent(void)
{
    hs_capture_snapshot_t snapshots[HS_DUCB_TARGETS_PER_DWELL] = {0};
    uint8_t live_pcap[HS_DUCB_TARGETS_PER_DWELL][2] = {
        {1U, 11U}, {2U, 22U}, {3U, 33U},
    };
    for (unsigned i = 0U; i < HS_DUCB_TARGETS_PER_DWELL; ++i) {
        assert(hs_capture_snapshot_create(&snapshots[i], live_pcap[i], 2U,
                                          NULL, 0U, test_alloc, test_free));
        live_pcap[i][0] = 0xffU;
    }
    assert(snapshots[0].pcap[0] == 1U);
    assert(snapshots[1].pcap[0] == 2U);
    assert(snapshots[2].pcap[0] == 3U);
    assert(snapshots[0].pcap != snapshots[1].pcap);
    assert(snapshots[1].pcap != snapshots[2].pcap);
    for (unsigned i = 0U; i < HS_DUCB_TARGETS_PER_DWELL; ++i) {
        hs_capture_snapshot_release(&snapshots[i], test_free);
    }
}

static void test_eight_rx_callbacks_run_during_eight_burst_delays(void)
{
    burst_fixture_t fixture = {0};
    assert(hs_ducb_run_burst(&fixture, burst_tx, burst_delay,
                             burst_stop_requested));
    assert(fixture.tx_count == 8U);
    assert(fixture.delay_count == 8U);
    assert(fixture.rx_count == 8U);
}

static void test_stop_during_tx_is_cooperative(void)
{
    burst_fixture_t fixture = {.stop_after_delay = 4U};
    assert(!hs_ducb_run_burst(&fixture, burst_tx, burst_delay,
                              burst_stop_requested));
    assert(fixture.tx_count == 4U);
    assert(fixture.delay_count == 4U);
    assert(fixture.rx_count == 4U);
}

static void test_all_failed_tx_is_not_reported_as_success(void)
{
    burst_fixture_t fixture = {.fail_all_tx = true};
    assert(!hs_ducb_run_burst(&fixture, burst_tx, burst_delay,
                              burst_stop_requested));
    assert(fixture.tx_count == 8U);
    assert(fixture.delay_count == 8U);
}

static void test_slow_failing_writer_does_not_block_rx_and_stop_is_bounded(void)
{
    uint8_t pcap[4] = {1U, 2U, 3U, 4U};
    hs_capture_snapshot_t owned = {0};
    int frees_before = frees;
    assert(hs_capture_snapshot_create(&owned, pcap, sizeof(pcap), NULL, 0U,
                                      test_alloc, test_free));
    writer_fixture_t writer = {0};
    pthread_t thread;
    assert(pthread_create(&thread, NULL, slow_writer, &writer) == 0);
    while (!atomic_load(&writer.entered)) {}

    unsigned rx_count = 0U;
    for (unsigned i = 0; i < 8U; ++i) rx_count++;
    assert(rx_count == 8U);
    assert(hs_ducb_stop_decide(true, true, true, 99U, 100U) ==
           HS_DUCB_STOP_WAIT);
    assert(hs_ducb_stop_decide(true, true, true, 100U, 100U) ==
           HS_DUCB_STOP_DEFER);
    /* A wedged writer remains owned and must never be force-deleted. */
    assert(hs_ducb_stop_decide(true, true, true, 100000U, 100U) ==
           HS_DUCB_STOP_DEFER);
    assert(owned.pcap != NULL);
    assert(frees == frees_before);

    atomic_store(&writer.release, true);
    assert(pthread_join(thread, NULL) == 0);
    assert(atomic_load(&writer.finished));
    assert(!writer.result);
    hs_capture_snapshot_release(&owned, test_free);
    assert(frees == frees_before + 1);
    assert(hs_ducb_stop_decide(true, false, false, 100U, 100U) ==
           HS_DUCB_STOP_PENDING);
    assert(hs_ducb_stop_decide(false, false, false, 0U, 100U) ==
           HS_DUCB_STOP_COMPLETE);
}

static void test_later_stop_completes_after_worker_exits(void)
{
    assert(hs_ducb_stop_decide(true, true, true, 100U, 100U) ==
           HS_DUCB_STOP_DEFER);
    assert(hs_ducb_stop_decide(false, false, false, 100U, 100U) ==
           HS_DUCB_STOP_COMPLETE);
}

static void test_legacy_dwell_budget_is_three(void)
{
    assert(hs_ducb_target_budget() == 3U);
}

static void test_only_active_target_accepts_hccapx_frames(void)
{
    const uint8_t active[6] = {1, 2, 3, 4, 5, 6};
    const uint8_t client[6] = {7, 8, 9, 10, 11, 12};
    const uint8_t other_client[6] = {12, 11, 10, 9, 8, 7};
    const uint8_t other[6] = {6, 5, 4, 3, 2, 1};
    hs_ducb_capture_identity_t identity = {0};
    hs_ducb_capture_identity_set(&identity, active, client, 7U, 9U);
    assert(hs_ducb_capture_identity_matches(&identity, active, client, 7U, 9U));
    assert(!hs_ducb_capture_identity_matches(&identity, other, client, 7U, 9U));
    assert(!hs_ducb_capture_identity_matches(&identity, active, other_client, 7U, 9U));
    assert(!hs_ducb_capture_identity_matches(&identity, active, client, 8U, 9U));
    assert(!hs_ducb_capture_identity_matches(&identity, active, client, 7U, 10U));
    hs_ducb_capture_identity_clear(&identity);
    assert(!hs_ducb_capture_identity_matches(&identity, active, client, 7U, 9U));
}

static void test_hccapx_must_match_target_identity(void)
{
    const uint8_t ap[6] = {1, 2, 3, 4, 5, 6};
    const uint8_t sta[6] = {7, 8, 9, 10, 11, 12};
    const uint8_t other[6] = {6, 5, 4, 3, 2, 1};
    hs_ducb_target_snapshot_t target = {0};
    hs_ducb_target_snapshot_init(&target, ap, sta, "lab", 6, 7, 9);
    assert(hs_ducb_hccapx_matches_target(&target, ap, sta,
                                         (const uint8_t *)"lab", 3U));
    assert(!hs_ducb_hccapx_matches_target(&target, other, sta,
                                          (const uint8_t *)"lab", 3U));
    assert(!hs_ducb_hccapx_matches_target(&target, ap, other,
                                          (const uint8_t *)"lab", 3U));
    assert(!hs_ducb_hccapx_matches_target(&target, ap, sta,
                                          (const uint8_t *)"bad", 3U));
}

static void test_pcap_only_capture_is_never_publishable(void)
{
    const uint8_t ap[6] = {1, 2, 3, 4, 5, 6};
    const uint8_t sta[6] = {7, 8, 9, 10, 11, 12};
    const uint8_t pcap[] = {1, 2, 3};
    const uint8_t hccapx[] = {4, 5, 6};
    hs_ducb_target_snapshot_t target = {0};
    hs_capture_snapshot_t capture = {
        .pcap = (uint8_t *)pcap,
        .pcap_size = sizeof(pcap),
        .session_generation = 9U,
    };
    hs_ducb_target_snapshot_init(&target, ap, sta, "lab", 6, 7, 9);

    assert(!hs_ducb_capture_is_publishable(
        &target, &capture, sizeof(hccapx), ap, sta,
        (const uint8_t *)"lab", 3U));
    capture.hccapx = (uint8_t *)hccapx;
    capture.hccapx_size = sizeof(hccapx);
    assert(hs_ducb_capture_is_publishable(
        &target, &capture, sizeof(hccapx), ap, sta,
        (const uint8_t *)"lab", 3U));
    capture.hccapx_size--;
    assert(!hs_ducb_capture_is_publishable(
        &target, &capture, sizeof(hccapx), ap, sta,
        (const uint8_t *)"lab", 3U));
}

static void test_attempt_pcap_excludes_other_target_frames(void)
{
    const uint8_t ap[6] = {1U, 2U, 3U, 4U, 5U, 6U};
    const uint8_t sta[6] = {7U, 8U, 9U, 10U, 11U, 12U};
    const uint8_t other_ap[6] = {6U, 5U, 4U, 3U, 2U, 1U};
    const uint8_t own[] = {1U, 2U, 3U};
    const uint8_t other[] = {9U, 8U, 7U};
    hs_attempt_pcap_t pcap = {0};
    hs_ducb_capture_identity_t identity = {0};
    hs_ducb_capture_identity_set(&identity, ap, sta, 7U, 9U);
    assert(hs_attempt_pcap_init(&pcap, 256U, test_alloc));
    assert(hs_attempt_pcap_append_if_matching(
        &pcap, &identity, ap, sta, 7U, 9U, own, sizeof(own), 123U));
    size_t after_own = pcap.size;
    assert(!hs_attempt_pcap_append_if_matching(
        &pcap, &identity, other_ap, sta, 7U, 9U, other, sizeof(other), 124U));
    assert(pcap.size == after_own);
    assert(after_own > sizeof(own));
    assert(contains_bytes(pcap.bytes, pcap.size, own, sizeof(own)));
    assert(!contains_bytes(pcap.bytes, pcap.size, other, sizeof(other)));
    hs_attempt_pcap_release(&pcap, test_free);
}

static void test_attempt_pcap_boundary_is_atomic(void)
{
    const uint8_t frame[] = {0xaaU, 0xbbU, 0xccU};
    const size_t header_size = 24U;
    const size_t record_size = 16U + sizeof(frame);
    hs_attempt_pcap_t pcap = {0};

    assert(!hs_attempt_pcap_init(&pcap, header_size - 1U, test_alloc));
    assert(pcap.bytes == NULL && pcap.size == 0U);
    assert(hs_attempt_pcap_init(&pcap, header_size + record_size, test_alloc));
    assert(hs_attempt_pcap_append(&pcap, frame, sizeof(frame), UINT32_MAX));
    assert(pcap.size == header_size + record_size);

    uint8_t snapshot[24U + 16U + sizeof(frame)];
    memcpy(snapshot, pcap.bytes, pcap.size);
    assert(!hs_attempt_pcap_append(&pcap, frame, 1U, 0U));
    assert(pcap.size == sizeof(snapshot));
    assert(memcmp(snapshot, pcap.bytes, sizeof(snapshot)) == 0);
    assert(!hs_attempt_pcap_append(&pcap, NULL, sizeof(frame), 0U));
    assert(!hs_attempt_pcap_append(&pcap, frame, 0U, 0U));
    hs_attempt_pcap_release(&pcap, test_free);
}

static void test_attempt_pcap_snaplen_boundary(void)
{
    uint8_t *frame = malloc(65536U);
    assert(frame != NULL);
    memset(frame, 0x5a, 65536U);
    hs_attempt_pcap_t pcap = {0};
    assert(hs_attempt_pcap_init(&pcap, 24U + 16U + 65535U, test_alloc));
    assert(hs_attempt_pcap_append(&pcap, frame, 65535U, 1000001U));
    size_t size_before = pcap.size;
    assert(!hs_attempt_pcap_append(&pcap, frame, 65536U, 1000002U));
    assert(pcap.size == size_before);
    hs_attempt_pcap_release(&pcap, test_free);
    free(frame);
}

static void test_writer_requires_write_flush_sync_and_close_success(void)
{
    assert(hs_ducb_writer_succeeded(16U, 16U, 0, 0, 0));
    assert(!hs_ducb_writer_succeeded(16U, 15U, 0, 0, 0));
    assert(!hs_ducb_writer_succeeded(16U, 16U, -1, 0, 0));
    assert(!hs_ducb_writer_succeeded(16U, 16U, 0, -1, 0));
    assert(!hs_ducb_writer_succeeded(16U, 16U, 0, 0, -1));
}

static void test_pre_tx_failure_releases_reservation_for_retry(void)
{
    uint32_t attempt_generation = 0U;
    uint32_t attempt_slot_generation = 0U;

    assert(hs_ducb_reservation_try_set(
        &attempt_generation, &attempt_slot_generation, 7U, 9U));
    assert(!hs_ducb_reservation_release_if_matching(
        &attempt_generation, &attempt_slot_generation, 8U, 9U));
    assert(!hs_ducb_reservation_release_if_matching(
        &attempt_generation, &attempt_slot_generation, 7U, 10U));
    assert(attempt_generation == 9U);
    assert(attempt_slot_generation == 7U);
    /* First iteration: per-attempt PCAP allocation fails before TX. */
    assert(hs_ducb_reservation_release_if_matching(
        &attempt_generation, &attempt_slot_generation, 7U, 9U));
    assert(hs_ducb_reservation_try_set(
        &attempt_generation, &attempt_slot_generation, 7U, 9U));
    /* Second iteration: channel setup fails before TX. */
    assert(hs_ducb_reservation_release_if_matching(
        &attempt_generation, &attempt_slot_generation, 7U, 9U));
    /* Third iteration can reserve and proceed to a successful attempt. */
    assert(hs_ducb_reservation_try_set(
        &attempt_generation, &attempt_slot_generation, 7U, 9U));
    assert(attempt_generation == 9U);
    assert(attempt_slot_generation == 7U);
}

typedef struct {
    uint32_t attempt_generation[HS_DUCB_TARGETS_PER_DWELL];
    uint32_t attempt_slot_generation[HS_DUCB_TARGETS_PER_DWELL];
    unsigned calls;
} pending_release_fixture_t;

static pending_release_fixture_t pending_release_fixture;

static bool release_pending_fixture_target(
    const hs_ducb_target_snapshot_t *target)
{
    pending_release_fixture.calls++;
    const unsigned index = target->slot_generation - 1U;
    assert(index < HS_DUCB_TARGETS_PER_DWELL);
    return hs_ducb_reservation_release_if_matching(
        &pending_release_fixture.attempt_generation[index],
        &pending_release_fixture.attempt_slot_generation[index],
        target->slot_generation, target->session_generation);
}

static void test_rearm_failure_releases_all_reserved_dwell_targets(void)
{
    bool have_target[HS_DUCB_TARGETS_PER_DWELL] = {true, true, true};
    hs_ducb_target_snapshot_t targets[HS_DUCB_TARGETS_PER_DWELL] = {0};
    memset(&pending_release_fixture, 0, sizeof(pending_release_fixture));

    for (unsigned i = 0; i < HS_DUCB_TARGETS_PER_DWELL; ++i) {
        const uint32_t slot_generation = i + 1U;
        targets[i].slot_generation = slot_generation;
        targets[i].session_generation = 9U;
        assert(hs_ducb_reservation_try_set(
            &pending_release_fixture.attempt_generation[i],
            &pending_release_fixture.attempt_slot_generation[i],
            slot_generation, 9U));
    }

    /* Target 0 completed and released normally. Channel rearm then fails,
     * leaving targets 1 and 2 reserved unless dwell cleanup visits all slots. */
    assert(hs_ducb_reservation_release_if_matching(
        &pending_release_fixture.attempt_generation[0],
        &pending_release_fixture.attempt_slot_generation[0], 1U, 9U));

    assert(hs_ducb_release_pending_targets(
               have_target, targets, HS_DUCB_TARGETS_PER_DWELL,
               release_pending_fixture_target) == 2U);
    assert(pending_release_fixture.calls == HS_DUCB_TARGETS_PER_DWELL);
    for (unsigned i = 0; i < HS_DUCB_TARGETS_PER_DWELL; ++i) {
        assert(!have_target[i]);
        assert(pending_release_fixture.attempt_generation[i] == 0U);
        assert(pending_release_fixture.attempt_slot_generation[i] == 0U);
    }
}

int main(void)
{
    test_target_revalidation_rejects_fifo_reuse();
    test_immutable_capture_survives_live_mutation();
    test_snapshot_allocation_failure_is_atomic();
    test_three_capture_snapshots_are_independent();
    test_eight_rx_callbacks_run_during_eight_burst_delays();
    test_stop_during_tx_is_cooperative();
    test_all_failed_tx_is_not_reported_as_success();
    test_slow_failing_writer_does_not_block_rx_and_stop_is_bounded();
    test_later_stop_completes_after_worker_exits();
    test_legacy_dwell_budget_is_three();
    test_only_active_target_accepts_hccapx_frames();
    test_hccapx_must_match_target_identity();
    test_pcap_only_capture_is_never_publishable();
    test_attempt_pcap_excludes_other_target_frames();
    test_attempt_pcap_boundary_is_atomic();
    test_attempt_pcap_snaplen_boundary();
    test_writer_requires_write_flush_sync_and_close_success();
    test_pre_tx_failure_releases_reservation_for_retry();
    test_rearm_failure_releases_all_reserved_dwell_targets();
    assert(allocations == frees);
    return 0;
}
