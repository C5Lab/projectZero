#include "../modules/recon/recon_targets.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void* deny_alloc(size_t bytes) {
    (void)bytes;
    return NULL;
}

static size_t allocation_calls;
static size_t allocation_bytes;

static void* count_alloc(size_t bytes) {
    allocation_calls++;
    allocation_bytes = bytes;
    return malloc(bytes);
}

static C5ReconScanResult result(uint16_t number, const char* ssid) {
    C5ReconScanResult result = {.number = number, .channel = 6};
    snprintf(result.ssid, sizeof(result.ssid), "%s", ssid);
    result.bssid[5] = (uint8_t)number;
    return result;
}

static void test_valid_snapshot_is_copied_before_module_can_free_it(void) {
    C5ReconSavedTargets saved = {0};
    C5ReconScanResult borrowed[] = {
        result(2, "Beta"), result(7, "Alpha"), result(3, "Unselected")};
    uint16_t selected[] = {7, 2};
    C5ReconTargetSession session = {
        .version = C5_RECON_TARGET_SESSION_VERSION,
        .size = sizeof(C5ReconTargetSession),
        .selected_count = 2,
        .selected_numbers = selected,
        .result_count = 3,
        .results = borrowed,
    };
    allocation_calls = 0;
    allocation_bytes = 0;
    assert(c5_recon_targets_replace(&saved, &session, sizeof(session), count_alloc));
    assert(saved.count == 2 && !saved.failed && saved.targets != NULL);
    assert(allocation_calls == 1 && allocation_bytes == 2 * sizeof(C5ReconTarget));
    selected[0] = 99;
    borrowed[1].number = 99;
    borrowed[1].ssid[0] = 'X';
    assert(saved.targets[0].number == 7);
    assert(strcmp(saved.targets[0].ssid, "Alpha") == 0);
    assert(saved.targets[1].number == 2 && saved.targets[1].bssid[5] == 2);
    c5_recon_targets_clear(&saved);
    assert(saved.targets == NULL && saved.count == 0 && !saved.failed);
}

static void test_invalid_or_failed_replacement_discards_old_targets(void) {
    C5ReconSavedTargets saved = {0};
    C5ReconScanResult borrowed[] = {result(1, "Old")};
    uint16_t selected[] = {1};
    C5ReconTargetSession session = {
        .version = C5_RECON_TARGET_SESSION_VERSION,
        .size = sizeof(C5ReconTargetSession),
        .selected_count = 1,
        .selected_numbers = selected,
        .result_count = 1,
        .results = borrowed,
    };
    assert(c5_recon_targets_replace(&saved, &session, sizeof(session), malloc));
    assert(!c5_recon_targets_replace(&saved, &session, sizeof(session), deny_alloc));
    assert(saved.targets == NULL && saved.count == 0 && saved.failed);

    assert(c5_recon_targets_replace(&saved, &session, sizeof(session), malloc));
    session.version++;
    assert(!c5_recon_targets_replace(&saved, &session, sizeof(session), malloc));
    assert(saved.targets == NULL && saved.count == 0 && saved.failed);
    session.version--;

    assert(c5_recon_targets_replace(&saved, &session, sizeof(session), malloc));
    assert(!c5_recon_targets_replace(&saved, &session, sizeof(session) - 1, malloc));
    assert(saved.targets == NULL && saved.count == 0 && saved.failed);
    c5_recon_targets_clear(&saved);
}

static void test_invalid_rows_do_not_enter_saved_selection(void) {
    C5ReconSavedTargets saved = {0};
    C5ReconScanResult borrowed[] = {result(1, "Good"), result(2, "Duplicate")};
    uint16_t selected[] = {1, 1};
    C5ReconTargetSession session = {
        .version = C5_RECON_TARGET_SESSION_VERSION,
        .size = sizeof(C5ReconTargetSession),
        .selected_count = 2,
        .selected_numbers = selected,
        .result_count = 2,
        .results = borrowed,
    };
    assert(!c5_recon_targets_replace(&saved, &session, sizeof(session), malloc));
    assert(saved.failed && saved.count == 0);
    selected[1] = 3;
    assert(!c5_recon_targets_replace(&saved, &session, sizeof(session), malloc));
    assert(saved.failed && saved.count == 0);
    selected[1] = 2;
    memset(borrowed[1].ssid, 'Q', sizeof(borrowed[1].ssid));
    assert(!c5_recon_targets_replace(&saved, &session, sizeof(session), malloc));
    assert(saved.failed && saved.count == 0);
    borrowed[1] = result(2, "Good");
    assert(c5_recon_targets_replace(&saved, &session, sizeof(session), malloc));
    assert(saved.count == 2);
    borrowed[1].number = 1;
    assert(!c5_recon_targets_replace(&saved, &session, sizeof(session), malloc));
    assert(saved.failed && saved.count == 0 && saved.targets == NULL);
    borrowed[1] = result(2, "Good");
    session.selected_count = C5_RECON_SCAN_MAX_RESULTS + 1;
    assert(!c5_recon_targets_replace(&saved, &session, sizeof(session), malloc));
    assert(saved.failed && saved.count == 0 && saved.targets == NULL);
    session.selected_count = 2;
    session.result_count = C5_RECON_SCAN_MAX_RESULTS + 1;
    assert(!c5_recon_targets_replace(&saved, &session, sizeof(session), malloc));
    assert(saved.failed && saved.count == 0 && saved.targets == NULL);
    session.result_count = 2;
    session.selected_numbers = NULL;
    assert(!c5_recon_targets_replace(&saved, &session, sizeof(session), malloc));
    assert(saved.failed && saved.count == 0 && saved.targets == NULL);
    c5_recon_targets_clear(&saved);
}

static void test_empty_snapshot_clears_prior_targets_without_error(void) {
    C5ReconSavedTargets saved = {0};
    C5ReconScanResult borrowed[] = {result(4, "Saved")};
    uint16_t selected[] = {4};
    C5ReconTargetSession session = {
        .version = C5_RECON_TARGET_SESSION_VERSION,
        .size = sizeof(C5ReconTargetSession),
        .selected_count = 1,
        .selected_numbers = selected,
        .result_count = 1,
        .results = borrowed,
    };
    assert(c5_recon_targets_replace(&saved, &session, sizeof(session), malloc));
    session.selected_count = 0;
    session.selected_numbers = NULL;
    allocation_calls = 0;
    assert(c5_recon_targets_replace(&saved, &session, sizeof(session), count_alloc));
    assert(saved.targets == NULL && saved.count == 0 && !saved.failed);
    assert(allocation_calls == 0);
}

static void test_unsafe_seventh_target_is_rejected(void) {
    C5ReconSavedTargets saved = {0};
    C5ReconScanResult borrowed[C5_RECON_SAFE_SELECTED_NETWORKS + 1];
    uint16_t selected[C5_RECON_SAFE_SELECTED_NETWORKS + 1];
    for(size_t i = 0; i < C5_RECON_SAFE_SELECTED_NETWORKS + 1; i++) {
        selected[i] = (uint16_t)(i + 1);
        borrowed[i] = result(selected[i], "AP");
    }
    C5ReconTargetSession session = {
        .version = C5_RECON_TARGET_SESSION_VERSION,
        .size = sizeof(C5ReconTargetSession),
        .selected_count = C5_RECON_SAFE_SELECTED_NETWORKS + 1,
        .selected_numbers = selected,
        .result_count = C5_RECON_SAFE_SELECTED_NETWORKS + 1,
        .results = borrowed,
    };
    assert(!c5_recon_targets_replace(&saved, &session, sizeof(session), malloc));
    assert(saved.failed && saved.targets == NULL && saved.count == 0);
}

int main(void) {
    test_valid_snapshot_is_copied_before_module_can_free_it();
    test_invalid_or_failed_replacement_discards_old_targets();
    test_invalid_rows_do_not_enter_saved_selection();
    test_empty_snapshot_clears_prior_targets_without_error();
    test_unsafe_seventh_target_is_rejected();
    puts("recon target handoff tests passed");
    return 0;
}
