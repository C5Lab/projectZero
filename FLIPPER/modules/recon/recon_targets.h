#ifndef LAB_C5_RECON_TARGETS_H
#define LAB_C5_RECON_TARGETS_H

#include "recon_scan.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define C5_RECON_TARGET_SESSION_VERSION 1u
/* JanOS cmd_select_networks builds an unchecked 500-byte summary. Six
 * 32-byte SSIDs plus BSSID/channel/auth text fit even at maximum length. */
#define C5_RECON_SAFE_SELECTED_NETWORKS 6u

/* Both arrays are borrowed only for the synchronous save_session callback. */
typedef struct {
    uint32_t version;
    uint32_t size;
    size_t selected_count;
    const uint16_t* selected_numbers;
    size_t result_count;
    const C5ReconScanResult* results;
} C5ReconTargetSession;

typedef struct {
    C5ReconTarget* targets;
    size_t count;
    bool failed;
} C5ReconSavedTargets;

typedef void* (*C5ReconAllocFn)(size_t bytes);

void c5_recon_targets_clear(C5ReconSavedTargets* saved);
bool c5_recon_targets_replace(
    C5ReconSavedTargets* saved,
    const void* data,
    size_t data_size,
    C5ReconAllocFn allocate);

#endif
