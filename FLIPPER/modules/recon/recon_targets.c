#include "recon_targets.h"

#include <stdlib.h>
#include <string.h>

void c5_recon_targets_clear(C5ReconSavedTargets* saved) {
    if(!saved) return;
    free(saved->targets);
    saved->targets = NULL;
    saved->count = 0;
    saved->failed = false;
}

bool c5_recon_targets_replace(
    C5ReconSavedTargets* saved,
    const void* data,
    size_t data_size,
    C5ReconAllocFn allocate) {
    if(!saved) return false;
    c5_recon_targets_clear(saved);

    if(!data || data_size != sizeof(C5ReconTargetSession)) goto invalid;
    const C5ReconTargetSession* session = data;
    if(session->version != C5_RECON_TARGET_SESSION_VERSION ||
       session->size != sizeof(C5ReconTargetSession) ||
       session->selected_count > C5_RECON_SAFE_SELECTED_NETWORKS ||
       session->result_count > C5_RECON_SCAN_MAX_RESULTS ||
       session->selected_count > session->result_count ||
       (session->selected_count && !session->selected_numbers) ||
       (session->result_count && !session->results)) {
        goto invalid;
    }

    for(size_t i = 0; i < session->selected_count; i++) {
        uint16_t number = session->selected_numbers[i];
        if(!number) goto invalid;
        for(size_t previous = 0; previous < i; previous++) {
            if(session->selected_numbers[previous] == number) goto invalid;
        }
        const C5ReconScanResult* match = NULL;
        for(size_t j = 0; j < session->result_count; j++) {
            const C5ReconScanResult* candidate = &session->results[j];
            if(candidate->number != number) continue;
            if(match) goto invalid;
            match = candidate;
        }
        if(!match || !match->ssid[0] || !memchr(match->ssid, '\0', sizeof(match->ssid)))
            goto invalid;
    }

    if(!session->selected_count) return true;
    if(!allocate) goto invalid;
    C5ReconTarget* targets = allocate(session->selected_count * sizeof(*targets));
    if(!targets) goto invalid;

    for(size_t i = 0; i < session->selected_count; i++) {
        uint16_t number = session->selected_numbers[i];
        const C5ReconScanResult* match = NULL;
        for(size_t j = 0; j < session->result_count; j++) {
            if(session->results[j].number == number) {
                match = &session->results[j];
                break;
            }
        }
        C5ReconTarget* target = &targets[i];
        target->number = match->number;
        memcpy(target->ssid, match->ssid, sizeof(target->ssid));
        memcpy(target->bssid, match->bssid, sizeof(target->bssid));
        target->channel = match->channel;
    }
    saved->targets = targets;
    saved->count = session->selected_count;
    return true;

invalid:
    saved->failed = true;
    return false;
}
