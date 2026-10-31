#ifndef LAB_C5_BEACON_MODULE_H
#define LAB_C5_BEACON_MODULE_H

#include <stdint.h>

#define C5_BEACON_LAUNCH_VERSION 1u

/* Beacon has no Recon target. The host supplies only its tick rate. */
typedef struct {
    uint32_t version;
    uint32_t size;
    uint32_t ticks_per_second;
} C5BeaconLaunchContext;

#endif
