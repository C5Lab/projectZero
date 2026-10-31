#ifndef LAB_C5_RECON_MODULE_H
#define LAB_C5_RECON_MODULE_H

#include <stddef.h>
#include <stdint.h>

#define C5_RECON_LAUNCH_VERSION 1u

typedef enum {
    C5ReconModeScanner = 0,
    C5ReconModeSnifferStart,
    C5ReconModeSnifferResume,
    C5ReconModeSnifferResults,
    C5ReconModeProbeResults,
} C5ReconMode;

typedef enum {
    C5ReconFieldSsid = 1u << 0,
    C5ReconFieldBssid = 1u << 1,
    C5ReconFieldChannel = 1u << 2,
    C5ReconFieldSecurity = 1u << 3,
    C5ReconFieldPower = 1u << 4,
    C5ReconFieldBand = 1u << 5,
    C5ReconFieldVendor = 1u << 6,
    C5ReconFieldAll = 0x7fu,
} C5ReconField;

/* Borrowed for enter() only. The FAL copies selected numbers before return. */
typedef struct {
    uint32_t version;
    uint32_t size;
    C5ReconMode mode;
    int16_t min_power_dbm;
    uint16_t field_mask;
    size_t selected_count;
    const uint16_t* selected_numbers;
} C5ReconLaunchContext;

#endif
