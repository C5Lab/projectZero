#ifndef LAB_C5_ARP_MODULE_H
#define LAB_C5_ARP_MODULE_H

#include <stdbool.h>
#include <stdint.h>

#define C5_ARP_LAUNCH_VERSION 1u

/* selected_number is 1-based for Recon. Zero with saved_only and empty SSID
 * opens the ARP FAL's own saved-credential list. No password crosses this API. */
typedef struct {
    uint32_t version;
    uint32_t size;
    uint16_t selected_number;
    char ssid[33];
    bool saved_only;
} C5ArpLaunchContext;

#endif
