#ifndef LAB_C5_NMAP_MODULE_H
#define LAB_C5_NMAP_MODULE_H

#include <stdint.h>

#define C5_NMAP_LAUNCH_VERSION 1u

/* Nmap discovers the current JanOS STA connection itself via list_hosts.
 * No host-side cached Wi-Fi state, network index, or password is borrowed. */
typedef struct {
    uint32_t version;
    uint32_t size;
    uint32_t ticks_per_second;
} C5NmapLaunchContext;

#endif
