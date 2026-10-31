#ifndef LAB_C5_CONNECT_MODULE_H
#define LAB_C5_CONNECT_MODULE_H

#include <stdint.h>

#define C5_CONNECT_LAUNCH_VERSION 1u

/* Borrowed for enter() only. ticks_per_second is furi_ms_to_ticks(1000). */
typedef struct {
    uint32_t version;
    uint32_t size;
    uint32_t ticks_per_second;
    char ssid[33];
} C5ConnectLaunchContext;

#endif
