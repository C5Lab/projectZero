#ifndef LAB_C5_MITM_PCAP_MODULE_H
#define LAB_C5_MITM_PCAP_MODULE_H

#include <stdint.h>

#define C5_MITM_PCAP_LAUNCH_VERSION 1u

/* Borrowed only by enter(); no secret crosses the launch boundary. */
typedef struct {
    uint32_t version;
    uint32_t size;
    uint16_t selected_number;
    char ssid[33];
    char bssid[18];
    uint32_t ticks_per_second;
} C5MitmPcapLaunchContext;

#endif
