#ifndef LAB_C5_WPASEC_MODULE_H
#define LAB_C5_WPASEC_MODULE_H

#include <stdbool.h>
#include <stdint.h>

#define C5_WPASEC_LAUNCH_VERSION 1u

/* A verified firmware TLS gate must be supplied by the host; false blocks TX. */
typedef struct {
    uint32_t version;
    uint32_t size;
    uint32_t ticks_per_second;
    bool tls_verified;
} C5WpasecLaunchContext;

#endif
