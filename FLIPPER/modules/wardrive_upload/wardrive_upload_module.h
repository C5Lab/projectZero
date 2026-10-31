#ifndef LAB_C5_WARDRIVE_UPLOAD_MODULE_H
#define LAB_C5_WARDRIVE_UPLOAD_MODULE_H

#include <stdbool.h>
#include <stdint.h>

#define C5_WARDRIVE_UPLOAD_LAUNCH_VERSION 1u

typedef enum {
    C5WardriveUploadWigle = 0,
    C5WardriveUploadWdgwars = 1,
} C5WardriveUploadProvider;

/* The host owns the firmware gate. Keep tls_verified false until the installed
 * JanOS build has passed certificate and hostname verification tests. */
typedef struct {
    uint32_t version;
    uint32_t size;
    C5WardriveUploadProvider provider;
    uint32_t ticks_per_second;
    bool tls_verified;
} C5WardriveUploadLaunchContext;

#endif
