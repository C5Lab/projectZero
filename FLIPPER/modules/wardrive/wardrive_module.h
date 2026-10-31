#ifndef LAB_C5_WARDRIVE_MODULE_H
#define LAB_C5_WARDRIVE_MODULE_H

#include <stdint.h>

#define C5_WARDRIVE_LAUNCH_VERSION 1u

typedef enum {
    C5WardriveModeLegacy = 0,
    C5WardriveModePromisc,
    C5WardriveModePromiscTrace,
} C5WardriveMode;

/* Borrowed for enter() only. ticks_per_second is furi_ms_to_ticks(1000). */
typedef struct {
    uint32_t version;
    uint32_t size;
    C5WardriveMode mode;
    uint32_t ticks_per_second;
} C5WardriveLaunchContext;

#endif
