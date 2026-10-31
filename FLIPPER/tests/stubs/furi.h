#pragma once

#include <stdint.h>

typedef struct FuriMutex FuriMutex;

typedef enum {
    FuriMutexTypeNormal,
    FuriMutexTypeRecursive,
} FuriMutexType;

#define FuriWaitForever UINT32_MAX

FuriMutex* furi_mutex_alloc(FuriMutexType type);
void furi_mutex_free(FuriMutex* mutex);
int furi_mutex_acquire(FuriMutex* mutex, uint32_t timeout);
int furi_mutex_release(FuriMutex* mutex);
