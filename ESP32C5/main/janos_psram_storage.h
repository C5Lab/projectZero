#ifndef JANOS_PSRAM_STORAGE_H
#define JANOS_PSRAM_STORAGE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void *(*janos_psram_aligned_calloc_fn)(size_t alignment, size_t count,
                                               size_t size,
                                               uint32_t capabilities);
typedef void (*janos_psram_free_fn)(void *memory);

typedef struct {
    void *destination;
    size_t size;
    size_t alignment;
} janos_psram_request_t;

/* Allocates every request with the same explicit capability mask. After input
 * validation, an allocation failure wipes and releases earlier allocations and
 * leaves every destination NULL. Invalid input is rejected without mutation;
 * destinations must initially be NULL. */
bool janos_psram_allocate_all(janos_psram_request_t *requests, size_t count,
                              janos_psram_aligned_calloc_fn allocate,
                              janos_psram_free_fn release,
                              uint32_t capabilities);

/* Wipes allocations before releasing them and clears every destination. */
void janos_psram_release_all(janos_psram_request_t *requests, size_t count,
                             janos_psram_free_fn release);

#ifdef __cplusplus
}
#endif

#endif
