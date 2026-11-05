#include "janos_psram_storage.h"

#include <string.h>

static void secure_wipe(void *memory, size_t size)
{
    volatile unsigned char *bytes = memory;
    while (bytes != NULL && size-- != 0U) *bytes++ = 0U;
}

static void *destination_load(const janos_psram_request_t *request)
{
    void *memory = NULL;
    memcpy(&memory, request->destination, sizeof(memory));
    return memory;
}

static void destination_store(const janos_psram_request_t *request, void *memory)
{
    memcpy(request->destination, &memory, sizeof(memory));
}

void janos_psram_release_all(janos_psram_request_t *requests, size_t count,
                             janos_psram_free_fn release)
{
    if (requests == NULL || release == NULL) return;
    while (count != 0U) {
        --count;
        if (requests[count].destination == NULL) continue;
        void *memory = destination_load(&requests[count]);
        if (memory == NULL) continue;
        secure_wipe(memory, requests[count].size);
        release(memory);
        destination_store(&requests[count], NULL);
    }
}

bool janos_psram_allocate_all(janos_psram_request_t *requests, size_t count,
                              janos_psram_aligned_calloc_fn allocate,
                              janos_psram_free_fn release,
                              uint32_t capabilities)
{
    if (requests == NULL || count == 0U || allocate == NULL || release == NULL)
        return false;
    for (size_t index = 0U; index < count; ++index) {
        size_t alignment = requests[index].alignment;
        if (requests[index].destination == NULL || requests[index].size == 0U ||
            alignment < sizeof(void *) || (alignment & (alignment - 1U)) != 0U ||
            destination_load(&requests[index]) != NULL)
            return false;
    }
    for (size_t index = 0U; index < count; ++index) {
        void *memory = allocate(requests[index].alignment, 1U,
                                requests[index].size, capabilities);
        if (memory == NULL) {
            janos_psram_release_all(requests, index, release);
            return false;
        }
        destination_store(&requests[index], memory);
    }
    return true;
}
