#pragma once
/* Deterministic scheduler for the recorder tests: the worker runs when pumped
 * or when stop waits on its completion semaphore. Queues retain FIFO order. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define pdTRUE 1
#define pdFALSE 0
#define pdPASS 1
#define portMAX_DELAY UINT32_MAX
#define MALLOC_CAP_SPIRAM 1
#define MALLOC_CAP_8BIT 2
typedef int BaseType_t;
typedef struct { void **items; unsigned size, start, count; } *QueueHandle_t;
typedef struct { bool value, completion; } *SemaphoreHandle_t;
static void (*scheduled_worker)(void *);
static unsigned semaphore_creations;
static bool fail_allocation;

static inline void *heap_caps_calloc(size_t n, size_t size, unsigned caps)
{ (void)caps; return fail_allocation ? NULL : calloc(n, size); }
static inline void heap_caps_free(void *p) { free(p); }
static inline int64_t esp_timer_get_time(void) { return 123456; }
static inline QueueHandle_t xQueueCreate(unsigned count, size_t size)
{
    assert(size == sizeof(void *));
    QueueHandle_t q = calloc(1, sizeof(*q));
    q->items = calloc(count, size); q->size = count;
    return q;
}
static inline int xQueueSend(QueueHandle_t q, const void *p, uint32_t wait)
{
    (void)wait;
    if (q->count == q->size) return pdFALSE;
    memcpy(&q->items[(q->start + q->count++) % q->size], p, sizeof(void *));
    return pdTRUE;
}
static inline int xQueueReceive(QueueHandle_t q, void *p, uint32_t wait)
{
    (void)wait;
    if (!q->count) return pdFALSE;
    memcpy(p, &q->items[q->start], sizeof(void *));
    q->start = (q->start + 1) % q->size; --q->count;
    return pdTRUE;
}
static inline void vQueueDelete(QueueHandle_t q) { free(q->items); free(q); }
static inline SemaphoreHandle_t xSemaphoreCreateMutex(void)
{
    SemaphoreHandle_t s = calloc(1, sizeof(*s));
    s->value = true; ++semaphore_creations; return s;
}
static inline SemaphoreHandle_t xSemaphoreCreateBinary(void)
{
    SemaphoreHandle_t s = calloc(1, sizeof(*s));
    s->completion = true; return s;
}
static inline int xSemaphoreTake(SemaphoreHandle_t s, uint32_t wait)
{
    if (!s->value && wait && s->completion) scheduled_worker(NULL);
    if (!s->value) return pdFALSE;
    s->value = false; return pdTRUE;
}
static inline int xSemaphoreGive(SemaphoreHandle_t s) { s->value = true; return pdTRUE; }
static inline void vSemaphoreDelete(SemaphoreHandle_t s) { free(s); }
static inline int xTaskCreate(void (*fn)(void *), const char *name,
                              unsigned stack, void *arg, unsigned priority, void *handle)
{
    (void)name; (void)stack; (void)arg; (void)priority; (void)handle;
    scheduled_worker = fn; return pdPASS;
}
static inline void vTaskDelete(void *handle) { (void)handle; }
#define ESP_LOGW(tag, ...) do { (void)(tag); if (0) printf(__VA_ARGS__); } while (0)
#define ESP_LOGI(tag, ...) ESP_LOGW(tag, __VA_ARGS__)
