#ifndef JANOS_TEST_ESP_LOG_H
#define JANOS_TEST_ESP_LOG_H

#include "esp_event.h"
#include <stdio.h>

#define ESP_LOG_VERBOSE 5
#define ESP_LOG_DEBUG 4
#define JANOS_TEST_LOG(tag, ...) do { \
    (void)(tag); \
    if (0) printf(__VA_ARGS__); \
} while (0)
#define ESP_LOGV(tag, ...) JANOS_TEST_LOG(tag, __VA_ARGS__)
#define ESP_LOGD(tag, ...) JANOS_TEST_LOG(tag, __VA_ARGS__)
#define ESP_LOGI(tag, ...) JANOS_TEST_LOG(tag, __VA_ARGS__)
#define ESP_LOGW(tag, ...) JANOS_TEST_LOG(tag, __VA_ARGS__)
#define ESP_LOGE(tag, ...) JANOS_TEST_LOG(tag, __VA_ARGS__)

#endif
