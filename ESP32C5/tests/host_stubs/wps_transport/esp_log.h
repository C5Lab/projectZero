#pragma once

typedef enum {
    ESP_LOG_NONE,
    ESP_LOG_ERROR,
    ESP_LOG_WARN,
    ESP_LOG_INFO,
    ESP_LOG_DEBUG,
    ESP_LOG_VERBOSE,
} esp_log_level_t;

static inline void esp_log_level_set(const char *tag, esp_log_level_t level)
{
    (void)tag;
    (void)level;
}

void test_esp_log_error(const char *tag, const char *format, ...);
#define ESP_LOGE(tag, ...) test_esp_log_error(tag, __VA_ARGS__)
