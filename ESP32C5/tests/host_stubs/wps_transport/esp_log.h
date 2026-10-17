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
