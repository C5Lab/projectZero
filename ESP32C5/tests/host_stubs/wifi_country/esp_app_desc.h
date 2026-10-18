#ifndef JANOS_TEST_WIFI_COUNTRY_ESP_APP_DESC_H
#define JANOS_TEST_WIFI_COUNTRY_ESP_APP_DESC_H
#include <stdint.h>
typedef struct {
    uint8_t app_elf_sha256[32];
} esp_app_desc_t;
const esp_app_desc_t *esp_app_get_description(void);
#endif
