#pragma once

#ifndef OTA_DIAG_HOST_TEST
#include "esp_partition.h"
#endif

void ota_diag_print(const esp_partition_t *boot, const esp_partition_t *running,
                    const esp_partition_t *ota0, const esp_partition_t *ota1,
                    void (*emit)(const char *line));
