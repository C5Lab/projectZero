/* Minimal US/PA fixtures; also test against the installed IDF tables when available. */
#include "esp_wifi.h"

#ifndef TEST_PA_EXTENDED
#define TEST_PA_EXTENDED 0
#endif

const wifi_regdomain_t regdomain_table[WIFI_MAX_SUPPORT_COUNTRY_NUM] = {
    {{'U', 'S'}, 0}, {{'P', 'A'}, 1},
};
const wifi_regulatory_t regulatory_data[] = {
    {6, {{1, 11, 2, 30, 0, 0}, {36, 48, 3, 23, 0, 0},
         {52, 64, 3, 24, 1, 0}, {100, 144, 4, 24, 1, 0},
         {149, 169, 3, 27, 0, 0}, {173, 177, 2, 27, 0, 0}}},
    {5, {{1, 13, 2, 36, 0, 0}, {36, 48, 3, 36, 0, 0},
         {52, 64, 3, 30, 0, 0},
#if TEST_PA_EXTENDED
         {100, 144, 4, 30, 0, 0}, {149, 177, 3, 36, 0, 0}}},
#else
         {100, 140, 4, 30, 0, 0}, {149, 165, 3, 36, 0, 0}}},
#endif
};
