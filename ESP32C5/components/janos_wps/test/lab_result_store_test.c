#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lab_result_store.h"

#ifdef _WIN32
#include <direct.h>
#define MAKE_DIR(path) _mkdir(path)
#else
#include <sys/stat.h>
#define MAKE_DIR(path) mkdir(path, 0700)
#endif

static void read_text(const char *path, char *output, size_t capacity)
{
    FILE *file = fopen(path, "rb");
    assert(file != NULL);
    size_t count = fread(output, 1, capacity - 1U, file);
    assert(!ferror(file));
    output[count] = '\0';
    assert(fclose(file) == 0);
}

int main(int argc, char **argv)
{
    assert(argc == 2);
    const char *root = argv[1];
    (void)MAKE_DIR(root);

    lab_result_record_t result = {
        .bssid = {0x68, 0xff, 0x7b, 0xcd, 0xfc, 0x40},
        .ssid = "Lab \"AP\"",
        .pin = "12345670",
        .network_key = (const uint8_t *)"key\\value",
        .network_key_len = 9,
        .recovery_source = "pixie_mode_4",
        .manufacturer = "TP-Link",
        .model_name = "TL-WR840N",
        .model_number = "V6",
        .device_name = "Lab Router",
        .operation_id = 17,
        .authenticated_m7 = true,
    };
    assert(lab_result_store_success(root, &result) == LAB_STORE_OK);

    char path[512];
    assert(snprintf(path, sizeof(path),
                    "%s/results/wps_68-ff-7b-cd-fc-40.json", root) > 0);
    char text[2048];
    read_text(path, text, sizeof(text));
    assert(strstr(text, "\"schema\":1") != NULL);
    assert(strstr(text, "\"authenticated_m7\":true") != NULL);
    assert(strstr(text, "\"ssid\":\"Lab \\\"AP\\\"\"") != NULL);
    assert(strstr(text, "\"pin\":\"12345670\"") != NULL);
    assert(strstr(text, "\"network_key\":\"key\\\\value\"") != NULL);
    assert(strstr(text, "\"manufacturer\":\"TP-Link\"") != NULL);

    result.authenticated_m7 = false;
    assert(lab_result_store_success(root, &result) == LAB_STORE_INVALID);

    lab_device_observation_t observation = {
        .bssid = {0x78, 0x44, 0x76, 0xf1, 0xb0, 0x88},
        .ssid = "Pure Rental Apartments",
        .stage = "adapter_open",
        .reason = "timeout",
        .manufacturer = "Realtek",
        .model_name = "RTL8xxx",
        .device_name = "TOTOLINK",
    };
    assert(lab_result_store_observation(root, &observation) == LAB_STORE_OK);
    assert(lab_result_store_observation(root, &observation) == LAB_STORE_DUPLICATE);
    assert(snprintf(path, sizeof(path), "%s/unknown_devices.jsonl", root) > 0);
    read_text(path, text, sizeof(text));
    assert(strstr(text, "\"oui\":\"78:44:76\"") != NULL);
    assert(strstr(text, "\"ssid\":\"Pure Rental Apartments\"") != NULL);
    assert(strstr(text, "\"manufacturer\":\"Realtek\"") != NULL);
    assert(strstr(text, "12345670") == NULL);
    assert(strstr(text, "key\\\\value") == NULL);
    assert(strchr(text, '\n') != NULL);

    puts("PASS: WPS lab result store");
    return 0;
}
