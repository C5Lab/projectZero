/* Execute the real OTA diagnostic module against an in-memory flash boundary. */
#define OTA_DIAG_HOST_TEST 1

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int esp_err_t;
#define ESP_OK 0
#define ESP_FAIL (-1)
#define ESP_ERR_NOT_FOUND 0x105
#define ESP_PARTITION_TYPE_APP 0
#define ESP_PARTITION_TYPE_DATA 1
#define ESP_PARTITION_SUBTYPE_DATA_OTA 0
#define ESP_PARTITION_SUBTYPE_APP_OTA_MIN 0x10
#define ESP_PARTITION_SUBTYPE_APP_OTA_0 0x10
#define ESP_PARTITION_SUBTYPE_APP_OTA_1 0x11
#define ESP_OTA_IMG_NEW 0U
#define ESP_OTA_IMG_PENDING_VERIFY 1U
#define ESP_OTA_IMG_VALID 2U
#define ESP_OTA_IMG_INVALID 3U
#define ESP_OTA_IMG_ABORTED 4U
#define ESP_OTA_IMG_UNDEFINED 0xFFFFFFFFU

typedef uint32_t esp_ota_img_states_t;
typedef struct esp_partition_t {
    void *flash_chip;
    int type;
    int subtype;
    uint32_t address;
    uint32_t size;
    uint32_t erase_size;
    char label[17];
    bool encrypted;
    bool readonly;
} esp_partition_t;
typedef struct {
    uint32_t ota_seq;
    uint8_t seq_label[20];
    uint32_t ota_state;
    uint32_t crc;
} esp_ota_select_entry_t;

_Static_assert(ESP_OTA_IMG_UNDEFINED == UINT32_MAX, "IDF undefined state changed");
_Static_assert(sizeof(esp_ota_select_entry_t) == 32, "IDF otadata record changed");

static int internal_chip;
static int external_chip;
static esp_partition_t data = {.flash_chip = &internal_chip, .type = ESP_PARTITION_TYPE_DATA,
                               .subtype = ESP_PARTITION_SUBTYPE_DATA_OTA, .address = 0x17000,
                               .size = 0x2000, .erase_size = 0x1000, .label = "otadata"};
static esp_partition_t app0 = {.flash_chip = &internal_chip, .type = ESP_PARTITION_TYPE_APP,
                               .subtype = ESP_PARTITION_SUBTYPE_APP_OTA_0, .address = 0x20000,
                               .size = 0x3f0000, .erase_size = 0x1000, .label = "ota_0"};
static esp_partition_t app1 = {.flash_chip = &internal_chip, .type = ESP_PARTITION_TYPE_APP,
                               .subtype = ESP_PARTITION_SUBTYPE_APP_OTA_1, .address = 0x410000,
                               .size = 0x3f0000, .erase_size = 0x1000, .label = "ota_1"};
static esp_ota_select_entry_t records[2];
static bool data_missing;
static int read_failure_index = -1;
static int ota_app_count = 2;
static esp_err_t state_result[2] = {ESP_ERR_NOT_FOUND, ESP_ERR_NOT_FOUND};
static esp_ota_img_states_t state_value[2];
static int emitted_lines;

static uint32_t bootloader_common_ota_select_crc(const esp_ota_select_entry_t *entry)
{
    /* IDF esp_rom_crc32_le(UINT32_MAX, &entry->ota_seq, 4). */
    uint32_t crc = 0;
    const uint8_t *bytes = (const uint8_t *)&entry->ota_seq;
    for (size_t byte = 0; byte < 4; ++byte) {
        crc ^= bytes[byte];
        for (unsigned bit = 0; bit < 8; ++bit) {
            crc = (crc >> 1) ^ ((crc & 1U) ? 0xedb88320U : 0U);
        }
    }
    return ~crc;
}

static bool bootloader_common_ota_select_invalid(const esp_ota_select_entry_t *entry)
{
    return entry->ota_seq == UINT32_MAX || entry->ota_state == ESP_OTA_IMG_INVALID ||
           entry->ota_state == ESP_OTA_IMG_ABORTED;
}

static bool bootloader_common_ota_select_valid(const esp_ota_select_entry_t *entry)
{
    return !bootloader_common_ota_select_invalid(entry) &&
           entry->crc == bootloader_common_ota_select_crc(entry);
}

static int bootloader_common_get_active_otadata(esp_ota_select_entry_t *entries)
{
    const bool first = bootloader_common_ota_select_valid(&entries[0]);
    const bool second = bootloader_common_ota_select_valid(&entries[1]);
    if (first && second) return entries[0].ota_seq >= entries[1].ota_seq ? 0 : 1;
    if (first) return 0;
    if (second) return 1;
    return -1;
}

static const esp_partition_t *esp_partition_find_first(int type, int subtype, const char *label)
{
    (void)label;
    if (type == ESP_PARTITION_TYPE_DATA && subtype == ESP_PARTITION_SUBTYPE_DATA_OTA) {
        return data_missing ? NULL : &data;
    }
    if (type == ESP_PARTITION_TYPE_APP && subtype == ESP_PARTITION_SUBTYPE_APP_OTA_0) {
        return ota_app_count > 0 ? &app0 : NULL;
    }
    if (type == ESP_PARTITION_TYPE_APP && subtype == ESP_PARTITION_SUBTYPE_APP_OTA_1) {
        return ota_app_count > 1 ? &app1 : NULL;
    }
    return NULL;
}

static esp_err_t esp_partition_read(const esp_partition_t *partition, size_t offset,
                                    void *destination, size_t size)
{
    if (partition != &data || size != sizeof(records[0])) return ESP_FAIL;
    const int index = offset == 0 ? 0 : offset == data.erase_size ? 1 : -1;
    if (index < 0 || index == read_failure_index) return ESP_FAIL;
    memcpy(destination, &records[index], size);
    return ESP_OK;
}

static esp_err_t esp_ota_get_state_partition(const esp_partition_t *partition,
                                              esp_ota_img_states_t *value)
{
    if (partition != &app0 && partition != &app1) return ESP_ERR_NOT_FOUND;
    const int index = partition == &app0 ? 0 : 1;
    if (state_result[index] == ESP_OK) *value = state_value[index];
    return state_result[index];
}

static uint8_t esp_ota_get_app_partition_count(void)
{
    return (uint8_t)ota_app_count;
}

#include "../main/ota_diag.c"

static void emit(const char *line)
{
    if (strncmp(line, "OTA_DIAG: ", 10) != 0 || strlen(line) > 511) abort();
    puts(line);
    emitted_lines++;
}

static void set_record(int index, uint32_t seq, uint32_t state)
{
    records[index].ota_seq = seq;
    records[index].ota_state = state;
    records[index].crc = bootloader_common_ota_select_crc(&records[index]);
}

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    /* Keep strict compilation useful while the production function is still a stub. */
    (void)esp_partition_find_first;
    (void)esp_partition_read;
    (void)esp_ota_get_state_partition;
    (void)esp_ota_get_app_partition_count;
    (void)bootloader_common_get_active_otadata;
    memset(records, 0xff, sizeof(records));
    const esp_partition_t *boot = &app0;
    const char *scenario = argv[1];
    if (strcmp(scenario, "empty_rf") == 0) {
    } else if (strcmp(scenario, "boot_unavailable") == 0) {
        boot = NULL;
    } else if (strcmp(scenario, "empty_classic") == 0) {
        data.address = 0xf000;
    } else if (strcmp(scenario, "bad_crc") == 0) {
        set_record(0, 1, ESP_OTA_IMG_UNDEFINED);
        records[0].crc ^= 1U;
    } else if (strcmp(scenario, "one_good_one_bad") == 0) {
        set_record(0, 1, ESP_OTA_IMG_VALID);
        set_record(1, 2, ESP_OTA_IMG_VALID);
        records[1].crc ^= 1U;
    } else if (strcmp(scenario, "two_good") == 0) {
        set_record(0, 1, ESP_OTA_IMG_VALID);
        set_record(1, 2, ESP_OTA_IMG_VALID);
        boot = &app1;
    } else if (strcmp(scenario, "tie") == 0) {
        set_record(0, 1, ESP_OTA_IMG_VALID);
        set_record(1, 1, ESP_OTA_IMG_VALID);
    } else if (strcmp(scenario, "invalid_aborted") == 0) {
        set_record(0, 1, ESP_OTA_IMG_INVALID);
        set_record(1, 2, ESP_OTA_IMG_ABORTED);
    } else if (strcmp(scenario, "missing_partition") == 0) {
        data_missing = true;
    } else if (strcmp(scenario, "short_partition") == 0) {
        data.size = 0x1000;
    } else if (strcmp(scenario, "read_error") == 0) {
        set_record(0, 1, ESP_OTA_IMG_VALID);
        set_record(1, 2, ESP_OTA_IMG_VALID);
        read_failure_index = 1;
    } else if (strcmp(scenario, "state_undefined") == 0) {
        set_record(0, 1, ESP_OTA_IMG_UNDEFINED);
        state_result[0] = ESP_OK;
        state_value[0] = ESP_OTA_IMG_UNDEFINED;
    } else if (strcmp(scenario, "state_not_found") == 0) {
        set_record(0, 1, ESP_OTA_IMG_VALID);
    } else if (strcmp(scenario, "state_error") == 0) {
        set_record(0, 1, ESP_OTA_IMG_VALID);
        state_result[0] = ESP_FAIL;
    } else if (strcmp(scenario, "state_unrecognized") == 0) {
        set_record(0, 1, 0x12345678U);
        state_result[0] = ESP_OK;
        state_value[0] = 0x12345678U;
    } else if (strcmp(scenario, "seq_zero") == 0) {
        set_record(0, 0, ESP_OTA_IMG_VALID);
    } else if (strcmp(scenario, "boot_mismatch") == 0) {
        set_record(0, 1, ESP_OTA_IMG_VALID);
        set_record(1, 2, ESP_OTA_IMG_VALID);
    } else if (strcmp(scenario, "boot_external_chip") == 0) {
        set_record(0, 1, ESP_OTA_IMG_VALID);
        static esp_partition_t external_boot;
        external_boot = app0;
        external_boot.flash_chip = &external_chip;
        boot = &external_boot;
    } else if (strcmp(scenario, "no_apps") == 0) {
        set_record(0, 1, ESP_OTA_IMG_VALID);
        ota_app_count = 0;
    } else {
        return 2;
    }
    if (bootloader_common_ota_select_crc(&(esp_ota_select_entry_t){.ota_seq = 1}) != 0x4743989aU) abort();
    ota_diag_print(boot, &app0, &app0, &app1, emit);
    return emitted_lines == 7 ? 0 : 3;
}
