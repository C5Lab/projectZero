/* Execute the production cmd_ota_info and OTA diagnostic against fake IDF I/O.
 * The Python test generates the production includes from current source.
 */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int esp_err_t;
typedef uint32_t esp_ota_img_states_t;
typedef struct {
    int type;
    int subtype;
    uint32_t address;
    uint32_t size;
    uint32_t erase_size;
    char label[17];
    bool encrypted;
    bool readonly;
    void *flash_chip;
} esp_partition_t;
typedef struct { char version[32]; } esp_app_desc_t;

#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_ERR_NOT_FOUND 0x105
#define ESP_PARTITION_TYPE_APP 0
#define ESP_PARTITION_TYPE_DATA 1
#define ESP_PARTITION_SUBTYPE_APP_OTA_0 16
#define ESP_PARTITION_SUBTYPE_APP_OTA_1 17
#define ESP_PARTITION_SUBTYPE_APP_OTA_MIN 16
#define ESP_PARTITION_SUBTYPE_DATA_OTA 0
#define ESP_PARTITION_SUBTYPE_DATA_NVS 2
#define ESP_PARTITION_SUBTYPE_DATA_PHY 1
#define ESP_OTA_IMG_UNDEFINED 0xFFFFFFFFU
#define ESP_OTA_IMG_NEW 0U
#define ESP_OTA_IMG_PENDING_VERIFY 1U
#define ESP_OTA_IMG_VALID 2U
#define ESP_OTA_IMG_INVALID 3U
#define ESP_OTA_IMG_ABORTED 4U
#define TAG "test"
#include "ota_definitions_production.inc"
#define OTA_DIAG_HOST_TEST 1

typedef struct {
    uint32_t ota_seq;
    uint8_t seq_label[20];
    uint32_t ota_state;
    uint32_t crc;
} esp_ota_select_entry_t;
_Static_assert(sizeof(esp_ota_select_entry_t) == 32, "IDF otadata record changed");
_Static_assert(ESP_OTA_IMG_UNDEFINED == UINT32_MAX, "IDF undefined state changed");

static char ota_channel[8] = "main";
static int fake_flash;
static void *esp_flash_default_chip = &fake_flash;
static esp_partition_t nvs = {
    .type = ESP_PARTITION_TYPE_DATA, .subtype = ESP_PARTITION_SUBTYPE_DATA_NVS,
    .address = TEST_RF_PROFILE ? 0x11000 : 0x9000,
    .size = 0x6000, .erase_size = 0x1000,
    .label = "nvs", .flash_chip = &fake_flash,
};
static esp_partition_t ota0 = {
    .type = ESP_PARTITION_TYPE_APP, .subtype = ESP_PARTITION_SUBTYPE_APP_OTA_0,
    .address = 0x20000, .size = 0x3f0000, .erase_size = 0x1000,
    .label = "ota_0", .flash_chip = &fake_flash,
};
static esp_partition_t ota1 = {
    .type = ESP_PARTITION_TYPE_APP, .subtype = ESP_PARTITION_SUBTYPE_APP_OTA_1,
    .address = 0x410000, .size = 0x3f0000, .erase_size = 0x1000,
    .label = "ota_1", .flash_chip = &fake_flash,
};
static esp_partition_t otadata = {
    .type = ESP_PARTITION_TYPE_DATA, .subtype = ESP_PARTITION_SUBTYPE_DATA_OTA,
    .address = TEST_RF_PROFILE ? 0x17000 : 0xf000, .size = 0x2000,
    .erase_size = 0x1000,
    .label = "otadata", .flash_chip = &fake_flash,
};
static esp_partition_t phy_init = {
    .type = ESP_PARTITION_TYPE_DATA, .subtype = ESP_PARTITION_SUBTYPE_DATA_PHY,
    .address = TEST_RF_PROFILE ? 0x19000 : 0x11000,
    .size = 0x1000, .erase_size = 0x1000,
    .label = "phy_init", .flash_chip = &fake_flash,
};
static esp_partition_t secrets = {
    .type = ESP_PARTITION_TYPE_DATA, .subtype = 0x40,
    .address = 0x1a000, .size = 0x4000, .erase_size = 0x1000,
    .label = "secrets", .flash_chip = &fake_flash,
};
static bool not_found;
static int write_calls;

#ifdef TEST_TAB5_PARSER
#include "ota_rf.h"
static ota_info_report_t tab5_report;
static int tab5_diag_consumed;
#endif

static void test_log(const char *fmt, ...)
{
    char line[2048];
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(line, sizeof(line), fmt, args);
    va_end(args);
    if (len < 0 || (size_t)len >= sizeof(line)) abort();
    puts(line);
#ifdef TEST_TAB5_PARSER
    bool consumed = ota_info_report_feed_line(&tab5_report, line);
    if (strncmp(line, "OTA_DIAG:", 9) == 0 && consumed) tab5_diag_consumed++;
#endif
}
#define MY_LOG_INFO(tag, ...) test_log(__VA_ARGS__)

const esp_partition_t *esp_partition_find_first(int type, int subtype, const char *label)
{
    const esp_partition_t *parts[] = {&nvs, &otadata, &phy_init, &secrets, &ota0, &ota1};
    for (size_t i = 0; i < sizeof(parts) / sizeof(parts[0]); ++i) {
        const esp_partition_t *part = parts[i];
        if (part->type == type && part->subtype == subtype &&
            (!label || strcmp(label, part->label) == 0)) return part;
    }
    return NULL;
}

const esp_partition_t *esp_ota_get_boot_partition(void) { return &ota0; }
const esp_partition_t *esp_ota_get_running_partition(void) { return &ota0; }
const esp_partition_t *esp_ota_get_next_update_partition(const esp_partition_t *from)
{
    (void)from;
    return &ota1;
}

esp_err_t esp_ota_get_state_partition(const esp_partition_t *part, esp_ota_img_states_t *state)
{
    assert(part == &ota0 || part == &ota1);
    if (not_found) return ESP_ERR_NOT_FOUND;
    *state = ESP_OTA_IMG_UNDEFINED;
    return ESP_OK;
}

esp_err_t esp_ota_get_partition_description(const esp_partition_t *part, esp_app_desc_t *desc)
{
    assert(part == &ota0 || part == &ota1);
    memcpy(desc->version, "1.7.7", sizeof("1.7.7"));
    return ESP_OK;
}

esp_err_t esp_partition_read(const esp_partition_t *part, size_t offset, void *dst, size_t len)
{
    assert(part == &otadata && offset <= part->size && len <= part->size - offset);
    memset(dst, 0xff, len);
    return ESP_OK;
}

static uint32_t bootloader_common_ota_select_crc(const esp_ota_select_entry_t *entry)
{
    uint32_t crc = 0;
    const uint8_t *bytes = (const uint8_t *)&entry->ota_seq;
    for (size_t byte = 0; byte < 4; ++byte) {
        crc ^= bytes[byte];
        for (unsigned bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ ((crc & 1U) ? 0xedb88320U : 0U);
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

static uint8_t esp_ota_get_app_partition_count(void) { return 2; }

const char *esp_err_to_name(esp_err_t err)
{
    return err == ESP_ERR_NOT_FOUND ? "ESP_ERR_NOT_FOUND" : "ESP_FAIL";
}

/* Any write reached from ota_info is a failed read-only contract. */
esp_err_t esp_partition_write(const esp_partition_t *part, size_t offset, const void *data, size_t len)
{
    (void)part; (void)offset; (void)data; (void)len;
    write_calls++;
    abort();
}
esp_err_t esp_partition_erase_range(const esp_partition_t *part, size_t offset, size_t len)
{
    (void)part; (void)offset; (void)len;
    write_calls++;
    abort();
}
esp_err_t esp_ota_set_boot_partition(const esp_partition_t *part)
{
    (void)part;
    write_calls++;
    abort();
}
esp_err_t esp_ota_mark_app_valid_cancel_rollback(void)
{
    write_calls++;
    abort();
}

#include "ota_diag_production.inc"
#include "ota_rf_layout_production.inc"
#include "ota_info_production.inc"

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    if (strcmp(argv[1], "not_found") == 0) not_found = true;
    else if (strcmp(argv[1], "ok_undefined") != 0) return 2;
#ifdef TEST_TAB5_PARSER
    ota_info_report_reset(&tab5_report);
#endif
    int result = cmd_ota_info(1, argv);
#ifdef TEST_TAB5_PARSER
    fprintf(stderr, "TAB5_DEFAULT=%d\nTAB5_RF=%d\nTAB5_OFFSET=%lu\nTAB5_LAYOUT=%d\n"
            "TAB5_BOOT=%s\nTAB5_RUNNING=%s\nTAB5_STATE=%d\nTAB5_NEXT=%s\n"
            "TAB5_APP0=%s\nTAB5_APP0_STATE=%d\nTAB5_APP1=%s\nTAB5_APP1_STATE=%d\n"
            "TAB5_DIAG_CONSUMED=%d\n",
            tab5_report.has_default_source, tab5_report.has_rf_source,
            (unsigned long)tab5_report.table_offset, (int)tab5_report.layout,
            tab5_report.boot, tab5_report.running, tab5_report.running_state,
            tab5_report.next, tab5_report.slots[0].ver, tab5_report.slots[0].state,
            tab5_report.slots[1].ver, tab5_report.slots[1].state, tab5_diag_consumed);
#endif
    if (write_calls != 0) return 3;
    return result;
}
