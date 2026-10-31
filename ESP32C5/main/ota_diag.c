#include "ota_diag.h"

#include <inttypes.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#ifndef OTA_DIAG_HOST_TEST
#include "bootloader_common.h"
#include "esp_flash_partitions.h"
#include "esp_ota_ops.h"
#endif

typedef void (*ota_diag_emit_t)(const char *line);

static void emitf(ota_diag_emit_t emit, const char *format, ...)
{
    char line[512];
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    if (length < 0 || (size_t)length >= sizeof(line)) {
        emit("OTA_DIAG: unknown reason=line_format");
        return;
    }
    emit(line);
}

static const char *state_name(uint32_t state)
{
    switch (state) {
    case ESP_OTA_IMG_NEW: return "new";
    case ESP_OTA_IMG_PENDING_VERIFY: return "pending_verify";
    case ESP_OTA_IMG_VALID: return "valid";
    case ESP_OTA_IMG_INVALID: return "invalid";
    case ESP_OTA_IMG_ABORTED: return "aborted";
    case ESP_OTA_IMG_UNDEFINED: return "undefined";
    default: return NULL;
    }
}

static void print_state(const char *label, const esp_partition_t *partition,
                        ota_diag_emit_t emit)
{
    if (partition == NULL) {
        emitf(emit, "OTA_DIAG: state %s result=unknown value=unknown reason=partition_missing", label);
        return;
    }
    esp_ota_img_states_t value = ESP_OTA_IMG_UNDEFINED;
    esp_err_t result = esp_ota_get_state_partition(partition, &value);
    if (result == ESP_OK) {
        const char *name = state_name((uint32_t)value);
        if (name == NULL) {
            emitf(emit, "OTA_DIAG: state %s result=ok value=unknown(0x%08" PRIx32
                  ") reason=unrecognized_state", label, (uint32_t)value);
        } else {
            emitf(emit, "OTA_DIAG: state %s result=ok value=%s(0x%08" PRIx32 ")",
                  label, name, (uint32_t)value);
        }
    } else if (result == ESP_ERR_NOT_FOUND) {
        emitf(emit, "OTA_DIAG: state %s result=not_found value=unknown reason=ESP_ERR_NOT_FOUND",
              label);
    } else {
        emitf(emit, "OTA_DIAG: state %s result=error value=unknown err=0x%08" PRIx32
              " reason=state_api_error",
              label, (uint32_t)result);
    }
}

static void print_unknown_records(ota_diag_emit_t emit, const char *reason)
{
    emitf(emit, "OTA_DIAG: otadata=unknown reason=%s", reason);
    emitf(emit, "OTA_DIAG: record[0]=unknown reason=%s", reason);
    emitf(emit, "OTA_DIAG: record[1]=unknown reason=%s", reason);
    emitf(emit, "OTA_DIAG: selection=unknown reason=%s", reason);
}

static bool record_empty(const esp_ota_select_entry_t *record)
{
    const uint8_t *bytes = (const uint8_t *)record;
    for (size_t i = 0; i < sizeof(*record); ++i) {
        if (bytes[i] != UINT8_MAX) return false;
    }
    return true;
}

static void print_record(int index, const esp_ota_select_entry_t *record,
                         ota_diag_emit_t emit)
{
    const uint32_t calculated = bootloader_common_ota_select_crc(record);
    emitf(emit,
          "OTA_DIAG: record[%d] empty=%s seq=%" PRIu32
          " state=0x%08" PRIx32 " crc_stored=0x%08" PRIx32
          " crc_calc=0x%08" PRIx32 " crc_ok=%s selectable=%s",
          index, record_empty(record) ? "yes" : "no", record->ota_seq,
          (uint32_t)record->ota_state, record->crc, calculated,
          record->crc == calculated ? "yes" : "no",
          bootloader_common_ota_select_valid(record) ? "yes" : "no");
}

static void print_selection(esp_ota_select_entry_t records[2],
                            const esp_partition_t *boot, ota_diag_emit_t emit)
{
    const uint8_t app_count = esp_ota_get_app_partition_count();
    if (app_count == 0) {
        emit("OTA_DIAG: selection=unknown reason=no_ota_apps");
        return;
    }
    const int active = bootloader_common_get_active_otadata(records);
    if (active < 0) {
        const bool both_rejected = bootloader_common_ota_select_invalid(&records[0]) &&
                                   bootloader_common_ota_select_invalid(&records[1]);
        const char *reason = both_rejected ? "both_records_rejected" : "no_valid_record";
        if (boot == NULL) {
            emitf(emit, "OTA_DIAG: selection=none reason=%s boot=unknown boot_reason=boot_unavailable",
                  reason);
        } else {
            emitf(emit, "OTA_DIAG: selection=none reason=%s boot=%.16s", reason, boot->label);
        }
        return;
    }
    if (active > 1) {
        emit("OTA_DIAG: selection=unknown reason=active_index_out_of_range");
        return;
    }
    const esp_ota_select_entry_t *selected = &records[active];
    const bool seq_zero = selected->ota_seq == 0;
    const bool state_unrecognized = state_name(selected->ota_state) == NULL;
    const char *anomaly = seq_zero && state_unrecognized ?
        " anomaly=seq_zero,state_unrecognized" : seq_zero ? " anomaly=seq_zero" :
        state_unrecognized ? " anomaly=state_unrecognized" : "";
    /* Match ESP-IDF's unsigned wraparound for seq==0; flag it, but do not invent a different slot. */
    const uint32_t slot = (selected->ota_seq - 1U) % app_count;
    const esp_partition_t *target = esp_partition_find_first(
        ESP_PARTITION_TYPE_APP, ESP_PARTITION_SUBTYPE_APP_OTA_MIN + slot, NULL);
    if (target == NULL) {
        emitf(emit, "OTA_DIAG: selection=entry%d slot=ota_%" PRIu32
              " boot_match=unknown reason=slot_missing%s", active, slot, anomaly);
    } else if (boot == NULL) {
        emitf(emit, "OTA_DIAG: selection=entry%d slot=ota_%" PRIu32
              " boot_match=unknown reason=boot_missing%s", active, slot, anomaly);
    } else {
        const bool same = boot->flash_chip == target->flash_chip &&
                          boot->address == target->address && boot->size == target->size &&
                          boot->type == target->type && boot->subtype == target->subtype;
        emitf(emit, "OTA_DIAG: selection=entry%d slot=ota_%" PRIu32 " boot_match=%s%s",
              active, slot, same ? "yes" : "no", anomaly);
    }
}

void ota_diag_print(const esp_partition_t *boot, const esp_partition_t *running,
                    const esp_partition_t *ota0, const esp_partition_t *ota1,
                    void (*emit)(const char *line))
{
    if (emit == NULL) return;
    print_state("running", running, emit);
    print_state("ota_0", ota0, emit);
    print_state("ota_1", ota1, emit);

    const esp_partition_t *data = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_OTA, NULL);
    if (data == NULL) {
        print_unknown_records(emit, "partition_missing");
        return;
    }
    if (data->erase_size < sizeof(esp_ota_select_entry_t) ||
        data->size / data->erase_size < 2) {
        print_unknown_records(emit, "partition_geometry");
        return;
    }
    emitf(emit, "OTA_DIAG: otadata offset=0x%08" PRIx32 " size=0x%08" PRIx32
          " erase=0x%08" PRIx32, data->address, data->size, data->erase_size);

    esp_ota_select_entry_t records[2];
    bool readable[2];
    for (int i = 0; i < 2; ++i) {
        const size_t offset = i == 0 ? 0 : data->erase_size;
        const esp_err_t result = esp_partition_read(data, offset, &records[i], sizeof(records[i]));
        readable[i] = result == ESP_OK;
        if (readable[i]) {
            print_record(i, &records[i], emit);
        } else {
            emitf(emit, "OTA_DIAG: record[%d]=unknown reason=read_error err=0x%08" PRIx32,
                  i, (uint32_t)result);
        }
    }
    if (!readable[0] || !readable[1]) {
        emit("OTA_DIAG: selection=unknown reason=record_read_error");
        return;
    }
    print_selection(records, boot, emit);
}
