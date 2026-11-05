#include "router_fingerprint.h"

#include <stdint.h>
#include <string.h>

typedef struct {
    bool present;
    bool conflict;
    char selected[ROUTER_EVIDENCE_TEXT_MAX + 1U];
} router_value_set_t;

static bool bounded_length(const char *text, size_t *length)
{
    size_t index;

    if (text == NULL || length == NULL) return false;
    for (index = 0U; index <= ROUTER_EVIDENCE_TEXT_MAX; ++index) {
        if (text[index] == '\0') {
            *length = index;
            return true;
        }
    }
    return false;
}

static size_t utf8_sequence_length(const uint8_t *bytes, size_t remaining)
{
    const uint8_t first = bytes[0];

    if (first < 0x80U) return 1U;
    if (first >= 0xC2U && first <= 0xDFU) {
        if (remaining >= 2U && bytes[1] >= 0x80U && bytes[1] <= 0xBFU) return 2U;
        return 0U;
    }
    if (first >= 0xE0U && first <= 0xEFU) {
        if (remaining < 3U || bytes[2] < 0x80U || bytes[2] > 0xBFU) return 0U;
        if (first == 0xE0U) {
            return bytes[1] >= 0xA0U && bytes[1] <= 0xBFU ? 3U : 0U;
        }
        if (first == 0xEDU) {
            return bytes[1] >= 0x80U && bytes[1] <= 0x9FU ? 3U : 0U;
        }
        return bytes[1] >= 0x80U && bytes[1] <= 0xBFU ? 3U : 0U;
    }
    if (first >= 0xF0U && first <= 0xF4U) {
        if (remaining < 4U ||
            bytes[2] < 0x80U || bytes[2] > 0xBFU ||
            bytes[3] < 0x80U || bytes[3] > 0xBFU) {
            return 0U;
        }
        if (first == 0xF0U) {
            return bytes[1] >= 0x90U && bytes[1] <= 0xBFU ? 4U : 0U;
        }
        if (first == 0xF4U) {
            return bytes[1] >= 0x80U && bytes[1] <= 0x8FU ? 4U : 0U;
        }
        return bytes[1] >= 0x80U && bytes[1] <= 0xBFU ? 4U : 0U;
    }
    return 0U;
}

static bool ascii_alphanumeric(uint8_t byte)
{
    return (byte >= (uint8_t)'0' && byte <= (uint8_t)'9') ||
           (byte >= (uint8_t)'A' && byte <= (uint8_t)'Z') ||
           (byte >= (uint8_t)'a' && byte <= (uint8_t)'z');
}

static bool canonicalize(const char *input,
                         char output[ROUTER_EVIDENCE_TEXT_MAX + 1U])
{
    size_t input_length;
    size_t read_index = 0U;
    size_t write_index = 0U;
    bool separator_pending = false;

    if (!bounded_length(input, &input_length)) return false;
    while (read_index < input_length) {
        const uint8_t *bytes = (const uint8_t *)&input[read_index];
        size_t sequence_length = utf8_sequence_length(bytes, input_length - read_index);

        if (sequence_length == 0U) return false;
        if (sequence_length == 1U && !ascii_alphanumeric(bytes[0])) {
            if (write_index > 0U) separator_pending = true;
            ++read_index;
            continue;
        }
        if (separator_pending) {
            output[write_index++] = ' ';
            separator_pending = false;
        }
        if (sequence_length == 1U && bytes[0] >= (uint8_t)'A' && bytes[0] <= (uint8_t)'Z') {
            output[write_index++] = (char)(bytes[0] + ((uint8_t)'a' - (uint8_t)'A'));
        } else {
            memcpy(&output[write_index], bytes, sequence_length);
            write_index += sequence_length;
        }
        read_index += sequence_length;
    }
    output[write_index] = '\0';
    return true;
}

static void add_value(router_value_set_t *set, const char *value)
{
    int comparison;

    if (value[0] == '\0') return;
    if (!set->present) {
        memcpy(set->selected, value, strlen(value) + 1U);
        set->present = true;
        return;
    }
    comparison = strcmp(value, set->selected);
    if (comparison == 0) return;
    set->conflict = true;
    if (comparison < 0) memcpy(set->selected, value, strlen(value) + 1U);
}

static bool copy_bounded_utf8(char *destination, size_t maximum, const char *source)
{
    size_t source_length = strlen(source);
    size_t read_index = 0U;
    size_t write_index = 0U;

    while (read_index < source_length) {
        size_t sequence_length = utf8_sequence_length(
            (const uint8_t *)&source[read_index], source_length - read_index);
        if (sequence_length == 0U || write_index + sequence_length > maximum) break;
        memcpy(&destination[write_index], &source[read_index], sequence_length);
        write_index += sequence_length;
        read_index += sequence_length;
    }
    while (write_index > 0U && destination[write_index - 1U] == ' ') --write_index;
    destination[write_index] = '\0';
    return read_index != source_length;
}

bool router_fingerprint_normalize(const router_evidence_t *items,
                                  size_t count,
                                  router_fingerprint_t *out)
{
    router_fingerprint_t result;
    router_value_set_t vendors;
    router_value_set_t models;
    router_value_set_t firmware;
    bool complete_structured = false;
    bool weak_model = false;
    size_t index;

    if (out == NULL || count > ROUTER_EVIDENCE_MAX || (count > 0U && items == NULL)) {
        return false;
    }
    memset(&result, 0, sizeof(result));
    memset(&vendors, 0, sizeof(vendors));
    memset(&models, 0, sizeof(models));
    memset(&firmware, 0, sizeof(firmware));

    for (index = 0U; index < count; ++index) {
        char vendor[ROUTER_EVIDENCE_TEXT_MAX + 1U];
        char model[ROUTER_EVIDENCE_TEXT_MAX + 1U];
        char version[ROUTER_EVIDENCE_TEXT_MAX + 1U];
        const router_evidence_t *item = &items[index];

        if (item->source < ROUTER_EVIDENCE_OUI ||
            item->source >= ROUTER_EVIDENCE_SOURCE_COUNT ||
            (item->locally_administered_mac && item->source != ROUTER_EVIDENCE_OUI) ||
            !canonicalize(item->vendor, vendor) ||
            !canonicalize(item->model, model) ||
            !canonicalize(item->firmware, version)) {
            return false;
        }

        if (item->source == ROUTER_EVIDENCE_OUI) {
            if (!item->locally_administered_mac) add_value(&vendors, vendor);
            continue;
        }
        if (item->source == ROUTER_EVIDENCE_UPNP_STRUCTURED) {
            add_value(&vendors, vendor);
            add_value(&models, model);
            add_value(&firmware, version);
            if (model[0] != '\0' && version[0] != '\0') {
                complete_structured = true;
            }
        } else {
            if (item->source == ROUTER_EVIDENCE_DHCP ||
                item->source == ROUTER_EVIDENCE_HTTP_TITLE) {
                add_value(&vendors, vendor);
            }
            add_value(&models, model);
            if (model[0] != '\0') weak_model = true;
        }
    }

    if (vendors.present) {
        result.truncated |= copy_bounded_utf8(result.vendor, ROUTER_VENDOR_MAX,
                                              vendors.selected);
    }
    if (models.present) {
        result.truncated |= copy_bounded_utf8(result.model, ROUTER_MODEL_MAX,
                                              models.selected);
    }
    if (firmware.present) {
        result.truncated |= copy_bounded_utf8(result.firmware, ROUTER_FIRMWARE_MAX,
                                              firmware.selected);
    }
    result.conflict = vendors.conflict || models.conflict || firmware.conflict;
    if (!result.conflict && !result.truncated && complete_structured &&
        vendors.present && models.present && firmware.present) {
        result.confidence = ROUTER_CONFIDENCE_CONFIRMED;
    } else if (!result.conflict && weak_model) {
        result.confidence = ROUTER_CONFIDENCE_PROBABLE;
    } else {
        result.confidence = ROUTER_CONFIDENCE_UNKNOWN;
    }

    *out = result;
    return true;
}
