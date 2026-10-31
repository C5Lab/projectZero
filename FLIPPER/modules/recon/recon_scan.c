#include "recon_scan.h"

#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FIELD_CAPACITY 48u
#define MIN_POWER (-110)
#define MAX_POWER 0

static void release_arrays(C5ReconScan* scan) {
    free(scan->results);
    free(scan->selected_numbers);
    free(scan->visible_indices);
    scan->results = NULL;
    scan->selected_numbers = NULL;
    scan->visible_indices = NULL;
    scan->capacity = 0;
}

static bool allocate_arrays(C5ReconScan* scan, size_t count) {
    if(!scan || !count || count > C5_RECON_SCAN_MAX_RESULTS) return false;
    release_arrays(scan);
    scan->results = calloc(count, sizeof(*scan->results));
    scan->selected_numbers = calloc(count, sizeof(*scan->selected_numbers));
    scan->visible_indices = calloc(count, sizeof(*scan->visible_indices));
    if(!scan->results || !scan->selected_numbers || !scan->visible_indices) {
        release_arrays(scan);
        return false;
    }
    scan->capacity = count;
    return true;
}

static int16_t clamp_power(int32_t power) {
    if(power < MIN_POWER) return MIN_POWER;
    if(power > MAX_POWER) return MAX_POWER;
    return (int16_t)power;
}

void c5_recon_scan_init(C5ReconScan* scan, int16_t min_power_dbm) {
    if(!scan) return;
    memset(scan, 0, sizeof(*scan));
    scan->min_power_dbm = clamp_power(min_power_dbm);
    scan->best_rssi = MIN_POWER;
}

void c5_recon_scan_deinit(C5ReconScan* scan) {
    if(!scan) return;
    release_arrays(scan);
    memset(scan, 0, sizeof(*scan));
}

bool c5_recon_scan_begin(C5ReconScan* scan) {
    if(!scan) return false;
    int16_t min_power = scan->min_power_dbm;
    c5_recon_scan_deinit(scan);
    c5_recon_scan_init(scan, min_power);
    if(!allocate_arrays(scan, C5_RECON_SCAN_MAX_RESULTS)) return false;
    scan->loading = true;
    return true;
}

static size_t parse_count(const char* line) {
    const char* found = strstr(line, "Found ");
    const char* retrieved = strstr(line, "Retrieved ");
    const char* begin = found ? found + sizeof("Found ") - 1 :
                        retrieved ? retrieved + sizeof("Retrieved ") - 1 : NULL;
    if(!begin) return 0;
    char* end = NULL;
    unsigned long count = strtoul(begin, &end, 10);
    if(end == begin || !count) return 0;
    if(found && !strstr(end, "networks")) return 0;
    if(retrieved && !strstr(end, "network records")) return 0;
    return count > C5_RECON_SCAN_MAX_RESULTS ? C5_RECON_SCAN_MAX_RESULTS : (size_t)count;
}

static bool retrieved_zero_records(const char* line) {
    const char* begin = strstr(line, "Retrieved ");
    if(!begin) return false;
    begin += sizeof("Retrieved ") - 1;
    if(!isdigit((unsigned char)*begin)) return false;
    char* end = NULL;
    unsigned long count = strtoul(begin, &end, 10);
    if(end == begin || count != 0) return false;
    const char records[] = " network records";
    if(strncmp(end, records, sizeof(records) - 1) != 0) return false;
    const char* suffix = end + sizeof(records) - 1;
    return *suffix == '\0' || strncmp(suffix, " in ", 4) == 0;
}

static const char* after_field(const char* end, size_t index) {
    while(*end == ' ' || *end == '\t') end++;
    if(index == 7) return *end == '\0' ? end : NULL;
    if(*end++ != ',') return NULL;
    while(*end == ' ' || *end == '\t') end++;
    return *end == '"' ? end : NULL;
}

/* JanOS wraps every field in quotes, then escape_csv_field() wraps an SSID or
 * vendor containing comma/quote in a second pair. Only fields 1 and 2 can
 * have that inner layer. The row still has exactly eight fields.
 */
static bool decode_inner(
    const char* begin,
    const char* end,
    char output[FIELD_CAPACITY]) {
    size_t length = 0;
    bool needs_quotes = false;
    for(const char* cursor = begin; cursor < end;) {
        char ch = *cursor++;
        if(ch == '"') {
            if(cursor >= end || *cursor != '"') return false;
            cursor++;
        }
        if(ch == '"' || ch == ',' || ch == '\r' || ch == '\n') needs_quotes = true;
        if(length + 1 < FIELD_CAPACITY) output[length++] = ch;
    }
    output[length] = '\0';
    return needs_quotes;
}

static bool parse_fields_at(
    const char* cursor,
    size_t index,
    char fields[8][FIELD_CAPACITY]) {
    if(index == 8) return *cursor == '\0';
    if(*cursor != '"') return false;

    /* RFC 4180 first: doubled quotes inside one field decode to one quote.
     * If this cannot form eight fields, try JanOS's older nested wrapper. */
    const char* close = NULL;
    const char* field_cursor = cursor + 1;
    size_t length = 0;
    while(*field_cursor) {
        if(*field_cursor == '"') {
            if(field_cursor[1] == '"') {
                if(length + 1 < FIELD_CAPACITY) fields[index][length++] = '"';
                field_cursor += 2;
                continue;
            }
            close = field_cursor;
            const char* next = after_field(close + 1, index);
            if(next) {
                fields[index][length] = '\0';
                if(parse_fields_at(next, index + 1, fields)) return true;
            }
            break;
        }
        if(*field_cursor == '\r' || *field_cursor == '\n') break;
        if(length + 1 < FIELD_CAPACITY) fields[index][length++] = *field_cursor;
        field_cursor++;
    }

    if((index != 1 && index != 2) || cursor[1] != '"') return false;
    /* An inner quote pair can also represent a literal quote. Try each pair
     * followed by a separator; the remaining fields disambiguate it.
     */
    size_t remaining = strlen(cursor);
    if(remaining >= 4) {
        for(size_t offset = remaining - 2; offset >= 2; offset--) {
            close = cursor + offset;
            if(close[0] != '"' || close[1] != '"') continue;
            const char* next = after_field(close + 2, index);
            if(!next || !decode_inner(cursor + 2, close, fields[index])) continue;
            if(parse_fields_at(next, index + 1, fields)) return true;
        }
    }
    return false;
}

static size_t parse_fields(const char* line, char fields[8][FIELD_CAPACITY]) {
    return parse_fields_at(line, 0, fields) ? 8 : 0;
}

static void copy_field(char* dest, size_t capacity, const char* source, const char* fallback) {
    if(!dest || !capacity) return;
    const char* value = source && source[0] ? source : fallback;
    if(!value) value = "";
    strncpy(dest, value, capacity - 1);
    dest[capacity - 1] = '\0';
}

static bool bssid_empty(const uint8_t bssid[6]) {
    for(size_t i = 0; i < 6; i++) if(bssid[i]) return false;
    return true;
}

static void parse_bssid(const char* source, uint8_t dest[6]) {
    memset(dest, 0, 6);
    if(!source || !source[0]) return;
    unsigned values[6];
    if(sscanf(source, "%x:%x:%x:%x:%x:%x", &values[0], &values[1], &values[2],
              &values[3], &values[4], &values[5]) != 6) return;
    for(size_t i = 0; i < 6; i++) if(values[i] > 0xff) return;
    for(size_t i = 0; i < 6; i++) dest[i] = (uint8_t)values[i];
}

static uint8_t parse_channel(const char* source) {
    if(!source || !source[0]) return 0;
    char* end = NULL;
    unsigned long value = strtoul(source, &end, 10);
    if(end == source) return 0;
    return value > UINT8_MAX ? UINT8_MAX : (uint8_t)value;
}

static uint8_t parse_band(const char* source) {
    if(!source || !source[0]) return C5ReconBandUnknown;
    if(strncmp(source, "2.4", 3) == 0) return C5ReconBand24;
    if(source[0] == '5' || strstr(source, "5G") || strstr(source, "5g")) return C5ReconBand5;
    return C5ReconBandUnknown;
}

static bool security_open(const char* source) {
    if(!source) return false;
    while(*source && isspace((unsigned char)*source)) source++;
    char token[8];
    size_t i = 0;
    while(source[i] && !isspace((unsigned char)source[i]) && i < sizeof(token) - 1) {
        token[i] = (char)tolower((unsigned char)source[i]);
        i++;
    }
    token[i] = '\0';
    return strcmp(token, "open") == 0;
}

static void trim(char* text) {
    char* start = text;
    while(*start && isspace((unsigned char)*start)) start++;
    char* end = start + strlen(start);
    while(end > start && isspace((unsigned char)end[-1])) end--;
    size_t length = (size_t)(end - start);
    memmove(text, start, length);
    text[length] = '\0';
}

static void vendor_ascii(const char* source, char* dest, size_t capacity) {
    size_t out = 0;
    for(size_t i = 0; source[i] && out + 1 < capacity;) {
        uint8_t a = (uint8_t)source[i];
        if(a < 0x80) {
            dest[out++] = (char)a;
            i++;
            continue;
        }
        uint8_t b = (uint8_t)source[i + 1];
        if(!b) { dest[out++] = '?'; break; }
        char mapped = '\0';
        if(a == 0xC4) {
            if(b == 0x84) mapped = 'A'; else if(b == 0x85) mapped = 'a';
            else if(b == 0x86) mapped = 'C'; else if(b == 0x87) mapped = 'c';
            else if(b == 0x98) mapped = 'E'; else if(b == 0x99) mapped = 'e';
        } else if(a == 0xC5) {
            if(b == 0x81) mapped = 'L'; else if(b == 0x82) mapped = 'l';
            else if(b == 0x83) mapped = 'N'; else if(b == 0x84) mapped = 'n';
            else if(b == 0x9A) mapped = 'S'; else if(b == 0x9B) mapped = 's';
            else if(b == 0xB9) mapped = 'Z'; else if(b == 0xBA) mapped = 'z';
            else if(b == 0xBB) mapped = 'Z'; else if(b == 0xBC) mapped = 'z';
        } else if(a == 0xC3) {
            if(b == 0x93) mapped = 'O'; else if(b == 0xB3) mapped = 'o';
        }
        if(mapped) { dest[out++] = mapped; i += 2; }
        else { dest[out++] = '?'; i++; }
    }
    dest[out] = '\0';
}

static void update_vendor(C5ReconScan* scan, const uint8_t bssid[6], const char* name, uint32_t tick) {
    if(bssid_empty(bssid) || !name || !name[0]) return;
    size_t candidate = C5_RECON_SCAN_VENDOR_CACHE_SIZE;
    uint32_t oldest = UINT32_MAX;
    for(size_t i = 0; i < C5_RECON_SCAN_VENDOR_CACHE_SIZE; i++) {
        C5ReconVendorEntry* entry = &scan->vendors[i];
        if(entry->valid && memcmp(entry->oui, bssid, 3) == 0) { candidate = i; break; }
        if(!entry->valid) { candidate = i; break; }
        if(entry->last_tick < oldest) { oldest = entry->last_tick; candidate = i; }
    }
    if(candidate >= C5_RECON_SCAN_VENDOR_CACHE_SIZE) return;
    C5ReconVendorEntry* entry = &scan->vendors[candidate];
    memcpy(entry->oui, bssid, 3);
    copy_field(entry->name, sizeof(entry->name), name, "");
    entry->last_tick = tick;
    entry->valid = true;
}

const char* c5_recon_scan_vendor(const C5ReconScan* scan, const uint8_t bssid[6]) {
    if(!scan || !bssid || bssid_empty(bssid)) return NULL;
    for(size_t i = 0; i < C5_RECON_SCAN_VENDOR_CACHE_SIZE; i++) {
        const C5ReconVendorEntry* entry = &scan->vendors[i];
        if(entry->valid && memcmp(entry->oui, bssid, 3) == 0)
            return entry->name[0] ? entry->name : NULL;
    }
    return NULL;
}

static void rebuild_visible(C5ReconScan* scan) {
    if(!scan->results || !scan->visible_indices) return;
    scan->visible_count = 0;
    for(size_t i = 0; i < scan->count && i < scan->capacity; i++) {
        const C5ReconScanResult* result = &scan->results[i];
        if(!result->power_valid || result->power_dbm >= scan->min_power_dbm)
            scan->visible_indices[scan->visible_count++] = (uint16_t)i;
    }
    if(scan->visible_index >= scan->visible_count)
        scan->visible_index = scan->visible_count ? scan->visible_count - 1 : 0;
    if(scan->visible_offset >= scan->visible_count)
        scan->visible_offset = scan->visible_count ? scan->visible_count - 1 : 0;
    if(scan->visible_offset > scan->visible_index) scan->visible_offset = scan->visible_index;
}

void c5_recon_scan_set_min_power(C5ReconScan* scan, int16_t min_power_dbm) {
    if(!scan) return;
    scan->min_power_dbm = clamp_power(min_power_dbm);
    rebuild_visible(scan);
}

static uint32_t process_line(C5ReconScan* scan, const char* line, uint32_t tick) {
    while(*line == ' ' || *line == '\t') line++;
    if(strstr(line, "Scan failed with status:") || strstr(line, "Failed to start scan:")) {
        scan->loading = false;
        return C5ReconScanEventError;
    }
    if(strstr(line, "Scan already in progress")) {
        scan->loading = false;
        return C5ReconScanEventStillRunning;
    }
    if(scan->count == 0 && retrieved_zero_records(line)) {
        scan->loading = false;
        if(!scan->last_update_tick) scan->last_update_tick = tick;
        return C5ReconScanEventDone | C5ReconScanEventNoResults;
    }
    size_t expected = parse_count(line);
    if(expected && scan->count == 0 && scan->capacity != expected) {
        if(!allocate_arrays(scan, expected)) { scan->loading = false; return C5ReconScanEventNoMemory; }
    }
    if(strncmp(line, "Scan results", 12) == 0) {
        scan->loading = false;
        if(!scan->last_update_tick) scan->last_update_tick = tick;
        return C5ReconScanEventDone;
    }
    if(strncmp(line, "No scan", 7) == 0 || strncmp(line, "No networks found", 17) == 0 ||
       strncmp(line, "Scan still in progress", 22) == 0) {
        scan->loading = false;
        return strncmp(line, "Scan still in progress", 22) == 0 ?
                   C5ReconScanEventStillRunning : C5ReconScanEventNoResults;
    }
    if(line[0] != '"' || !scan->results || scan->count >= scan->capacity) return 0;
    char fields[8][FIELD_CAPACITY] = {{0}};
    if(parse_fields(line, fields) < 8) return 0;
    bool hidden = fields[1][0] == '\0';
    C5ReconScanResult* result = &scan->results[scan->count];
    memset(result, 0, sizeof(*result));
    result->number = (uint16_t)strtoul(fields[0], NULL, 10);
    copy_field(result->ssid, sizeof(result->ssid), fields[1], "Hidden");
    copy_field(result->security, sizeof(result->security), fields[5], "Unknown");
    parse_bssid(fields[3], result->bssid);
    result->channel = parse_channel(fields[4]);
    result->band = parse_band(fields[7]);
    if(fields[2][0]) {
        char vendor[FIELD_CAPACITY];
        vendor_ascii(fields[2], vendor, sizeof(vendor));
        trim(vendor);
        update_vendor(scan, result->bssid, vendor, tick);
    }
    char* power_end = NULL;
    long power = strtol(fields[6], &power_end, 10);
    if(fields[6][0] && power_end && *power_end == '\0') {
        int32_t bounded = power < INT32_MIN ? INT32_MIN : power > INT32_MAX ? INT32_MAX : (int32_t)power;
        result->power_dbm = clamp_power(bounded);
        result->power_valid = true;
    }
    scan->count++;
    if(result->band == C5ReconBand24) scan->band_24_count++;
    else if(result->band == C5ReconBand5) scan->band_5_count++;
    if(hidden || strcmp(result->ssid, "Hidden") == 0) scan->hidden_count++;
    if(security_open(result->security)) scan->open_count++;
    if(result->power_valid && (!scan->best_rssi_valid || result->power_dbm > scan->best_rssi)) {
        scan->best_rssi_valid = true;
        scan->best_rssi = result->power_dbm;
        copy_field(scan->best_ssid, sizeof(scan->best_ssid), result->ssid, "");
    }
    scan->last_update_tick = tick;
    rebuild_visible(scan);
    return C5ReconScanEventRow;
}

uint32_t c5_recon_scan_feed(C5ReconScan* scan, const uint8_t* bytes, size_t length, uint32_t tick) {
    if(!scan || !scan->loading || !bytes || !length) return 0;
    uint32_t events = 0;
    for(size_t i = 0; i < length && scan->loading; i++) {
        char ch = (char)bytes[i];
        if(ch == '\r') continue;
        if(ch == '\n') {
            if(!scan->discard_line && scan->line_length) {
                scan->line[scan->line_length] = '\0';
                events |= process_line(scan, scan->line, tick);
            }
            scan->line_length = 0;
            scan->discard_line = false;
        } else if(!scan->discard_line) {
            if(scan->line_length + 1 < sizeof(scan->line)) scan->line[scan->line_length++] = ch;
            else { scan->line_length = 0; scan->discard_line = true; }
        }
    }
    return events;
}

const C5ReconScanResult* c5_recon_scan_visible(const C5ReconScan* scan, size_t index) {
    if(!scan || !scan->results || !scan->visible_indices || index >= scan->visible_count) return NULL;
    uint16_t actual = scan->visible_indices[index];
    return actual < scan->count && actual < scan->capacity ? &scan->results[actual] : NULL;
}

const C5ReconScanResult* c5_recon_scan_find_number(const C5ReconScan* scan, uint16_t number) {
    if(!scan || !scan->results) return NULL;
    for(size_t i = 0; i < scan->count; i++) if(scan->results[i].number == number) return &scan->results[i];
    return NULL;
}

bool c5_recon_scan_toggle_visible(C5ReconScan* scan, size_t index) {
    if(!c5_recon_scan_visible(scan, index) || !scan->selected_numbers) return false;
    C5ReconScanResult* result = &scan->results[scan->visible_indices[index]];
    result->selected = !result->selected;
    if(result->selected) {
        for(size_t i = 0; i < scan->selected_count; i++)
            if(scan->selected_numbers[i] == result->number) return true;
        if(scan->selected_count < scan->capacity)
            scan->selected_numbers[scan->selected_count++] = result->number;
    } else {
        for(size_t i = 0; i < scan->selected_count; i++) {
            if(scan->selected_numbers[i] == result->number) {
                for(size_t j = i; j + 1 < scan->selected_count; j++)
                    scan->selected_numbers[j] = scan->selected_numbers[j + 1];
                scan->selected_numbers[--scan->selected_count] = 0;
                break;
            }
        }
    }
    return true;
}

bool c5_recon_scan_export_targets(
    const C5ReconScan* scan,
    C5ReconTarget* output,
    size_t capacity,
    size_t* out_count) {
    if(!scan || !out_count) return false;
    *out_count = scan->selected_count;
    if(capacity < scan->selected_count || (scan->selected_count && !output)) return false;
    for(size_t i = 0; i < scan->selected_count; i++) {
        uint16_t number = scan->selected_numbers[i];
        const C5ReconScanResult* result = c5_recon_scan_find_number(scan, number);
        C5ReconTarget* target = &output[i];
        memset(target, 0, sizeof(*target));
        target->number = number;
        if(result) {
            memcpy(target->ssid, result->ssid, sizeof(target->ssid));
            memcpy(target->bssid, result->bssid, sizeof(target->bssid));
            target->channel = result->channel;
        }
    }
    return true;
}
