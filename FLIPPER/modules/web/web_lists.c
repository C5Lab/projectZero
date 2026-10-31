#include "web_lists.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

static size_t c5_web_list_limit(C5WebListKind kind) {
    switch(kind) {
    case C5WebListPortalSsids:
        return C5_WEB_SSID_MAX;
    case C5WebListHtml:
        return C5_WEB_HTML_MAX;
    case C5WebListKarmaProbes:
        return C5_WEB_PROBE_MAX;
    case C5WebListEvilPasswords:
        return C5_WEB_PASS_MAX;
    case C5WebListPasswordsText:
        return C5_WEB_TEXT_MAX;
    default:
        return 0;
    }
}

bool c5_web_list_begin(C5WebList* list, C5WebListKind kind, void* entries, size_t capacity) {
    size_t limit = c5_web_list_limit(kind);
    if(!list) return false;
    memset(list, 0, sizeof(*list));
    if(!entries || !capacity || capacity > limit) return false;
    list->kind = kind;
    list->entries = entries;
    list->capacity = capacity;
    list->active = true;
    return true;
}

void c5_web_list_end(C5WebList* list) {
    if(!list) return;
    list->active = false;
    list->line_length = 0;
    list->discard_line = false;
}

static void c5_web_copy_trim(char* output, size_t capacity, const char* source, bool trim_tabs) {
    if(!capacity) return;
    size_t length = strlen(source);
    if(length >= capacity) length = capacity - 1;
    memcpy(output, source, length);
    output[length] = '\0';
    while(length && (output[length - 1] == ' ' || output[length - 1] == '\r' ||
                     output[length - 1] == '\n' || (trim_tabs && output[length - 1] == '\t'))) {
        output[--length] = '\0';
    }
}

static void c5_web_trim(char* text) {
    char* start = text;
    while(isspace((unsigned char)*start)) start++;
    char* end = start + strlen(start);
    while(end > start && isspace((unsigned char)end[-1])) end--;
    *end = '\0';
    if(start != text) memmove(text, start, (size_t)(end - start) + 1);
}

/* Match the ASCII representation used by the previous on-device lists. */
static void c5_web_utf8_to_ascii_pl(const char* source, char* output, size_t capacity) {
    if(!capacity) return;
    size_t out = 0;
    for(size_t i = 0; source[i] && out + 1 < capacity;) {
        uint8_t first = (uint8_t)source[i];
        if(first < 0x80) {
            output[out++] = (char)first;
            i++;
            continue;
        }
        uint8_t next = (uint8_t)source[i + 1];
        if(!next) {
            output[out++] = '?';
            break;
        }
        char mapped = '\0';
        if(first == 0xC4) {
            if(next == 0x84) mapped = 'A';
            else if(next == 0x85) mapped = 'a';
            else if(next == 0x86) mapped = 'C';
            else if(next == 0x87) mapped = 'c';
            else if(next == 0x98) mapped = 'E';
            else if(next == 0x99) mapped = 'e';
        } else if(first == 0xC5) {
            if(next == 0x81) mapped = 'L';
            else if(next == 0x82) mapped = 'l';
            else if(next == 0x83) mapped = 'N';
            else if(next == 0x84) mapped = 'n';
            else if(next == 0x9A) mapped = 'S';
            else if(next == 0x9B) mapped = 's';
            else if(next == 0xB9 || next == 0xBB) mapped = 'Z';
            else if(next == 0xBA || next == 0xBC) mapped = 'z';
        } else if(first == 0xC3) {
            if(next == 0x93) mapped = 'O';
            else if(next == 0xB3) mapped = 'o';
        }
        if(mapped) {
            output[out++] = mapped;
            i += 2;
        } else {
            output[out++] = '?';
            i++;
        }
    }
    output[out] = '\0';
}

static const char* c5_web_skip_space(const char* cursor) {
    while(*cursor == ' ' || *cursor == '\t') cursor++;
    return cursor;
}

static bool c5_web_parse_id_name(const char* line, uint8_t* id, const char** name) {
    if(!isdigit((unsigned char)line[0])) return false;
    char* end = NULL;
    long parsed = strtol(line, &end, 10);
    if(parsed <= 0 || parsed > 255 || !end) return false;
    end = (char*)c5_web_skip_space(end);
    if(!*end) return false;
    *id = (uint8_t)parsed;
    *name = end;
    return true;
}

static uint32_t c5_web_list_finish(C5WebList* list) {
    c5_web_list_end(list);
    return C5WebListEventDone;
}

static uint32_t c5_web_list_process_named(C5WebList* list, const char* line) {
    const char* cursor = c5_web_skip_space(line);
    if(!*cursor) {
        if(list->kind == C5WebListKarmaProbes ? list->header_seen : list->count > 0) {
            return c5_web_list_finish(list);
        }
        return 0;
    }

    if(list->kind == C5WebListPortalSsids) {
        if(strncmp(cursor, "ssid.txt not found", 19) == 0 ||
           strncmp(cursor, "ssid.txt is empty", 18) == 0 ||
           strncmp(cursor, "No SSID", 7) == 0) {
            list->missing = true;
            list->count = 0;
            return C5WebListEventMissing | c5_web_list_finish(list);
        }
        if(strncmp(cursor, "SSID presets", 12) == 0) {
            list->header_seen = true;
            return 0;
        }
    } else if(list->kind == C5WebListHtml) {
        if(strncmp(cursor, "HTML files", 10) == 0) {
            list->header_seen = true;
            return 0;
        }
        if(strncmp(cursor, "No HTML", 7) == 0 || strncmp(cursor, "No html", 7) == 0) {
            list->count = 0;
            return c5_web_list_finish(list);
        }
    } else {
        if(strncmp(cursor, "Probes", 6) == 0 || strncmp(cursor, "Probe", 5) == 0) {
            list->header_seen = true;
            return 0;
        }
        if(strncmp(cursor, "No probes", 9) == 0 || strncmp(cursor, "No Probes", 9) == 0) {
            return c5_web_list_finish(list);
        }
    }

    if(!isdigit((unsigned char)cursor[0])) {
        if(list->kind == C5WebListKarmaProbes ? list->header_seen : list->count > 0) {
            return c5_web_list_finish(list);
        }
        return 0;
    }

    uint8_t id = 0;
    const char* name = NULL;
    if(!c5_web_parse_id_name(cursor, &id, &name)) return 0;

    if(list->kind == C5WebListPortalSsids) {
        if(list->count >= list->capacity) return 0;
        C5WebSsidEntry* entry = &((C5WebSsidEntry*)list->entries)[list->count++];
        entry->id = id;
        c5_web_copy_trim(entry->ssid, sizeof(entry->ssid), name, true);
    } else if(list->kind == C5WebListHtml) {
        if(list->count >= list->capacity) return 0;
        C5WebHtmlEntry* entry = &((C5WebHtmlEntry*)list->entries)[list->count++];
        entry->id = id;
        c5_web_copy_trim(entry->name, sizeof(entry->name), name, false);
    } else {
        char parsed_name[48];
        c5_web_copy_trim(parsed_name, sizeof(parsed_name), name, true);
        if(!parsed_name[0]) return 0;
        C5WebProbeEntry* entries = list->entries;
        for(size_t i = 0; i < list->count; i++) {
            if(strcmp(entries[i].name, parsed_name) == 0) {
                entries[i].id = id;
                return C5WebListEventEntries;
            }
        }
        if(list->count >= list->capacity) return 0;
        C5WebProbeEntry* entry = &entries[list->count++];
        entry->id = id;
        c5_web_copy_trim(entry->name, sizeof(entry->name), parsed_name, true);
    }
    list->header_seen = true;
    return C5WebListEventEntries;
}

static uint32_t c5_web_list_process_evil_pass(C5WebList* list, const char* line) {
    if(list->count >= list->capacity) return 0;
    const char* cursor = c5_web_skip_space(line);
    if(*cursor != '"') return 0;
    const char* ssid_start = cursor + 1;
    const char* ssid_end = strchr(ssid_start, '"');
    if(!ssid_end) return 0;
    const char* pass_open = strchr(ssid_end + 1, '"');
    if(!pass_open) return 0;
    const char* pass_start = pass_open + 1;
    const char* pass_end = strchr(pass_start, '"');
    if(!pass_end) return 0;

    char raw_ssid[33];
    char raw_pass[64];
    size_t ssid_len = (size_t)(ssid_end - ssid_start);
    size_t pass_len = (size_t)(pass_end - pass_start);
    if(ssid_len >= sizeof(raw_ssid)) ssid_len = sizeof(raw_ssid) - 1;
    if(pass_len >= sizeof(raw_pass)) pass_len = sizeof(raw_pass) - 1;
    memcpy(raw_ssid, ssid_start, ssid_len);
    raw_ssid[ssid_len] = '\0';
    memcpy(raw_pass, pass_start, pass_len);
    raw_pass[pass_len] = '\0';

    C5WebPassEntry* entry = &((C5WebPassEntry*)list->entries)[list->count];
    entry->id = (uint16_t)(list->count + 1);
    c5_web_utf8_to_ascii_pl(raw_ssid, entry->ssid, sizeof(entry->ssid));
    c5_web_utf8_to_ascii_pl(raw_pass, entry->pass, sizeof(entry->pass));
    c5_web_trim(entry->ssid);
    c5_web_trim(entry->pass);
    if(!entry->ssid[0]) strcpy(entry->ssid, "<hidden>");
    list->count++;
    return C5WebListEventEntries;
}

static uint32_t c5_web_list_process_text(C5WebList* list, const char* line) {
    if(list->count >= list->capacity) return 0;
    C5WebTextLine* entry = &((C5WebTextLine*)list->entries)[list->count];
    c5_web_utf8_to_ascii_pl(line, *entry, sizeof(*entry));
    c5_web_trim(*entry);
    if(strncmp(*entry, "TX:", 3) == 0) return 0;
    size_t length = strlen(*entry);
    if(length > list->max_line_length) list->max_line_length = length;
    list->count++;
    return C5WebListEventEntries;
}

static uint32_t c5_web_list_process_line(C5WebList* list) {
    list->line[list->line_length] = '\0';
    if(list->kind == C5WebListEvilPasswords) {
        return c5_web_list_process_evil_pass(list, list->line);
    } else if(list->kind == C5WebListPasswordsText) {
        return c5_web_list_process_text(list, list->line);
    }
    return c5_web_list_process_named(list, list->line);
}

uint32_t c5_web_list_feed(C5WebList* list, const uint8_t* bytes, size_t length) {
    if(!list || !list->active || !bytes || !length) return 0;
    uint32_t events = 0;
    for(size_t i = 0; i < length && list->active; i++) {
        char ch = (char)bytes[i];
        if(ch == '\r') continue;
        /* JanOS prints its prompt at the start of a line. A '>' within a
           numbered SSID/probe row or quoted password is part of the data. */
        bool prompt = ch == '>' && list->line_length == 0;
        if(prompt || ch == '\n') {
            bool discarded = list->discard_line;
            bool had_line = list->line_length > 0 && !discarded;
            if(had_line) events |= c5_web_list_process_line(list);
            list->line_length = 0;
            list->discard_line = false;
            if(!list->active) break;
            if(prompt) {
                events |= c5_web_list_finish(list);
            } else if(!had_line && !discarded && list->header_seen &&
                      list->kind != C5WebListEvilPasswords &&
                      list->kind != C5WebListPasswordsText) {
                events |= c5_web_list_finish(list);
            }
            continue;
        }
        if(list->discard_line) continue;
        if(list->line_length + 1 >= sizeof(list->line)) {
            list->line_length = 0;
            list->discard_line = true;
            continue;
        }
        list->line[list->line_length++] = ch;
    }
    return events;
}
