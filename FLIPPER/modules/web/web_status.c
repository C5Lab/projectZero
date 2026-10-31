#include "web_status.h"

#include <ctype.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

static void c5_web_status_trim(char* text) {
    char* start = text;
    while(*start && isspace((unsigned char)*start)) start++;
    char* end = start + strlen(start);
    while(end > start && isspace((unsigned char)end[-1])) end--;
    *end = '\0';
    if(start != text) memmove(text, start, (size_t)(end - start) + 1);
}

/* Same limited Polish UTF-8 transliteration as the existing Flipper UI. */
static void c5_web_status_to_ascii(const char* source, char* out, size_t capacity) {
    size_t written = 0;
    for(size_t i = 0; source[i] && written + 1 < capacity;) {
        uint8_t lead = (uint8_t)source[i];
        if(lead < 0x80) {
            out[written++] = source[i++];
            continue;
        }
        uint8_t next = (uint8_t)source[i + 1];
        if(next == 0) {
            out[written++] = '?';
            break;
        }
        char mapped = '\0';
        if(lead == 0xC4) {
            switch(next) {
            case 0x84: mapped = 'A'; break;
            case 0x85: mapped = 'a'; break;
            case 0x86: mapped = 'C'; break;
            case 0x87: mapped = 'c'; break;
            case 0x98: mapped = 'E'; break;
            case 0x99: mapped = 'e'; break;
            }
        } else if(lead == 0xC5) {
            switch(next) {
            case 0x81: mapped = 'L'; break;
            case 0x82: mapped = 'l'; break;
            case 0x83: mapped = 'N'; break;
            case 0x84: mapped = 'n'; break;
            case 0x9A: mapped = 'S'; break;
            case 0x9B: mapped = 's'; break;
            case 0xB9: mapped = 'Z'; break;
            case 0xBA: mapped = 'z'; break;
            case 0xBB: mapped = 'Z'; break;
            case 0xBC: mapped = 'z'; break;
            }
        } else if(lead == 0xC3) {
            if(next == 0x93) mapped = 'O';
            else if(next == 0xB3) mapped = 'o';
        }
        if(mapped) {
            out[written++] = mapped;
            i += 2;
        } else {
            out[written++] = '?';
            i++;
        }
    }
    out[written] = '\0';
}

static void c5_web_status_copy_ascii(char* out, size_t capacity, const char* text) {
    c5_web_status_to_ascii(text, out, capacity);
    c5_web_status_trim(out);
}

static void c5_web_status_set_note(C5WebStatus* status, const char* note) {
    size_t length = strlen(note);
    if(length >= sizeof(status->note)) length = sizeof(status->note) - 1;
    memcpy(status->note, note, length);
    status->note[length] = '\0';
}

static void c5_web_status_parse_client_count(C5WebStatus* status, const char* text) {
    const char* equal = strchr(text, '=');
    if(!equal) return;
    equal++;
    while(*equal == ' ' || *equal == '\t') equal++;
    char* end = NULL;
    long count = strtol(equal, &end, 10);
    if(end != equal && count >= 0 && count <= INT32_MAX) status->client_count = (int32_t)count;
}

static bool c5_web_status_query_value(
    const char* query,
    const char* key,
    char* out,
    size_t capacity) {
    size_t key_length = strlen(key);
    const char* cursor = query;
    while((cursor = strstr(cursor, key))) {
        const char* after = cursor + key_length;
        if((cursor == query || cursor[-1] == '&') && *after == '=') {
            size_t written = 0;
            for(after++; *after && *after != '&'; after++) {
                if(written + 1 < capacity) out[written++] = *after == '+' ? ' ' : *after;
            }
            out[written] = '\0';
            c5_web_status_trim(out);
            return out[0] != '\0';
        }
        cursor += key_length;
    }
    return false;
}

static void c5_web_status_assign_after_marker(
    char* out,
    size_t capacity,
    const char* marker_position,
    const char* marker) {
    const char* value = marker_position + strlen(marker);
    while(*value == ' ' || *value == '\t') value++;
    if(*value) c5_web_status_copy_ascii(out, capacity, value);
}

static void c5_web_status_assign_quoted_ssid(C5WebStatus* status, const char* text) {
    const char* value = strstr(text, "SSID='");
    if(!value) return;
    value += strlen("SSID='");
    const char* end = strchr(value, '\'');
    if(!end || end == value) return;
    size_t length = (size_t)(end - value);
    if(length >= sizeof(status->ssid)) length = sizeof(status->ssid) - 1;
    char raw[C5_WEB_STATUS_SSID_CAPACITY];
    memcpy(raw, value, length);
    raw[length] = '\0';
    c5_web_status_copy_ascii(status->ssid, sizeof(status->ssid), raw);
}

static void c5_web_status_portal_line(C5WebStatus* status, const char* line) {
    const char* pointer;
    if((pointer = strstr(line, "Starting captive portal with SSID:"))) {
        c5_web_status_assign_after_marker(
            status->ssid, sizeof(status->ssid), pointer, "Starting captive portal with SSID:");
    } else if((pointer = strstr(line, "AP Name:"))) {
        c5_web_status_assign_after_marker(status->ssid, sizeof(status->ssid), pointer, "AP Name:");
    } else if((pointer = strstr(line, "Portal: Client count"))) {
        c5_web_status_parse_client_count(status, pointer);
    } else if((pointer = strstr(line, "Portal password received:")) ||
              (pointer = strstr(line, "Password:"))) {
        const char* marker = strstr(pointer, "Portal password received:") == pointer
                                 ? "Portal password received:"
                                 : "Password:";
        const char* value = pointer + strlen(marker);
        while(*value == ' ' || *value == '\t') value++;
        if(*value) {
            c5_web_status_copy_ascii(status->last_password, sizeof(status->last_password), value);
            status->password_count++;
        }
    } else if((pointer = strstr(line, "Received POST data:"))) {
        const char* query = pointer + strlen("Received POST data:");
        while(*query == ' ' || *query == '\t') query++;
        if(*query &&
           (c5_web_status_query_value(
                query, "google_user", status->last_username, sizeof(status->last_username)) ||
            c5_web_status_query_value(
                query, "username", status->last_username, sizeof(status->last_username)) ||
            c5_web_status_query_value(
                query, "user", status->last_username, sizeof(status->last_username)) ||
            c5_web_status_query_value(
                query, "login", status->last_username, sizeof(status->last_username)) ||
            c5_web_status_query_value(
                query, "email", status->last_username, sizeof(status->last_username)))) {
            status->username_count++;
        }
    }
}

static void c5_web_status_evil_line(
    C5WebStatus* status,
    const char* line,
    C5WebStatusEventCallback callback,
    void* context) {
    const char* pointer;
    if((pointer = strstr(line, "Starting captive portal for Evil Twin attack on:"))) {
        c5_web_status_assign_after_marker(
            status->ssid,
            sizeof(status->ssid),
            pointer,
            "Starting captive portal for Evil Twin attack on:");
        c5_web_status_set_note(status, "Portal");
    } else if((pointer = strstr(line, "AP Name:"))) {
        c5_web_status_assign_after_marker(status->ssid, sizeof(status->ssid), pointer, "AP Name:");
    } else if(strstr(line, "Captive portal started successfully")) {
        c5_web_status_set_note(status, "Portal");
    } else if(strstr(line, "Deauth attack started.")) {
        c5_web_status_set_note(status, "Deauth");
    } else if((pointer = strstr(line, "Portal: Client count"))) {
        c5_web_status_parse_client_count(status, pointer);
    } else if((pointer = strstr(line, "Password:")) ||
              (pointer = strstr(line, "Portal password received:"))) {
        const char* marker = strstr(pointer, "Password:") == pointer
                                 ? "Password:"
                                 : "Portal password received:";
        const char* value = pointer + strlen(marker);
        while(*value == ' ' || *value == '\t') value++;
        if(*value) {
            c5_web_status_copy_ascii(status->last_password, sizeof(status->last_password), value);
            status->password_count++;
            c5_web_status_set_note(status, "Received");
        }
    } else if(strstr(line, "Stopping deauth attack to attempt connection")) {
        c5_web_status_set_note(status, "Checking");
    } else if(strstr(line, "Resuming deauth attack - password was incorrect.")) {
        c5_web_status_set_note(status, "Wrong");
        status->last_password[0] = '\0';
        status->password_count = 0;
        if(callback) callback(context, C5WebStatusBadPassword);
    } else if(strstr(line, "Deauth attack resumed successfully.")) {
        c5_web_status_set_note(status, "Deauth");
    } else if((pointer = strstr(line, "Attempting to connect to SSID="))) {
        c5_web_status_assign_quoted_ssid(status, pointer);
        c5_web_status_set_note(status, "Checking");
    } else if(strstr(line, "Attempting to connect, connectAttemptCount=")) {
        c5_web_status_set_note(status, "Checking");
    } else if((pointer = strstr(line, "Wi-Fi: connected to SSID="))) {
        c5_web_status_assign_quoted_ssid(status, pointer);
        c5_web_status_set_note(status, "Verified");
    } else if(strstr(line, "Password verified!")) {
        c5_web_status_set_note(status, "Verified");
    } else if(strstr(line, "Evil twin: connection failed")) {
        c5_web_status_set_note(status, "Wrong");
        status->last_password[0] = '\0';
        status->password_count = 0;
    } else if(strstr(line, "Evil Twin portal shut down successfully!")) {
        c5_web_status_set_note(status, "Stopped");
    } else if(strstr(line, "Password saved to eviltwin.txt")) {
        c5_web_status_set_note(status, "Verified");
        if(callback) callback(context, C5WebStatusPasswordSaved);
    }
}

static void c5_web_status_line(
    C5WebStatus* status,
    C5WebStatusEventCallback callback,
    void* context) {
    status->line[status->line_length] = '\0';
    const char* cursor = status->line;
    while(*cursor == ' ' || *cursor == '\t' || *cursor == '>') cursor++;
    if(*cursor) {
        if(status->mode == C5WebStatusEvilTwin) {
            c5_web_status_evil_line(status, cursor, callback, context);
        } else {
            c5_web_status_portal_line(status, cursor);
        }
    }
    status->line_length = 0;
}

void c5_web_status_reset(C5WebStatus* status, C5WebStatusMode mode) {
    if(!status) return;
    memset(status, 0, sizeof(*status));
    status->mode = mode;
    status->client_count = -1;
}

void c5_web_status_feed(
    C5WebStatus* status,
    const uint8_t* bytes,
    size_t length,
    C5WebStatusEventCallback callback,
    void* context) {
    if(!status || !bytes || !length) return;
    for(size_t i = 0; i < length; ++i) {
        uint8_t ch = bytes[i];
        if(ch == '\r') continue;
        if(ch == '\n') {
            if(!status->dropping_line && status->line_length) {
                c5_web_status_line(status, callback, context);
            }
            status->line_length = 0;
            status->dropping_line = false;
            continue;
        }
        if(status->dropping_line) continue;
        if(status->line_length + 1 >= sizeof(status->line)) {
            status->line_length = 0;
            status->dropping_line = true;
            continue;
        }
        status->line[status->line_length++] = (char)ch;
    }
}
