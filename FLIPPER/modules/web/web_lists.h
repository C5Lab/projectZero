#ifndef LAB_C5_WEB_LISTS_H
#define LAB_C5_WEB_LISTS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define C5_WEB_SSID_MAX 48u
#define C5_WEB_HTML_MAX 16u
#define C5_WEB_PROBE_MAX 32u
#define C5_WEB_PASS_MAX 32u
#define C5_WEB_TEXT_MAX 32u

typedef struct {
    uint8_t id;
    char ssid[33];
} C5WebSsidEntry;

typedef struct {
    uint8_t id;
    char name[32];
} C5WebHtmlEntry;

typedef struct {
    uint8_t id;
    char name[48];
} C5WebProbeEntry;

typedef struct {
    uint16_t id;
    char ssid[33];
    char pass[64];
} C5WebPassEntry;

typedef char C5WebTextLine[96];

typedef enum {
    C5WebListPortalSsids,
    C5WebListHtml,
    C5WebListKarmaProbes,
    C5WebListEvilPasswords,
    C5WebListPasswordsText,
} C5WebListKind;

typedef enum {
    C5WebListEventNone = 0,
    C5WebListEventEntries = 1u << 0,
    C5WebListEventDone = 1u << 1,
    C5WebListEventMissing = 1u << 2,
} C5WebListEvent;

/* The entry array belongs to the caller and must outlive the active listing.
 * Allocate it only while the corresponding Web screen is open. One list is
 * active at a time; late UART bytes after end are ignored.
 */
typedef struct {
    C5WebListKind kind;
    void* entries;
    size_t capacity;
    size_t count;
    size_t max_line_length;
    bool active;
    bool header_seen;
    bool missing;
    bool discard_line;
    char line[160];
    size_t line_length;
} C5WebList;

bool c5_web_list_begin(C5WebList* list, C5WebListKind kind, void* entries, size_t capacity);
uint32_t c5_web_list_feed(C5WebList* list, const uint8_t* bytes, size_t length);
void c5_web_list_end(C5WebList* list);

#endif
