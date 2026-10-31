#ifndef LAB_C5_WEB_STATUS_H
#define LAB_C5_WEB_STATUS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define C5_WEB_STATUS_SSID_CAPACITY 33u
#define C5_WEB_STATUS_PASSWORD_CAPACITY 48u
#define C5_WEB_STATUS_USERNAME_CAPACITY 48u
#define C5_WEB_STATUS_NOTE_CAPACITY 16u
#define C5_WEB_STATUS_LINE_CAPACITY 160u

typedef enum {
    C5WebStatusPortal,
    C5WebStatusEvilTwin,
} C5WebStatusMode;

typedef enum {
    C5WebStatusBadPassword,
    C5WebStatusPasswordSaved,
} C5WebStatusEvent;

typedef void (*C5WebStatusEventCallback)(void* context, C5WebStatusEvent event);

/* Allocate this state only while Portal/Evil Twin status is needed. The event
 * callback reports UI notifications without making the parser own UI state. */
typedef struct {
    C5WebStatusMode mode;
    char ssid[C5_WEB_STATUS_SSID_CAPACITY];
    int32_t client_count; /* -1 means unknown. */
    uint32_t password_count;
    char last_password[C5_WEB_STATUS_PASSWORD_CAPACITY];
    uint32_t username_count;
    char last_username[C5_WEB_STATUS_USERNAME_CAPACITY];
    char note[C5_WEB_STATUS_NOTE_CAPACITY];
    char line[C5_WEB_STATUS_LINE_CAPACITY];
    size_t line_length;
    bool dropping_line;
} C5WebStatus;

void c5_web_status_reset(C5WebStatus* status, C5WebStatusMode mode);
void c5_web_status_feed(
    C5WebStatus* status,
    const uint8_t* bytes,
    size_t length,
    C5WebStatusEventCallback callback,
    void* context);

#endif
