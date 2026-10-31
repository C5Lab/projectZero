#ifndef LAB_C5_MODULE_API_H
#define LAB_C5_MODULE_API_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <gui/canvas.h>
#include <input/input.h>

#define C5_MODULE_APP_ID "lab_c5"
#define C5_MODULE_API_VERSION 3u
#define C5_MODULE_RAW_TX_MAX 512u
#define C5_TEXT_INPUT_HEADER_CAPACITY 32u
#define C5_TEXT_INPUT_VALUE_CAPACITY 64u

typedef enum {
    GPS_TIME_24H = 0,
    GPS_UTC_OFFSET_MIN,
    GPS_DST,
    GPS_ZDA_TZ,
    C5SettingKarmaDurationSec,
} C5Setting;

typedef enum {
    C5InputIgnored = 0,
    C5InputConsumed,
    C5InputSwitchTerminal,
    C5InputSwitchModule,
    C5InputToggleConsole,
    C5InputOpenAttacks,
} C5InputResult;

typedef struct {
    char header[C5_TEXT_INPUT_HEADER_CAPACITY];
    char initial[C5_TEXT_INPUT_VALUE_CAPACITY];
    uint8_t capacity; /* Includes the terminating NUL. */
    uint8_t minimum_length;
} C5TextInputRequest;

typedef struct C5HostApiV3 {
    uint32_t version;
    uint32_t size;
    void* ctx;
    void (*send_command)(void* ctx, const char* command);
    /* A complete LF-terminated batch is transmitted under one UART mutex hold.
       This does not change screens, parsers, or command state in the host. */
    bool (*send_raw_lines)(void* ctx, const char* batch, size_t length);
    /* Copies the request; the host opens the dialog from its app loop. */
    bool (*request_text_input)(void* ctx, const C5TextInputRequest* request);
    void (*request_redraw)(void* ctx);
    void (*show_status)(void* ctx, const char* message, uint32_t duration_ms, bool fullscreen);
    int32_t (*get_setting)(void* ctx, C5Setting setting);
    void (*set_setting)(void* ctx, C5Setting setting, int32_t value);
    /* Called by a module's leave() with its small, versioned selection data. */
    void (*save_session)(void* ctx, const void* data, size_t size);
} C5HostApiV3;

typedef struct C5ModuleV3 {
    uint32_t version;
    uint32_t size;
    /* params is borrowed only for this call. A module copies launch data it needs. */
    void* (*enter)(const C5HostApiV3* host, const void* params, size_t params_size);
    void (*leave)(void* state, const C5HostApiV3* host);
    /* A module uses either on_bytes or on_line. Raw input takes precedence. */
    void (*on_line)(void* state, const C5HostApiV3* host, const char* line);
    void (*on_bytes)(void* state, const C5HostApiV3* host, const uint8_t* bytes, size_t length);
    C5InputResult (*on_input)(void* state, const C5HostApiV3* host, const InputEvent* event);
    void (*on_text_input)(void* state, const C5HostApiV3* host, bool accepted, const char* text);
    void (*draw)(void* state, const C5HostApiV3* host, Canvas* canvas);
    void (*tick)(void* state, const C5HostApiV3* host, uint32_t now_ticks);
} C5ModuleV3;

#endif
