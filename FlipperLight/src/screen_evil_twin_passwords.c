/**
 * Evil Twin Passwords Screen
 * 
 * Command: show_pass evil
 * Response lines: "SSID", "password"
 * 
 * Scrollable list with star selection for future Connect feature.
 */

#include "app.h"
#include "uart_comm.h"
#include "screen.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <furi.h>

#define TAG "EvilTwinPW"
#define MAX_ET_ENTRIES 32

// ============================================================================
// Data Structures
// ============================================================================

typedef struct {
    char ssid[33];
    char password[65];
} EvilTwinEntry;

typedef struct {
    WiFiApp* app;
    volatile bool should_exit;
    volatile bool data_loaded;
    EvilTwinEntry entries[MAX_ET_ENTRIES];
    uint8_t entry_count;
    uint8_t selected_idx;
    bool selected_flags[MAX_ET_ENTRIES]; // star selection per entry
    FuriThread* thread;
} EvilTwinPWData;

typedef struct {
    EvilTwinPWData* data;
} EvilTwinPWModel;

// ============================================================================
// Cleanup
// ============================================================================

void evil_twin_passwords_cleanup_internal(View* view, void* data) {
    UNUSED(view);
    EvilTwinPWData* d = (EvilTwinPWData*)data;
    if(!d) return;
    
    FURI_LOG_I(TAG, "Evil Twin Passwords cleanup starting");
    d->should_exit = true;
    if(d->thread) {
        furi_thread_join(d->thread);
        furi_thread_free(d->thread);
    }
    free(d);
    FURI_LOG_I(TAG, "Evil Twin Passwords cleanup complete");
}

// ============================================================================
// UART Read Thread
// ============================================================================

static int32_t evil_twin_pw_thread(void* context) {
    EvilTwinPWData* data = (EvilTwinPWData*)context;
    WiFiApp* app = data->app;
    
    if(data->should_exit) return 0;
    
    uart_clear_buffer(app);
    uart_send_command(app, "show_pass evil");
    
    uint32_t deadline = furi_get_tick() + 5000;
    while(furi_get_tick() < deadline && !data->should_exit) {
        const char* line = uart_read_line(app, 1000);
        if(!line) break;
        
        FURI_LOG_I(TAG, "RX: '%s'", line);
        
        // Skip echo
        if(strncmp(line, "show_pass", 9) == 0) continue;
        
        // Parse: "SSID", "password"
        if(line[0] != '"') continue;
        if(data->entry_count >= MAX_ET_ENTRIES) continue;
        
        const char* p = line;
        char ssid[33] = {0};
        char password[65] = {0};
        
        if(!csv_next_quoted_field(&p, ssid, sizeof(ssid))) continue;
        if(!csv_next_quoted_field(&p, password, sizeof(password))) continue;
        
        EvilTwinEntry* entry = &data->entries[data->entry_count];
        strncpy(entry->ssid, ssid, sizeof(entry->ssid) - 1);
        entry->ssid[sizeof(entry->ssid) - 1] = '\0';
        strncpy(entry->password, password, sizeof(entry->password) - 1);
        entry->password[sizeof(entry->password) - 1] = '\0';
        data->entry_count++;
        
        FURI_LOG_I(TAG, "Entry %u: '%s' / '%s'", data->entry_count, ssid, password);
    }
    
    data->data_loaded = true;
    FURI_LOG_I(TAG, "Loaded %u entries", data->entry_count);
    return 0;
}

// ============================================================================
// Drawing
// ============================================================================

static void evil_twin_pw_draw(Canvas* canvas, void* model) {
    EvilTwinPWModel* m = (EvilTwinPWModel*)model;
    if(!m || !m->data) return;
    EvilTwinPWData* data = m->data;
    
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    screen_draw_title(canvas, "Evil Twin Passwords");
    
    canvas_set_font(canvas, FontSecondary);
    
    if(!data->data_loaded) {
        screen_draw_centered_text(canvas, "Loading...", 36);
        return;
    }
    
    if(data->entry_count == 0) {
        screen_draw_centered_text(canvas, "No passwords found", 36);
        return;
    }
    
    // One entry per page: SSID + full password
    EvilTwinEntry* entry = &data->entries[data->selected_idx];
    
    // Star selection marker + SSID (bold)
    canvas_set_font(canvas, FontPrimary);
    char ssid_line[36];
    snprintf(ssid_line, sizeof(ssid_line), "%c %s",
             data->selected_flags[data->selected_idx] ? '*' : ' ',
             entry->ssid);
    canvas_draw_str(canvas, 2, 24, ssid_line);
    canvas_set_font(canvas, FontSecondary);
    
    // Password on next line(s) - split if too long
    size_t pw_len = strlen(entry->password);
    char pw_line[22];
    
    // First line of password
    snprintf(pw_line, sizeof(pw_line), "%.21s", entry->password);
    canvas_draw_str(canvas, 4, 37, pw_line);
    
    // Second line if password is longer than 21 chars
    if(pw_len > 21) {
        snprintf(pw_line, sizeof(pw_line), "%.21s", entry->password + 21);
        canvas_draw_str(canvas, 4, 46, pw_line);
    }
    
    // Counter at bottom right
    char indicator[16];
    snprintf(indicator, sizeof(indicator), "%u/%u", data->selected_idx + 1, data->entry_count);
    canvas_draw_str(canvas, 96, 64, indicator);
}

// ============================================================================
// Input Handling
// ============================================================================

static bool evil_twin_pw_input(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;
    
    EvilTwinPWModel* m = view_get_model(view);
    if(!m || !m->data) {
        view_commit_model(view, false);
        return false;
    }
    EvilTwinPWData* data = m->data;
    
    bool is_navigation = (event->key == InputKeyUp || event->key == InputKeyDown);
    if(is_navigation) {
        if(event->type != InputTypePress && event->type != InputTypeRepeat) {
            view_commit_model(view, false);
            return false;
        }
    } else {
        if(event->type != InputTypeShort) {
            view_commit_model(view, false);
            return false;
        }
    }
    
    if(event->key == InputKeyBack) {
        view_commit_model(view, false);
        screen_pop(data->app);
        return true;
    }
    
    if(!data->data_loaded || data->entry_count == 0) {
        view_commit_model(view, false);
        return true;
    }
    
    if(event->key == InputKeyUp) {
        if(data->selected_idx > 0) data->selected_idx--;
    } else if(event->key == InputKeyDown) {
        if(data->selected_idx < data->entry_count - 1) data->selected_idx++;
    } else if(event->key == InputKeyOk) {
        // Toggle star selection
        data->selected_flags[data->selected_idx] = !data->selected_flags[data->selected_idx];
    }
    
    view_commit_model(view, true);
    return true;
}

// ============================================================================
// Screen Creation
// ============================================================================

View* screen_evil_twin_passwords_create(WiFiApp* app, void** out_data) {
    EvilTwinPWData* data = (EvilTwinPWData*)malloc(sizeof(EvilTwinPWData));
    if(!data) return NULL;
    
    memset(data, 0, sizeof(EvilTwinPWData));
    data->app = app;
    data->should_exit = false;
    data->data_loaded = false;
    data->entry_count = 0;
    data->selected_idx = 0;
    
    View* view = view_alloc();
    if(!view) {
        free(data);
        return NULL;
    }
    
    view_allocate_model(view, ViewModelTypeLocking, sizeof(EvilTwinPWModel));
    EvilTwinPWModel* m = view_get_model(view);
    if(!m) {
        free(data);
        view_free(view);
        return NULL;
    }
    m->data = data;
    view_commit_model(view, true);
    
    view_set_draw_callback(view, evil_twin_pw_draw);
    view_set_input_callback(view, evil_twin_pw_input);
    view_set_context(view, view);
    
    // Start thread to fetch data from board
    data->thread = furi_thread_alloc();
    furi_thread_set_name(data->thread, "EvilTwinPW");
    furi_thread_set_stack_size(data->thread, 2048);
    furi_thread_set_callback(data->thread, evil_twin_pw_thread);
    furi_thread_set_context(data->thread, data);
    furi_thread_start(data->thread);
    
    if(out_data) *out_data = data;
    return view;
}
