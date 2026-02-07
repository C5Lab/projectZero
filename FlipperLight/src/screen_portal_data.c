/**
 * Portal Data Screen
 * 
 * Command: show_pass portal
 * Response lines: "SSID", "field1=val1", "field2=val2", ...
 * Variable number of fields per line.
 * 
 * Scrollable list showing SSID and captured fields.
 */

#include "app.h"
#include "uart_comm.h"
#include "screen.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <furi.h>

#define TAG "PortalData"
#define MAX_PORTAL_ENTRIES 32

// ============================================================================
// Data Structures
// ============================================================================

typedef struct {
    char ssid[33];
    char fields[160]; // joined "field1=val1, field2=val2, ..."
} PortalEntry;

typedef struct {
    WiFiApp* app;
    volatile bool should_exit;
    volatile bool data_loaded;
    PortalEntry entries[MAX_PORTAL_ENTRIES];
    uint8_t entry_count;
    uint8_t selected_idx;
    FuriThread* thread;
} PortalDataData;

typedef struct {
    PortalDataData* data;
} PortalDataModel;

// ============================================================================
// Cleanup
// ============================================================================

void portal_data_cleanup_internal(View* view, void* data) {
    UNUSED(view);
    PortalDataData* d = (PortalDataData*)data;
    if(!d) return;
    
    FURI_LOG_I(TAG, "Portal Data cleanup starting");
    d->should_exit = true;
    if(d->thread) {
        furi_thread_join(d->thread);
        furi_thread_free(d->thread);
    }
    free(d);
    FURI_LOG_I(TAG, "Portal Data cleanup complete");
}

// ============================================================================
// UART Read Thread
// ============================================================================

static int32_t portal_data_thread(void* context) {
    PortalDataData* data = (PortalDataData*)context;
    WiFiApp* app = data->app;
    
    if(data->should_exit) return 0;
    
    uart_clear_buffer(app);
    uart_send_command(app, "show_pass portal");
    
    uint32_t deadline = furi_get_tick() + 5000;
    while(furi_get_tick() < deadline && !data->should_exit) {
        const char* line = uart_read_line(app, 1000);
        if(!line) break;
        
        FURI_LOG_I(TAG, "RX: '%s'", line);
        
        // Skip echo
        if(strncmp(line, "show_pass", 9) == 0) continue;
        
        // Must start with quote (CSV data)
        if(line[0] != '"') continue;
        if(data->entry_count >= MAX_PORTAL_ENTRIES) continue;
        
        const char* p = line;
        char ssid[33] = {0};
        
        // First field is SSID
        if(!csv_next_quoted_field(&p, ssid, sizeof(ssid))) continue;
        
        PortalEntry* entry = &data->entries[data->entry_count];
        strncpy(entry->ssid, ssid, sizeof(entry->ssid) - 1);
        entry->ssid[sizeof(entry->ssid) - 1] = '\0';
        
        // Remaining fields: variable count, join with ", "
        entry->fields[0] = '\0';
        size_t fields_len = 0;
        char field_buf[80] = {0};
        
        while(csv_next_quoted_field(&p, field_buf, sizeof(field_buf))) {
            size_t flen = strlen(field_buf);
            if(fields_len > 0 && fields_len + 2 < sizeof(entry->fields)) {
                memcpy(entry->fields + fields_len, ", ", 2);
                fields_len += 2;
            }
            if(fields_len + flen < sizeof(entry->fields)) {
                memcpy(entry->fields + fields_len, field_buf, flen);
                fields_len += flen;
            }
            entry->fields[fields_len] = '\0';
        }
        
        data->entry_count++;
        FURI_LOG_I(TAG, "Entry %u: '%s' -> '%s'", data->entry_count, ssid, entry->fields);
    }
    
    data->data_loaded = true;
    FURI_LOG_I(TAG, "Loaded %u entries", data->entry_count);
    return 0;
}

// ============================================================================
// Drawing
// ============================================================================

static void portal_data_draw(Canvas* canvas, void* model) {
    PortalDataModel* m = (PortalDataModel*)model;
    if(!m || !m->data) return;
    PortalDataData* data = m->data;
    
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    screen_draw_title(canvas, "Portal Data");
    
    canvas_set_font(canvas, FontSecondary);
    
    if(!data->data_loaded) {
        screen_draw_centered_text(canvas, "Loading...", 36);
        return;
    }
    
    if(data->entry_count == 0) {
        screen_draw_centered_text(canvas, "No portal data found", 36);
        return;
    }
    
    // One entry per page: SSID on first line, each field on its own line
    PortalEntry* entry = &data->entries[data->selected_idx];
    
    // Line 1: SSID (bold)
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 2, 24, entry->ssid);
    canvas_set_font(canvas, FontSecondary);
    
    // Lines 2+: each field on its own line, splitting by ", "
    const char* fp = entry->fields;
    uint8_t field_y = 35;
    while(*fp && field_y <= 55) {
        const char* sep = strstr(fp, ", ");
        size_t len;
        if(sep) {
            len = sep - fp;
        } else {
            len = strlen(fp);
        }
        
        char field_line[22];
        size_t copy_len = len < sizeof(field_line) - 1 ? len : sizeof(field_line) - 1;
        memcpy(field_line, fp, copy_len);
        field_line[copy_len] = '\0';
        canvas_draw_str(canvas, 4, field_y, field_line);
        field_y += 9;
        
        if(sep) {
            fp = sep + 2;
        } else {
            break;
        }
    }
    
    // Counter at bottom right
    char indicator[16];
    snprintf(indicator, sizeof(indicator), "%u/%u", data->selected_idx + 1, data->entry_count);
    canvas_draw_str(canvas, 96, 64, indicator);
}

// ============================================================================
// Input Handling
// ============================================================================

static bool portal_data_input(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;
    
    PortalDataModel* m = view_get_model(view);
    if(!m || !m->data) {
        view_commit_model(view, false);
        return false;
    }
    PortalDataData* data = m->data;
    
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
    }
    
    view_commit_model(view, true);
    return true;
}

// ============================================================================
// Screen Creation
// ============================================================================

View* screen_portal_data_create(WiFiApp* app, void** out_data) {
    PortalDataData* data = (PortalDataData*)malloc(sizeof(PortalDataData));
    if(!data) return NULL;
    
    memset(data, 0, sizeof(PortalDataData));
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
    
    view_allocate_model(view, ViewModelTypeLocking, sizeof(PortalDataModel));
    PortalDataModel* m = view_get_model(view);
    if(!m) {
        free(data);
        view_free(view);
        return NULL;
    }
    m->data = data;
    view_commit_model(view, true);
    
    view_set_draw_callback(view, portal_data_draw);
    view_set_input_callback(view, portal_data_input);
    view_set_context(view, view);
    
    // Start thread to fetch data from board
    data->thread = furi_thread_alloc();
    furi_thread_set_name(data->thread, "PortalData");
    furi_thread_set_stack_size(data->thread, 2048);
    furi_thread_set_callback(data->thread, portal_data_thread);
    furi_thread_set_context(data->thread, data);
    furi_thread_start(data->thread);
    
    if(out_data) *out_data = data;
    return view;
}
