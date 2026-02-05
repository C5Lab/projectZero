/**
 * Handshaker Attack Screen
 * 
 * Memory lifecycle:
 * - screen_handshaker_create(): Allocates HandshakerData, FuriStrings, FuriThread, View
 * - handshaker_cleanup(): Called by screen_pop, frees all allocated resources
 */

#include "screen_attacks.h"
#include "uart_comm.h"
#include "screen.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// ============================================================================
// Data Structures
// ============================================================================

typedef struct {
    WiFiApp* app;
    volatile bool attack_finished;
    uint32_t handshake_count;
    FuriString* last_handshake_ssid;
    FuriString* log_buffer;
    FuriThread* thread;
} HandshakerData;

typedef struct {
    HandshakerData* data;
} HandshakerModel;

// ============================================================================
// Cleanup - Frees all screen resources
// ============================================================================

static void handshaker_cleanup_internal(View* view, void* data) {
    UNUSED(view);
    HandshakerData* d = (HandshakerData*)data;
    if(!d) return;
    
    // Signal thread to stop and wait
    d->attack_finished = true;
    if(d->thread) {
        furi_thread_join(d->thread);
        furi_thread_free(d->thread);
    }
    
    // Free string resources
    if(d->last_handshake_ssid) furi_string_free(d->last_handshake_ssid);
    if(d->log_buffer) furi_string_free(d->log_buffer);
    
    free(d);
}

// ============================================================================
// Drawing
// ============================================================================

static void handshaker_draw(Canvas* canvas, void* model) {
    HandshakerModel* m = (HandshakerModel*)model;
    if(!m || !m->data) return;
    HandshakerData* data = m->data;
    
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    screen_draw_title(canvas, "Handshaker");
    
    canvas_set_font(canvas, FontSecondary);
    screen_draw_centered_text(canvas, "Attack Running", 32);
    
    char status[128];
    snprintf(status, sizeof(status), "Captures: %lu", data->handshake_count);
    screen_draw_centered_text(canvas, status, 48);
    
    if(furi_string_size(data->last_handshake_ssid) > 0) {
        snprintf(status, sizeof(status), "Last: %s", furi_string_get_cstr(data->last_handshake_ssid));
        screen_draw_centered_text(canvas, status, 58);
    }
}

// ============================================================================
// Input Handling
// ============================================================================

static bool handshaker_input(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;
    
    HandshakerModel* m = view_get_model(view);
    if(!m || !m->data) {
        view_commit_model(view, false);
        return false;
    }
    HandshakerData* data = m->data;
    
    if(event->type != InputTypeShort) {
        view_commit_model(view, false);
        return false;
    }
    
    if(event->key == InputKeyBack) {
        data->attack_finished = true;
        uart_send_command(data->app, "stop");
        view_commit_model(view, false);
        screen_pop_to_main(data->app);
        return true;
    }

    view_commit_model(view, false);
    return true;
}

// ============================================================================
// Attack Thread
// ============================================================================

static int32_t handshaker_thread(void* context) {
    HandshakerData* data = (HandshakerData*)context;
    WiFiApp* app = data->app;
    
    // Build select_networks command
    char cmd[256];
    size_t pos = snprintf(cmd, sizeof(cmd), "select_networks");
    for(uint32_t i = 0; i < app->selected_count; i++) {
        pos += snprintf(cmd + pos, sizeof(cmd) - pos, " %lu", (unsigned long)app->selected_networks[i]);
    }
    
    uart_send_command(app, cmd);
    furi_delay_ms(500);
    uart_clear_buffer(app);
    
    // Start handshaker attack
    uart_send_command(app, "start_handshake");
    
    // Monitor for handshakes
    while(!data->attack_finished) {
        const char* line = uart_read_line(app, 1000);
        if(line) {
            furi_string_cat_str(data->log_buffer, line);
            furi_string_cat_str(data->log_buffer, "\n");
            
            if(strstr(line, "Complete 4-way handshake saved for SSID:")) {
                data->handshake_count++;
                const char* ssid_start = strstr(line, "SSID: ");
                if(ssid_start) {
                    ssid_start += 6;
                    const char* ssid_end = strstr(ssid_start, " (");
                    if(ssid_end) {
                        furi_string_set_strn(data->last_handshake_ssid, ssid_start, ssid_end - ssid_start);
                    }
                }
            }
        }
        furi_delay_ms(100);
    }
    
    return 0;
}

// ============================================================================
// Screen Creation
// ============================================================================

View* screen_handshaker_create(WiFiApp* app, void** out_data) {
    // Allocate screen data
    HandshakerData* data = (HandshakerData*)malloc(sizeof(HandshakerData));
    if(!data) return NULL;
    
    data->app = app;
    data->attack_finished = false;
    data->handshake_count = 0;
    data->last_handshake_ssid = furi_string_alloc();
    data->log_buffer = furi_string_alloc();
    data->thread = NULL;
    
    // Allocate view
    View* view = view_alloc();
    if(!view) {
        furi_string_free(data->last_handshake_ssid);
        furi_string_free(data->log_buffer);
        free(data);
        return NULL;
    }
    
    // Setup view model
    view_allocate_model(view, ViewModelTypeLocking, sizeof(HandshakerModel));
    HandshakerModel* m = view_get_model(view);
    m->data = data;
    view_commit_model(view, true);
    
    view_set_draw_callback(view, handshaker_draw);
    view_set_input_callback(view, handshaker_input);
    view_set_context(view, view);
    
    // Start attack thread
    data->thread = furi_thread_alloc();
    furi_thread_set_name(data->thread, "Handshaker");
    furi_thread_set_stack_size(data->thread, 2048);
    furi_thread_set_callback(data->thread, handshaker_thread);
    furi_thread_set_context(data->thread, data);
    furi_thread_start(data->thread);
    
    if(out_data) *out_data = data;
    return view;
}

void handshaker_cleanup(View* view, void* data) {
    handshaker_cleanup_internal(view, data);
}
