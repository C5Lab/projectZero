/**
 * Global Handshaker Attack Screen
 * 
 * Captures handshakes from all visible networks (no select_networks).
 * Command: start_handshake
 */

#include "app.h"
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
    char last_ssid[33];
    FuriThread* thread;
} GlobalHandshakerData;

typedef struct {
    GlobalHandshakerData* data;
} GlobalHandshakerModel;

// ============================================================================
// Cleanup
// ============================================================================

void global_handshaker_screen_cleanup(View* view, void* data) {
    UNUSED(view);
    GlobalHandshakerData* d = (GlobalHandshakerData*)data;
    if(!d) return;
    
    d->attack_finished = true;
    if(d->thread) {
        furi_thread_join(d->thread);
        furi_thread_free(d->thread);
    }
    free(d);
}

// ============================================================================
// Drawing
// ============================================================================

static void global_handshaker_draw(Canvas* canvas, void* model) {
    GlobalHandshakerModel* m = (GlobalHandshakerModel*)model;
    if(!m || !m->data) return;
    GlobalHandshakerData* data = m->data;
    
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    screen_draw_title(canvas, "Global Handshaker");
    
    canvas_set_font(canvas, FontSecondary);
    screen_draw_centered_text(canvas, "Attack Running", 26);
    
    char line[48];
    snprintf(line, sizeof(line), "Total: %lu", data->handshake_count);
    screen_draw_centered_text(canvas, line, 40);
    
    if(data->last_ssid[0]) {
        snprintf(line, sizeof(line), "Last: %.20s", data->last_ssid);
        screen_draw_centered_text(canvas, line, 54);
    }
}

// ============================================================================
// Input Handling
// ============================================================================

static bool global_handshaker_input(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;
    
    GlobalHandshakerModel* m = view_get_model(view);
    if(!m || !m->data) {
        view_commit_model(view, false);
        return false;
    }
    GlobalHandshakerData* data = m->data;
    
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

static int32_t global_handshaker_thread(void* context) {
    GlobalHandshakerData* data = (GlobalHandshakerData*)context;
    WiFiApp* app = data->app;
    
    furi_delay_ms(200);
    uart_clear_buffer(app);
    
    // No select_networks - attack all networks
    uart_send_command(app, "start_handshake");
    
    // Monitor for handshakes
    // Looking for: "Complete 4-way handshake saved for SSID: [SSID]"
    while(!data->attack_finished) {
        const char* line = uart_read_line(app, 500);
        if(line) {
            const char* marker = strstr(line, "Complete 4-way handshake saved for SSID:");
            if(marker) {
                marker += 41;
                while(*marker == ' ') marker++;
                
                // Copy SSID until space or parenthesis
                size_t i = 0;
                while(*marker && *marker != '(' && i < 32) {
                    data->last_ssid[i++] = *marker++;
                }
                while(i > 0 && data->last_ssid[i-1] == ' ') i--;
                data->last_ssid[i] = '\0';
                
                data->handshake_count++;
            }
        }
        furi_delay_ms(100);
    }
    
    return 0;
}

// ============================================================================
// Screen Creation
// ============================================================================

View* global_handshaker_screen_create(WiFiApp* app, void** out_data) {
    GlobalHandshakerData* data = (GlobalHandshakerData*)malloc(sizeof(GlobalHandshakerData));
    if(!data) return NULL;
    
    data->app = app;
    data->attack_finished = false;
    data->handshake_count = 0;
    memset(data->last_ssid, 0, sizeof(data->last_ssid));
    data->thread = NULL;
    
    View* view = view_alloc();
    if(!view) {
        free(data);
        return NULL;
    }
    
    view_allocate_model(view, ViewModelTypeLocking, sizeof(GlobalHandshakerModel));
    GlobalHandshakerModel* m = view_get_model(view);
    m->data = data;
    view_commit_model(view, true);
    
    view_set_draw_callback(view, global_handshaker_draw);
    view_set_input_callback(view, global_handshaker_input);
    view_set_context(view, view);
    
    data->thread = furi_thread_alloc();
    furi_thread_set_name(data->thread, "GHandshaker");
    furi_thread_set_stack_size(data->thread, 2048);
    furi_thread_set_callback(data->thread, global_handshaker_thread);
    furi_thread_set_context(data->thread, data);
    furi_thread_start(data->thread);
    
    if(out_data) *out_data = data;
    return view;
}
