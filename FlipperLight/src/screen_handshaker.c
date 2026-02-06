/**
 * Handshaker Attack Screen
 * 
 * Captures WPA handshakes from selected networks.
 * Sends: select_networks [nums...] -> start_handshake
 * Parses UART for handshake completion messages.
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

#define MAX_CAPTURED_HANDSHAKES 10

typedef struct {
    char ssid[33];
} CapturedHandshake;

typedef struct {
    WiFiApp* app;
    volatile bool attack_finished;
    uint32_t handshake_count;
    CapturedHandshake captured[MAX_CAPTURED_HANDSHAKES];
    FuriThread* thread;
} HandshakerData;

typedef struct {
    HandshakerData* data;
} HandshakerModel;

// ============================================================================
// Cleanup
// ============================================================================

static void handshaker_cleanup_internal(View* view, void* data) {
    UNUSED(view);
    HandshakerData* d = (HandshakerData*)data;
    if(!d) return;
    
    d->attack_finished = true;
    if(d->thread) {
        furi_thread_join(d->thread);
        furi_thread_free(d->thread);
    }
    free(d);
}

// ============================================================================
// Helper - Get network name by index
// ============================================================================

static const char* get_network_name(WiFiApp* app, uint32_t idx_one_based) {
    if(!app || !app->scan_results || idx_one_based == 0 || idx_one_based > app->scan_result_count) {
        return "(unknown)";
    }
    const char* name = app->scan_results[idx_one_based - 1].ssid;
    return (name && name[0]) ? name : "(hidden)";
}

// ============================================================================
// Drawing
// ============================================================================

static void handshaker_draw(Canvas* canvas, void* model) {
    HandshakerModel* m = (HandshakerModel*)model;
    if(!m || !m->data) return;
    HandshakerData* data = m->data;
    WiFiApp* app = data->app;
    
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    screen_draw_title(canvas, "Handshaker");
    
    canvas_set_font(canvas, FontSecondary);
    
    // Show target networks (first 2)
    uint8_t y = 22;
    canvas_draw_str(canvas, 2, y, "Targets:");
    y += 10;
    
    uint8_t shown = 0;
    for(uint32_t i = 0; i < app->selected_count && shown < 2; i++) {
        const char* name = get_network_name(app, app->selected_networks[i]);
        char line[32];
        snprintf(line, sizeof(line), " %.20s", name);
        canvas_draw_str(canvas, 2, y, line);
        y += 9;
        shown++;
    }
    if(app->selected_count > 2) {
        char more[24];
        snprintf(more, sizeof(more), " +%lu more", (unsigned long)(app->selected_count - 2));
        canvas_draw_str(canvas, 2, y, more);
        y += 9;
    }
    
    // Show capture status
    y = 52;
    if(data->handshake_count > 0) {
        char status[64];
        snprintf(status, sizeof(status), "Captured: %lu", data->handshake_count);
        canvas_draw_str(canvas, 2, y, status);
        
        // Show last captured SSID
        if(data->handshake_count <= MAX_CAPTURED_HANDSHAKES) {
            const char* last_ssid = data->captured[data->handshake_count - 1].ssid;
            canvas_draw_str(canvas, 2, 62, last_ssid);
        }
    } else {
        canvas_draw_str(canvas, 2, y, "Waiting for handshake...");
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
    
    furi_delay_ms(200);
    uart_clear_buffer(app);
    
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
    // Looking for: "Complete 4-way handshake saved for SSID: [SSID]"
    while(!data->attack_finished) {
        const char* line = uart_read_line(app, 500);
        if(line) {
            // Check for complete handshake message
            const char* marker = strstr(line, "Complete 4-way handshake saved for SSID:");
            if(marker) {
                // Extract SSID
                marker += 41; // Skip past the marker text
                while(*marker == ' ') marker++; // Skip whitespace
                
                if(data->handshake_count < MAX_CAPTURED_HANDSHAKES) {
                    // Copy SSID until space or end (MAC info follows in parentheses)
                    char* dest = data->captured[data->handshake_count].ssid;
                    size_t i = 0;
                    while(*marker && *marker != '(' && i < 32) {
                        dest[i++] = *marker++;
                    }
                    // Trim trailing space
                    while(i > 0 && dest[i-1] == ' ') i--;
                    dest[i] = '\0';
                    
                    data->handshake_count++;
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
    HandshakerData* data = (HandshakerData*)malloc(sizeof(HandshakerData));
    if(!data) return NULL;
    
    data->app = app;
    data->attack_finished = false;
    data->handshake_count = 0;
    memset(data->captured, 0, sizeof(data->captured));
    data->thread = NULL;
    
    View* view = view_alloc();
    if(!view) {
        free(data);
        return NULL;
    }
    
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
