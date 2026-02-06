/**
 * SAE Overflow Attack Screen
 * 
 * Requires exactly 1 network selected.
 * Sends: select_networks [num] -> start_sae_overflow
 * Displays: SSID, Channel, BSSID of attacked network
 */

#include "screen_attacks.h"
#include "uart_comm.h"
#include "screen.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <furi.h>

#define TAG "SAEOverflow"

// ============================================================================
// Data Structures
// ============================================================================

typedef struct {
    WiFiApp* app;
    uint8_t state;              // 0 = checking, 1 = attack running
    volatile bool attack_finished;
    char target_ssid[33];
    uint8_t target_channel;
    char target_bssid[18];
    FuriThread* thread;
} SAEData;

typedef struct {
    SAEData* data;
} SAEModel;

// ============================================================================
// Cleanup
// ============================================================================

static void sae_cleanup_internal(View* view, void* data) {
    UNUSED(view);
    SAEData* d = (SAEData*)data;
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

static void sae_draw(Canvas* canvas, void* model) {
    SAEModel* m = (SAEModel*)model;
    if(!m || !m->data) return;
    SAEData* data = m->data;
    
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    screen_draw_title(canvas, "SAE Overflow");
    
    canvas_set_font(canvas, FontSecondary);
    
    if(data->state == 0) {
        // Check if exactly 1 network selected
        if(data->app->selected_count != 1) {
            screen_draw_centered_text(canvas, "Error:", 28);
            screen_draw_centered_text(canvas, "Select exactly", 40);
            screen_draw_centered_text(canvas, "1 network", 52);
        } else {
            screen_draw_centered_text(canvas, "Starting...", 32);
        }
    } else {
        // Attack running - show target info
        screen_draw_centered_text(canvas, "Attack Running", 24);
        
        char line[64];
        snprintf(line, sizeof(line), "SSID: %s", data->target_ssid);
        canvas_draw_str(canvas, 2, 38, line);
        
        snprintf(line, sizeof(line), "Channel: %u", data->target_channel);
        canvas_draw_str(canvas, 2, 50, line);
        
        snprintf(line, sizeof(line), "BSSID: %s", data->target_bssid);
        canvas_draw_str(canvas, 2, 62, line);
    }
}

// ============================================================================
// Input Handling
// ============================================================================

static bool sae_input(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;
    
    SAEModel* m = view_get_model(view);
    if(!m || !m->data) {
        view_commit_model(view, false);
        return false;
    }
    SAEData* data = m->data;
    
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

static int32_t sae_attack_thread(void* context) {
    SAEData* data = (SAEData*)context;
    WiFiApp* app = data->app;
    
    FURI_LOG_I(TAG, "Thread started");
    
    // Check if exactly 1 network selected
    if(app->selected_count != 1) {
        FURI_LOG_E(TAG, "Error: selected_count=%lu, need exactly 1", (unsigned long)app->selected_count);
        // Stay in state 0 - error will be displayed
        return 0;
    }
    
    FURI_LOG_I(TAG, "Exactly 1 network selected, proceeding");
    
    // Get target network info
    uint32_t target_idx = app->selected_networks[0];
    FURI_LOG_I(TAG, "Target index: %lu", (unsigned long)target_idx);
    
    if(target_idx > 0 && target_idx <= app->scan_result_count) {
        WiFiNetwork* net = &app->scan_results[target_idx - 1];
        strncpy(data->target_ssid, net->ssid[0] ? net->ssid : "(hidden)", sizeof(data->target_ssid) - 1);
        data->target_channel = net->channel;
        strncpy(data->target_bssid, net->bssid, sizeof(data->target_bssid) - 1);
        FURI_LOG_I(TAG, "Target: SSID=%s, CH=%u, BSSID=%s", data->target_ssid, data->target_channel, data->target_bssid);
    } else {
        FURI_LOG_E(TAG, "Invalid target_idx=%lu, scan_result_count=%lu", (unsigned long)target_idx, (unsigned long)app->scan_result_count);
    }
    
    // Initial delay and clear buffer
    FURI_LOG_I(TAG, "Initial delay...");
    furi_delay_ms(300);
    uart_clear_buffer(app);
    furi_delay_ms(100);
    
    // Send select_networks command
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "select_networks %lu", (unsigned long)target_idx);
    FURI_LOG_I(TAG, "Sending: %s", cmd);
    uart_send_command(app, cmd);
    
    // Longer delay for command processing
    FURI_LOG_I(TAG, "Waiting 800ms for command processing...");
    furi_delay_ms(800);
    uart_clear_buffer(app);
    furi_delay_ms(100);
    
    // Start SAE overflow attack
    FURI_LOG_I(TAG, "Sending: sae_overflow");
    uart_send_command(app, "sae_overflow");
    data->state = 1;
    FURI_LOG_I(TAG, "Attack started, state=1");
    
    // Monitor for completion
    while(!data->attack_finished) {
        const char* line = uart_read_line(app, 500);
        if(line && line[0]) {
            FURI_LOG_I(TAG, "UART RX: %s", line);
            // Parse any status updates
            if(strstr(line, "stopped")) {
                FURI_LOG_I(TAG, "Received 'stopped', finishing attack");
                data->attack_finished = true;
            }
        }
        furi_delay_ms(100);
    }
    
    FURI_LOG_I(TAG, "Thread exiting");
    return 0;
}

// ============================================================================
// Screen Creation
// ============================================================================

View* screen_sae_overflow_create(WiFiApp* app, void** out_data) {
    SAEData* data = (SAEData*)malloc(sizeof(SAEData));
    if(!data) return NULL;
    
    data->app = app;
    data->state = 0;
    data->attack_finished = false;
    memset(data->target_ssid, 0, sizeof(data->target_ssid));
    memset(data->target_bssid, 0, sizeof(data->target_bssid));
    data->target_channel = 0;
    data->thread = NULL;
    
    View* view = view_alloc();
    if(!view) {
        free(data);
        return NULL;
    }
    
    view_allocate_model(view, ViewModelTypeLocking, sizeof(SAEModel));
    SAEModel* m = view_get_model(view);
    m->data = data;
    view_commit_model(view, true);
    
    view_set_draw_callback(view, sae_draw);
    view_set_input_callback(view, sae_input);
    view_set_context(view, view);
    
    // Start attack thread
    data->thread = furi_thread_alloc();
    furi_thread_set_name(data->thread, "SAEOverflow");
    furi_thread_set_stack_size(data->thread, 2048);
    furi_thread_set_callback(data->thread, sae_attack_thread);
    furi_thread_set_context(data->thread, data);
    furi_thread_start(data->thread);
    
    if(out_data) *out_data = data;
    return view;
}

void sae_overflow_cleanup(View* view, void* data) {
    sae_cleanup_internal(view, data);
}
