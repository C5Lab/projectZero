/**
 * Deauth Attack Screen
 * 
 * Memory lifecycle:
 * - screen_deauth_create(): Allocates DeauthData, FuriString, FuriThread, View
 * - deauth_cleanup(): Called by screen_pop, frees all allocated resources
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

struct DeauthData {
    WiFiApp* app;
    uint8_t state;                  // 0 = sending select_networks, 1 = attack running
    volatile bool attack_finished;
    FuriString* status_message;
    FuriThread* thread;
};

typedef struct {
    DeauthData* data;
} DeauthModel;

// ============================================================================
// Cleanup - Frees all screen resources
// ============================================================================

void deauth_cleanup(View* view, void* data) {
    UNUSED(view);
    DeauthData* d = (DeauthData*)data;
    if(!d) return;
    
    // Signal thread to stop and wait
    d->attack_finished = true;
    if(d->thread) {
        furi_thread_join(d->thread);
        furi_thread_free(d->thread);
    }
    
    // Free string resources
    if(d->status_message) {
        furi_string_free(d->status_message);
    }
    
    free(d);
}

// ============================================================================
// Drawing
// ============================================================================

static void deauth_draw(Canvas* canvas, void* model) {
    DeauthModel* m = (DeauthModel*)model;
    if(!m || !m->data) return;
    DeauthData* data = m->data;
    
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    screen_draw_title(canvas, "Deauth Attack");
    
    canvas_set_font(canvas, FontSecondary);
    
    if(data->state == 0) {
        screen_draw_centered_text(canvas, "Initializing...", 32);
    } else {
        screen_draw_centered_text(canvas, "Attack Running", 32);
        
        char info[32];
        snprintf(info, sizeof(info), "Targets: %lu networks", data->app->selected_count);
        screen_draw_centered_text(canvas, info, 48);
    }
}

// ============================================================================
// Input Handling
// ============================================================================

static bool deauth_input(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;
    
    DeauthModel* m = view_get_model(view);
    if(!m || !m->data) {
        view_commit_model(view, false);
        return false;
    }
    DeauthData* data = m->data;
    
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

static int32_t deauth_attack_thread(void* context) {
    DeauthData* data = (DeauthData*)context;
    WiFiApp* app = data->app;
    
    data->state = 0;
    furi_delay_ms(200);
    uart_clear_buffer(app);
    
    // Build select_networks command
    char cmd[256];
    size_t pos = snprintf(cmd, sizeof(cmd), "select_networks");
    for(uint32_t i = 0; i < app->selected_count; i++) {
        pos += snprintf(cmd + pos, sizeof(cmd) - pos, " %lu", (unsigned long)app->selected_networks[i]);
    }
    
    uart_send_command(app, cmd);
    furi_delay_ms(800);
    uart_clear_buffer(app);
    
    // Start deauth attack
    uart_send_command(app, "start_deauth");
    data->state = 1;
    
    // Monitor for completion
    while(!data->attack_finished) {
        const char* line = uart_read_line(app, 500);
        if(line) {
            furi_string_set(data->status_message, line);
            if(strstr(line, "Deauth attack stopped") || strstr(line, "stopped")) {
                data->attack_finished = true;
            }
        }
        furi_delay_ms(50);
    }
    
    return 0;
}

// ============================================================================
// Screen Creation
// ============================================================================

View* screen_deauth_create(WiFiApp* app, DeauthData** out_data) {
    // Allocate screen data
    DeauthData* data = (DeauthData*)malloc(sizeof(DeauthData));
    if(!data) return NULL;
    
    data->app = app;
    data->state = 0;
    data->attack_finished = false;
    data->status_message = furi_string_alloc();
    data->thread = NULL;
    
    // Allocate view
    View* view = view_alloc();
    if(!view) {
        furi_string_free(data->status_message);
        free(data);
        return NULL;
    }
    
    // Setup view model
    view_allocate_model(view, ViewModelTypeLocking, sizeof(DeauthModel));
    DeauthModel* m = view_get_model(view);
    m->data = data;
    view_commit_model(view, true);
    
    view_set_draw_callback(view, deauth_draw);
    view_set_input_callback(view, deauth_input);
    view_set_context(view, view);
    
    // Start attack thread
    data->thread = furi_thread_alloc();
    furi_thread_set_name(data->thread, "DeauthAttack");
    furi_thread_set_stack_size(data->thread, 2048);
    furi_thread_set_callback(data->thread, deauth_attack_thread);
    furi_thread_set_context(data->thread, data);
    furi_thread_start(data->thread);
    
    if(out_data) *out_data = data;
    return view;
}
