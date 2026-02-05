/**
 * SAE Overflow Attack Screen
 * 
 * Memory lifecycle:
 * - screen_sae_overflow_create(): Allocates SAEData, View
 * - sae_cleanup(): Called by screen_pop, frees all allocated resources
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
    uint8_t state;              // 0 = initializing, 1 = attack running
    volatile bool attack_finished;
    char target_ssid[64];
    uint32_t target_channel;
    char target_bssid[32];
} SAEData;

typedef struct {
    SAEData* data;
} SAEModel;

// ============================================================================
// Cleanup - Frees all screen resources
// ============================================================================

static void sae_cleanup(View* view, void* data) {
    UNUSED(view);
    SAEData* d = (SAEData*)data;
    if(!d) return;
    
    d->attack_finished = true;
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
        if(data->app->selected_count == 1) {
            screen_draw_centered_text(canvas, "Starting attack...", 32);
            data->state = 1;
        } else {
            screen_draw_centered_text(canvas, "Error: Select", 32);
            screen_draw_centered_text(canvas, "exactly 1 network", 42);
        }
    } else {
        screen_draw_centered_text(canvas, "Attack Running", 32);
        screen_draw_status(canvas, "SSID: ", 48);
        canvas_draw_str(canvas, 40, 48, data->target_ssid);
        
        char info[64];
        snprintf(info, sizeof(info), "Ch: %lu BSSID: %s", data->target_channel, data->target_bssid);
        screen_draw_status(canvas, info, 58);
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
// Screen Creation
// ============================================================================

View* screen_sae_overflow_create(WiFiApp* app, void** out_data) {
    // Allocate screen data
    SAEData* data = (SAEData*)malloc(sizeof(SAEData));
    if(!data) return NULL;
    
    data->app = app;
    data->state = 0;
    data->attack_finished = false;
    memset(data->target_ssid, 0, sizeof(data->target_ssid));
    memset(data->target_bssid, 0, sizeof(data->target_bssid));
    data->target_channel = 0;
    
    // Allocate view
    View* view = view_alloc();
    if(!view) {
        free(data);
        return NULL;
    }
    
    // Setup view model
    view_allocate_model(view, ViewModelTypeLocking, sizeof(SAEModel));
    SAEModel* m = view_get_model(view);
    m->data = data;
    view_commit_model(view, true);
    
    view_set_draw_callback(view, sae_draw);
    view_set_input_callback(view, sae_input);
    view_set_context(view, view);
    
    if(out_data) *out_data = data;
    return view;
}

void sae_overflow_cleanup(View* view, void* data) {
    sae_cleanup(view, data);
}
