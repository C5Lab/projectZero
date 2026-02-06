/**
 * Blackout Attack Screen
 * 
 * Deauths all networks around.
 * Command: start_blackout
 */

#include "app.h"
#include "uart_comm.h"
#include "screen.h"
#include <stdlib.h>
#include <string.h>

// ============================================================================
// Data Structures
// ============================================================================

typedef struct {
    WiFiApp* app;
    volatile bool attack_finished;
    uint8_t state;  // 0=confirm, 1=running
    FuriThread* thread;
} BlackoutData;

typedef struct {
    BlackoutData* data;
} BlackoutModel;

// ============================================================================
// Cleanup
// ============================================================================

static void blackout_cleanup_internal(View* view, void* data) {
    UNUSED(view);
    BlackoutData* d = (BlackoutData*)data;
    if(!d) return;
    
    d->attack_finished = true;
    if(d->thread) {
        furi_thread_join(d->thread);
        furi_thread_free(d->thread);
    }
    free(d);
}

void blackout_screen_cleanup(View* view, void* data) {
    blackout_cleanup_internal(view, data);
}

// ============================================================================
// Drawing
// ============================================================================

static void blackout_draw(Canvas* canvas, void* model) {
    BlackoutModel* m = (BlackoutModel*)model;
    if(!m || !m->data) return;
    BlackoutData* data = m->data;
    
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    screen_draw_title(canvas, "Blackout");
    
    canvas_set_font(canvas, FontSecondary);
    
    if(data->state == 0) {
        // Confirmation screen
        screen_draw_centered_text(canvas, "This will deauth all", 24);
        screen_draw_centered_text(canvas, "networks around you.", 36);
        screen_draw_centered_text(canvas, "Are you sure?", 48);
        canvas_draw_str(canvas, 2, 62, "OK: Yes");
        canvas_draw_str(canvas, 80, 62, "Back: No");
    } else {
        // Attack running
        screen_draw_centered_text(canvas, "Attack in Progress", 32);
        screen_draw_centered_text(canvas, "Press Back to Stop", 50);
    }
}

// ============================================================================
// Input Handling
// ============================================================================

static bool blackout_input(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;
    
    BlackoutModel* m = view_get_model(view);
    if(!m || !m->data) {
        view_commit_model(view, false);
        return false;
    }
    BlackoutData* data = m->data;
    
    if(event->type != InputTypeShort) {
        view_commit_model(view, false);
        return false;
    }
    
    if(data->state == 0) {
        // Confirmation state
        if(event->key == InputKeyOk) {
            data->state = 1;  // Proceed to attack
            view_commit_model(view, true);
            return true;
        } else if(event->key == InputKeyBack) {
            view_commit_model(view, false);
            screen_pop(data->app);
            return true;
        }
    } else {
        // Attack running state
        if(event->key == InputKeyBack) {
            data->attack_finished = true;
            uart_send_command(data->app, "stop");
            view_commit_model(view, false);
            screen_pop_to_main(data->app);
            return true;
        }
    }
    
    view_commit_model(view, false);
    return true;
}

// ============================================================================
// Attack Thread
// ============================================================================

static int32_t blackout_thread(void* context) {
    BlackoutData* data = (BlackoutData*)context;
    WiFiApp* app = data->app;
    
    // Wait for user confirmation
    while(data->state == 0 && !data->attack_finished) {
        furi_delay_ms(100);
    }
    
    if(data->attack_finished) return 0;
    
    // User confirmed - start attack
    furi_delay_ms(200);
    uart_clear_buffer(app);
    uart_send_command(app, "start_blackout");
    
    // Just wait until stopped
    while(!data->attack_finished) {
        furi_delay_ms(100);
    }
    
    return 0;
}

// ============================================================================
// Screen Creation
// ============================================================================

View* blackout_screen_create(WiFiApp* app, void** out_data) {
    BlackoutData* data = (BlackoutData*)malloc(sizeof(BlackoutData));
    if(!data) return NULL;
    
    data->app = app;
    data->attack_finished = false;
    data->state = 0;
    data->thread = NULL;
    
    View* view = view_alloc();
    if(!view) {
        free(data);
        return NULL;
    }
    
    view_allocate_model(view, ViewModelTypeLocking, sizeof(BlackoutModel));
    BlackoutModel* m = view_get_model(view);
    m->data = data;
    view_commit_model(view, true);
    
    view_set_draw_callback(view, blackout_draw);
    view_set_input_callback(view, blackout_input);
    view_set_context(view, view);
    
    data->thread = furi_thread_alloc();
    furi_thread_set_name(data->thread, "Blackout");
    furi_thread_set_stack_size(data->thread, 2048);
    furi_thread_set_callback(data->thread, blackout_thread);
    furi_thread_set_context(data->thread, data);
    furi_thread_start(data->thread);
    
    if(out_data) *out_data = data;
    return view;
}
