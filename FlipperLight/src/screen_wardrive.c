/**
 * Wardrive Screen
 * 
 * GPS-based network logging.
 * Command: start_wardrive
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
    bool gps_fix;
    char last_log_line[64];
    uint32_t network_count;
    FuriThread* thread;
} WardriveData;

typedef struct {
    WardriveData* data;
} WardriveModel;

// ============================================================================
// Cleanup
// ============================================================================

void wardrive_screen_cleanup(View* view, void* data) {
    UNUSED(view);
    WardriveData* d = (WardriveData*)data;
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

static void wardrive_draw(Canvas* canvas, void* model) {
    WardriveModel* m = (WardriveModel*)model;
    if(!m || !m->data) return;
    WardriveData* data = m->data;
    
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    screen_draw_title(canvas, "Wardrive");
    
    canvas_set_font(canvas, FontSecondary);
    
    if(!data->gps_fix) {
        screen_draw_centered_text(canvas, "Acquiring GPS Fix", 32);
        screen_draw_centered_text(canvas, "Need clear sky view", 44);
    } else {
        char line[48];
        snprintf(line, sizeof(line), "Networks: %lu", data->network_count);
        screen_draw_centered_text(canvas, line, 28);
        
        // Show last log line (truncated)
        if(data->last_log_line[0]) {
            canvas_draw_str(canvas, 2, 44, data->last_log_line);
        }
    }
}

// ============================================================================
// Input Handling
// ============================================================================

static bool wardrive_input(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;
    
    WardriveModel* m = view_get_model(view);
    if(!m || !m->data) {
        view_commit_model(view, false);
        return false;
    }
    WardriveData* data = m->data;
    
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

static int32_t wardrive_thread(void* context) {
    WardriveData* data = (WardriveData*)context;
    WiFiApp* app = data->app;
    
    furi_delay_ms(200);
    uart_clear_buffer(app);
    uart_send_command(app, "start_wardrive");
    
    // Wait for GPS fix and parse logs
    while(!data->attack_finished) {
        const char* line = uart_read_line(app, 500);
        if(line) {
            // Check for GPS fix
            if(strstr(line, "GPS fix obtained")) {
                data->gps_fix = true;
            }
            
            // Parse "Logged N networks to /path/file.log"
            const char* logged = strstr(line, "Logged ");
            if(logged) {
                logged += 7;
                data->network_count = (uint32_t)strtol(logged, NULL, 10);
                
                // Copy the whole line for display
                strncpy(data->last_log_line, line, sizeof(data->last_log_line) - 1);
                data->last_log_line[sizeof(data->last_log_line) - 1] = '\0';
            }
        }
        furi_delay_ms(100);
    }
    
    return 0;
}

// ============================================================================
// Screen Creation
// ============================================================================

View* wardrive_screen_create(WiFiApp* app, void** out_data) {
    WardriveData* data = (WardriveData*)malloc(sizeof(WardriveData));
    if(!data) return NULL;
    
    data->app = app;
    data->attack_finished = false;
    data->gps_fix = false;
    memset(data->last_log_line, 0, sizeof(data->last_log_line));
    data->network_count = 0;
    data->thread = NULL;
    
    View* view = view_alloc();
    if(!view) {
        free(data);
        return NULL;
    }
    
    view_allocate_model(view, ViewModelTypeLocking, sizeof(WardriveModel));
    WardriveModel* m = view_get_model(view);
    m->data = data;
    view_commit_model(view, true);
    
    view_set_draw_callback(view, wardrive_draw);
    view_set_input_callback(view, wardrive_input);
    view_set_context(view, view);
    
    data->thread = furi_thread_alloc();
    furi_thread_set_name(data->thread, "Wardrive");
    furi_thread_set_stack_size(data->thread, 2048);
    furi_thread_set_callback(data->thread, wardrive_thread);
    furi_thread_set_context(data->thread, data);
    furi_thread_start(data->thread);
    
    if(out_data) *out_data = data;
    return view;
}
