/**
 * Scan Time Settings Screen
 * 
 * Allows editing channel scan time min/max values.
 * Reads current values via: channel_time read min / channel_time read max
 * Saves via: channel_time set min <ms> / channel_time set max <ms>
 * 
 * Validation: both in [100, 1500], min < max
 * Left/Right adjust by 50
 */

#include "app.h"
#include "uart_comm.h"
#include "screen.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <furi.h>

#define TAG "ScanTime"

#define SCAN_TIME_MIN_LIMIT 100
#define SCAN_TIME_MAX_LIMIT 1500
#define SCAN_TIME_STEP 50
#define SCAN_TIME_DEFAULT_MIN 200
#define SCAN_TIME_DEFAULT_MAX 400

// ============================================================================
// Data Structures
// ============================================================================

typedef struct {
    WiFiApp* app;
    volatile bool should_exit;
    volatile bool values_loaded;
    int32_t min_val;
    int32_t max_val;
    uint8_t selected_field; // 0=min, 1=max
    FuriThread* thread;
} ScanTimeData;

typedef struct {
    ScanTimeData* data;
} ScanTimeModel;

// ============================================================================
// Cleanup
// ============================================================================

void scan_time_cleanup_internal(View* view, void* data) {
    UNUSED(view);
    ScanTimeData* d = (ScanTimeData*)data;
    if(!d) return;
    
    FURI_LOG_I(TAG, "Scan time cleanup starting");
    d->should_exit = true;
    if(d->thread) {
        furi_thread_join(d->thread);
        furi_thread_free(d->thread);
    }
    free(d);
    FURI_LOG_I(TAG, "Scan time cleanup complete");
}

// ============================================================================
// UART Read Thread
// ============================================================================

// Read UART response, skipping echo lines.
// Reads lines in a loop until a numeric response is found or timeout.
static int scan_time_read_value(WiFiApp* app, const char* command, int default_val) {
    uart_send_command(app, command);
    
    uint32_t deadline = furi_get_tick() + 2000;
    while(furi_get_tick() < deadline) {
        const char* line = uart_read_line(app, 500);
        if(!line) break;
        
        FURI_LOG_I(TAG, "RX after '%s': '%s'", command, line);
        
        // Skip echo lines (start with "channel_time")
        if(strncmp(line, "channel_time", 12) == 0) {
            continue;
        }
        
        // Try to parse as number
        int val = atoi(line);
        if(val >= SCAN_TIME_MIN_LIMIT && val <= SCAN_TIME_MAX_LIMIT) {
            return val;
        }
        
        // Non-echo, non-numeric line - skip
        FURI_LOG_W(TAG, "Unexpected response: '%s'", line);
    }
    
    return default_val;
}

static int32_t scan_time_read_thread(void* context) {
    ScanTimeData* data = (ScanTimeData*)context;
    WiFiApp* app = data->app;
    
    if(data->should_exit) return 0;
    
    uart_clear_buffer(app);
    
    // Read min value
    data->min_val = scan_time_read_value(app, "channel_time read min", SCAN_TIME_DEFAULT_MIN);
    FURI_LOG_I(TAG, "min_val = %ld", (long)data->min_val);
    
    if(data->should_exit) return 0;
    
    // Read max value
    data->max_val = scan_time_read_value(app, "channel_time read max", SCAN_TIME_DEFAULT_MAX);
    FURI_LOG_I(TAG, "max_val = %ld", (long)data->max_val);
    
    data->values_loaded = true;
    return 0;
}

// ============================================================================
// Drawing
// ============================================================================

static void scan_time_draw(Canvas* canvas, void* model) {
    ScanTimeModel* m = (ScanTimeModel*)model;
    if(!m || !m->data) return;
    ScanTimeData* data = m->data;
    
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    screen_draw_title(canvas, "Scan Time");
    
    canvas_set_font(canvas, FontSecondary);
    
    if(!data->values_loaded) {
        screen_draw_centered_text(canvas, "Reading...", 36);
        return;
    }
    
    char line[32];
    
    // Min field
    snprintf(line, sizeof(line), "%s Min: %ld ms", 
             data->selected_field == 0 ? ">" : " ", 
             (long)data->min_val);
    canvas_draw_str(canvas, 2, 28, line);
    
    // Max field
    snprintf(line, sizeof(line), "%s Max: %ld ms", 
             data->selected_field == 1 ? ">" : " ", 
             (long)data->max_val);
    canvas_draw_str(canvas, 2, 40, line);
    
    // Instructions
    canvas_draw_str(canvas, 2, 56, "Left/Right: +/-50");
    canvas_draw_str(canvas, 2, 64, "OK: Save  Back: Cancel");
}

// ============================================================================
// Input Handling
// ============================================================================

static bool scan_time_input(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;
    
    ScanTimeModel* m = view_get_model(view);
    if(!m || !m->data) {
        view_commit_model(view, false);
        return false;
    }
    ScanTimeData* data = m->data;
    
    if(event->type != InputTypePress && event->type != InputTypeRepeat) {
        view_commit_model(view, false);
        return false;
    }
    
    // Block input until values are loaded
    if(!data->values_loaded) {
        if(event->key == InputKeyBack) {
            view_commit_model(view, false);
            screen_pop(data->app);
            return true;
        }
        view_commit_model(view, false);
        return true;
    }
    
    if(event->key == InputKeyUp) {
        if(data->selected_field > 0) data->selected_field--;
    } else if(event->key == InputKeyDown) {
        if(data->selected_field < 1) data->selected_field++;
    } else if(event->key == InputKeyLeft) {
        // Decrease selected value by 50
        if(data->selected_field == 0) {
            int32_t new_val = data->min_val - SCAN_TIME_STEP;
            if(new_val >= SCAN_TIME_MIN_LIMIT) {
                data->min_val = new_val;
            }
        } else {
            int32_t new_val = data->max_val - SCAN_TIME_STEP;
            if(new_val >= SCAN_TIME_MIN_LIMIT) {
                data->max_val = new_val;
            }
        }
    } else if(event->key == InputKeyRight) {
        // Increase selected value by 50
        if(data->selected_field == 0) {
            int32_t new_val = data->min_val + SCAN_TIME_STEP;
            if(new_val <= SCAN_TIME_MAX_LIMIT) {
                data->min_val = new_val;
            }
        } else {
            int32_t new_val = data->max_val + SCAN_TIME_STEP;
            if(new_val <= SCAN_TIME_MAX_LIMIT) {
                data->max_val = new_val;
            }
        }
    } else if(event->key == InputKeyOk) {
        // Validate: min < max
        if(data->min_val >= data->max_val) {
            // Invalid - don't save, just redraw
            view_commit_model(view, true);
            return true;
        }
        
        // Send commands
        char cmd[48];
        snprintf(cmd, sizeof(cmd), "channel_time set min %ld", (long)data->min_val);
        uart_send_command(data->app, cmd);
        
        snprintf(cmd, sizeof(cmd), "channel_time set max %ld", (long)data->max_val);
        uart_send_command(data->app, cmd);
        
        FURI_LOG_I(TAG, "Saved: min=%ld max=%ld", (long)data->min_val, (long)data->max_val);
        
        view_commit_model(view, false);
        screen_pop(data->app);
        return true;
    } else if(event->key == InputKeyBack) {
        view_commit_model(view, false);
        screen_pop(data->app);
        return true;
    }
    
    view_commit_model(view, true);
    return true;
}

// ============================================================================
// Screen Creation
// ============================================================================

View* screen_settings_scan_time_create(WiFiApp* app, void** out_data) {
    ScanTimeData* data = (ScanTimeData*)malloc(sizeof(ScanTimeData));
    if(!data) return NULL;
    
    data->app = app;
    data->should_exit = false;
    data->values_loaded = false;
    data->min_val = SCAN_TIME_DEFAULT_MIN;
    data->max_val = SCAN_TIME_DEFAULT_MAX;
    data->selected_field = 0;
    data->thread = NULL;
    
    View* view = view_alloc();
    if(!view) {
        free(data);
        return NULL;
    }
    
    view_allocate_model(view, ViewModelTypeLocking, sizeof(ScanTimeModel));
    ScanTimeModel* m = view_get_model(view);
    if(!m) {
        free(data);
        view_free(view);
        return NULL;
    }
    m->data = data;
    view_commit_model(view, true);
    
    view_set_draw_callback(view, scan_time_draw);
    view_set_input_callback(view, scan_time_input);
    view_set_context(view, view);
    
    // Start thread to read current values from board
    data->thread = furi_thread_alloc();
    furi_thread_set_name(data->thread, "ScanTimeRd");
    furi_thread_set_stack_size(data->thread, 2048);
    furi_thread_set_callback(data->thread, scan_time_read_thread);
    furi_thread_set_context(data->thread, data);
    furi_thread_start(data->thread);
    
    if(out_data) *out_data = data;
    return view;
}
