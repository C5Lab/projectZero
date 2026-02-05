/**
 * Sniffer Screen
 * 
 * Memory lifecycle:
 * - screen_sniffer_create(): Allocates SnifferData, FuriStrings, FuriThread, View
 * - sniffer_cleanup(): Called by screen_pop, frees all allocated resources
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
    volatile bool sniffer_running;
    uint32_t packet_count;
    FuriString* results;
    FuriString* probes;
    uint8_t display_mode;       // 0 = counter, 1 = results, 2 = probes
    FuriThread* thread;
} SnifferData;

typedef struct {
    SnifferData* data;
} SnifferModel;

// ============================================================================
// Cleanup - Frees all screen resources
// ============================================================================

static void sniffer_cleanup_internal(View* view, void* data) {
    UNUSED(view);
    SnifferData* d = (SnifferData*)data;
    if(!d) return;
    
    // Signal thread to stop and wait
    d->sniffer_running = false;
    if(d->thread) {
        furi_thread_join(d->thread);
        furi_thread_free(d->thread);
    }
    
    // Free string resources
    if(d->results) furi_string_free(d->results);
    if(d->probes) furi_string_free(d->probes);
    
    free(d);
}

// ============================================================================
// Drawing
// ============================================================================

static void sniffer_draw(Canvas* canvas, void* model) {
    SnifferModel* m = (SnifferModel*)model;
    if(!m || !m->data) return;
    SnifferData* data = m->data;
    
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    screen_draw_title(canvas, "Sniffer");
    
    canvas_set_font(canvas, FontSecondary);
    
    if(data->display_mode == 0) {
        char status[64];
        snprintf(status, sizeof(status), "Packets: %lu", data->packet_count);
        screen_draw_centered_text(canvas, status, 32);
        screen_draw_centered_text(canvas, "Sniffing...", 48);
    } else if(data->display_mode == 1) {
        screen_draw_status(canvas, "APs & Clients:", 22);
        canvas_draw_str(canvas, 2, 32, furi_string_get_cstr(data->results));
    } else {
        screen_draw_status(canvas, "Probe Requests:", 22);
        canvas_draw_str(canvas, 2, 32, furi_string_get_cstr(data->probes));
    }
}

// ============================================================================
// Input Handling
// ============================================================================

static bool sniffer_input(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;
    
    SnifferModel* m = view_get_model(view);
    if(!m || !m->data) {
        view_commit_model(view, false);
        return false;
    }
    SnifferData* data = m->data;
    
    if(event->type != InputTypeShort) {
        view_commit_model(view, false);
        return false;
    }
    
    if(event->key == InputKeyBack) {
        if(data->display_mode > 0) {
            data->display_mode = 0;
            uart_send_command(data->app, "start_sniffer");
            data->sniffer_running = true;
        } else {
            data->sniffer_running = false;
            uart_send_command(data->app, "stop");
            view_commit_model(view, false);
            screen_pop_to_main(data->app);
            return true;
        }
    } else if(event->key == InputKeyLeft && data->display_mode > 0) {
        data->display_mode = 0;
        uart_send_command(data->app, "start_sniffer");
        data->sniffer_running = true;
    } else if(event->key == InputKeyRight) {
        if(data->display_mode == 0) {
            uart_send_command(data->app, "stop");
            furi_delay_ms(500);
            uart_clear_buffer(data->app);
            uart_send_command(data->app, "show_sniffer_results");
            data->display_mode = 1;
            data->sniffer_running = false;
        }
    }

    view_commit_model(view, true);
    return true;
}

// ============================================================================
// Sniffer Thread
// ============================================================================

static int32_t sniffer_thread(void* context) {
    SnifferData* data = (SnifferData*)context;
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
    
    // Start sniffer
    uart_send_command(app, "start_sniffer");
    data->sniffer_running = true;
    
    // Monitor for packet count updates
    while(data->sniffer_running) {
        const char* line = uart_read_line(app, 1000);
        if(line) {
            if(strstr(line, "Sniffer packet count:")) {
                sscanf(line, "Sniffer packet count: %lu", &data->packet_count);
            }
        }
        furi_delay_ms(100);
    }
    
    // After stopping, get results
    const char* result_line = NULL;
    bool reading_results = false;
    while((result_line = uart_read_line(app, 1000)) != NULL) {
        if(strstr(result_line, "show_sniffer_results") || strstr(result_line, ">")) {
            reading_results = true;
            continue;
        }
        if(reading_results) {
            furi_string_cat_str(data->results, result_line);
            furi_string_cat_str(data->results, "\n");
            if(strstr(result_line, "No APs") || strstr(result_line, "^")) {
                break;
            }
        }
    }
    
    // Get probes
    uart_send_command(app, "show_probes");
    bool reading_probes = false;
    while((result_line = uart_read_line(app, 1000)) != NULL) {
        if(strstr(result_line, "Probe requests:") || strstr(result_line, "Probe")) {
            reading_probes = true;
        }
        if(reading_probes) {
            furi_string_cat_str(data->probes, result_line);
            furi_string_cat_str(data->probes, "\n");
        }
    }
    
    return 0;
}

// ============================================================================
// Screen Creation
// ============================================================================

View* screen_sniffer_create(WiFiApp* app, void** out_data) {
    // Allocate screen data
    SnifferData* data = (SnifferData*)malloc(sizeof(SnifferData));
    if(!data) return NULL;
    
    data->app = app;
    data->sniffer_running = false;
    data->packet_count = 0;
    data->display_mode = 0;
    data->results = furi_string_alloc();
    data->probes = furi_string_alloc();
    data->thread = NULL;
    
    // Allocate view
    View* view = view_alloc();
    if(!view) {
        furi_string_free(data->results);
        furi_string_free(data->probes);
        free(data);
        return NULL;
    }
    
    // Setup view model
    view_allocate_model(view, ViewModelTypeLocking, sizeof(SnifferModel));
    SnifferModel* m = view_get_model(view);
    m->data = data;
    view_commit_model(view, true);
    
    view_set_draw_callback(view, sniffer_draw);
    view_set_input_callback(view, sniffer_input);
    view_set_context(view, view);
    
    // Start sniffer thread
    data->thread = furi_thread_alloc();
    furi_thread_set_name(data->thread, "Sniffer");
    furi_thread_set_stack_size(data->thread, 2048);
    furi_thread_set_callback(data->thread, sniffer_thread);
    furi_thread_set_context(data->thread, data);
    furi_thread_start(data->thread);
    
    if(out_data) *out_data = data;
    return view;
}

void sniffer_cleanup(View* view, void* data) {
    sniffer_cleanup_internal(view, data);
}
