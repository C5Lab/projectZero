/**
 * Sniffer Dog Attack Screen
 * 
 * Deauth sniffer - monitors and reports kicked stations.
 * Command: start_sniffer_dog
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
    uint32_t kick_count;
    char last_sta[20];
    char last_ap[20];
    FuriThread* thread;
} SnifferDogData;

typedef struct {
    SnifferDogData* data;
} SnifferDogModel;

// ============================================================================
// Cleanup
// ============================================================================

void sniffer_dog_screen_cleanup(View* view, void* data) {
    UNUSED(view);
    SnifferDogData* d = (SnifferDogData*)data;
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

static void sniffer_dog_draw(Canvas* canvas, void* model) {
    SnifferDogModel* m = (SnifferDogModel*)model;
    if(!m || !m->data) return;
    SnifferDogData* data = m->data;
    
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    screen_draw_title(canvas, "Sniffer Dog");
    
    canvas_set_font(canvas, FontSecondary);
    
    char line[48];
    snprintf(line, sizeof(line), "Stations kicked: %lu", data->kick_count);
    canvas_draw_str(canvas, 2, 26, line);
    
    if(data->last_sta[0]) {
        snprintf(line, sizeof(line), "STA: %s", data->last_sta);
        canvas_draw_str(canvas, 2, 40, line);
        snprintf(line, sizeof(line), "from AP: %s", data->last_ap);
        canvas_draw_str(canvas, 2, 52, line);
    }
}

// ============================================================================
// Input Handling
// ============================================================================

static bool sniffer_dog_input(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;
    
    SnifferDogModel* m = view_get_model(view);
    if(!m || !m->data) {
        view_commit_model(view, false);
        return false;
    }
    SnifferDogData* data = m->data;
    
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

static int32_t sniffer_dog_thread(void* context) {
    SnifferDogData* data = (SnifferDogData*)context;
    WiFiApp* app = data->app;
    
    furi_delay_ms(200);
    uart_clear_buffer(app);
    uart_send_command(app, "start_sniffer_dog");
    
    // Parse: [SnifferDog #N] DEAUTH sent: AP=XX:XX:XX:XX:XX:XX -> STA=YY:YY:YY:YY:YY:YY
    while(!data->attack_finished) {
        const char* line = uart_read_line(app, 500);
        if(line) {
            const char* marker = strstr(line, "[SnifferDog #");
            if(marker) {
                // Extract count
                marker += 13;
                uint32_t num = (uint32_t)strtol(marker, NULL, 10);
                if(num > data->kick_count) {
                    data->kick_count = num;
                }
                
                // Extract AP
                const char* ap = strstr(line, "AP=");
                if(ap) {
                    ap += 3;
                    size_t i = 0;
                    while(*ap && *ap != ' ' && i < 17) {
                        data->last_ap[i++] = *ap++;
                    }
                    data->last_ap[i] = '\0';
                }
                
                // Extract STA
                const char* sta = strstr(line, "STA=");
                if(sta) {
                    sta += 4;
                    size_t i = 0;
                    while(*sta && *sta != ' ' && i < 17) {
                        data->last_sta[i++] = *sta++;
                    }
                    data->last_sta[i] = '\0';
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

View* sniffer_dog_screen_create(WiFiApp* app, void** out_data) {
    SnifferDogData* data = (SnifferDogData*)malloc(sizeof(SnifferDogData));
    if(!data) return NULL;
    
    data->app = app;
    data->attack_finished = false;
    data->kick_count = 0;
    memset(data->last_sta, 0, sizeof(data->last_sta));
    memset(data->last_ap, 0, sizeof(data->last_ap));
    data->thread = NULL;
    
    View* view = view_alloc();
    if(!view) {
        free(data);
        return NULL;
    }
    
    view_allocate_model(view, ViewModelTypeLocking, sizeof(SnifferDogModel));
    SnifferDogModel* m = view_get_model(view);
    m->data = data;
    view_commit_model(view, true);
    
    view_set_draw_callback(view, sniffer_dog_draw);
    view_set_input_callback(view, sniffer_dog_input);
    view_set_context(view, view);
    
    data->thread = furi_thread_alloc();
    furi_thread_set_name(data->thread, "SnifferDog");
    furi_thread_set_stack_size(data->thread, 2048);
    furi_thread_set_callback(data->thread, sniffer_dog_thread);
    furi_thread_set_context(data->thread, data);
    furi_thread_start(data->thread);
    
    if(out_data) *out_data = data;
    return view;
}
