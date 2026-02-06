/**
 * Portal Attack Screen
 * 
 * Custom SSID captive portal.
 * Commands: list_sd, select_html, start_portal
 * 
 * Flow:
 * 1. User presses OK to open TextInput for SSID
 * 2. Select HTML file from list
 * 3. Run portal attack
 */

#include "app.h"
#include "uart_comm.h"
#include "screen.h"
#include <gui/modules/text_input.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <furi.h>

#define TAG "Portal"

// ============================================================================
// Data Structures
// ============================================================================

#define PORTAL_MAX_HTML_FILES 20
#define PORTAL_SSID_MAX_LEN 32
#define PORTAL_TEXT_INPUT_VIEW_ID 999  // High ID to avoid conflicts

typedef struct PortalData PortalData;

struct PortalData {
    WiFiApp* app;
    volatile bool attack_finished;
    uint8_t state;  // 0=waiting for SSID input, 1=select HTML, 2=running
    char ssid[PORTAL_SSID_MAX_LEN + 1];
    char** html_files;
    uint8_t html_file_count;
    uint8_t html_selection;
    bool html_loaded;
    uint32_t submit_count;
    char last_data[64];
    FuriThread* thread;
    TextInput* text_input;
    bool ssid_entered;
    bool text_input_shown;
    View* main_view;
};

typedef struct {
    PortalData* data;
} PortalModel;

// ============================================================================
// Cleanup
// ============================================================================

static void portal_cleanup_internal(View* view, void* data) {
    UNUSED(view);
    PortalData* d = (PortalData*)data;
    if(!d) return;
    
    FURI_LOG_I(TAG, "Cleanup starting");
    
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
    
    // Remove TextInput from dispatcher if it was added
    if(d->text_input) {
        view_dispatcher_remove_view(d->app->view_dispatcher, PORTAL_TEXT_INPUT_VIEW_ID);
        text_input_free(d->text_input);
    }
    
    free(d);
    FURI_LOG_I(TAG, "Cleanup complete");
}

void portal_screen_cleanup(View* view, void* data) {
    portal_cleanup_internal(view, data);
}

// ============================================================================
// TextInput callback - called when user confirms SSID
// ============================================================================

static void portal_ssid_result_callback(void* context) {
    PortalData* data = (PortalData*)context;
    if(!data || !data->app) return;
    
    FURI_LOG_I(TAG, "SSID entered: %s", data->ssid);
    
    // SSID is now in data->ssid buffer
    data->ssid_entered = true;
    data->state = 1;  // Move to HTML selection
    
    // Switch back to the Portal main view using its stored ID
    uint32_t main_view_id = screen_get_current_view_id();
    FURI_LOG_I(TAG, "Switching back to main view ID %lu", (unsigned long)main_view_id);
    view_dispatcher_switch_to_view(data->app->view_dispatcher, main_view_id);
}

static void portal_show_text_input(PortalData* data) {
    if(!data || !data->text_input || data->text_input_shown) return;

    FURI_LOG_I(TAG, "Showing TextInput");
    data->text_input_shown = true;

    // Add TextInput view to dispatcher
    View* ti_view = text_input_get_view(data->text_input);
    view_dispatcher_add_view(data->app->view_dispatcher, PORTAL_TEXT_INPUT_VIEW_ID, ti_view);

    // Switch to TextInput
    view_dispatcher_switch_to_view(data->app->view_dispatcher, PORTAL_TEXT_INPUT_VIEW_ID);
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
        // Auto-show TextInput on first entry
        if(!data->text_input_shown) {
            portal_show_text_input(data);
            return;
        }

        // Prompt to enter SSID
        screen_draw_title(canvas, "Portal");
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
        
        // Show entered SSID at top
        char ssid_line[48];
        snprintf(ssid_line, sizeof(ssid_line), "SSID: %s", data->ssid);
        canvas_draw_str(canvas, 2, 21, ssid_line);
        
        if(!data->html_loaded) {
            screen_draw_centered_text(canvas, "Loading files...", 40);
        } else if(data->html_file_count == 0) {
            screen_draw_centered_text(canvas, "No HTML files on SD", 40);
        } else {
            uint8_t y = 30;
            uint8_t max_visible = 4;
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
        screen_draw_title(canvas, "Portal Active");
        canvas_set_font(canvas, FontSecondary);
        
        char line[48];
        snprintf(line, sizeof(line), "AP: %s", data->ssid);
        canvas_draw_str(canvas, 2, 24, line);
        
        snprintf(line, sizeof(line), "Submissions: %lu", data->submit_count);
        canvas_draw_str(canvas, 2, 38, line);
        
        if(data->last_data[0]) {
            canvas_draw_str(canvas, 2, 52, "Last:");
            // Truncate if too long
            char truncated[24];
            strncpy(truncated, data->last_data, 23);
            truncated[23] = '\0';
            canvas_draw_str(canvas, 2, 62, truncated);
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
    
    if(event->type != InputTypeShort && event->type != InputTypeRepeat) {
        view_commit_model(view, false);
        return false;
    }
    
    if(data->state == 0) {
        // Waiting for SSID input
        if(event->key == InputKeyOk) {
            portal_show_text_input(data);
            view_commit_model(view, false);
            return true;
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
                FURI_LOG_I(TAG, "Selected HTML file %u: %s", data->html_selection, 
                    data->html_files[data->html_selection]);
                data->state = 2;  // Start attack
            }
        } else if(event->key == InputKeyBack) {
            view_commit_model(view, false);
            screen_pop(data->app);
            return true;
        }
    } else if(data->state == 2) {
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
    
    FURI_LOG_I(TAG, "Thread started, waiting for SSID");
    
    // Wait for SSID to be entered
    while(!data->ssid_entered && !data->attack_finished) {
        furi_delay_ms(100);
    }
    if(data->attack_finished) {
        FURI_LOG_I(TAG, "Thread aborted before SSID");
        return 0;
    }
    
    FURI_LOG_I(TAG, "SSID ready: %s, loading HTML files", data->ssid);
    
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
            FURI_LOG_I(TAG, "list_sd: %s", line);
            
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
                            FURI_LOG_I(TAG, "Added HTML: %s", name);
                        }
                    }
                }
            }
        }
    }
    data->html_loaded = true;
    FURI_LOG_I(TAG, "Loaded %u HTML files", data->html_file_count);
    
    // Wait for HTML selection
    while(data->state == 1 && !data->attack_finished) {
        furi_delay_ms(100);
    }
    if(data->attack_finished) {
        FURI_LOG_I(TAG, "Thread aborted before HTML selection");
        return 0;
    }
    
    // Send select_html command
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "select_html %u", data->html_selection + 1);
    FURI_LOG_I(TAG, "Sending: %s", cmd);
    uart_send_command(app, cmd);
    furi_delay_ms(500);
    uart_clear_buffer(app);
    
    // Start portal
    snprintf(cmd, sizeof(cmd), "start_portal %s", data->ssid);
    FURI_LOG_I(TAG, "Sending: %s", cmd);
    uart_send_command(app, cmd);
    
    // Monitor for submissions
    FURI_LOG_I(TAG, "Monitoring for submissions");
    while(!data->attack_finished) {
        const char* line = uart_read_line(app, 500);
        if(line && line[0]) {
            FURI_LOG_I(TAG, "RX: %s", line);
            
            // Check for password submission
            const char* pwd = strstr(line, "Password:");
            if(pwd) {
                pwd += 9;  // Skip "Password:"
                while(*pwd == ' ') pwd++;
                strncpy(data->last_data, pwd, sizeof(data->last_data) - 1);
                data->last_data[sizeof(data->last_data) - 1] = '\0';
                data->submit_count++;
                FURI_LOG_I(TAG, "Password captured: %s (total: %lu)", 
                    data->last_data, data->submit_count);
            }
        }
        furi_delay_ms(100);
    }
    
    FURI_LOG_I(TAG, "Thread finished");
    return 0;
}

// ============================================================================
// Screen Creation
// ============================================================================

View* portal_screen_create(WiFiApp* app, void** out_data) {
    FURI_LOG_I(TAG, "Creating Portal screen");
    
    PortalData* data = (PortalData*)malloc(sizeof(PortalData));
    if(!data) return NULL;
    
    memset(data, 0, sizeof(PortalData));
    data->app = app;
    data->attack_finished = false;
    data->state = 0;
    data->ssid_entered = false;
    data->text_input_shown = false;
    data->html_files = NULL;
    data->html_file_count = 0;
    data->html_selection = 0;
    data->html_loaded = false;
    data->submit_count = 0;
    
    // Create main view
    View* view = view_alloc();
    if(!view) {
        free(data);
        return NULL;
    }
    data->main_view = view;
    
    view_allocate_model(view, ViewModelTypeLocking, sizeof(PortalModel));
    PortalModel* m = view_get_model(view);
    m->data = data;
    view_commit_model(view, true);
    
    view_set_draw_callback(view, portal_draw);
    view_set_input_callback(view, portal_input);
    view_set_context(view, view);
    
    // Create TextInput for SSID entry
    data->text_input = text_input_alloc();
    if(data->text_input) {
        text_input_set_header_text(data->text_input, "Enter Portal SSID:");
        text_input_set_result_callback(
            data->text_input,
            portal_ssid_result_callback,
            data,
            data->ssid,
            PORTAL_SSID_MAX_LEN,
            true  // clear default text
        );
        FURI_LOG_I(TAG, "TextInput created");
    }
    
    // Start thread
    data->thread = furi_thread_alloc();
    furi_thread_set_name(data->thread, "Portal");
    furi_thread_set_stack_size(data->thread, 2048);
    furi_thread_set_callback(data->thread, portal_thread);
    furi_thread_set_context(data->thread, data);
    furi_thread_start(data->thread);
    
    if(out_data) *out_data = data;
    
    FURI_LOG_I(TAG, "Portal screen created");
    return view;
}
