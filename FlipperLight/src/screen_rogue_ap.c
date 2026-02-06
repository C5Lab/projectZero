/**
 * Rogue AP Attack Screen
 *
 * Creates a WPA2-protected fake AP with a captive portal HTML page.
 * Flow:
 *   1. select_networks <index>
 *   2. show_pass evil  -> check if password is known
 *   3. (optional) TextInput for password
 *   4. list_sd -> select HTML file
 *   5. start_rogueap <SSID> <password>
 *   6. Monitor client connect / disconnect / password capture
 *
 * Memory lifecycle:
 * - screen_rogue_ap_create(): Allocates RogueApData, strings, thread, view, TextInput
 * - rogue_ap_cleanup_internal(): Frees everything on screen pop
 */

#include "screen_attacks.h"
#include "uart_comm.h"
#include "screen.h"
#include <gui/modules/text_input.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <furi.h>

#define TAG "RogueAP"

// ============================================================================
// Data Structures
// ============================================================================

#define ROGUEAP_MAX_HTML_FILES  20
#define ROGUEAP_PASSWORD_MAX    64
#define ROGUEAP_TEXT_INPUT_ID   998

typedef struct {
    WiFiApp* app;
    volatile bool attack_finished;
    uint8_t state;
    // 0 = checking password (thread)
    // 1 = waiting for password input (TextInput)
    // 2 = select HTML file
    // 3 = attack running

    // Network info
    char ssid[33];
    char password[ROGUEAP_PASSWORD_MAX + 1];
    uint32_t net_index; // 1-based

    // HTML files
    char** html_files;
    uint8_t html_file_count;
    uint8_t html_selection;
    bool html_loaded;

    // Attack status
    uint8_t client_count;
    char last_mac[18];
    char last_password[64];
    bool client_connected;

    // Flipper resources
    FuriThread* thread;
    TextInput* text_input;
    bool text_input_added;
    bool password_entered;
    View* main_view;
} RogueApData;

typedef struct {
    RogueApData* data;
} RogueApModel;

// ============================================================================
// Cleanup
// ============================================================================

static void rogue_ap_cleanup_internal_impl(View* view, void* data) {
    UNUSED(view);
    RogueApData* d = (RogueApData*)data;
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

    if(d->text_input) {
        if(d->text_input_added) {
            view_dispatcher_remove_view(d->app->view_dispatcher, ROGUEAP_TEXT_INPUT_ID);
        }
        text_input_free(d->text_input);
    }

    free(d);
    FURI_LOG_I(TAG, "Cleanup complete");
}

void rogue_ap_cleanup_internal(View* view, void* data) {
    rogue_ap_cleanup_internal_impl(view, data);
}

// ============================================================================
// TextInput callback
// ============================================================================

static void rogue_ap_password_callback(void* context) {
    RogueApData* data = (RogueApData*)context;
    if(!data || !data->app) return;

    FURI_LOG_I(TAG, "Password entered: %s", data->password);
    data->password_entered = true;
    data->state = 2; // Move to HTML selection

    uint32_t main_view_id = screen_get_current_view_id();
    view_dispatcher_switch_to_view(data->app->view_dispatcher, main_view_id);
}

static void rogue_ap_show_text_input(RogueApData* data) {
    if(!data || !data->text_input) return;

    if(!data->text_input_added) {
        View* ti_view = text_input_get_view(data->text_input);
        view_dispatcher_add_view(data->app->view_dispatcher, ROGUEAP_TEXT_INPUT_ID, ti_view);
        data->text_input_added = true;
    }

    view_dispatcher_switch_to_view(data->app->view_dispatcher, ROGUEAP_TEXT_INPUT_ID);
}

// ============================================================================
// Drawing
// ============================================================================

static void rogue_ap_draw(Canvas* canvas, void* model) {
    RogueApModel* m = (RogueApModel*)model;
    if(!m || !m->data) return;
    RogueApData* data = m->data;

    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);

    if(data->state == 0) {
        // Checking password
        screen_draw_title(canvas, "Rogue AP");
        canvas_set_font(canvas, FontSecondary);
        screen_draw_centered_text(canvas, "Checking password...", 32);

    } else if(data->state == 1) {
        // Waiting for password input - TextInput is shown
        screen_draw_title(canvas, "Rogue AP");
        canvas_set_font(canvas, FontSecondary);
        screen_draw_centered_text(canvas, "Enter password", 32);
        if(!data->text_input_added) {
            rogue_ap_show_text_input(data);
        }

    } else if(data->state == 2) {
        // HTML file selection
        screen_draw_title(canvas, "Select HTML");
        canvas_set_font(canvas, FontSecondary);

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

    } else if(data->state == 3) {
        // Attack running
        char title[48];
        snprintf(title, sizeof(title), "Rogue AP %s", data->ssid);
        screen_draw_title(canvas, title);
        canvas_set_font(canvas, FontSecondary);

        char line[48];
        snprintf(line, sizeof(line), "Clients: %u", data->client_count);
        canvas_draw_str(canvas, 2, 24, line);

        if(data->client_connected && data->last_mac[0]) {
            snprintf(line, sizeof(line), "MAC: %s", data->last_mac);
            canvas_draw_str(canvas, 2, 36, line);
        }

        if(data->last_password[0]) {
            canvas_draw_str(canvas, 2, 48, "Password:");
            char truncated[22];
            strncpy(truncated, data->last_password, 21);
            truncated[21] = '\0';
            canvas_draw_str(canvas, 2, 58, truncated);
        }
    }
}

// ============================================================================
// Input Handling
// ============================================================================

static bool rogue_ap_input(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;

    RogueApModel* m = view_get_model(view);
    if(!m || !m->data) {
        view_commit_model(view, false);
        return false;
    }
    RogueApData* data = m->data;

    if(event->type != InputTypeShort && event->type != InputTypeRepeat) {
        view_commit_model(view, false);
        return false;
    }

    if(data->state == 0 || data->state == 1) {
        // Checking password / waiting for TextInput
        if(event->key == InputKeyBack) {
            data->attack_finished = true;
            view_commit_model(view, false);
            screen_pop(data->app);
            return true;
        }
        if(data->state == 1 && event->key == InputKeyOk) {
            rogue_ap_show_text_input(data);
            view_commit_model(view, false);
            return true;
        }
    } else if(data->state == 2) {
        // HTML selection
        if(event->key == InputKeyUp) {
            if(data->html_selection > 0) data->html_selection--;
        } else if(event->key == InputKeyDown) {
            if(data->html_selection + 1 < data->html_file_count) data->html_selection++;
        } else if(event->key == InputKeyOk) {
            if(data->html_file_count > 0) {
                FURI_LOG_I(TAG, "Selected HTML %u: %s", data->html_selection,
                    data->html_files[data->html_selection]);
                data->state = 3;
            }
        } else if(event->key == InputKeyBack) {
            data->attack_finished = true;
            view_commit_model(view, false);
            screen_pop(data->app);
            return true;
        }
    } else if(data->state == 3) {
        // Attack running
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
// Password discovery helper
// ============================================================================

static bool rogue_ap_check_password(RogueApData* data) {
    WiFiApp* app = data->app;

    uart_clear_buffer(app);
    uart_send_command(app, "show_pass evil");
    furi_delay_ms(200);

    uint32_t start = furi_get_tick();
    uint32_t last_rx = start;

    while((furi_get_tick() - last_rx) < 1000 &&
          (furi_get_tick() - start) < 5000 &&
          !data->attack_finished) {
        const char* line = uart_read_line(app, 300);
        if(line) {
            last_rx = furi_get_tick();
            FURI_LOG_I(TAG, "show_pass: %s", line);

            // Parse "SSID", "password"
            const char* p = line;
            // Skip whitespace
            while(*p == ' ' || *p == '\t') p++;
            if(*p != '"') continue;
            p++; // skip opening quote
            const char* ssid_start = p;
            while(*p && *p != '"') p++;
            if(*p != '"') continue;
            size_t ssid_len = p - ssid_start;
            p++; // skip closing quote

            // Skip separator
            while(*p == ',' || *p == ' ' || *p == '\t') p++;

            if(*p != '"') continue;
            p++; // skip opening quote
            const char* pass_start = p;
            while(*p && *p != '"') p++;
            if(*p != '"') continue;
            size_t pass_len = p - pass_start;

            // Compare SSID
            if(ssid_len == strlen(data->ssid) &&
               strncmp(ssid_start, data->ssid, ssid_len) == 0) {
                if(pass_len < sizeof(data->password)) {
                    strncpy(data->password, pass_start, pass_len);
                    data->password[pass_len] = '\0';
                    FURI_LOG_I(TAG, "Password found: %s", data->password);
                    return true;
                }
            }
        }
    }
    return false;
}

// ============================================================================
// Attack Thread
// ============================================================================

static int32_t rogue_ap_thread(void* context) {
    RogueApData* data = (RogueApData*)context;
    WiFiApp* app = data->app;

    FURI_LOG_I(TAG, "Thread started for SSID: %s (index %lu)", data->ssid, (unsigned long)data->net_index);

    // Step 1: select_networks
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "select_networks %lu", (unsigned long)data->net_index);
    uart_send_command(app, cmd);
    furi_delay_ms(500);
    uart_clear_buffer(app);

    if(data->attack_finished) return 0;

    // Step 2: Check if password is known
    data->state = 0;
    bool found = rogue_ap_check_password(data);

    if(data->attack_finished) return 0;

    if(!found) {
        // Need user to enter password
        data->state = 1;
        FURI_LOG_I(TAG, "Password unknown, requesting user input");

        // Wait for password entry
        while(!data->password_entered && !data->attack_finished) {
            furi_delay_ms(100);
        }
        if(data->attack_finished) return 0;
    } else {
        data->state = 2; // skip to HTML selection
    }

    // Step 3: Load HTML files
    FURI_LOG_I(TAG, "Loading HTML files");
    furi_delay_ms(200);
    uart_clear_buffer(app);
    uart_send_command(app, "list_sd");
    furi_delay_ms(100);

    uint32_t start = furi_get_tick();
    uint32_t last_rx = start;
    while((furi_get_tick() - last_rx) < 1000 &&
          (furi_get_tick() - start) < 5000 &&
          !data->attack_finished) {
        const char* line = uart_read_line(app, 300);
        if(line) {
            last_rx = furi_get_tick();
            FURI_LOG_I(TAG, "list_sd: %s", line);

            if(strstr(line, "HTML files") || strstr(line, "SD card")) continue;

            uint32_t idx = 0;
            char name[64] = {0};
            if(sscanf(line, "%lu %63s", &idx, name) == 2 && idx > 0 && name[0]) {
                if(data->html_file_count < ROGUEAP_MAX_HTML_FILES) {
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
    FURI_LOG_I(TAG, "Loaded %u HTML files", data->html_file_count);

    // Wait for user to select HTML
    while(data->state == 2 && !data->attack_finished) {
        furi_delay_ms(100);
    }
    if(data->attack_finished) return 0;

    // Step 4: Send select_html command
    snprintf(cmd, sizeof(cmd), "select_html %u", data->html_selection + 1);
    FURI_LOG_I(TAG, "Sending: %s", cmd);
    uart_send_command(app, cmd);
    furi_delay_ms(500);
    uart_clear_buffer(app);

    // Step 5: Start Rogue AP
    snprintf(cmd, sizeof(cmd), "start_rogueap %s %s", data->ssid, data->password);
    FURI_LOG_I(TAG, "Sending: %s", cmd);
    uart_send_command(app, cmd);

    // Step 6: Monitor output
    FURI_LOG_I(TAG, "Monitoring Rogue AP");
    while(!data->attack_finished) {
        const char* line = uart_read_line(app, 500);
        if(line && line[0]) {
            FURI_LOG_I(TAG, "RX: %s", line);

            // Client connected
            if(strstr(line, "Client connected")) {
                const char* mac = strstr(line, "MAC:");
                if(mac) {
                    mac += 4;
                    while(*mac == ' ') mac++;
                    strncpy(data->last_mac, mac, sizeof(data->last_mac) - 1);
                    data->last_mac[sizeof(data->last_mac) - 1] = '\0';
                }
                data->client_connected = true;
                data->client_count++;
            }

            // Client disconnected
            if(strstr(line, "Client disconnected")) {
                data->client_connected = false;
                if(data->client_count > 0) data->client_count--;
            }

            // Password captured
            const char* pwd = strstr(line, "Password:");
            if(pwd && !strstr(line, "AP Name")) {
                pwd += 9;
                while(*pwd == ' ') pwd++;
                strncpy(data->last_password, pwd, sizeof(data->last_password) - 1);
                data->last_password[sizeof(data->last_password) - 1] = '\0';
                FURI_LOG_I(TAG, "Password captured: %s", data->last_password);
            }

            // Portal data saved
            if(strstr(line, "Portal data saved")) {
                FURI_LOG_I(TAG, "Portal data saved to file");
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

View* screen_rogue_ap_create(WiFiApp* app, void** out_data) {
    FURI_LOG_I(TAG, "Creating Rogue AP screen");

    if(!app || app->selected_count != 1) {
        FURI_LOG_E(TAG, "Exactly 1 network must be selected");
        return NULL;
    }

    RogueApData* data = (RogueApData*)malloc(sizeof(RogueApData));
    if(!data) return NULL;

    memset(data, 0, sizeof(RogueApData));
    data->app = app;
    data->attack_finished = false;
    data->state = 0;
    data->net_index = app->selected_networks[0]; // 1-based
    data->html_files = NULL;
    data->html_file_count = 0;
    data->html_selection = 0;
    data->html_loaded = false;
    data->password_entered = false;
    data->text_input_added = false;
    data->client_count = 0;
    data->client_connected = false;

    // Copy SSID from scan results
    uint32_t idx0 = data->net_index - 1; // 0-based
    if(idx0 < app->scan_result_count && app->scan_results) {
        strncpy(data->ssid, app->scan_results[idx0].ssid, sizeof(data->ssid) - 1);
        data->ssid[sizeof(data->ssid) - 1] = '\0';
    } else {
        strncpy(data->ssid, "Unknown", sizeof(data->ssid) - 1);
    }

    // Create main view
    View* view = view_alloc();
    if(!view) {
        free(data);
        return NULL;
    }
    data->main_view = view;

    view_allocate_model(view, ViewModelTypeLocking, sizeof(RogueApModel));
    RogueApModel* m = view_get_model(view);
    m->data = data;
    view_commit_model(view, true);

    view_set_draw_callback(view, rogue_ap_draw);
    view_set_input_callback(view, rogue_ap_input);
    view_set_context(view, view);

    // Create TextInput for password entry
    data->text_input = text_input_alloc();
    if(data->text_input) {
        text_input_set_header_text(data->text_input, "Enter Password:");
        text_input_set_result_callback(
            data->text_input,
            rogue_ap_password_callback,
            data,
            data->password,
            ROGUEAP_PASSWORD_MAX,
            true);
        FURI_LOG_I(TAG, "TextInput created");
    }

    // Start thread
    data->thread = furi_thread_alloc();
    furi_thread_set_name(data->thread, "RogueAP");
    furi_thread_set_stack_size(data->thread, 2048);
    furi_thread_set_callback(data->thread, rogue_ap_thread);
    furi_thread_set_context(data->thread, data);
    furi_thread_start(data->thread);

    if(out_data) *out_data = data;

    FURI_LOG_I(TAG, "Rogue AP screen created");
    return view;
}
