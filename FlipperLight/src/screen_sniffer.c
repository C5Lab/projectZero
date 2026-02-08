/**
 * Sniffer Screen
 * 
 * Passive packet capture with Results and Probes views.
 * Sends: select_networks [nums...] -> start_sniffer
 * Left = Results (show_sniffer_results), Right = Probes (show_probes)
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

#define MAX_RESULTS_LINES 20
#define MAX_LINE_LEN 40

typedef struct {
    WiFiApp* app;
    volatile bool running;
    volatile bool attack_finished;
    uint32_t packet_count;
    uint8_t display_mode;       // 0 = counter, 1 = results, 2 = probes
    
    // Results/Probes storage
    char results[MAX_RESULTS_LINES][MAX_LINE_LEN];
    uint8_t results_count;
    char probes[MAX_RESULTS_LINES][MAX_LINE_LEN];
    uint8_t probes_count;
    uint8_t scroll_offset;
    uint8_t selected_result;    // For Results list selection
    uint8_t selected_probe;     // For Probes list selection
    
    FuriThread* thread;
} SnifferData;

typedef struct {
    SnifferData* data;
} SnifferModel;

// ============================================================================
// Cleanup
// ============================================================================

static void sniffer_cleanup_internal(View* view, void* data) {
    UNUSED(view);
    SnifferData* d = (SnifferData*)data;
    if(!d) return;
    
    d->running = false;
    d->attack_finished = true;
    if(d->thread) {
        furi_thread_join(d->thread);
        furi_thread_free(d->thread);
    }
    free(d);
}

// ============================================================================
// Helper - Get network name
// ============================================================================

static const char* get_network_name(WiFiApp* app, uint32_t idx_one_based) {
    if(!app || !app->scan_results || idx_one_based == 0 || idx_one_based > app->scan_result_count) {
        return "(unknown)";
    }
    const char* name = app->scan_results[idx_one_based - 1].ssid;
    return (name && name[0]) ? name : "(hidden)";
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
    
    if(data->display_mode == 0) {
        // Counter mode
        screen_draw_title(canvas, "Sniffer");
        
        canvas_set_font(canvas, FontSecondary);
        
        // Show target networks (first 2)
        uint8_t y = 20;
        uint8_t shown = 0;
        for(uint32_t i = 0; i < data->app->selected_count && shown < 2; i++) {
            const char* name = get_network_name(data->app, data->app->selected_networks[i]);
            canvas_draw_str(canvas, 2, y, name);
            y += 9;
            shown++;
        }
        
        // Packet counter - large centered
        canvas_set_font(canvas, FontBigNumbers);
        char count_str[16];
        snprintf(count_str, sizeof(count_str), "%lu", data->packet_count);
        uint8_t count_width = strlen(count_str) * 10;
        canvas_draw_str(canvas, (128 - count_width) / 2, 48, count_str);
        
        // Navigation hints
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str(canvas, 2, 62, "<Results");
        canvas_draw_str(canvas, 88, 62, "Probes>");
        
    } else if(data->display_mode == 1) {
        // Results mode - selectable list
        screen_draw_title(canvas, "Results");
        
        canvas_set_font(canvas, FontSecondary);
        
        if(data->results_count == 0) {
            screen_draw_centered_text(canvas, "No APs with clients", 32);
        } else {
            uint8_t y = 21;  // 1px more spacing under title
            uint8_t max_lines = 4;  // 4 rows to avoid overlap with hint bar
            
            // Adjust scroll to keep selection visible
            if(data->selected_result < data->scroll_offset) {
                data->scroll_offset = data->selected_result;
            } else if(data->selected_result >= data->scroll_offset + max_lines) {
                data->scroll_offset = data->selected_result - max_lines + 1;
            }
            
            for(uint8_t i = data->scroll_offset; i < data->results_count && (i - data->scroll_offset) < max_lines; i++) {
                uint8_t display_y = y + ((i - data->scroll_offset) * 9);
                
                if(i == data->selected_result) {
                    // Highlight selected result
                    canvas_set_color(canvas, ColorBlack);
                    canvas_draw_box(canvas, 0, display_y - 7, 128, 9);
                    canvas_set_color(canvas, ColorWhite);
                    canvas_draw_str(canvas, 2, display_y, data->results[i]);
                    canvas_set_color(canvas, ColorBlack);
                } else {
                    canvas_draw_str(canvas, 2, display_y, data->results[i]);
                }
            }
        }
        
        canvas_draw_str(canvas, 2, 62, "<Back");
        canvas_draw_str(canvas, 76, 62, "OK:Deauth");
        
    } else {
        // Probes mode - selectable list for Karma attack
        screen_draw_title(canvas, "Probes");
        
        canvas_set_font(canvas, FontSecondary);
        
        if(data->probes_count == 0) {
            screen_draw_centered_text(canvas, "No probe requests", 32);
        } else {
            uint8_t y = 21;  // 1px more spacing under title
            uint8_t max_lines = 4;  // 4 rows to avoid overlap with hint bar
            
            // Adjust scroll to keep selection visible
            if(data->selected_probe < data->scroll_offset) {
                data->scroll_offset = data->selected_probe;
            } else if(data->selected_probe >= data->scroll_offset + max_lines) {
                data->scroll_offset = data->selected_probe - max_lines + 1;
            }
            
            for(uint8_t i = data->scroll_offset; i < data->probes_count && (i - data->scroll_offset) < max_lines; i++) {
                uint8_t display_y = y + ((i - data->scroll_offset) * 9);
                
                if(i == data->selected_probe) {
                    // Highlight selected probe
                    canvas_set_color(canvas, ColorBlack);
                    canvas_draw_box(canvas, 0, display_y - 7, 128, 9);
                    canvas_set_color(canvas, ColorWhite);
                    canvas_draw_str(canvas, 2, display_y, data->probes[i]);
                    canvas_set_color(canvas, ColorBlack);
                } else {
                    canvas_draw_str(canvas, 2, display_y, data->probes[i]);
                }
            }
        }
        
        canvas_draw_str(canvas, 2, 62, "<Back");
        canvas_draw_str(canvas, 78, 62, "OK:Karma");
    }
}

// ============================================================================
// Load Results from UART
// ============================================================================

// Helper: check if SSID matches any selected network
static bool is_ssid_selected(WiFiApp* app, const char* ssid) {
    if(!app || !ssid || !app->scan_results) return false;
    for(uint32_t i = 0; i < app->selected_count; i++) {
        uint32_t idx = app->selected_networks[i];
        if(idx == 0 || idx > app->scan_result_count) continue;
        const char* sel_ssid = app->scan_results[idx - 1].ssid;
        if(sel_ssid && strcmp(sel_ssid, ssid) == 0) return true;
    }
    return false;
}

static void load_results(SnifferData* data) {
    WiFiApp* app = data->app;
    
    data->results_count = 0;
    uart_clear_buffer(app);
    uart_send_command(app, "show_sniffer_results");
    furi_delay_ms(200);
    
    // Parse output
    // Format: "SSID, CH#: count" followed by MAC addresses
    bool include_current = false;
    uint32_t start = furi_get_tick();
    while((furi_get_tick() - start) < 3000 && data->results_count < MAX_RESULTS_LINES) {
        const char* line = uart_read_line(app, 500);
        if(!line) continue;
        
        // Skip command echo and prompt
        if(strstr(line, "show_sniffer") || line[0] == '>') continue;
        if(strstr(line, "No APs")) {
            strncpy(data->results[0], "No APs with clients", MAX_LINE_LEN - 1);
            data->results_count = 1;
            break;
        }
        
        // Check if this is a network header line (contains ", CH")
        const char* ch_marker = strstr(line, ", CH");
        if(ch_marker) {
            // Extract SSID (everything before ", CH") and check if selected
            char ssid[33] = {0};
            size_t ssid_len = ch_marker - line;
            if(ssid_len >= sizeof(ssid)) ssid_len = sizeof(ssid) - 1;
            strncpy(ssid, line, ssid_len);
            ssid[ssid_len] = '\0';
            include_current = is_ssid_selected(app, ssid);
        }
        
        // Only store if current network is selected
        if(include_current) {
            strncpy(data->results[data->results_count], line, MAX_LINE_LEN - 1);
            data->results[data->results_count][MAX_LINE_LEN - 1] = '\0';
            data->results_count++;
        }
    }
}

static void load_probes(SnifferData* data) {
    WiFiApp* app = data->app;
    
    data->probes_count = 0;
    uart_clear_buffer(app);
    uart_send_command(app, "show_probes");
    furi_delay_ms(200);
    
    // Parse output
    // Format: "Probe requests: N" followed by "SSID (MAC)"
    uint32_t start = furi_get_tick();
    bool past_header = false;
    while((furi_get_tick() - start) < 3000 && data->probes_count < MAX_RESULTS_LINES) {
        const char* line = uart_read_line(app, 500);
        if(!line) continue;
        
        // Skip command echo and prompt
        if(strstr(line, "show_probes") || line[0] == '>') continue;
        
        // Skip header line "Probe requests: N"
        if(strstr(line, "Probe requests:")) {
            past_header = true;
            continue;
        }
        
        if(!past_header) continue;
        
        // Store line (truncate if needed)
        strncpy(data->probes[data->probes_count], line, MAX_LINE_LEN - 1);
        data->probes[data->probes_count][MAX_LINE_LEN - 1] = '\0';
        data->probes_count++;
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
    
    if(data->display_mode == 0) {
        // Counter mode
        if(event->key == InputKeyBack) {
            data->running = false;
            data->attack_finished = true;
            uart_send_command(data->app, "stop");
            view_commit_model(view, false);
            screen_pop_to_main(data->app);
            return true;
        } else if(event->key == InputKeyLeft) {
            // Results
            data->running = false;
            uart_send_command(data->app, "stop");
            furi_delay_ms(300);
            load_results(data);
            data->scroll_offset = 0;
            data->selected_result = 0;
            data->display_mode = 1;
        } else if(event->key == InputKeyRight) {
            // Probes
            data->running = false;
            uart_send_command(data->app, "stop");
            furi_delay_ms(300);
            load_probes(data);
            data->scroll_offset = 0;
            data->selected_probe = 0;
            data->display_mode = 2;
        }
    } else if(data->display_mode == 1) {
        // Results mode - selectable list
        if(event->key == InputKeyBack || event->key == InputKeyLeft) {
            // Back to counter, restart sniffer
            data->scroll_offset = 0;
            data->selected_result = 0;
            data->display_mode = 0;
            uart_send_command(data->app, "start_sniffer_noscan");
            data->running = true;
        } else if(event->key == InputKeyUp) {
            if(data->selected_result > 0) data->selected_result--;
        } else if(event->key == InputKeyDown) {
            if(data->selected_result + 1 < data->results_count) data->selected_result++;
        } else if(event->key == InputKeyOk) {
            // Deauth single client - check if selected line is a client MAC
            const char* sel_line = data->results[data->selected_result];
            if(sel_line && !strstr(sel_line, ", CH")) {
                // This is a client MAC line - find parent network
                char ssid[33] = {0};
                uint8_t channel = 0;
                uint8_t net_ordinal = 0;

                // Walk backwards to find parent network header
                for(int j = (int)data->selected_result - 1; j >= 0; j--) {
                    const char* ch_marker = strstr(data->results[j], ", CH");
                    if(ch_marker) {
                        // Extract SSID (everything before ", CH")
                        size_t ssid_len = ch_marker - data->results[j];
                        if(ssid_len >= sizeof(ssid)) ssid_len = sizeof(ssid) - 1;
                        strncpy(ssid, data->results[j], ssid_len);
                        ssid[ssid_len] = '\0';

                        // Extract channel (number after "CH" before ":")
                        channel = (uint8_t)atoi(ch_marker + 4);

                        // Count ordinal (how many network headers up to j)
                        for(int k = 0; k <= j; k++) {
                            if(strstr(data->results[k], ", CH")) {
                                net_ordinal++;
                            }
                        }
                        break;
                    }
                }

                if(net_ordinal > 0) {
                    // Extract MAC from the client line (trim spaces)
                    const char* mac_str = sel_line;
                    while(*mac_str == ' ') mac_str++;
                    char mac[18] = {0};
                    strncpy(mac, mac_str, sizeof(mac) - 1);
                    // Trim trailing spaces/newlines
                    size_t ml = strlen(mac);
                    while(ml > 0 && (mac[ml-1] == ' ' || mac[ml-1] == '\n' || mac[ml-1] == '\r')) {
                        mac[--ml] = '\0';
                    }

                    WiFiApp* app = data->app;
                    view_commit_model(view, false);

                    void* deauth_data = NULL;
                    View* next = screen_deauth_client_create(
                        app, 0, mac, ssid, channel, &deauth_data);
                    if(next) {
                        screen_push_with_cleanup(app, next, deauth_client_cleanup_internal, deauth_data);
                    }
                    return true;
                }
            }
        }
    } else {
        // Probes mode - selectable list
        if(event->key == InputKeyBack || event->key == InputKeyLeft) {
            // Back to counter, restart sniffer
            data->scroll_offset = 0;
            data->selected_probe = 0;
            data->display_mode = 0;
            uart_send_command(data->app, "start_sniffer_noscan");
            data->running = true;
        } else if(event->key == InputKeyUp) {
            if(data->selected_probe > 0) data->selected_probe--;
        } else if(event->key == InputKeyDown) {
            if(data->selected_probe + 1 < data->probes_count) data->selected_probe++;
        } else if(event->key == InputKeyOk) {
            // Launch Karma attack with selected probe SSID
            if(data->probes_count > 0) {
                // Extract SSID from probe line (format: "SSID (MAC)")
                char probe_ssid[64] = {0};
                const char* probe_line = data->probes[data->selected_probe];
                const char* paren = strstr(probe_line, " (");
                if(paren) {
                    size_t len = paren - probe_line;
                    if(len >= sizeof(probe_ssid)) len = sizeof(probe_ssid) - 1;
                    strncpy(probe_ssid, probe_line, len);
                    probe_ssid[len] = '\0';
                } else {
                    strncpy(probe_ssid, probe_line, sizeof(probe_ssid) - 1);
                    probe_ssid[sizeof(probe_ssid) - 1] = '\0';
                }

                WiFiApp* app = data->app;
                view_commit_model(view, false);

                void* karma_data = NULL;
                View* next = screen_karma_probe_create(app, probe_ssid, &karma_data);
                if(next) {
                    screen_push_with_cleanup(app, next, karma_probe_cleanup_internal, karma_data);
                }
                return true;
            }
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
    
    furi_delay_ms(200);
    uart_clear_buffer(app);
    
    // Build select_networks command
    char cmd[256];
    size_t pos = snprintf(cmd, sizeof(cmd), "select_networks");
    for(uint32_t i = 0; i < app->selected_count; i++) {
        pos += snprintf(cmd + pos, sizeof(cmd) - pos, " %lu", (unsigned long)app->selected_networks[i]);
    }
    
    uart_send_command(app, cmd);
    furi_delay_ms(500);
    uart_clear_buffer(app);
    
    // Start sniffer (noscan - networks already selected above)
    uart_send_command(app, "start_sniffer_noscan");
    data->running = true;
    
    // Monitor for packet count updates
    // Format: "Sniffer packet count: N"
    while(!data->attack_finished) {
        if(data->running) {
            const char* line = uart_read_line(app, 500);
            if(line) {
                const char* count_marker = strstr(line, "Sniffer packet count:");
                if(count_marker) {
                    count_marker += 21; // Skip marker
                    while(*count_marker == ' ') count_marker++;
                    data->packet_count = (uint32_t)strtol(count_marker, NULL, 10);
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

View* screen_sniffer_create(WiFiApp* app, void** out_data) {
    SnifferData* data = (SnifferData*)malloc(sizeof(SnifferData));
    if(!data) return NULL;
    
    data->app = app;
    data->running = false;
    data->attack_finished = false;
    data->packet_count = 0;
    data->display_mode = 0;
    data->results_count = 0;
    data->probes_count = 0;
    data->scroll_offset = 0;
    data->selected_result = 0;
    data->selected_probe = 0;
    memset(data->results, 0, sizeof(data->results));
    memset(data->probes, 0, sizeof(data->probes));
    data->thread = NULL;
    
    View* view = view_alloc();
    if(!view) {
        free(data);
        return NULL;
    }
    
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
