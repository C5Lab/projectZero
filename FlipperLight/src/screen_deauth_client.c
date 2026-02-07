/**
 * Deauth Single Client Screen
 *
 * Deauthenticates a single client from a specific network.
 * Flow:
 *   1. select_networks <net_index>
 *   2. select_stations <MAC>
 *   3. start_deauth
 *   Back -> stop, return to main menu
 *
 * Memory lifecycle:
 * - screen_deauth_client_create(): Allocates DeauthClientData, thread, view
 * - deauth_client_cleanup_internal(): Frees everything on screen pop
 */

#include "screen_attacks.h"
#include "uart_comm.h"
#include "screen.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <furi.h>

#define TAG "DeauthClient"

// ============================================================================
// Data Structures
// ============================================================================

typedef struct {
    WiFiApp* app;
    volatile bool attack_finished;
    char mac[18];
    char ssid[33];
    uint8_t channel;
    uint8_t net_index; // 1-based ordinal position of network in sniffer results
    FuriThread* thread;
} DeauthClientData;

typedef struct {
    DeauthClientData* data;
} DeauthClientModel;

// ============================================================================
// Cleanup
// ============================================================================

void deauth_client_cleanup_internal(View* view, void* data) {
    UNUSED(view);
    DeauthClientData* d = (DeauthClientData*)data;
    if(!d) return;

    FURI_LOG_I(TAG, "Deauth Client cleanup starting");
    d->attack_finished = true;
    if(d->thread) {
        furi_thread_join(d->thread);
        furi_thread_free(d->thread);
    }
    free(d);
    FURI_LOG_I(TAG, "Deauth Client cleanup complete");
}

// ============================================================================
// Drawing
// ============================================================================

static void deauth_client_draw(Canvas* canvas, void* model) {
    DeauthClientModel* m = (DeauthClientModel*)model;
    if(!m || !m->data) return;
    DeauthClientData* data = m->data;

    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    screen_draw_title(canvas, "Deauthenticating");

    canvas_set_font(canvas, FontSecondary);

    char line[48];
    snprintf(line, sizeof(line), "MAC: %s", data->mac);
    canvas_draw_str(canvas, 2, 28, line);

    snprintf(line, sizeof(line), "from %s ch: %u", data->ssid, data->channel);
    canvas_draw_str(canvas, 2, 42, line);
}

// ============================================================================
// Input Handling
// ============================================================================

static bool deauth_client_input(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;

    DeauthClientModel* m = view_get_model(view);
    if(!m || !m->data) {
        view_commit_model(view, false);
        return false;
    }
    DeauthClientData* data = m->data;

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

static int32_t deauth_client_thread(void* context) {
    DeauthClientData* data = (DeauthClientData*)context;
    WiFiApp* app = data->app;

    FURI_LOG_I(TAG, "Thread started: MAC=%s, SSID=%s, CH=%u, net_index=%u",
        data->mac, data->ssid, data->channel, data->net_index);

    furi_delay_ms(200);
    uart_clear_buffer(app);

    // Step 1: select_networks
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "select_networks %u", data->net_index);
    FURI_LOG_I(TAG, "Sending: %s", cmd);
    uart_send_command(app, cmd);
    furi_delay_ms(500);

    if(data->attack_finished) return 0;

    // Step 2: select_stations
    uart_clear_buffer(app);
    snprintf(cmd, sizeof(cmd), "select_stations %s", data->mac);
    FURI_LOG_I(TAG, "Sending: %s", cmd);
    uart_send_command(app, cmd);
    furi_delay_ms(500);

    if(data->attack_finished) return 0;

    // Step 3: start_deauth
    uart_clear_buffer(app);
    FURI_LOG_I(TAG, "Sending: start_deauth");
    uart_send_command(app, "start_deauth");

    // Monitor until stopped
    while(!data->attack_finished) {
        const char* line = uart_read_line(app, 500);
        if(line) {
            FURI_LOG_I(TAG, "deauth output: %s", line);
            if(strstr(line, "Deauth attack stopped") || strstr(line, "stopped")) {
                data->attack_finished = true;
            }
        }
        furi_delay_ms(50);
    }

    FURI_LOG_I(TAG, "Thread finished");
    return 0;
}

// ============================================================================
// Screen Creation
// ============================================================================

View* screen_deauth_client_create(
    WiFiApp* app,
    uint8_t net_index,
    const char* mac,
    const char* ssid,
    uint8_t channel,
    void** out_data) {

    FURI_LOG_I(TAG, "Creating Deauth Client screen: MAC=%s SSID=%s CH=%u idx=%u",
        mac, ssid, channel, net_index);

    DeauthClientData* data = (DeauthClientData*)malloc(sizeof(DeauthClientData));
    if(!data) return NULL;

    memset(data, 0, sizeof(DeauthClientData));
    data->app = app;
    data->attack_finished = false;
    data->net_index = net_index;
    data->channel = channel;

    strncpy(data->mac, mac, sizeof(data->mac) - 1);
    data->mac[sizeof(data->mac) - 1] = '\0';
    strncpy(data->ssid, ssid, sizeof(data->ssid) - 1);
    data->ssid[sizeof(data->ssid) - 1] = '\0';

    View* view = view_alloc();
    if(!view) {
        free(data);
        return NULL;
    }

    view_allocate_model(view, ViewModelTypeLocking, sizeof(DeauthClientModel));
    DeauthClientModel* m = view_get_model(view);
    m->data = data;
    view_commit_model(view, true);

    view_set_draw_callback(view, deauth_client_draw);
    view_set_input_callback(view, deauth_client_input);
    view_set_context(view, view);

    // Start thread
    data->thread = furi_thread_alloc();
    furi_thread_set_name(data->thread, "DeauthCli");
    furi_thread_set_stack_size(data->thread, 2048);
    furi_thread_set_callback(data->thread, deauth_client_thread);
    furi_thread_set_context(data->thread, data);
    furi_thread_start(data->thread);

    if(out_data) *out_data = data;

    FURI_LOG_I(TAG, "Deauth Client screen created");
    return view;
}
