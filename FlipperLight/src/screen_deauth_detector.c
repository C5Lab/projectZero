/**
 * Deauth Detector Screen
 *
 * Monitors WiFi for deauthentication attacks in real-time.
 * - Sends 'deauth_detector' command to start monitoring
 * - Parses incoming deauth events
 * - Displays last 3 events and total counter
 * - Back button sends 'stop' and returns to main menu
 *
 * Memory lifecycle:
 * - screen_deauth_detector_create(): Allocates DeauthDetectorData, thread, view
 * - deauth_detector_cleanup_internal(): Frees everything on screen pop
 */

#include "screen_attacks.h"
#include "uart_comm.h"
#include "screen.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <furi.h>

#define TAG "DeauthDetector"

// ============================================================================
// Data Structures
// ============================================================================

#define MAX_RECENT_EVENTS 3
#define MAX_AP_NAME_LEN 32
#define MAX_BSSID_LEN 18

typedef struct {
    uint8_t channel;
    char ap_name[MAX_AP_NAME_LEN];
    char bssid[MAX_BSSID_LEN];
    int8_t rssi;
} DeauthEvent;

typedef struct {
    WiFiApp* app;
    volatile bool running;
    
    // Event storage - circular buffer for last 3 events
    DeauthEvent events[MAX_RECENT_EVENTS];
    uint8_t event_count; // How many slots are filled (0-3)
    uint32_t total_count; // Total events detected
    
    // Flipper resources
    FuriThread* thread;
    View* view;
} DeauthDetectorData;

typedef struct {
    DeauthDetectorData* data;
} DeauthDetectorModel;

// ============================================================================
// Cleanup
// ============================================================================

static void deauth_detector_cleanup_impl(View* view, void* data) {
    UNUSED(view);
    DeauthDetectorData* d = (DeauthDetectorData*)data;
    if(!d) return;

    FURI_LOG_I(TAG, "Cleanup starting");

    d->running = false;
    if(d->thread) {
        furi_thread_join(d->thread);
        furi_thread_free(d->thread);
    }

    free(d);
    FURI_LOG_I(TAG, "Cleanup complete");
}

void deauth_detector_cleanup_internal(View* view, void* data) {
    deauth_detector_cleanup_impl(view, data);
}

// ============================================================================
// Event Parsing
// ============================================================================

// Parse format: [DEAUTH] CH: 6 | AP: MyNetwork (AA:BB:CC:DD:EE:FF) | RSSI: -45
static bool parse_deauth_event(const char* line, DeauthEvent* event) {
    if(!line || !event) return false;
    
    // Check for [DEAUTH] prefix
    if(strncmp(line, "[DEAUTH]", 8) != 0) return false;
    
    const char* p = line + 8;
    
    // Parse channel: "CH: 6"
    const char* ch_start = strstr(p, "CH:");
    if(!ch_start) return false;
    ch_start += 3;
    while(*ch_start == ' ') ch_start++;
    event->channel = (uint8_t)atoi(ch_start);
    
    // Parse AP name: "AP: MyNetwork (AA:BB:CC:DD:EE:FF)"
    const char* ap_start = strstr(p, "AP:");
    if(!ap_start) return false;
    ap_start += 3;
    while(*ap_start == ' ') ap_start++;
    
    // Find opening parenthesis to get AP name
    const char* paren = strchr(ap_start, '(');
    if(!paren) return false;
    
    // Extract AP name
    size_t ap_len = paren - ap_start;
    while(ap_len > 0 && ap_start[ap_len - 1] == ' ') ap_len--; // Trim trailing spaces
    if(ap_len >= MAX_AP_NAME_LEN) ap_len = MAX_AP_NAME_LEN - 1;
    strncpy(event->ap_name, ap_start, ap_len);
    event->ap_name[ap_len] = '\0';
    
    // Extract BSSID from parentheses
    paren++; // Skip '('
    const char* bssid_end = strchr(paren, ')');
    if(!bssid_end) return false;
    size_t bssid_len = bssid_end - paren;
    if(bssid_len >= MAX_BSSID_LEN) bssid_len = MAX_BSSID_LEN - 1;
    strncpy(event->bssid, paren, bssid_len);
    event->bssid[bssid_len] = '\0';
    
    // Parse RSSI: "RSSI: -45"
    const char* rssi_start = strstr(p, "RSSI:");
    if(!rssi_start) return false;
    rssi_start += 5;
    while(*rssi_start == ' ') rssi_start++;
    event->rssi = (int8_t)atoi(rssi_start);
    
    return true;
}

// ============================================================================
// Drawing
// ============================================================================

static void deauth_detector_draw(Canvas* canvas, void* model) {
    DeauthDetectorModel* m = (DeauthDetectorModel*)model;
    if(!m || !m->data) return;
    DeauthDetectorData* data = m->data;

    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    screen_draw_title(canvas, "Deauth Detector");
    
    canvas_set_font(canvas, FontSecondary);
    
    if(data->event_count == 0) {
        screen_draw_centered_text(canvas, "Monitoring...", 32);
        screen_draw_centered_text(canvas, "Waiting for deauth", 44);
    } else {
        // Display last 3 events (newest first)
        uint8_t y = 20;
        for(int i = data->event_count - 1; i >= 0 && (data->event_count - 1 - i) < MAX_RECENT_EVENTS; i--) {
            DeauthEvent* evt = &data->events[i];
            
            // Line 1: AP name and channel
            char line1[48];
            snprintf(line1, sizeof(line1), "%s (CH:%u)", evt->ap_name, evt->channel);
            canvas_draw_str(canvas, 2, y, line1);
            y += 10;
            
            // Line 2: BSSID and RSSI
            char line2[48];
            snprintf(line2, sizeof(line2), "%s R:%d", evt->bssid, evt->rssi);
            canvas_draw_str(canvas, 2, y, line2);
            y += 12;
            
            if(y > 52) break; // Don't overflow screen
        }
    }
    
    // Show total counter at bottom
    char counter[32];
    snprintf(counter, sizeof(counter), "Total: %lu", (unsigned long)data->total_count);
    canvas_draw_str(canvas, 2, 62, counter);
}

// ============================================================================
// Input Handling
// ============================================================================

static bool deauth_detector_input(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;

    DeauthDetectorModel* m = view_get_model(view);
    if(!m || !m->data) {
        view_commit_model(view, false);
        return false;
    }
    DeauthDetectorData* data = m->data;

    if(event->type != InputTypeShort && event->type != InputTypeRepeat) {
        view_commit_model(view, false);
        return false;
    }

    if(event->key == InputKeyBack) {
        data->running = false;
        uart_send_command(data->app, "stop");
        view_commit_model(view, false);
        screen_pop_to_main(data->app);
        return true;
    }

    view_commit_model(view, false);
    return true;
}

// ============================================================================
// Detector Thread
// ============================================================================

static int32_t deauth_detector_thread(void* context) {
    DeauthDetectorData* data = (DeauthDetectorData*)context;
    if(!data || !data->app) return -1;
    WiFiApp* app = data->app;

    FURI_LOG_I(TAG, "Detector thread started");

    // Start deauth detection
    uart_clear_buffer(app);
    uart_send_command(app, "deauth_detector");
    furi_delay_ms(200);

    // Main loop - read and parse deauth events
    while(data->running) {
        const char* line = uart_read_line(app, 100);
        if(line) {
            FURI_LOG_I(TAG, "Received: %s", line);
            
            DeauthEvent event;
            if(parse_deauth_event(line, &event)) {
                FURI_LOG_I(TAG, "Parsed deauth: CH:%u AP:%s BSSID:%s RSSI:%d",
                    event.channel, event.ap_name, event.bssid, event.rssi);
                
                // Add to circular buffer (shift existing events)
                if(data->event_count < MAX_RECENT_EVENTS) {
                    // Still have room, just add
                    data->events[data->event_count] = event;
                    data->event_count++;
                } else {
                    // Buffer full, shift and add to end
                    for(uint8_t i = 0; i < MAX_RECENT_EVENTS - 1; i++) {
                        data->events[i] = data->events[i + 1];
                    }
                    data->events[MAX_RECENT_EVENTS - 1] = event;
                }
                
                data->total_count++;
            }
        }
    }

    FURI_LOG_I(TAG, "Detector thread finished");
    return 0;
}

// ============================================================================
// Screen Creation
// ============================================================================

View* screen_deauth_detector_create(WiFiApp* app, void** out_data) {
    FURI_LOG_I(TAG, "Creating Deauth Detector screen");

    DeauthDetectorData* data = (DeauthDetectorData*)malloc(sizeof(DeauthDetectorData));
    if(!data) {
        FURI_LOG_E(TAG, "Failed to allocate data");
        return NULL;
    }

    memset(data, 0, sizeof(DeauthDetectorData));
    data->app = app;
    data->running = true;
    data->event_count = 0;
    data->total_count = 0;

    // Create view
    View* view = view_alloc();
    if(!view) {
        free(data);
        return NULL;
    }
    data->view = view;

    view_allocate_model(view, ViewModelTypeLocking, sizeof(DeauthDetectorModel));
    DeauthDetectorModel* m = view_get_model(view);
    m->data = data;
    view_commit_model(view, true);

    view_set_draw_callback(view, deauth_detector_draw);
    view_set_input_callback(view, deauth_detector_input);
    view_set_context(view, view);

    // Start detector thread
    data->thread = furi_thread_alloc();
    if(!data->thread) {
        FURI_LOG_E(TAG, "Failed to allocate thread");
        view_free(view);
        free(data);
        return NULL;
    }
    furi_thread_set_name(data->thread, "DeauthDet");
    furi_thread_set_stack_size(data->thread, 4096);
    furi_thread_set_callback(data->thread, deauth_detector_thread);
    furi_thread_set_context(data->thread, data);
    furi_thread_start(data->thread);

    if(out_data) *out_data = data;

    FURI_LOG_I(TAG, "Deauth Detector screen created");
    return view;
}
