/**
 * Handshakes Screen
 * 
 * Command: list_dir /sdcard/lab/handshakes
 * Response:
 *   Files in /sdcard/lab/handshakes:
 *   1 filename1.pcap
 *   2 filename1.hccapx
 *   ...
 *   Found N file(s) in /sdcard/lab/handshakes
 * 
 * Only .pcap files are shown, with extension stripped.
 */

#include "app.h"
#include "uart_comm.h"
#include "screen.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <furi.h>

#define TAG "Handshakes"
#define MAX_HANDSHAKE_ENTRIES 32

// ============================================================================
// Data Structures
// ============================================================================

typedef struct {
    char name[80]; // filename without .pcap extension
} HandshakeEntry;

typedef struct {
    WiFiApp* app;
    volatile bool should_exit;
    volatile bool data_loaded;
    HandshakeEntry entries[MAX_HANDSHAKE_ENTRIES];
    uint8_t entry_count;
    uint8_t selected_idx;
    FuriThread* thread;
} HandshakesData;

typedef struct {
    HandshakesData* data;
} HandshakesModel;

// ============================================================================
// Cleanup
// ============================================================================

void handshakes_cleanup_internal(View* view, void* data) {
    UNUSED(view);
    HandshakesData* d = (HandshakesData*)data;
    if(!d) return;
    
    FURI_LOG_I(TAG, "Handshakes cleanup starting");
    d->should_exit = true;
    if(d->thread) {
        furi_thread_join(d->thread);
        furi_thread_free(d->thread);
    }
    free(d);
    FURI_LOG_I(TAG, "Handshakes cleanup complete");
}

// ============================================================================
// UART Read Thread
// ============================================================================

static int32_t handshakes_thread(void* context) {
    HandshakesData* data = (HandshakesData*)context;
    WiFiApp* app = data->app;
    
    if(data->should_exit) return 0;
    
    uart_clear_buffer(app);
    uart_send_command(app, "list_dir /sdcard/lab/handshakes");
    
    uint32_t deadline = furi_get_tick() + 5000;
    while(furi_get_tick() < deadline && !data->should_exit) {
        const char* line = uart_read_line(app, 1000);
        if(!line) break;
        
        FURI_LOG_I(TAG, "RX: '%s'", line);
        
        // Skip echo
        if(strncmp(line, "list_dir", 8) == 0) continue;
        // Skip header "Files in ..."
        if(strncmp(line, "Files in", 8) == 0) continue;
        // Stop at footer "Found N file(s) ..."
        if(strncmp(line, "Found", 5) == 0) break;
        
        if(data->entry_count >= MAX_HANDSHAKE_ENTRIES) continue;
        
        // Lines are: "<number> <filename>"
        // Skip the number and space(s)
        const char* p = line;
        while(*p >= '0' && *p <= '9') p++;
        while(*p == ' ') p++;
        
        if(*p == '\0') continue;
        
        // Only interested in .pcap files (not .hccapx)
        const char* ext = strstr(p, ".pcap");
        if(!ext) continue;
        
        // Make sure it ends with .pcap (not .pcapng or similar)
        // and it's not .hccapx that contains "pcap" substring
        size_t fname_len = strlen(p);
        if(fname_len < 5) continue;
        
        // Check the file ends exactly with ".pcap"
        if(strcmp(p + fname_len - 5, ".pcap") != 0) continue;
        
        // Store name without .pcap extension
        HandshakeEntry* entry = &data->entries[data->entry_count];
        size_t name_len = fname_len - 5; // strip ".pcap"
        if(name_len >= sizeof(entry->name)) {
            name_len = sizeof(entry->name) - 1;
        }
        memcpy(entry->name, p, name_len);
        entry->name[name_len] = '\0';
        data->entry_count++;
        
        FURI_LOG_I(TAG, "Handshake %u: '%s'", data->entry_count, entry->name);
    }
    
    data->data_loaded = true;
    FURI_LOG_I(TAG, "Loaded %u handshakes", data->entry_count);
    return 0;
}

// ============================================================================
// Drawing
// ============================================================================

static void handshakes_draw(Canvas* canvas, void* model) {
    HandshakesModel* m = (HandshakesModel*)model;
    if(!m || !m->data) return;
    HandshakesData* data = m->data;
    
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    screen_draw_title(canvas, "Handshakes");
    
    canvas_set_font(canvas, FontSecondary);
    
    if(!data->data_loaded) {
        screen_draw_centered_text(canvas, "Loading...", 36);
        return;
    }
    
    if(data->entry_count == 0) {
        screen_draw_centered_text(canvas, "No handshakes found", 36);
        return;
    }
    
    const uint8_t item_height = 9;
    const uint8_t start_y = 22;
    const uint8_t max_visible = 5;
    
    uint8_t first_idx = 0;
    if(data->selected_idx >= max_visible) {
        first_idx = data->selected_idx - (max_visible - 1);
    }
    
    for(uint8_t i = 0; i < max_visible && (first_idx + i) < data->entry_count; i++) {
        uint8_t idx = first_idx + i;
        uint8_t y = start_y + (i * item_height);
        
        HandshakeEntry* entry = &data->entries[idx];
        
        if(idx == data->selected_idx) {
            canvas_set_color(canvas, ColorBlack);
            canvas_draw_box(canvas, 0, y - 8, 128, item_height);
            canvas_set_color(canvas, ColorWhite);
        } else {
            canvas_set_color(canvas, ColorBlack);
        }
        
        char line[24];
        snprintf(line, sizeof(line), "%.21s", entry->name);
        canvas_draw_str(canvas, 2, y, line);
    }
    
    canvas_set_color(canvas, ColorBlack);
}

// ============================================================================
// Input Handling
// ============================================================================

static bool handshakes_input(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;
    
    HandshakesModel* m = view_get_model(view);
    if(!m || !m->data) {
        view_commit_model(view, false);
        return false;
    }
    HandshakesData* data = m->data;
    
    bool is_navigation = (event->key == InputKeyUp || event->key == InputKeyDown);
    if(is_navigation) {
        if(event->type != InputTypePress && event->type != InputTypeRepeat) {
            view_commit_model(view, false);
            return false;
        }
    } else {
        if(event->type != InputTypeShort) {
            view_commit_model(view, false);
            return false;
        }
    }
    
    if(event->key == InputKeyBack) {
        view_commit_model(view, false);
        screen_pop(data->app);
        return true;
    }
    
    if(!data->data_loaded || data->entry_count == 0) {
        view_commit_model(view, false);
        return true;
    }
    
    if(event->key == InputKeyUp) {
        if(data->selected_idx > 0) data->selected_idx--;
    } else if(event->key == InputKeyDown) {
        if(data->selected_idx < data->entry_count - 1) data->selected_idx++;
    }
    
    view_commit_model(view, true);
    return true;
}

// ============================================================================
// Screen Creation
// ============================================================================

View* screen_handshakes_create(WiFiApp* app, void** out_data) {
    HandshakesData* data = (HandshakesData*)malloc(sizeof(HandshakesData));
    if(!data) return NULL;
    
    memset(data, 0, sizeof(HandshakesData));
    data->app = app;
    data->should_exit = false;
    data->data_loaded = false;
    data->entry_count = 0;
    data->selected_idx = 0;
    
    View* view = view_alloc();
    if(!view) {
        free(data);
        return NULL;
    }
    
    view_allocate_model(view, ViewModelTypeLocking, sizeof(HandshakesModel));
    HandshakesModel* m = view_get_model(view);
    if(!m) {
        free(data);
        view_free(view);
        return NULL;
    }
    m->data = data;
    view_commit_model(view, true);
    
    view_set_draw_callback(view, handshakes_draw);
    view_set_input_callback(view, handshakes_input);
    view_set_context(view, view);
    
    // Start thread to fetch data from board
    data->thread = furi_thread_alloc();
    furi_thread_set_name(data->thread, "Handshakes");
    furi_thread_set_stack_size(data->thread, 2048);
    furi_thread_set_callback(data->thread, handshakes_thread);
    furi_thread_set_context(data->thread, data);
    furi_thread_start(data->thread);
    
    if(out_data) *out_data = data;
    return view;
}
