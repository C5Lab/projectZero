/**
 * Bluetooth Menu and Screens
 * 
 * Contains:
 * - Bluetooth Menu
 * - AirTag Scan
 * - BT Scan
 * - BT Locator
 */

#include "screen_attacks.h"
#include "uart_comm.h"
#include "screen.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// ============================================================================
// Forward declarations
// ============================================================================

static View* airtag_scan_screen_create(WiFiApp* app, void** out_data);
static View* bt_scan_screen_create(WiFiApp* app, void** out_data);
static View* bt_locator_screen_create(WiFiApp* app, void** out_data);

static void airtag_scan_cleanup(View* view, void* data);
static void bt_scan_cleanup(View* view, void* data);
static void bt_locator_cleanup(View* view, void* data);

// ============================================================================
// Bluetooth Menu
// ============================================================================

typedef struct {
    WiFiApp* app;
    uint8_t selected;
} BluetoothMenuModel;

static void bluetooth_menu_draw(Canvas* canvas, void* model) {
    BluetoothMenuModel* m = (BluetoothMenuModel*)model;
    if(!m) return;
    
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    screen_draw_title(canvas, "Bluetooth");
    
    const char* items[] = {
        "AirTag scan",
        "BT scan",
        "BT Locator"
    };
    const uint8_t item_count = 3;
    
    canvas_set_font(canvas, FontSecondary);
    for(uint8_t i = 0; i < item_count; i++) {
        uint8_t y = 22 + (i * 10);
        if(i == m->selected) {
            canvas_draw_box(canvas, 0, y - 8, 128, 10);
            canvas_set_color(canvas, ColorWhite);
            canvas_draw_str(canvas, 2, y, items[i]);
            canvas_set_color(canvas, ColorBlack);
        } else {
            canvas_draw_str(canvas, 2, y, items[i]);
        }
    }
}

static bool bluetooth_menu_input(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;
    
    BluetoothMenuModel* m = view_get_model(view);
    if(!m) {
        view_commit_model(view, false);
        return false;
    }
    WiFiApp* app = m->app;
    
    if(event->type != InputTypeShort) {
        view_commit_model(view, false);
        return false;
    }
    
    if(event->key == InputKeyUp) {
        if(m->selected > 0) m->selected--;
    } else if(event->key == InputKeyDown) {
        if(m->selected < 2) m->selected++;
    } else if(event->key == InputKeyOk) {
        uint8_t sel = m->selected;
        view_commit_model(view, false);
        
        View* next = NULL;
        void* data = NULL;
        void (*cleanup)(View*, void*) = NULL;
        
        if(sel == 0) {
            next = airtag_scan_screen_create(app, &data);
            cleanup = airtag_scan_cleanup;
        } else if(sel == 1) {
            next = bt_scan_screen_create(app, &data);
            cleanup = bt_scan_cleanup;
        } else if(sel == 2) {
            next = bt_locator_screen_create(app, &data);
            cleanup = bt_locator_cleanup;
        }
        
        if(next) {
            screen_push_with_cleanup(app, next, cleanup, data);
        }
        return true;
    } else if(event->key == InputKeyBack) {
        view_commit_model(view, false);
        screen_pop(app);
        return true;
    }
    
    view_commit_model(view, true);
    return true;
}

View* screen_bluetooth_menu_create(WiFiApp* app) {
    View* view = view_alloc();
    if(!view) return NULL;
    
    view_allocate_model(view, ViewModelTypeLocking, sizeof(BluetoothMenuModel));
    BluetoothMenuModel* m = view_get_model(view);
    m->app = app;
    m->selected = 0;
    view_commit_model(view, true);
    
    view_set_draw_callback(view, bluetooth_menu_draw);
    view_set_input_callback(view, bluetooth_menu_input);
    view_set_context(view, view);
    
    return view;
}

// ============================================================================
// AirTag Scan - Continuously displays airtag/smarttag counts
// ============================================================================

typedef struct {
    WiFiApp* app;
    volatile bool attack_finished;
    uint32_t airtag_count;
    uint32_t smarttag_count;
    FuriThread* thread;
} AirTagData;

typedef struct {
    AirTagData* data;
} AirTagModel;

static void airtag_scan_cleanup(View* view, void* data) {
    UNUSED(view);
    AirTagData* d = (AirTagData*)data;
    if(!d) return;
    
    d->attack_finished = true;
    if(d->thread) {
        furi_thread_join(d->thread);
        furi_thread_free(d->thread);
    }
    free(d);
}

static void airtag_draw(Canvas* canvas, void* model) {
    AirTagModel* m = (AirTagModel*)model;
    if(!m || !m->data) return;
    AirTagData* data = m->data;
    
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    screen_draw_title(canvas, "AirTag Scan");
    
    canvas_set_font(canvas, FontBigNumbers);
    
    // Draw centered numbers with labels
    char str[16];
    
    snprintf(str, sizeof(str), "%lu", data->airtag_count);
    canvas_draw_str_aligned(canvas, 32, 32, AlignCenter, AlignCenter, str);
    
    snprintf(str, sizeof(str), "%lu", data->smarttag_count);
    canvas_draw_str_aligned(canvas, 96, 32, AlignCenter, AlignCenter, str);
    
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str_aligned(canvas, 32, 50, AlignCenter, AlignTop, "AirTags");
    canvas_draw_str_aligned(canvas, 96, 50, AlignCenter, AlignTop, "SmartTags");
}

static bool airtag_input(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;
    
    AirTagModel* m = view_get_model(view);
    if(!m || !m->data) {
        view_commit_model(view, false);
        return false;
    }
    AirTagData* data = m->data;
    
    if(event->type != InputTypeShort) {
        view_commit_model(view, false);
        return false;
    }
    
    if(event->key == InputKeyBack) {
        data->attack_finished = true;
        uart_send_command(data->app, "stop");
        view_commit_model(view, false);
        screen_pop(data->app);
        return true;
    }
    
    view_commit_model(view, false);
    return false;
}

static int32_t airtag_thread(void* context) {
    AirTagData* data = (AirTagData*)context;
    WiFiApp* app = data->app;
    
    furi_delay_ms(200);
    uart_clear_buffer(app);
    
    uart_send_command(app, "scan_airtag");
    
    while(!data->attack_finished) {
        const char* line = uart_read_line(app, 500);
        if(line) {
            // Parse "count,count" format
            uint32_t at = 0, st = 0;
            if(sscanf(line, "%lu,%lu", &at, &st) == 2) {
                data->airtag_count = at;
                data->smarttag_count = st;
            }
        }
        furi_delay_ms(100);
    }
    
    return 0;
}

static View* airtag_scan_screen_create(WiFiApp* app, void** out_data) {
    AirTagData* data = (AirTagData*)malloc(sizeof(AirTagData));
    if(!data) return NULL;
    
    memset(data, 0, sizeof(AirTagData));
    data->app = app;
    data->attack_finished = false;
    data->thread = NULL;
    
    View* view = view_alloc();
    if(!view) {
        free(data);
        return NULL;
    }
    
    view_allocate_model(view, ViewModelTypeLocking, sizeof(AirTagModel));
    AirTagModel* m = view_get_model(view);
    m->data = data;
    view_commit_model(view, true);
    
    view_set_draw_callback(view, airtag_draw);
    view_set_input_callback(view, airtag_input);
    view_set_context(view, view);
    
    data->thread = furi_thread_alloc();
    furi_thread_set_name(data->thread, "AirTag");
    furi_thread_set_stack_size(data->thread, 2048);
    furi_thread_set_callback(data->thread, airtag_thread);
    furi_thread_set_context(data->thread, data);
    furi_thread_start(data->thread);
    
    if(out_data) *out_data = data;
    return view;
}

// ============================================================================
// BT Scan - Single scan, displays device list
// ============================================================================

#define BT_MAX_DEVICES 30

typedef struct {
    char mac[18];
    int rssi;
    char name[32];
} BTDevice;

typedef struct {
    WiFiApp* app;
    BTDevice devices[BT_MAX_DEVICES];
    uint8_t device_count;
    uint8_t selected;
    uint8_t scroll_offset;
    bool loaded;
} BTScanData;

typedef struct {
    BTScanData* data;
} BTScanModel;

static void bt_scan_cleanup(View* view, void* data) {
    UNUSED(view);
    if(data) free(data);
}

static void bt_scan_draw(Canvas* canvas, void* model) {
    BTScanModel* m = (BTScanModel*)model;
    if(!m || !m->data) return;
    BTScanData* data = m->data;
    
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    screen_draw_title(canvas, "BT Scan");
    canvas_set_font(canvas, FontSecondary);
    
    if(!data->loaded) {
        screen_draw_centered_text(canvas, "Scanning...", 32);
        return;
    }
    
    if(data->device_count == 0) {
        screen_draw_centered_text(canvas, "No devices found", 32);
        return;
    }
    
    uint8_t y = 21;
    uint8_t max_visible = 5;
    
    if(data->selected >= data->scroll_offset + max_visible) {
        data->scroll_offset = data->selected - max_visible + 1;
    } else if(data->selected < data->scroll_offset) {
        data->scroll_offset = data->selected;
    }
    
    for(uint8_t i = data->scroll_offset; i < data->device_count && (i - data->scroll_offset) < max_visible; i++) {
        uint8_t display_y = y + ((i - data->scroll_offset) * 9);
        
        char line[64];
        if(data->devices[i].name[0]) {
            snprintf(line, sizeof(line), "%ddB %.12s", data->devices[i].rssi, data->devices[i].name);
        } else {
            snprintf(line, sizeof(line), "%ddB %s", data->devices[i].rssi, data->devices[i].mac);
        }
        
        if(i == data->selected) {
            canvas_draw_box(canvas, 0, display_y - 7, 128, 9);
            canvas_set_color(canvas, ColorWhite);
        }
        canvas_draw_str(canvas, 2, display_y, line);
        canvas_set_color(canvas, ColorBlack);
    }
}

static bool bt_scan_input(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;
    
    BTScanModel* m = view_get_model(view);
    if(!m || !m->data) {
        view_commit_model(view, false);
        return false;
    }
    BTScanData* data = m->data;
    
    if(event->type != InputTypeShort && event->type != InputTypeRepeat) {
        view_commit_model(view, false);
        return false;
    }
    
    if(event->key == InputKeyUp) {
        if(data->selected > 0) data->selected--;
    } else if(event->key == InputKeyDown) {
        if(data->selected + 1 < data->device_count) data->selected++;
    } else if(event->key == InputKeyBack) {
        view_commit_model(view, false);
        screen_pop(data->app);
        return true;
    }
    
    view_commit_model(view, true);
    return true;
}

static void bt_parse_devices(BTScanData* data, WiFiApp* app) {
    uart_clear_buffer(app);
    uart_send_command(app, "scan_bt");
    furi_delay_ms(100);
    
    uint32_t start = furi_get_tick();
    bool parsing = false;
    
    while((furi_get_tick() - start) < 10000 && data->device_count < BT_MAX_DEVICES) {
        const char* line = uart_read_line(app, 300);
        if(!line || !line[0]) continue;
        
        if(strstr(line, "Found") && strstr(line, "devices")) {
            parsing = true;
            continue;
        }
        
        if(strstr(line, "Summary")) break;
        
        if(!parsing) continue;
        
        // Parse "  N. MAC  RSSI: -XX dBm  Name: ..."
        uint32_t idx = 0;
        char mac[18] = {0};
        int rssi = 0;
        char rest[64] = {0};
        
        if(sscanf(line, " %lu. %17s RSSI: %d dBm%63[^\n]", &idx, mac, &rssi, rest) >= 3) {
            BTDevice* dev = &data->devices[data->device_count];
            strncpy(dev->mac, mac, 17);
            dev->mac[17] = '\0';
            dev->rssi = rssi;
            dev->name[0] = '\0';
            
            // Try to extract name
            char* name_start = strstr(rest, "Name:");
            if(name_start) {
                name_start += 5;
                while(*name_start == ' ') name_start++;
                strncpy(dev->name, name_start, 31);
                dev->name[31] = '\0';
                // Trim newlines
                char* nl = strchr(dev->name, '\n');
                if(nl) *nl = '\0';
            }
            
            data->device_count++;
        }
    }
    
    data->loaded = true;
}

static View* bt_scan_screen_create(WiFiApp* app, void** out_data) {
    BTScanData* data = (BTScanData*)malloc(sizeof(BTScanData));
    if(!data) return NULL;
    
    memset(data, 0, sizeof(BTScanData));
    data->app = app;
    data->loaded = false;
    
    View* view = view_alloc();
    if(!view) {
        free(data);
        return NULL;
    }
    
    view_allocate_model(view, ViewModelTypeLocking, sizeof(BTScanModel));
    BTScanModel* m = view_get_model(view);
    m->data = data;
    view_commit_model(view, true);
    
    view_set_draw_callback(view, bt_scan_draw);
    view_set_input_callback(view, bt_scan_input);
    view_set_context(view, view);
    
    // Parse synchronously (blocking, but OK for scan)
    bt_parse_devices(data, app);
    
    if(out_data) *out_data = data;
    return view;
}

// ============================================================================
// BT Locator - Like BT Scan but clickable, tracks single device
// ============================================================================

typedef struct {
    WiFiApp* app;
    volatile bool attack_finished;
    uint8_t state;  // 0=device list, 1=tracking
    BTDevice devices[BT_MAX_DEVICES];
    uint8_t device_count;
    uint8_t selected;
    uint8_t scroll_offset;
    bool loaded;
    char tracked_mac[18];
    char tracked_name[32];
    int tracked_rssi;
    FuriThread* thread;
} BTLocatorData;

typedef struct {
    BTLocatorData* data;
} BTLocatorModel;

static void bt_locator_cleanup(View* view, void* data) {
    UNUSED(view);
    BTLocatorData* d = (BTLocatorData*)data;
    if(!d) return;
    
    d->attack_finished = true;
    if(d->thread) {
        furi_thread_join(d->thread);
        furi_thread_free(d->thread);
    }
    free(d);
}

static void bt_locator_draw(Canvas* canvas, void* model) {
    BTLocatorModel* m = (BTLocatorModel*)model;
    if(!m || !m->data) return;
    BTLocatorData* data = m->data;
    
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    
    if(data->state == 0) {
        screen_draw_title(canvas, "BT Locator");
        canvas_set_font(canvas, FontSecondary);
        
        if(!data->loaded) {
            screen_draw_centered_text(canvas, "Scanning...", 32);
            return;
        }
        
        if(data->device_count == 0) {
            screen_draw_centered_text(canvas, "No devices found", 32);
            return;
        }
        
        uint8_t y = 21;
        uint8_t max_visible = 5;
        
        if(data->selected >= data->scroll_offset + max_visible) {
            data->scroll_offset = data->selected - max_visible + 1;
        } else if(data->selected < data->scroll_offset) {
            data->scroll_offset = data->selected;
        }
        
        for(uint8_t i = data->scroll_offset; i < data->device_count && (i - data->scroll_offset) < max_visible; i++) {
            uint8_t display_y = y + ((i - data->scroll_offset) * 9);
            
            char line[64];
            if(data->devices[i].name[0]) {
                snprintf(line, sizeof(line), "%ddB %.12s", data->devices[i].rssi, data->devices[i].name);
            } else {
                snprintf(line, sizeof(line), "%ddB %s", data->devices[i].rssi, data->devices[i].mac);
            }
            
            if(i == data->selected) {
                canvas_draw_box(canvas, 0, display_y - 7, 128, 9);
                canvas_set_color(canvas, ColorWhite);
            }
            canvas_draw_str(canvas, 2, display_y, line);
            canvas_set_color(canvas, ColorBlack);
        }
    } else {
        // Tracking mode
        screen_draw_title(canvas, "Tracking");
        
        canvas_set_font(canvas, FontSecondary);
        
        // Show name or MAC
        char label[48];
        if(data->tracked_name[0]) {
            snprintf(label, sizeof(label), "%.20s", data->tracked_name);
        } else {
            snprintf(label, sizeof(label), "%s", data->tracked_mac);
        }
        screen_draw_centered_text(canvas, label, 28);
        
        // Show RSSI big
        canvas_set_font(canvas, FontBigNumbers);
        char rssi_str[16];
        snprintf(rssi_str, sizeof(rssi_str), "%d", data->tracked_rssi);
        screen_draw_centered_text(canvas, rssi_str, 48);
        
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str_aligned(canvas, 64, 60, AlignCenter, AlignTop, "dBm");
    }
}

static bool bt_locator_input(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;
    
    BTLocatorModel* m = view_get_model(view);
    if(!m || !m->data) {
        view_commit_model(view, false);
        return false;
    }
    BTLocatorData* data = m->data;
    
    if(event->type != InputTypeShort && event->type != InputTypeRepeat) {
        view_commit_model(view, false);
        return false;
    }
    
    if(data->state == 0) {
        // Device list
        if(event->key == InputKeyUp) {
            if(data->selected > 0) data->selected--;
        } else if(event->key == InputKeyDown) {
            if(data->selected + 1 < data->device_count) data->selected++;
        } else if(event->key == InputKeyOk) {
            if(data->device_count > 0) {
                BTDevice* dev = &data->devices[data->selected];
                strncpy(data->tracked_mac, dev->mac, 17);
                strncpy(data->tracked_name, dev->name, 31);
                data->tracked_rssi = dev->rssi;
                data->state = 1;
            }
        } else if(event->key == InputKeyBack) {
            view_commit_model(view, false);
            screen_pop(data->app);
            return true;
        }
    } else {
        // Tracking mode
        if(event->key == InputKeyBack) {
            data->attack_finished = true;
            uart_send_command(data->app, "stop");
            view_commit_model(view, false);
            screen_pop(data->app);
            return true;
        }
    }
    
    view_commit_model(view, true);
    return true;
}

static int32_t bt_locator_thread(void* context) {
    BTLocatorData* data = (BTLocatorData*)context;
    WiFiApp* app = data->app;
    
    // Initial scan - same as BT Scan
    uart_clear_buffer(app);
    uart_send_command(app, "scan_bt");
    furi_delay_ms(100);
    
    uint32_t start = furi_get_tick();
    bool parsing = false;
    
    while((furi_get_tick() - start) < 10000 && data->device_count < BT_MAX_DEVICES && !data->attack_finished) {
        const char* line = uart_read_line(app, 300);
        if(!line || !line[0]) continue;
        
        if(strstr(line, "Found") && strstr(line, "devices")) {
            parsing = true;
            continue;
        }
        
        if(strstr(line, "Summary")) break;
        
        if(!parsing) continue;
        
        uint32_t idx = 0;
        char mac[18] = {0};
        int rssi = 0;
        char rest[64] = {0};
        
        if(sscanf(line, " %lu. %17s RSSI: %d dBm%63[^\n]", &idx, mac, &rssi, rest) >= 3) {
            BTDevice* dev = &data->devices[data->device_count];
            strncpy(dev->mac, mac, 17);
            dev->mac[17] = '\0';
            dev->rssi = rssi;
            dev->name[0] = '\0';
            
            char* name_start = strstr(rest, "Name:");
            if(name_start) {
                name_start += 5;
                while(*name_start == ' ') name_start++;
                strncpy(dev->name, name_start, 31);
                dev->name[31] = '\0';
                char* nl = strchr(dev->name, '\n');
                if(nl) *nl = '\0';
            }
            
            data->device_count++;
        }
    }
    
    data->loaded = true;
    
    // Wait for device selection
    while(data->state == 0 && !data->attack_finished) {
        furi_delay_ms(100);
    }
    
    if(data->attack_finished) return 0;
    
    // Start tracking selected device
    char cmd[48];
    snprintf(cmd, sizeof(cmd), "scan_bt %s", data->tracked_mac);
    uart_clear_buffer(app);
    uart_send_command(app, cmd);
    
    // Continuously monitor for RSSI updates
    while(!data->attack_finished) {
        const char* line = uart_read_line(app, 500);
        if(line) {
            // Parse "MAC  RSSI: -XX dBm  Name: ..."
            char mac[18] = {0};
            int rssi = 0;
            
            if(sscanf(line, "%17s RSSI: %d dBm", mac, &rssi) == 2) {
                if(strcmp(mac, data->tracked_mac) == 0) {
                    data->tracked_rssi = rssi;
                }
            }
        }
        furi_delay_ms(100);
    }
    
    return 0;
}

static View* bt_locator_screen_create(WiFiApp* app, void** out_data) {
    BTLocatorData* data = (BTLocatorData*)malloc(sizeof(BTLocatorData));
    if(!data) return NULL;
    
    memset(data, 0, sizeof(BTLocatorData));
    data->app = app;
    data->attack_finished = false;
    data->state = 0;
    data->loaded = false;
    data->thread = NULL;
    
    View* view = view_alloc();
    if(!view) {
        free(data);
        return NULL;
    }
    
    view_allocate_model(view, ViewModelTypeLocking, sizeof(BTLocatorModel));
    BTLocatorModel* m = view_get_model(view);
    m->data = data;
    view_commit_model(view, true);
    
    view_set_draw_callback(view, bt_locator_draw);
    view_set_input_callback(view, bt_locator_input);
    view_set_context(view, view);
    
    data->thread = furi_thread_alloc();
    furi_thread_set_name(data->thread, "BTLoc");
    furi_thread_set_stack_size(data->thread, 2048);
    furi_thread_set_callback(data->thread, bt_locator_thread);
    furi_thread_set_context(data->thread, data);
    furi_thread_start(data->thread);
    
    if(out_data) *out_data = data;
    return view;
}
