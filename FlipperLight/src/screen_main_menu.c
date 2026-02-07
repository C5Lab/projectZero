#include "screen_main_menu.h"
#include "screen.h"
#include "screen_wifi_scan.h"
#include "uart_comm.h"
#include <stdlib.h>
#include <furi.h>

#define TAG "MainMenu"

// External menu create functions
extern View* screen_global_attacks_menu_create(WiFiApp* app);
extern View* screen_sniff_karma_menu_create(WiFiApp* app);
extern View* screen_bluetooth_menu_create(WiFiApp* app);
extern View* screen_deauth_detector_create(WiFiApp* app, void** out_data);
extern void deauth_detector_cleanup_internal(View* view, void* data);

typedef struct {
    WiFiApp* app;
    FuriTimer* check_connection_timer;
} MainMenuData;

typedef struct {
    MainMenuData* data;
    uint8_t selected;
} MainMenuModel;

static void main_menu_draw(Canvas* canvas, void* model) {
    MainMenuModel* m = (MainMenuModel*)model;
    if(!m || !m->data) return;
    
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    screen_draw_title(canvas, "C5Lab");
    
    if(!m->data->app->board_connected) {
        canvas_set_font(canvas, FontSecondary);
        screen_draw_centered_text(canvas, "Connect Board", 32);
        return;
    }
    
    const char* items[] = {
        "WiFi Scan & Attack",
        "Global WiFi Attacks",
        "WiFi Sniff&Karma",
        "Deauth Detector",
        "Bluetooth",
        "Compromised Data",
        "Settings"
    };
    const uint8_t item_count = 7;
    const uint8_t item_height = 9;
    const uint8_t start_y = 24;
    const uint8_t max_visible = 5; // Maximum items that fit on screen
    
    // Calculate scroll offset
    uint8_t scroll_start = 0;
    if(m->selected >= max_visible) {
        scroll_start = m->selected - max_visible + 1;
    }
    
    canvas_set_font(canvas, FontSecondary);
    for(uint8_t i = scroll_start; i < item_count && (i - scroll_start) < max_visible; i++) {
        uint8_t y = start_y + ((i - scroll_start) * item_height);
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

static bool main_menu_input(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;
    
    MainMenuModel* m = view_get_model(view);
    if(!m || !m->data) return false;
    
    WiFiApp* app = m->data->app;
    
    if(event->type != InputTypePress && event->type != InputTypeRepeat) {
        view_commit_model(view, false);
        return false;
    }
    
    // Block all input except Back if board not connected
    if(!app->board_connected) {
        if(event->key == InputKeyBack) {
            view_commit_model(view, false);
            view_dispatcher_stop(app->view_dispatcher);
            return true;
        }
        view_commit_model(view, false);
        return true;
    }
    
    bool handled = true;
    
    if(event->key == InputKeyUp) {
        if(m->selected > 0) {
            m->selected--;
        }
    } else if(event->key == InputKeyDown) {
        if(m->selected < 6) {
            m->selected++;
        }
    } else if(event->key == InputKeyOk) {
        uint8_t sel = m->selected;
        FURI_LOG_I(TAG, "OK pressed, selected=%u", sel);
        view_commit_model(view, true);
        
        View* next_screen = NULL;
        
        if(sel == 0) {
            // WiFi Scan & Attack
            FURI_LOG_I(TAG, "Creating WiFi Scan screen");
            next_screen = screen_wifi_scan_create(app);
        } else if(sel == 1) {
            // Global WiFi Attacks
            FURI_LOG_I(TAG, "Creating Global Attacks menu");
            next_screen = screen_global_attacks_menu_create(app);
        } else if(sel == 2) {
            // WiFi Sniff & Karma
            FURI_LOG_I(TAG, "Creating Sniff & Karma menu");
            next_screen = screen_sniff_karma_menu_create(app);
        } else if(sel == 3) {
            // Deauth Detector
            FURI_LOG_I(TAG, "Creating Deauth Detector screen");
            void* detector_data = NULL;
            next_screen = screen_deauth_detector_create(app, &detector_data);
            if(next_screen && detector_data) {
                screen_push_with_cleanup(app, next_screen, deauth_detector_cleanup_internal, detector_data);
                return true;
            }
        } else if(sel == 4) {
            // Bluetooth
            FURI_LOG_I(TAG, "Creating Bluetooth menu");
            next_screen = screen_bluetooth_menu_create(app);
        } else if(sel == 5) {
            // Compromised Data - TODO
            FURI_LOG_I(TAG, "Compromised Data - not implemented");
        } else if(sel == 6) {
            // Settings - TODO
            FURI_LOG_I(TAG, "Settings - not implemented");
        }
        
        if(next_screen) {
            FURI_LOG_I(TAG, "Pushing screen %p", (void*)next_screen);
            screen_push(app, next_screen);
        } else {
            FURI_LOG_W(TAG, "next_screen is NULL for sel=%u", sel);
        }
        return true;
    } else if(event->key == InputKeyBack) {
        // Exit app - stop the view dispatcher
        view_commit_model(view, false);
        view_dispatcher_stop(app->view_dispatcher);
        return true;
    }

    view_commit_model(view, true);
    return handled;
}

static void check_connection_timer_callback(void* context) {
    MainMenuData* data = (MainMenuData*)context;
    if(!data || !data->app) return;
    
    if(!data->app->board_connected) {
        if(uart_check_board_connection(data->app)) {
            data->app->board_connected = true;
            // Stop timer once board is connected - no need to keep pinging
            if(data->check_connection_timer) {
                furi_timer_stop(data->check_connection_timer);
            }
        }
    }
}

void main_menu_cleanup_internal(View* view, void* data) {
    UNUSED(view);
    MainMenuData* d = (MainMenuData*)data;
    if(!d) return;
    
    FURI_LOG_I(TAG, "Main menu cleanup starting");
    
    if(d->check_connection_timer) {
        furi_timer_stop(d->check_connection_timer);
        furi_timer_free(d->check_connection_timer);
    }
    
    free(d);
    FURI_LOG_I(TAG, "Main menu cleanup complete");
}

View* screen_main_menu_create(WiFiApp* app, void** out_data) {
    MainMenuData* data = (MainMenuData*)malloc(sizeof(MainMenuData));
    if(!data) return NULL;
    
    data->app = app;
    data->check_connection_timer = NULL;
    
    View* view = view_alloc();
    if(!view) {
        free(data);
        return NULL;
    }
    
    view_allocate_model(view, ViewModelTypeLocking, sizeof(MainMenuModel));
    
    MainMenuModel* m = view_get_model(view);
    if(!m) {
        free(data);
        view_free(view);
        return NULL;
    }
    m->data = data;
    m->selected = 0;
    
    // Create timer to check board connection periodically
    data->check_connection_timer = furi_timer_alloc(check_connection_timer_callback, FuriTimerTypePeriodic, data);
    if(data->check_connection_timer) {
        furi_timer_start(data->check_connection_timer, 1000); // Check every second
    }
    
    view_commit_model(view, true);
    
    view_set_draw_callback(view, main_menu_draw);
    view_set_input_callback(view, main_menu_input);
    view_set_context(view, view);  // Pass view as context so input can access model
    
    if(out_data) *out_data = data;
    
    return view;
}

void screen_main_menu_destroy(View* view) {
    // This is never called - cleanup is done via main_menu_cleanup_internal
    UNUSED(view);
}
