#include "screen_main_menu.h"
#include "screen.h"
#include "screen_wifi_scan.h"
#include <stdlib.h>
#include <furi.h>

#define TAG "MainMenu"

// External menu create functions
extern View* screen_global_attacks_menu_create(WiFiApp* app);
extern View* screen_sniff_karma_menu_create(WiFiApp* app);
extern View* screen_bluetooth_menu_create(WiFiApp* app);

typedef struct {
    WiFiApp* app;
    uint8_t selected;
} MainMenuModel;

static void main_menu_draw(Canvas* canvas, void* model) {
    MainMenuModel* m = (MainMenuModel*)model;
    if(!m) return;
    
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    screen_draw_title(canvas, "C5Lab");
    
    const char* items[] = {
        "WiFi Scan & Attack",
        "Global WiFi Attacks",
        "WiFi Sniff&Karma",
        "WiFi Monitor",
        "Bluetooth"
    };
    const uint8_t item_count = 5;
    const uint8_t item_height = 10;
    const uint8_t start_y = 22;
    
    canvas_set_font(canvas, FontSecondary);
    for(uint8_t i = 0; i < item_count; i++) {
        uint8_t y = start_y + (i * item_height);
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
    if(!m) return false;
    
    WiFiApp* app = m->app;
    
    if(event->type != InputTypePress && event->type != InputTypeRepeat) {
        view_commit_model(view, false);
        return false;
    }
    
    bool handled = true;
    
    if(event->key == InputKeyUp) {
        if(m->selected > 0) {
            m->selected--;
        }
    } else if(event->key == InputKeyDown) {
        if(m->selected < 4) {
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
            // WiFi Monitor - TODO
            FURI_LOG_I(TAG, "WiFi Monitor - not implemented");
        } else if(sel == 4) {
            // Bluetooth
            FURI_LOG_I(TAG, "Creating Bluetooth menu");
            next_screen = screen_bluetooth_menu_create(app);
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

View* screen_main_menu_create(WiFiApp* app) {
    View* view = view_alloc();
    if(!view) return NULL;
    
    view_allocate_model(view, ViewModelTypeLocking, sizeof(MainMenuModel));
    
    MainMenuModel* m = view_get_model(view);
    if(!m) {
        view_free(view);
        return NULL;
    }
    m->app = app;
    m->selected = 0;
    view_commit_model(view, true);
    
    view_set_draw_callback(view, main_menu_draw);
    view_set_input_callback(view, main_menu_input);
    view_set_context(view, view);  // Pass view as context so input can access model
    
    return view;
}

void screen_main_menu_destroy(View* view) {
    view_free(view);
}
