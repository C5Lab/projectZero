#include "screen_main_menu.h"
#include "screen.h"
#include "screen_wifi_scan.h"
#include <stdlib.h>

typedef struct {
    WiFiApp* app;
    uint8_t selected;
} MainMenuData;

static void main_menu_draw(Canvas* canvas, void* context) {
    MainMenuData* data = (MainMenuData*)context;
    
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
        if(i == data->selected) {
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
    MainMenuData* data = (MainMenuData*)context;
    WiFiApp* app = data->app;
    
    if(event->type != InputTypePress && event->type != InputTypeRepeat) {
        return false;
    }
    
    if(event->key == InputKeyUp) {
        if(data->selected > 0) {
            data->selected--;
        }
    } else if(event->key == InputKeyDown) {
        if(data->selected < 4) {
            data->selected++;
        }
    } else if(event->key == InputKeyOk) {
        if(data->selected == 0) {
            // WiFi Scan & Attack
            View* next_screen = screen_wifi_scan_create(app);
            screen_push(app, next_screen);
        } else if(data->selected == 1) {
            // Global WiFi Attacks - mock screen for now
        }
        // TODO: Other menu items
    } else if(event->key == InputKeyBack) {
        // Exit app
    }

    return true;
}

View* screen_main_menu_create(WiFiApp* app) {
    MainMenuData* data = (MainMenuData*)malloc(sizeof(MainMenuData));
    if(!data) return NULL;
    data->app = app;
    data->selected = 0;
    
    View* view = view_alloc();
    if(!view) {
        free(data);
        return NULL;
    }
    view_set_draw_callback(view, main_menu_draw);
    view_set_input_callback(view, main_menu_input);
    view_set_context(view, data);
    
    return view;
}

void screen_main_menu_destroy(View* view) {
    view_free(view);
}
