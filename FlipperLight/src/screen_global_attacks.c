/**
 * Global WiFi Attacks Menu
 * 
 * Menu for global attacks (no network selection required):
 * - Blackout
 * - Handshaker
 * - Portal
 * - Sniffer Dog
 * - Wardrive
 */

#include "app.h"
#include "screen.h"
#include <stdlib.h>

// ============================================================================
// External screen creators and cleanup functions
// ============================================================================

extern View* blackout_screen_create(WiFiApp* app, void** out_data);
extern View* global_handshaker_screen_create(WiFiApp* app, void** out_data);
extern View* portal_screen_create(WiFiApp* app, void** out_data);
extern View* sniffer_dog_screen_create(WiFiApp* app, void** out_data);
extern View* wardrive_screen_create(WiFiApp* app, void** out_data);

extern void blackout_screen_cleanup(View* view, void* data);
extern void global_handshaker_screen_cleanup(View* view, void* data);
extern void portal_screen_cleanup(View* view, void* data);
extern void sniffer_dog_screen_cleanup(View* view, void* data);
extern void wardrive_screen_cleanup(View* view, void* data);

// ============================================================================
// Global Attacks Menu
// ============================================================================

typedef struct {
    WiFiApp* app;
    uint8_t selected;
} GlobalAttacksMenuModel;

static void global_attacks_menu_draw(Canvas* canvas, void* model) {
    GlobalAttacksMenuModel* m = (GlobalAttacksMenuModel*)model;
    if(!m) return;
    
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    screen_draw_title(canvas, "Global Attacks");
    
    const char* items[] = {
        "Blackout",
        "Handshaker",
        "Portal",
        "Sniffer Dog",
        "Wardrive"
    };
    const uint8_t item_count = 5;
    
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

static bool global_attacks_menu_input(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;
    
    GlobalAttacksMenuModel* m = view_get_model(view);
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
        if(m->selected < 4) m->selected++;
    } else if(event->key == InputKeyOk) {
        uint8_t sel = m->selected;
        view_commit_model(view, false);
        
        View* next = NULL;
        void* data = NULL;
        void (*cleanup)(View*, void*) = NULL;
        
        if(sel == 0) {
            next = blackout_screen_create(app, &data);
            cleanup = blackout_screen_cleanup;
        } else if(sel == 1) {
            next = global_handshaker_screen_create(app, &data);
            cleanup = global_handshaker_screen_cleanup;
        } else if(sel == 2) {
            next = portal_screen_create(app, &data);
            cleanup = portal_screen_cleanup;
        } else if(sel == 3) {
            next = sniffer_dog_screen_create(app, &data);
            cleanup = sniffer_dog_screen_cleanup;
        } else if(sel == 4) {
            next = wardrive_screen_create(app, &data);
            cleanup = wardrive_screen_cleanup;
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

View* screen_global_attacks_menu_create(WiFiApp* app) {
    View* view = view_alloc();
    if(!view) return NULL;
    
    view_allocate_model(view, ViewModelTypeLocking, sizeof(GlobalAttacksMenuModel));
    GlobalAttacksMenuModel* m = view_get_model(view);
    m->app = app;
    m->selected = 0;
    view_commit_model(view, true);
    
    view_set_draw_callback(view, global_attacks_menu_draw);
    view_set_input_callback(view, global_attacks_menu_input);
    view_set_context(view, view);
    
    return view;
}
