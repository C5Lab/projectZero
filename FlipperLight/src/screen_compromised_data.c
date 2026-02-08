/**
 * Compromised Data Menu
 * 
 * Sub-screens:
 * - Evil Twin Passwords
 * - Portal Data
 * - Handshakes
 */

#include "app.h"
#include "screen.h"
#include "screen_compromised_data.h"
#include <stdlib.h>
#include <furi.h>

#define TAG "CompData"

// ============================================================================
// Data Structures
// ============================================================================

typedef struct {
    WiFiApp* app;
} CompDataMenuData;

typedef struct {
    CompDataMenuData* data;
    uint8_t selected;
} CompDataMenuModel;

// ============================================================================
// Cleanup
// ============================================================================

void compromised_data_menu_cleanup_internal(View* view, void* data) {
    UNUSED(view);
    CompDataMenuData* d = (CompDataMenuData*)data;
    if(!d) return;
    FURI_LOG_I(TAG, "Compromised Data menu cleanup");
    free(d);
}

// ============================================================================
// Drawing
// ============================================================================

static void comp_data_menu_draw(Canvas* canvas, void* model) {
    CompDataMenuModel* m = (CompDataMenuModel*)model;
    if(!m || !m->data) return;
    
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    screen_draw_title(canvas, "Compromised Data");
    
    const char* items[] = {
        "Evil Twin Passwords",
        "Portal Data",
        "Handshakes"
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

// ============================================================================
// Input Handling
// ============================================================================

static bool comp_data_menu_input(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;
    
    CompDataMenuModel* m = view_get_model(view);
    if(!m || !m->data) {
        view_commit_model(view, false);
        return false;
    }
    WiFiApp* app = m->data->app;
    
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
            FURI_LOG_I(TAG, "Creating Evil Twin Passwords screen");
            next = screen_evil_twin_passwords_create(app, &data);
            cleanup = evil_twin_passwords_cleanup_internal;
        } else if(sel == 1) {
            FURI_LOG_I(TAG, "Creating Portal Data screen");
            next = screen_portal_data_create(app, &data);
            cleanup = portal_data_cleanup_internal;
        } else if(sel == 2) {
            FURI_LOG_I(TAG, "Creating Handshakes screen");
            next = screen_handshakes_create(app, &data);
            cleanup = handshakes_cleanup_internal;
        }
        
        if(next && cleanup) {
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

// ============================================================================
// Screen Creation
// ============================================================================

View* screen_compromised_data_menu_create(WiFiApp* app, void** out_data) {
    CompDataMenuData* data = (CompDataMenuData*)malloc(sizeof(CompDataMenuData));
    if(!data) return NULL;
    
    data->app = app;
    
    View* view = view_alloc();
    if(!view) {
        free(data);
        return NULL;
    }
    
    view_allocate_model(view, ViewModelTypeLocking, sizeof(CompDataMenuModel));
    CompDataMenuModel* m = view_get_model(view);
    if(!m) {
        free(data);
        view_free(view);
        return NULL;
    }
    m->data = data;
    m->selected = 0;
    view_commit_model(view, true);
    
    view_set_draw_callback(view, comp_data_menu_draw);
    view_set_input_callback(view, comp_data_menu_input);
    view_set_context(view, view);
    
    if(out_data) *out_data = data;
    return view;
}
