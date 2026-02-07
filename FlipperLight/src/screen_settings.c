/**
 * Settings Menu
 * 
 * Sub-screens:
 * - Scan Time
 * - Red Team mode
 */

#include "app.h"
#include "screen.h"
#include "screen_settings.h"
#include <stdlib.h>
#include <furi.h>

#define TAG "Settings"

// ============================================================================
// Data Structures
// ============================================================================

typedef struct {
    WiFiApp* app;
} SettingsMenuData;

typedef struct {
    SettingsMenuData* data;
    uint8_t selected;
} SettingsMenuModel;

// ============================================================================
// Cleanup
// ============================================================================

void settings_menu_cleanup_internal(View* view, void* data) {
    UNUSED(view);
    SettingsMenuData* d = (SettingsMenuData*)data;
    if(!d) return;
    FURI_LOG_I(TAG, "Settings menu cleanup");
    free(d);
}

// ============================================================================
// Drawing
// ============================================================================

static void settings_menu_draw(Canvas* canvas, void* model) {
    SettingsMenuModel* m = (SettingsMenuModel*)model;
    if(!m || !m->data) return;
    
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    screen_draw_title(canvas, "Settings");
    
    const char* items[] = {
        "Scan Time",
        "Red Team mode"
    };
    const uint8_t item_count = 2;
    
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

static bool settings_menu_input(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;
    
    SettingsMenuModel* m = view_get_model(view);
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
        if(m->selected < 1) m->selected++;
    } else if(event->key == InputKeyOk) {
        uint8_t sel = m->selected;
        view_commit_model(view, false);
        
        View* next = NULL;
        void* data = NULL;
        void (*cleanup)(View*, void*) = NULL;
        
        if(sel == 0) {
            FURI_LOG_I(TAG, "Creating Scan Time screen");
            next = screen_settings_scan_time_create(app, &data);
            cleanup = scan_time_cleanup_internal;
        } else if(sel == 1) {
            FURI_LOG_I(TAG, "Creating Red Team mode screen");
            next = screen_settings_redteam_create(app, &data);
            cleanup = redteam_cleanup_internal;
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

View* screen_settings_menu_create(WiFiApp* app, void** out_data) {
    SettingsMenuData* data = (SettingsMenuData*)malloc(sizeof(SettingsMenuData));
    if(!data) return NULL;
    
    data->app = app;
    
    View* view = view_alloc();
    if(!view) {
        free(data);
        return NULL;
    }
    
    view_allocate_model(view, ViewModelTypeLocking, sizeof(SettingsMenuModel));
    SettingsMenuModel* m = view_get_model(view);
    if(!m) {
        free(data);
        view_free(view);
        return NULL;
    }
    m->data = data;
    m->selected = 0;
    view_commit_model(view, true);
    
    view_set_draw_callback(view, settings_menu_draw);
    view_set_input_callback(view, settings_menu_input);
    view_set_context(view, view);
    
    if(out_data) *out_data = data;
    return view;
}
