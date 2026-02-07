/**
 * Red Team Mode Settings Screen
 * 
 * Toggle checkbox for Red Team mode.
 * When unchecked (default), aggressive attack options are hidden
 * and "Attack" labels become "Test".
 * 
 * Setting is persisted to Flipper storage.
 */

#include "app.h"
#include "screen.h"
#include <stdlib.h>
#include <furi.h>
#include <storage/storage.h>

#define TAG "RedTeam"

// ============================================================================
// Data Structures
// ============================================================================

typedef struct {
    WiFiApp* app;
    bool checked;
} RedTeamData;

typedef struct {
    RedTeamData* data;
} RedTeamModel;

// ============================================================================
// Persistent Storage
// ============================================================================

static void redteam_save_setting(bool value) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    storage_simply_mkdir(storage, APP_DATA_PATH(""));
    File* file = storage_file_alloc(storage);
    if(storage_file_open(file, APP_DATA_PATH("redteam.conf"), FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        uint8_t val = value ? 1 : 0;
        storage_file_write(file, &val, 1);
        FURI_LOG_I(TAG, "Saved red_team_mode = %d", val);
    }
    storage_file_close(file);
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
}

// ============================================================================
// Cleanup
// ============================================================================

void redteam_cleanup_internal(View* view, void* data) {
    UNUSED(view);
    RedTeamData* d = (RedTeamData*)data;
    if(!d) return;
    FURI_LOG_I(TAG, "Red Team cleanup");
    free(d);
}

// ============================================================================
// Drawing
// ============================================================================

static void redteam_draw(Canvas* canvas, void* model) {
    RedTeamModel* m = (RedTeamModel*)model;
    if(!m || !m->data) return;
    RedTeamData* data = m->data;
    
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    screen_draw_title(canvas, "Red Team");
    
    canvas_set_font(canvas, FontSecondary);
    
    // Checkbox
    char line[32];
    snprintf(line, sizeof(line), "[%c] Red Team mode", data->checked ? 'x' : ' ');
    canvas_draw_str(canvas, 2, 28, line);
    
    // Warning
    canvas_draw_str(canvas, 2, 44, "Test only YOUR networks");
    
    // Instructions
    canvas_draw_str(canvas, 2, 62, "OK: Toggle  Back: Exit");
}

// ============================================================================
// Input Handling
// ============================================================================

static bool redteam_input(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;
    
    RedTeamModel* m = view_get_model(view);
    if(!m || !m->data) {
        view_commit_model(view, false);
        return false;
    }
    RedTeamData* data = m->data;
    
    if(event->type != InputTypeShort) {
        view_commit_model(view, false);
        return false;
    }
    
    if(event->key == InputKeyOk) {
        // Toggle checkbox
        data->checked = !data->checked;
        data->app->red_team_mode = data->checked;
        
        // Save to persistent storage
        redteam_save_setting(data->checked);
        
        FURI_LOG_I(TAG, "Red Team mode: %s", data->checked ? "ON" : "OFF");
    } else if(event->key == InputKeyBack) {
        view_commit_model(view, false);
        screen_pop(data->app);
        return true;
    }
    
    view_commit_model(view, true);
    return true;
}

// ============================================================================
// Screen Creation
// ============================================================================

View* screen_settings_redteam_create(WiFiApp* app, void** out_data) {
    RedTeamData* data = (RedTeamData*)malloc(sizeof(RedTeamData));
    if(!data) return NULL;
    
    data->app = app;
    data->checked = app->red_team_mode;
    
    View* view = view_alloc();
    if(!view) {
        free(data);
        return NULL;
    }
    
    view_allocate_model(view, ViewModelTypeLocking, sizeof(RedTeamModel));
    RedTeamModel* m = view_get_model(view);
    if(!m) {
        free(data);
        view_free(view);
        return NULL;
    }
    m->data = data;
    view_commit_model(view, true);
    
    view_set_draw_callback(view, redteam_draw);
    view_set_input_callback(view, redteam_input);
    view_set_context(view, view);
    
    if(out_data) *out_data = data;
    return view;
}
