#include "screen.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <furi.h>

typedef struct {
    ScreenDrawCallback draw_callback;
    ScreenInputCallback input_callback;
    void* context;
} ScreenData;

// Cleanup callback storage per stack entry
typedef struct {
    uint32_t view_id;
    void (*cleanup)(View*, void*);
    void* cleanup_data;
    View* view;
} ScreenStackEntry;

static ScreenStackEntry screen_view_stack[16];
static uint8_t screen_view_stack_size = 0;
static uint32_t screen_next_view_id = 1;

static void screen_draw_callback(Canvas* canvas, void* context) {
    ScreenData* data = (ScreenData*)context;
    if(data && data->draw_callback) {
        data->draw_callback(canvas, data->context);
    }
}

static bool screen_input_callback(InputEvent* event, void* context) {
    ScreenData* data = (ScreenData*)context;
    if(data && data->input_callback) {
        return data->input_callback(event, data->context);
    }
    return false;
}

View* screen_create(WiFiApp* app, ScreenDrawCallback draw, ScreenInputCallback input) {
    View* view = view_alloc();
    ScreenData* data = (ScreenData*)malloc(sizeof(ScreenData));
    
    data->draw_callback = draw;
    data->input_callback = input;
    data->context = app;
    
    view_set_draw_callback(view, screen_draw_callback);
    view_set_input_callback(view, screen_input_callback);
    view_set_context(view, data);
    
    return view;
}

void screen_push(WiFiApp* app, View* view) {
    if(!app || !view) return;
    uint32_t view_id = screen_next_view_id++;
    view_dispatcher_add_view(app->view_dispatcher, view_id, view);
    if(screen_view_stack_size < (sizeof(screen_view_stack) / sizeof(screen_view_stack[0]))) {
        ScreenStackEntry* entry = &screen_view_stack[screen_view_stack_size++];
        entry->view_id = view_id;
        entry->cleanup = NULL;
        entry->cleanup_data = NULL;
        entry->view = view;
    }
    view_dispatcher_switch_to_view(app->view_dispatcher, view_id);
}

void screen_push_with_cleanup(WiFiApp* app, View* view, void (*cleanup)(View*, void*), void* cleanup_data) {
    if(!app || !view) return;
    uint32_t view_id = screen_next_view_id++;
    view_dispatcher_add_view(app->view_dispatcher, view_id, view);
    if(screen_view_stack_size < (sizeof(screen_view_stack) / sizeof(screen_view_stack[0]))) {
        ScreenStackEntry* entry = &screen_view_stack[screen_view_stack_size++];
        entry->view_id = view_id;
        entry->cleanup = cleanup;
        entry->cleanup_data = cleanup_data;
        entry->view = view;
    }
    view_dispatcher_switch_to_view(app->view_dispatcher, view_id);
}

void screen_pop(WiFiApp* app) {
    if(screen_view_stack_size > 1) {
        screen_view_stack_size--;
        ScreenStackEntry popped = screen_view_stack[screen_view_stack_size];
        
        // Switch to previous view FIRST (safe to call from inside input handler)
        uint32_t prev_id = screen_view_stack[screen_view_stack_size - 1].view_id;
        view_dispatcher_switch_to_view(app->view_dispatcher, prev_id);
        
        // Remove from dispatcher
        view_dispatcher_remove_view(app->view_dispatcher, popped.view_id);
        
        // Call cleanup if registered
        if(popped.cleanup) {
            popped.cleanup(popped.view, popped.cleanup_data);
        }
        
        // Free the view
        if(popped.view) {
            view_free(popped.view);
        }
    }
}

void screen_pop_to_main(WiFiApp* app) {
    // Pop all views except the first one (main menu)
    while(screen_view_stack_size > 1) {
        screen_pop(app);
    }
    
    // Free scan results when returning to main menu
    if(app->scan_results) {
        free(app->scan_results);
        app->scan_results = NULL;
        app->scan_result_count = 0;
    }
}

void screen_pop_all(WiFiApp* app) {
    while(screen_view_stack_size > 0) {
        screen_view_stack_size--;
        ScreenStackEntry popped = screen_view_stack[screen_view_stack_size];
        
        view_dispatcher_remove_view(app->view_dispatcher, popped.view_id);
        
        if(popped.cleanup) {
            popped.cleanup(popped.view, popped.cleanup_data);
        }
        
        if(popped.view) {
            view_free(popped.view);
        }
    }
}

uint32_t screen_get_current_view_id(void) {
    if(screen_view_stack_size > 0) {
        return screen_view_stack[screen_view_stack_size - 1].view_id;
    }
    return 0;
}

void screen_draw_title(Canvas* canvas, const char* title) {
    canvas_set_color(canvas, ColorBlack);
    canvas_draw_str(canvas, 2, 10, title);
    
    // Show free heap memory
    size_t free_heap = memmgr_get_free_heap();
    char mem_str[16];
    if(free_heap >= 1024) {
        snprintf(mem_str, sizeof(mem_str), "%luKB", (unsigned long)(free_heap / 1024));
    } else {
        snprintf(mem_str, sizeof(mem_str), "%luB", (unsigned long)free_heap);
    }
    uint8_t mlen = strlen(mem_str);
    uint8_t mx = 126 - (mlen * 6);
    if(mx > 20) {
        //canvas_draw_str(canvas, mx, 10, mem_str);
    }
    canvas_draw_line(canvas, 0, 11, 128, 11);
}

void screen_draw_centered_text(Canvas* canvas, const char* text, uint8_t y) {
    canvas_set_color(canvas, ColorBlack);
    uint8_t len = strlen(text);
    uint8_t x = (128 - (len * 6)) / 2;
    canvas_draw_str(canvas, x, y, text);
}

void screen_draw_status(Canvas* canvas, const char* status, uint8_t y) {
    canvas_set_color(canvas, ColorBlack);
    canvas_draw_str(canvas, 2, y, status);
}
