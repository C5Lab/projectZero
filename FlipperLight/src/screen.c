#include "screen.h"
#include <stdlib.h>
#include <stdio.h>
#include <furi.h>

typedef struct {
    ScreenDrawCallback draw_callback;
    ScreenInputCallback input_callback;
    void* context;
} ScreenData;

// Cleanup function type for views
typedef void (*ViewCleanupFunc)(View* view, void* data);

static uint32_t screen_view_stack[16];
static View* screen_view_ptrs[16];
static ViewCleanupFunc screen_cleanup_funcs[16];
static void* screen_cleanup_data[16];
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
    if(!view) return NULL;
    
    ScreenData* data = (ScreenData*)malloc(sizeof(ScreenData));
    if(!data) {
        view_free(view);
        return NULL;
    }
    
    data->draw_callback = draw;
    data->input_callback = input;
    data->context = app;
    
    view_set_draw_callback(view, screen_draw_callback);
    view_set_input_callback(view, screen_input_callback);
    view_set_context(view, data);
    
    return view;
}

void screen_push(WiFiApp* app, View* view) {
    screen_push_with_cleanup(app, view, NULL, NULL);
}

void screen_push_with_cleanup(WiFiApp* app, View* view, void (*cleanup)(View*, void*), void* cleanup_data) {
    if(!app || !view) return;
    uint32_t view_id = screen_next_view_id++;
    view_dispatcher_add_view(app->view_dispatcher, view_id, view);
    if(screen_view_stack_size < 16) {
        screen_view_stack[screen_view_stack_size] = view_id;
        screen_view_ptrs[screen_view_stack_size] = view;
        screen_cleanup_funcs[screen_view_stack_size] = cleanup;
        screen_cleanup_data[screen_view_stack_size] = cleanup_data;
        screen_view_stack_size++;
    }
    view_dispatcher_switch_to_view(app->view_dispatcher, view_id);
}

void screen_pop(WiFiApp* app) {
    if(screen_view_stack_size > 1) {
        // Get current view info
        uint8_t idx = screen_view_stack_size - 1;
        uint32_t current_id = screen_view_stack[idx];
        View* current_view = screen_view_ptrs[idx];
        ViewCleanupFunc cleanup = screen_cleanup_funcs[idx];
        void* cleanup_data = screen_cleanup_data[idx];
        
        screen_view_stack_size--;
        
        // Switch to previous view first
        uint32_t prev_id = screen_view_stack[screen_view_stack_size - 1];
        view_dispatcher_switch_to_view(app->view_dispatcher, prev_id);
        
        // Remove from dispatcher
        view_dispatcher_remove_view(app->view_dispatcher, current_id);
        
        // Call cleanup function if set
        if(cleanup) {
            cleanup(current_view, cleanup_data);
        }
        
        // Free the view
        if(current_view) {
            view_free(current_view);
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
    // Remove all views from stack (for cleanup on exit)
    while(screen_view_stack_size > 0) {
        uint8_t idx = screen_view_stack_size - 1;
        uint32_t view_id = screen_view_stack[idx];
        View* view = screen_view_ptrs[idx];
        ViewCleanupFunc cleanup = screen_cleanup_funcs[idx];
        void* cleanup_data = screen_cleanup_data[idx];
        
        screen_view_stack_size--;
        
        view_dispatcher_remove_view(app->view_dispatcher, view_id);
        
        // Call cleanup function if set
        if(cleanup) {
            cleanup(view, cleanup_data);
        }
        
        if(view) {
            view_free(view);
        }
    }
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
        canvas_draw_str(canvas, mx, 10, mem_str);
    }
    canvas_draw_line(canvas, 0, 12, 128, 12);
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

uint32_t screen_get_current_view_id(void) {
    if(screen_view_stack_size > 0) {
        return screen_view_stack[screen_view_stack_size - 1];
    }
    return 0;
}
