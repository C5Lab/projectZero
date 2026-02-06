#include "screen.h"
#include <stdlib.h>

typedef struct {
    ScreenDrawCallback draw_callback;
    ScreenInputCallback input_callback;
    void* context;
} ScreenData;

static uint32_t screen_view_stack[16];
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
        screen_view_stack[screen_view_stack_size++] = view_id;
    } else {
        screen_view_stack[screen_view_stack_size - 1] = view_id;
    }
    view_dispatcher_switch_to_view(app->view_dispatcher, view_id);
}

void screen_pop(WiFiApp* app) {
    if(screen_view_stack_size > 1) {
        screen_view_stack_size--;
        uint32_t prev_id = screen_view_stack[screen_view_stack_size - 1];
        view_dispatcher_switch_to_view(app->view_dispatcher, prev_id);
    }
}

void screen_draw_title(Canvas* canvas, const char* title) {
    canvas_set_color(canvas, ColorBlack);
    canvas_draw_str(canvas, 2, 10, title);
    const char* version = "C5Lab v0.0.1";
    uint8_t vlen = strlen(version);
    uint8_t vx = 126 - (vlen * 6);
    if(vx > 20) {
        canvas_draw_str(canvas, vx, 10, version);
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
