#pragma once

#include "app.h"
#include <gui/view.h>

// Screen abstraction
typedef void (*ScreenDrawCallback)(Canvas* canvas, void* context);
typedef bool (*ScreenInputCallback)(InputEvent* event, void* context);

// Screen management
View* screen_create(WiFiApp* app, ScreenDrawCallback draw, ScreenInputCallback input);
void screen_push(WiFiApp* app, View* view);
void screen_push_with_cleanup(WiFiApp* app, View* view, void (*cleanup)(View*, void*), void* cleanup_data);
void screen_pop(WiFiApp* app);
void screen_pop_to_main(WiFiApp* app);
void screen_pop_all(WiFiApp* app);

// Helper drawing functions
void screen_draw_title(Canvas* canvas, const char* title);
void screen_draw_centered_text(Canvas* canvas, const char* text, uint8_t y);
void screen_draw_status(Canvas* canvas, const char* status, uint8_t y);

// Get current view ID (for temporary view switches like TextInput)
uint32_t screen_get_current_view_id(void);
