#pragma once

#include "app.h"

View* screen_main_menu_create(WiFiApp* app, void** out_data);
void screen_main_menu_destroy(View* view);
void main_menu_cleanup_internal(View* view, void* data);
