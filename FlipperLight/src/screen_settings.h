#pragma once

#include "app.h"
#include <gui/view.h>

// Settings menu
View* screen_settings_menu_create(WiFiApp* app, void** out_data);
void settings_menu_cleanup_internal(View* view, void* data);

// Scan Time sub-screen
View* screen_settings_scan_time_create(WiFiApp* app, void** out_data);
void scan_time_cleanup_internal(View* view, void* data);

// Red Team mode sub-screen
View* screen_settings_redteam_create(WiFiApp* app, void** out_data);
void redteam_cleanup_internal(View* view, void* data);
