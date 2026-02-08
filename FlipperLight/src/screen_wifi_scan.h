#pragma once

#include "app.h"

View* screen_wifi_scan_create(WiFiApp* app);
void screen_wifi_scan_destroy(View* view);

View* screen_attack_selection_create(WiFiApp* app);
void screen_attack_selection_destroy(View* view);
