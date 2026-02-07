#pragma once

#include "app.h"
#include <gui/view.h>

// Compromised Data menu
View* screen_compromised_data_menu_create(WiFiApp* app, void** out_data);
void compromised_data_menu_cleanup_internal(View* view, void* data);

// Evil Twin Passwords sub-screen
View* screen_evil_twin_passwords_create(WiFiApp* app, void** out_data);
void evil_twin_passwords_cleanup_internal(View* view, void* data);

// Portal Data sub-screen
View* screen_portal_data_create(WiFiApp* app, void** out_data);
void portal_data_cleanup_internal(View* view, void* data);

// Handshakes sub-screen
View* screen_handshakes_create(WiFiApp* app, void** out_data);
void handshakes_cleanup_internal(View* view, void* data);
