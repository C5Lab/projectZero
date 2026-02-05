/**
 * Attack Screen Declarations
 * 
 * Each attack screen follows the same lifecycle pattern:
 * 1. screen_*_create() - Allocates all resources (Data struct, strings, threads, view)
 * 2. *_cleanup() - Frees all resources when screen is popped
 * 
 * Usage with screen_push_with_cleanup():
 *   void* data = NULL;
 *   View* view = screen_*_create(app, &data);
 *   screen_push_with_cleanup(app, view, *_cleanup, data);
 */

#pragma once

#include "app.h"

// ============================================================================
// Forward Declarations for Cleanup Data
// ============================================================================

typedef struct DeauthData DeauthData;
typedef struct EvilTwinData EvilTwinData;

// ============================================================================
// Screen Creation Functions
// ============================================================================

// Deauth Attack - sends deauth frames to selected networks
View* screen_deauth_create(WiFiApp* app, DeauthData** out_data);

// Evil Twin - creates fake AP with captive portal
View* screen_evil_twin_create(WiFiApp* app, EvilTwinData** out_data);

// SAE Overflow - WPA3 SAE vulnerability attack
View* screen_sae_overflow_create(WiFiApp* app, void** out_data);

// Handshaker - captures WPA handshakes from selected networks
View* screen_handshaker_create(WiFiApp* app, void** out_data);

// Sniffer - passive packet capture
View* screen_sniffer_create(WiFiApp* app, void** out_data);

// Global Handshaker - captures handshakes from all visible networks
View* screen_global_handshaker_create(WiFiApp* app, void** out_data);

// ============================================================================
// Cleanup Functions (for use with screen_push_with_cleanup)
// ============================================================================

void deauth_cleanup(View* view, void* data);
void evil_twin_cleanup(View* view, void* data);
void sae_overflow_cleanup(View* view, void* data);
void handshaker_cleanup(View* view, void* data);
void sniffer_cleanup(View* view, void* data);
void global_handshaker_cleanup(View* view, void* data);
