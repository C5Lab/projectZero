#include "screen_wifi_scan.h"
#include "screen_attacks.h"
#include "screen.h"
#include "uart_comm.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct {
    WiFiApp* app;
    uint8_t selected_idx;
    uint32_t scroll_offset;
} WiFiScanModel;

typedef struct {
    WiFiApp* app;
    uint8_t attack_type; // 0=Deauth, 1=Evil Twin, 2=SAE, 3=Handshaker, 4=Sniffer
    uint8_t selected_idx;
} AttackSelectionModel;

// Helper to check if network is selected
static bool is_network_selected(WiFiApp* app, uint32_t net_index_one_based) {
    if(!app) return false;
    for(uint32_t i = 0; i < app->selected_count; i++) {
        if(app->selected_networks[i] == net_index_one_based) {
            return true;
        }
    }
    return false;
}

//=============================================================================
// Network Info Screen - shows details for selected network
//=============================================================================

typedef struct {
    WiFiApp* app;
    uint32_t network_idx; // 0-based index
} NetworkInfoModel;

static void network_info_draw(Canvas* canvas, void* model) {
    NetworkInfoModel* m = (NetworkInfoModel*)model;
    if(!m || !m->app) return;
    
    WiFiApp* app = m->app;
    if(m->network_idx >= app->scan_result_count || !app->scan_results) return;
    
    WiFiNetwork* net = &app->scan_results[m->network_idx];
    
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    screen_draw_title(canvas, "Network Info");
    
    canvas_set_font(canvas, FontSecondary);
    
    // SSID
    char line[48];
    snprintf(line, sizeof(line), "SSID: %s", net->ssid[0] ? net->ssid : "(hidden)");
    canvas_draw_str(canvas, 2, 20, line);
    
    // BSSID
    snprintf(line, sizeof(line), "BSSID: %s", net->bssid);
    canvas_draw_str(canvas, 2, 30, line);
    
    // Channel and RSSI
    snprintf(line, sizeof(line), "Ch: %d  Signal: %d dBm", net->channel, net->rssi);
    canvas_draw_str(canvas, 2, 40, line);
    
    // Auth/Encryption
    snprintf(line, sizeof(line), "Auth: %s", net->auth[0] ? net->auth : "Open");
    canvas_draw_str(canvas, 2, 50, line);
}

static bool network_info_input(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;
    
    NetworkInfoModel* m = view_get_model(view);
    if(!m || !m->app) {
        view_commit_model(view, false);
        return false;
    }
    
    if(event->type != InputTypeShort) {
        view_commit_model(view, false);
        return false;
    }
    
    // Any key goes back
    view_commit_model(view, false);
    screen_pop(m->app);
    return true;
}

static View* screen_network_info_create(WiFiApp* app, uint32_t network_idx) {
    View* view = view_alloc();
    if(!view) return NULL;
    
    view_allocate_model(view, ViewModelTypeLocking, sizeof(NetworkInfoModel));
    
    NetworkInfoModel* m = view_get_model(view);
    m->app = app;
    m->network_idx = network_idx;
    view_commit_model(view, true);
    
    view_set_draw_callback(view, network_info_draw);
    view_set_input_callback(view, network_info_input);
    view_set_context(view, view);
    
    return view;
}

static void wifi_scan_draw(Canvas* canvas, void* model) {
    WiFiScanModel* m = (WiFiScanModel*)model;
    if(!m) return;
    
    WiFiApp* app = m->app;
    if(!app) return;
    
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    
    if(app->scanning_in_progress) {
        // Scanning state
        screen_draw_title(canvas, "C5Lab");
        canvas_set_font(canvas, FontSecondary);
        screen_draw_centered_text(canvas, "Scanning networks...", 32);
        
        char count_str[32];
        snprintf(count_str, sizeof(count_str), "Found: %lu", (unsigned long)app->scan_result_count);
        screen_draw_centered_text(canvas, count_str, 48);
    } else if(app->scan_result_count == 0) {
        // No results or failed
        screen_draw_title(canvas, "C5Lab");
        canvas_set_font(canvas, FontSecondary);
        
        if(app->scan_failed) {
            screen_draw_centered_text(canvas, "Scan Failed", 28);
            screen_draw_centered_text(canvas, "Timeout - no response", 40);
        } else {
            char bytes_line[32];
            snprintf(bytes_line, sizeof(bytes_line), "Rcvd: %lu bytes", (unsigned long)app->scan_bytes_received);
            screen_draw_centered_text(canvas, bytes_line, 28);
            screen_draw_centered_text(canvas, "No networks found", 40);
        }
        screen_draw_centered_text(canvas, "Back=Menu", 56);
    } else {
        // Results with checkboxes - full screen list
        canvas_set_font(canvas, FontSecondary);
        const uint8_t item_height = 9;   // 9px per row for clear separation
        const uint8_t start_y = 8;       // First text baseline
        const uint8_t max_visible = 7;   // 7 rows fit cleanly on 64px screen
        
        uint8_t first_idx = 0;
        if(m->selected_idx >= max_visible) {
            first_idx = m->selected_idx - (max_visible - 1);
        }
        
        for(uint8_t i = 0; i < max_visible && (first_idx + i) < app->scan_result_count; i++) {
            uint8_t idx = first_idx + i;
            uint8_t y = start_y + (i * item_height);
            
            WiFiNetwork* net = &app->scan_results[idx];
            
            if(idx == m->selected_idx) {
                canvas_set_color(canvas, ColorBlack);
                canvas_draw_box(canvas, 0, y - 7, 128, item_height);
                canvas_set_color(canvas, ColorWhite);
            } else {
                canvas_set_color(canvas, ColorBlack);
            }
            
            bool selected = is_network_selected(app, idx + 1);
            char line[42];
            snprintf(line, sizeof(line), "%c %.18s [%d]",
                     selected ? '*' : ' ',
                     net->ssid[0] ? net->ssid : "(hidden)",
                     net->rssi);
            canvas_draw_str(canvas, 2, y, line);
        }
        
    }
}

static bool wifi_scan_input(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;
    
    WiFiScanModel* m = view_get_model(view);
    if(!m) return false;
    
    WiFiApp* app = m->app;
    if(!app) {
        view_commit_model(view, false);
        return false;
    }
    
    // For navigation (Up/Down) - accept Press and Repeat for smooth scrolling
    // For actions (OK, Back, Left, Right) - only accept Short to avoid double triggers
    bool is_navigation = (event->key == InputKeyUp || event->key == InputKeyDown);
    
    if(is_navigation) {
        if(event->type != InputTypePress && event->type != InputTypeRepeat) {
            view_commit_model(view, false);
            return false;
        }
    } else {
        if(event->type != InputTypeShort) {
            view_commit_model(view, false);
            return false;
        }
    }
    
    // Back button always works - also stop scanning
    if(event->key == InputKeyBack) {
        app->scanning_in_progress = false;
        view_commit_model(view, false);
        screen_pop(app);
        return true;
    }
    
    if(app->scanning_in_progress) {
        // Scanning in progress - ignore other input
        view_commit_model(view, false);
        return false;
    }
    
    // No results - only back works
    if(app->scan_result_count == 0) {
        view_commit_model(view, false);
        return false;
    }
    
    // Left button shows network info
    if(event->key == InputKeyLeft) {
        uint8_t idx = m->selected_idx;
        view_commit_model(view, false);
        View* info_view = screen_network_info_create(app, idx);
        if(info_view) {
            screen_push(app, info_view);
        }
        return true;
    }
    
    // Navigation in results list
    if(event->key == InputKeyUp) {
        if(m->selected_idx > 0) {
            m->selected_idx--;
        }
    } else if(event->key == InputKeyDown) {
        if(m->selected_idx < app->scan_result_count - 1) {
            m->selected_idx++;
        }
    } else if(event->key == InputKeyOk) {
        // Toggle network selection
        uint32_t net_idx = m->selected_idx + 1; // 1-based index
        bool already_selected = false;
        
        for(uint32_t i = 0; i < app->selected_count; i++) {
            if(app->selected_networks[i] == net_idx) {
                already_selected = true;
                // Remove from selection
                for(uint32_t j = i; j < app->selected_count - 1; j++) {
                    app->selected_networks[j] = app->selected_networks[j + 1];
                }
                app->selected_count--;
                break;
            }
        }
        
        if(!already_selected && app->selected_count < 50) {
            app->selected_networks[app->selected_count++] = net_idx;
        }
    } else if(event->key == InputKeyRight) {
        // Proceed to attack selection if networks are selected
        if(app->selected_count > 0) {
            view_commit_model(view, true);
            View* attack_screen = screen_attack_selection_create(app);
            if(attack_screen) {
                screen_push(app, attack_screen);
            }
            return true;
        }
    }
    
    view_commit_model(view, true);
    return true;
}

View* screen_wifi_scan_create(WiFiApp* app) {
    View* view = view_alloc();
    if(!view) return NULL;
    
    view_allocate_model(view, ViewModelTypeLocking, sizeof(WiFiScanModel));
    
    WiFiScanModel* m = view_get_model(view);
    if(!m) {
        view_free(view);
        return NULL;
    }
    
    m->app = app;
    m->selected_idx = 0;
    m->scroll_offset = 0;
    
    view_commit_model(view, true);
    
    // Clear previous selection
    app->selected_count = 0;
    memset(app->selected_networks, 0, sizeof(app->selected_networks));
    
    view_set_draw_callback(view, wifi_scan_draw);
    view_set_input_callback(view, wifi_scan_input);
    view_set_context(view, view);
    
    // Start scanning networks via UART
    uart_start_scan(app);
    
    return view;
}

void screen_wifi_scan_destroy(View* view) {
    view_free(view);
}

// ============================================================================
// Attack Item Filtering (Red Team mode)
// ============================================================================

typedef struct {
    const char* label;
    uint8_t attack_id; // 0=Deauth,1=EvilTwin,2=SAE,3=Handshaker,4=Sniffer,5=RogueAP,6=ARP
    bool red_team_only;
} AttackMenuItem;

static const AttackMenuItem all_attack_items[] = {
    {"Deauth",        0, true},
    {"Evil Twin",     1, true},
    {"SAE Overflow",  2, true},
    {"Handshaker",    3, true},
    {"Sniffer",       4, false},
    {"Rogue AP",      5, true},
    {"ARP Poisoning", 6, true},
};
#define ALL_ATTACK_ITEM_COUNT 7

static uint8_t get_visible_attack_items(WiFiApp* app, AttackMenuItem* out, uint8_t max_out) {
    uint8_t count = 0;
    for(uint8_t i = 0; i < ALL_ATTACK_ITEM_COUNT && count < max_out; i++) {
        if(app->red_team_mode || !all_attack_items[i].red_team_only) {
            out[count++] = all_attack_items[i];
        }
    }
    return count;
}

// ============================================================================
// Attack Selection Screen
// ============================================================================

static void attack_selection_draw(Canvas* canvas, void* model) {
    AttackSelectionModel* m = (AttackSelectionModel*)model;
    if(!m) return;
    
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    screen_draw_title(canvas, m->app->red_team_mode ? "Select Attack" : "Select Test");
    
    AttackMenuItem visible[ALL_ATTACK_ITEM_COUNT];
    uint8_t attack_count = get_visible_attack_items(m->app, visible, ALL_ATTACK_ITEM_COUNT);
    
    canvas_set_font(canvas, FontSecondary);
    uint8_t y = 22;
    const uint8_t max_visible = 5;
    uint8_t start = 0;
    if(m->attack_type >= max_visible) {
        start = m->attack_type - max_visible + 1;
    }
    
    for(uint8_t i = start; i < attack_count && (i - start) < max_visible; i++) {
        uint8_t display_y = y + ((i - start) * 10);
        if(i == m->attack_type) {
            canvas_draw_box(canvas, 0, display_y - 8, 128, 10);
            canvas_set_color(canvas, ColorWhite);
            canvas_draw_str(canvas, 2, display_y, visible[i].label);
            canvas_set_color(canvas, ColorBlack);
        } else {
            canvas_draw_str(canvas, 2, display_y, visible[i].label);
        }
    }
}

static bool attack_selection_input(InputEvent* event, void* context) {
    View* view = (View*)context;
    if(!view) return false;
    
    AttackSelectionModel* m = view_get_model(view);
    if(!m) return false;
    
    WiFiApp* app = m->app;
    if(!app) {
        view_commit_model(view, false);
        return false;
    }
    
    AttackMenuItem visible[ALL_ATTACK_ITEM_COUNT];
    uint8_t item_count = get_visible_attack_items(app, visible, ALL_ATTACK_ITEM_COUNT);
    
    if(event->type != InputTypePress && event->type != InputTypeRepeat) {
        view_commit_model(view, false);
        return false;
    }
    
    if(event->key == InputKeyUp) {
        if(m->attack_type > 0) {
            m->attack_type--;
        }
    } else if(event->key == InputKeyDown) {
        if(item_count > 0 && m->attack_type < item_count - 1) {
            m->attack_type++;
        }
    } else if(event->key == InputKeyOk) {
        // Map visual index to real attack type
        uint8_t visual_idx = m->attack_type;
        view_commit_model(view, false);
        
        if(visual_idx >= item_count) return true;
        uint8_t attack_type = visible[visual_idx].attack_id;
        
        // Rogue AP and ARP Poisoning require exactly 1 selected network
        if((attack_type == 5 || attack_type == 6) && app->selected_count != 1) {
            // Cannot launch - need exactly 1 network
            return true;
        }
        
        View* attack_view = NULL;
        void (*cleanup_func)(View*, void*) = NULL;
        void* cleanup_data = NULL;
        
        if(attack_type == 0) {
            DeauthData* data = NULL;
            attack_view = screen_deauth_create(app, &data);
            cleanup_func = deauth_cleanup;
            cleanup_data = data;
        } else if(attack_type == 1) {
            EvilTwinData* data = NULL;
            attack_view = screen_evil_twin_create(app, &data);
            cleanup_func = evil_twin_cleanup;
            cleanup_data = data;
        } else if(attack_type == 2) {
            attack_view = screen_sae_overflow_create(app, &cleanup_data);
            cleanup_func = sae_overflow_cleanup;
        } else if(attack_type == 3) {
            attack_view = screen_handshaker_create(app, &cleanup_data);
            cleanup_func = handshaker_cleanup;
        } else if(attack_type == 4) {
            attack_view = screen_sniffer_create(app, &cleanup_data);
            cleanup_func = sniffer_cleanup;
        } else if(attack_type == 5) {
            attack_view = screen_rogue_ap_create(app, &cleanup_data);
            cleanup_func = rogue_ap_cleanup_internal;
        } else if(attack_type == 6) {
            attack_view = screen_arp_poisoning_create(app, &cleanup_data);
            cleanup_func = arp_poisoning_cleanup_internal;
        }
        if(attack_view) {
            screen_push_with_cleanup(app, attack_view, cleanup_func, cleanup_data);
        }
        return true;
    } else if(event->key == InputKeyBack) {
        view_commit_model(view, false);
        screen_pop(app);
        return true;
    }
    
    view_commit_model(view, true);
    return true;
}

View* screen_attack_selection_create(WiFiApp* app) {
    View* view = view_alloc();
    if(!view) return NULL;
    
    view_allocate_model(view, ViewModelTypeLocking, sizeof(AttackSelectionModel));
    
    AttackSelectionModel* m = view_get_model(view);
    if(!m) {
        view_free(view);
        return NULL;
    }
    
    m->app = app;
    m->attack_type = 0;
    
    view_commit_model(view, true);
    
    view_set_draw_callback(view, attack_selection_draw);
    view_set_input_callback(view, attack_selection_input);
    view_set_context(view, view);
    
    return view;
}

void screen_attack_selection_destroy(View* view) {
    view_free(view);
}
