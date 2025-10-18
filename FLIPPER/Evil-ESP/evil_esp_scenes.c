#include <furi.h>
#include <furi_hal.h>
#include <gui/gui.h>
#include <gui/view_dispatcher.h>
#include <gui/scene_manager.h>
#include <gui/modules/submenu.h>
#include <gui/modules/text_box.h>
#include <gui/modules/text_input.h>
#include <gui/modules/popup.h>
#include <gui/modules/widget.h>
#include <notification/notification_messages.h>
#include <dialogs/dialogs.h>
#include <storage/storage.h>

#include "evil_esp.h"

// Configuration menu items
enum EvilEspConfigMenuIndex {
    EvilEspConfigMenuIndexCycleDelay = 0,
    EvilEspConfigMenuIndexScanTime,
    EvilEspConfigMenuIndexFramesPerAP,
    EvilEspConfigMenuIndexStartChannel,
    EvilEspConfigMenuIndexLedEnabled,
    EvilEspConfigMenuIndexDebugMode,
    EvilEspConfigMenuIndexGpioPins,
    EvilEspConfigMenuIndexSendToDevice,
};

// Debug logging functions
void debug_write_to_sd(const char* data) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* file = storage_file_alloc(storage);

    // Ensure debug directory exists
    storage_simply_mkdir(storage, EXT_PATH("apps_data"));

    // Open debug log file in append mode
    if(storage_file_open(file, EXT_PATH("apps_data/evil_esp_debug.txt"), FSAM_WRITE, FSOM_OPEN_APPEND)) {
        // Write timestamp and data
        char timestamp[32];
        uint32_t tick = furi_get_tick();
        snprintf(timestamp, sizeof(timestamp), "[%lu] ", tick);

        storage_file_write(file, timestamp, strlen(timestamp));
        storage_file_write(file, data, strlen(data));
        storage_file_write(file, "\n", 1);
        storage_file_sync(file);

        storage_file_close(file);
    }

    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
}

static void debug_clear_log() {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    storage_simply_remove(storage, EXT_PATH("apps_data/evil_esp_debug.txt"));
    furi_record_close(RECORD_STORAGE);
}

// Clear all network scan results and reset selection state
static void clear_network_scan_results(EvilEspApp* app, const char* debug_message) {
    // Clear previous scan results and selections completely
    app->network_count = 0;
    app->scan_in_progress = true;

    // Explicitly clear all networks and reset selection state
    for(int i = 0; i < EVIL_ESP_MAX_NETWORKS; i++) {
        memset(&app->networks[i], 0, sizeof(EvilEspNetwork));
        app->networks[i].selected = false;
        app->networks[i].index = i; // Internal array index
        app->networks[i].device_index = i; // Will be set properly by UART parser
    }

    // Clear attack state targets since networks are changing
    app->attack_state.num_targets = 0;
    memset(app->attack_state.target_indices, 0, sizeof(app->attack_state.target_indices));

    // Clear debug log at start of new scan
    debug_clear_log();
    if(debug_message) {
        debug_write_to_sd(debug_message);
    }

    FURI_LOG_I("EvilEsp", "Cleared %d networks and all selections: %s", EVIL_ESP_MAX_NETWORKS, debug_message ? debug_message : "");
}

// Submenu callback functions
static void evil_esp_submenu_callback_main_menu(void* context, uint32_t index) {
    EvilEspApp* app = context;
    view_dispatcher_send_custom_event(app->view_dispatcher, index);
}

static void evil_esp_submenu_callback_attacks(void* context, uint32_t index) {
    EvilEspApp* app = context;
    view_dispatcher_send_custom_event(app->view_dispatcher, index);
}

static void evil_esp_submenu_callback_sniffer(void* context, uint32_t index) {
    EvilEspApp* app = context;
    view_dispatcher_send_custom_event(app->view_dispatcher, index);
}

// Text input callback for UART terminal
static void evil_esp_text_input_callback_uart(void* context) {
    EvilEspApp* app = context;

    // Send the custom command (already logs TX automatically)
    if(strlen(app->text_input_store) > 0) {
        evil_esp_send_command(app, app->text_input_store);
    }

    // Switch to terminal display mode
    scene_manager_set_scene_state(app->scene_manager, EvilEspSceneUartTerminal, 1);
    scene_manager_next_scene(app->scene_manager, EvilEspSceneUartTerminal);
}

// Text input callback for Portal SSID
static void evil_esp_text_input_callback_portal(void* context) {
    EvilEspApp* app = context;

    // Send start_portal command with the SSID
    if(strlen(app->text_input_store) > 0) {
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "start_portal %s", app->text_input_store);
        evil_esp_send_command(app, cmd);
    }

    // Switch to terminal display mode
    scene_manager_set_scene_state(app->scene_manager, EvilEspSceneUartTerminal, 1);
    scene_manager_next_scene(app->scene_manager, EvilEspSceneUartTerminal);
}

// Text input callback for configuration
static void evil_esp_config_input_callback(void* context) {
    EvilEspApp* app = context;

    if(strlen(app->text_input_store) > 0) {
        uint32_t value = atoi(app->text_input_store);

        // Update the configuration based on which item was being edited
        switch(app->selected_network_index) {
        case EvilEspConfigMenuIndexCycleDelay:
            if(value >= 100 && value <= 60000) { // 100ms to 60s
                app->config.cycle_delay = value;
            }
            break;

        case EvilEspConfigMenuIndexScanTime:
            if(value >= 1000 && value <= 30000) { // 1s to 30s
                app->config.scan_time = value;
            }
            break;

        case EvilEspConfigMenuIndexFramesPerAP:
            if(value >= 1 && value <= 20) { // 1 to 20 frames
                app->config.num_frames = value;
            }
            break;

        case EvilEspConfigMenuIndexStartChannel:
            if(value >= 1 && value <= 14) { // WiFi channels 1-14
                app->config.start_channel = (uint8_t)value;
            }
            break;
        }
    }

    // Go back to config menu
    scene_manager_next_scene(app->scene_manager, EvilEspSceneConfig);
}

// Scene: Start
void evil_esp_scene_on_enter_start(void* context) {
    EvilEspApp* app = context;

    // Clear log to monitor for BOARD READY message
    evil_esp_clear_log(app);

    // Show connection message popup
    popup_set_header(app->popup, "Connect C5 Lab", 64, 8, AlignCenter, AlignTop);
    popup_set_text(app->popup, "Waiting for ESP...\nConnecting board...", 64, 35, AlignCenter, AlignCenter);
    popup_set_icon(app->popup, 0, 0, NULL); // No icon
    popup_set_callback(app->popup, NULL);
    popup_set_context(app->popup, app);
    popup_disable_timeout(app->popup); // Disable auto-timeout, we'll wait for BOARD READY
    view_dispatcher_switch_to_view(app->view_dispatcher, EvilEspViewPopup);
}

bool evil_esp_scene_on_event_start(void* context, SceneManagerEvent event) {
    EvilEspApp* app = context;
    
    static uint32_t popup_start_time = 0;
    static uint32_t last_log_check_time = 0;
    
    // Initialize popup timer on first call
    if(popup_start_time == 0) {
        popup_start_time = furi_get_tick();
    }

    if(event.type == SceneManagerEventTypeCustom) {
        if(event.event == EvilEspEventExit) {
            scene_manager_stop(app->scene_manager);
            view_dispatcher_stop(app->view_dispatcher);
            popup_start_time = 0;
            last_log_check_time = 0;
            return true;
        }
    }
    
    // Check log for "BOARD READY" message every 100ms
    uint32_t current_time = furi_get_tick();
    if(current_time - last_log_check_time > 100) {
        last_log_check_time = current_time;
        
        // Check if log contains "BOARD READY"
        if(app->log_string && furi_string_size(app->log_string) > 0) {
            const char* log_content = furi_string_get_cstr(app->log_string);
            if(strstr(log_content, "BOARD READY") != NULL) {
                FURI_LOG_I("EvilEsp", "BOARD READY detected! Auto-advancing to main menu");
                popup_start_time = 0;
                last_log_check_time = 0;
                // Go directly to main menu
                scene_manager_next_scene(app->scene_manager, EvilEspSceneMainMenu);
                return true;
            }
        }
    }
    
    // Handle manual back button press - allow user to skip waiting
    if(event.type == SceneManagerEventTypeBack) {
        popup_start_time = 0;
        last_log_check_time = 0;
        // Go to main menu
        scene_manager_next_scene(app->scene_manager, EvilEspSceneMainMenu);
        return true;
    }
    
    // Fallback: Auto-advance after 10 seconds if BOARD READY not detected
    if(current_time - popup_start_time > 10000) {
        FURI_LOG_W("EvilEsp", "Timeout waiting for BOARD READY, advancing to main menu anyway");
        popup_start_time = 0;
        last_log_check_time = 0;
        // Go to main menu after timeout
        scene_manager_next_scene(app->scene_manager, EvilEspSceneMainMenu);
        return true;
    }

    return false;
}

void evil_esp_scene_on_exit_start(void* context) {
    EvilEspApp* app = context;
    popup_reset(app->popup);
}

// Scene: Main Menu
enum EvilEspMainMenuIndex {
    EvilEspMainMenuIndexScanner,
    EvilEspMainMenuIndexSnifferMenu,
    EvilEspMainMenuIndexAttacks,
    EvilEspMainMenuIndexSniffer,
    EvilEspMainMenuIndexListPortals,
    EvilEspMainMenuIndexConfig,
    EvilEspMainMenuIndexDeviceInfo,
    EvilEspMainMenuIndexUartTerminal,
};

void evil_esp_scene_on_enter_main_menu(void* context) {
    EvilEspApp* app = context;

    // Clear the first visit flag if set (we now go directly to main menu after BOARD READY detection)
    if(app->first_main_menu_visit) {
        app->first_main_menu_visit = false;
    }

    submenu_reset(app->submenu);
    submenu_set_header(app->submenu, "C5 Lab 1.5");

    submenu_add_item(app->submenu, "Scanner", EvilEspMainMenuIndexScanner, evil_esp_submenu_callback_main_menu, app);
    submenu_add_item(app->submenu, "Sniffer", EvilEspMainMenuIndexSnifferMenu, evil_esp_submenu_callback_main_menu, app);
    submenu_add_item(app->submenu, "Targets", EvilEspMainMenuIndexSniffer, evil_esp_submenu_callback_main_menu, app);
    submenu_add_item(app->submenu, "Attacks", EvilEspMainMenuIndexAttacks, evil_esp_submenu_callback_main_menu, app);
    submenu_add_item(app->submenu, "List Portals", EvilEspMainMenuIndexListPortals, evil_esp_submenu_callback_main_menu, app);

    //submenu_add_item(app->submenu, "Configuration", EvilEspMainMenuIndexConfig, evil_esp_submenu_callback_main_menu, app);
    //submenu_add_item(app->submenu, "Help", EvilEspMainMenuIndexDeviceInfo, evil_esp_submenu_callback_main_menu, app);
    submenu_add_item(app->submenu, "UART Terminal", EvilEspMainMenuIndexUartTerminal, evil_esp_submenu_callback_main_menu, app);

    submenu_set_selected_item(app->submenu, app->selected_menu_index);
    view_dispatcher_switch_to_view(app->view_dispatcher, EvilEspViewMainMenu);
}

bool evil_esp_scene_on_event_main_menu(void* context, SceneManagerEvent event) {
    EvilEspApp* app = context;

    if(event.type == SceneManagerEventTypeBack) {
        // Exit the app when back is pressed from main menu
        scene_manager_stop(app->scene_manager);
        view_dispatcher_stop(app->view_dispatcher);
        return true;
    }
    else if(event.type == SceneManagerEventTypeCustom) {
        app->selected_menu_index = event.event;

        switch(event.event) {
        case EvilEspMainMenuIndexScanner:
            // Clear previous scan results before starting new scan
            clear_network_scan_results(app, "=== NEW SCAN STARTED FROM MAIN MENU ===");
            
            // Send scan command and open terminal to see results immediately
            evil_esp_send_command(app, "scan_networks");
            scene_manager_set_scene_state(app->scene_manager, EvilEspSceneUartTerminal, 1);
            scene_manager_next_scene(app->scene_manager, EvilEspSceneUartTerminal);
            return true;
        case EvilEspMainMenuIndexSnifferMenu:
            // Go to Sniffer submenu
            scene_manager_next_scene(app->scene_manager, EvilEspSceneSnifferMenu);
            return true;
        case EvilEspMainMenuIndexAttacks:
            scene_manager_next_scene(app->scene_manager, EvilEspSceneAttacks);
            return true;
        case EvilEspMainMenuIndexSniffer:
            // Go to target selection scene (repurposed sniffer scene)
            scene_manager_next_scene(app->scene_manager, EvilEspSceneSniffer);
            return true;
        case EvilEspMainMenuIndexListPortals:
            // Go to portal list scene
            scene_manager_next_scene(app->scene_manager, EvilEspSceneListPortals);
            return true;
        case EvilEspMainMenuIndexConfig:
            // Go to proper configuration scene
            scene_manager_next_scene(app->scene_manager, EvilEspSceneConfig);
            return true;
        case EvilEspMainMenuIndexDeviceInfo:
            // Go to help scene
            scene_manager_next_scene(app->scene_manager, EvilEspSceneDeviceInfo);
            return true;
        case EvilEspMainMenuIndexUartTerminal:
            // Go to text input first for custom commands
            strncpy(app->text_input_store, "", EVIL_ESP_TEXT_INPUT_STORE_SIZE - 1);
            scene_manager_set_scene_state(app->scene_manager, EvilEspSceneUartTerminal, 0);
            scene_manager_next_scene(app->scene_manager, EvilEspSceneUartTerminal);
            return true;
        }
    }

    return false;
}

void evil_esp_scene_on_exit_main_menu(void* context) {
    EvilEspApp* app = context;
    submenu_reset(app->submenu);
}

// Scene: Scanner
void evil_esp_scene_on_enter_scanner(void* context) {
    EvilEspApp* app = context;

    // Show loading screen for a few seconds, then show fake results
    evil_esp_show_loading(app, "Scanning WiFi networks...");

    // Clear previous scan results and selections completely
    clear_network_scan_results(app, "=== NEW SCAN STARTED ===");

    // Send scan command - UART worker will handle all parsing
    evil_esp_send_scan_command(app);
}

bool evil_esp_scene_on_event_scanner(void* context, SceneManagerEvent event) {
    EvilEspApp* app = context;

    // Handle scan completion event from UART worker
    if(event.type == SceneManagerEventTypeCustom) {
        if(event.event == EvilEspEventScanComplete) {
            FURI_LOG_I("EvilEsp", "Scan complete event received with %d networks", app->network_count);
            app->scan_in_progress = false;
            evil_esp_hide_loading(app);
            scene_manager_next_scene(app->scene_manager, EvilEspSceneScannerResults);
            return true;
        }
    }

    // Timeout after 15 seconds in case scan gets stuck
    static uint32_t scan_start_time = 0;
    if(scan_start_time == 0) {
        scan_start_time = furi_get_tick();
    }

    if(furi_get_tick() - scan_start_time > 45000) {
        FURI_LOG_I("EvilEsp", "Scan timeout reached with %d networks found", app->network_count);

        if(app->network_count == 0) {
            // No networks found after timeout - add diagnostic info
            strcpy(app->networks[0].ssid, "Scan Timeout");
            strcpy(app->networks[0].bssid, "No UART Data");
            app->networks[0].channel = 1;
            app->networks[0].rssi = -99;
            app->networks[0].band = EvilEspBand24GHz;
            app->networks[0].index = 0;
            app->networks[0].selected = false;

            strcpy(app->networks[1].ssid, "ESP Not Responding");
            const char* pins = (app->config.gpio_pins == EvilEspGpioPins13_14) ? "Pin 13/14" : "Pin 15/16";
            strcpy(app->networks[1].bssid, pins);
            app->networks[1].channel = 36;
            app->networks[1].rssi = -99;
            app->networks[1].band = EvilEspBand5GHz;
            app->networks[1].index = 1;
            app->networks[1].selected = false;

            app->network_count = 2;
        }

        app->scan_in_progress = false;
        evil_esp_hide_loading(app);
        scene_manager_next_scene(app->scene_manager, EvilEspSceneScannerResults);
        scan_start_time = 0;
        return true;
    }

    return false;
}

void evil_esp_scene_on_exit_scanner(void* context) {
    EvilEspApp* app = context;
    evil_esp_hide_loading(app);
}

// Scene: Scanner Results - ignore it, it is never displayed to the user!
void evil_esp_scene_on_enter_scanner_results(void* context) {
    EvilEspApp* app = context;

    furi_string_reset(app->text_box_string);

    if(app->network_count == 0) {
        furi_string_printf(app->text_box_string, "No networks found.\n\nPress BACK to return to menu.");
    } else {
        furi_string_printf(app->text_box_string, "Found %d networks:\n\n", app->network_count);

        for(uint8_t i = 0; i < app->network_count; i++) {
            char freq_str[4];
            if(app->networks[i].channel >= 36) {
                strcpy(freq_str, "5G");
            } else {
                strcpy(freq_str, "2G");
            }

            // More compact format to show longer network names
            furi_string_cat_printf(app->text_box_string, 
                "%d %s %d %s\n",   // indeks, SSID, kanał, autoryzacja
                i + 1,             // numer sieci (od 1)
                app->networks[i].ssid,  // SSID
                app->networks[i].channel, // numer kanału
                freq_str           // tutaj wstaw info o autoryzacji lub inny string
            );

        }

        furi_string_cat_printf(app->text_box_string, "Press OK to select targets\nPress BACK to return to menu");
    }

    text_box_set_text(app->text_box, furi_string_get_cstr(app->text_box_string));
    text_box_set_focus(app->text_box, TextBoxFocusEnd);
    view_dispatcher_switch_to_view(app->view_dispatcher, EvilEspViewTextBox);
}

bool evil_esp_scene_on_event_scanner_results(void* context, SceneManagerEvent event) {
    EvilEspApp* app = context;

    if(event.type == SceneManagerEventTypeCustom) {
        if(event.event == 0) { // OK pressed
            // Go to attack configuration
            scene_manager_next_scene(app->scene_manager, EvilEspSceneAttackConfig);
            return true;
        }
    }

    return false;
}

void evil_esp_scene_on_exit_scanner_results(void* context) {
    EvilEspApp* app = context;
    text_box_reset(app->text_box);
}

// Scene: Sniffer Menu
enum EvilEspSnifferMenuIndex {
    EvilEspSnifferMenuIndexSniffPackets,
    EvilEspSnifferMenuIndexShowClients,
    EvilEspSnifferMenuIndexShowProbes,
};

void evil_esp_scene_on_enter_sniffer_menu(void* context) {
    EvilEspApp* app = context;

    submenu_reset(app->submenu);
    submenu_set_header(app->submenu, "Sniffer");

    submenu_add_item(app->submenu, "Sniff Packets", EvilEspSnifferMenuIndexSniffPackets, evil_esp_submenu_callback_sniffer, app);
    submenu_add_item(app->submenu, "Show Clients", EvilEspSnifferMenuIndexShowClients, evil_esp_submenu_callback_sniffer, app);
    submenu_add_item(app->submenu, "Show Probes", EvilEspSnifferMenuIndexShowProbes, evil_esp_submenu_callback_sniffer, app);

    view_dispatcher_switch_to_view(app->view_dispatcher, EvilEspViewMainMenu);
}

bool evil_esp_scene_on_event_sniffer_menu(void* context, SceneManagerEvent event) {
    EvilEspApp* app = context;

    if(event.type == SceneManagerEventTypeCustom) {
        switch(event.event) {
        case EvilEspSnifferMenuIndexSniffPackets:
            // Start packet sniffer
            evil_esp_send_command(app, "start_sniffer");
            scene_manager_set_scene_state(app->scene_manager, EvilEspSceneUartTerminal, 1);
            scene_manager_next_scene(app->scene_manager, EvilEspSceneUartTerminal);
            return true;
        case EvilEspSnifferMenuIndexShowClients:
            // Show sniffer results
            evil_esp_send_command(app, "show_sniffer_results");
            scene_manager_set_scene_state(app->scene_manager, EvilEspSceneUartTerminal, 1);
            scene_manager_next_scene(app->scene_manager, EvilEspSceneUartTerminal);
            return true;
        case EvilEspSnifferMenuIndexShowProbes:
            // Show probe requests
            evil_esp_send_command(app, "show_probes");
            scene_manager_set_scene_state(app->scene_manager, EvilEspSceneUartTerminal, 1);
            scene_manager_next_scene(app->scene_manager, EvilEspSceneUartTerminal);
            return true;
        }
    }

    return false;
}

void evil_esp_scene_on_exit_sniffer_menu(void* context) {
    EvilEspApp* app = context;
    submenu_reset(app->submenu);
}

// Scene: Attacks
enum EvilEspAttacksMenuIndex {
    EvilEspAttacksMenuIndexDeauth,
    EvilEspAttacksMenuIndexDisassoc,
    EvilEspAttacksMenuIndexRandom,
    EvilEspAttacksMenuIndexWardrive,
    EvilEspAttacksMenuIndexBlackout,
    EvilEspAttacksMenuIndexSnifferDog,
    EvilEspAttacksMenuIndexPortal,
    EvilEspAttacksMenuIndexStop,
};

void evil_esp_scene_on_enter_attacks(void* context) {
    EvilEspApp* app = context;

    submenu_reset(app->submenu);
    submenu_set_header(app->submenu, "Attack Mode");

    submenu_add_item(app->submenu, "Deauth Attack", EvilEspAttacksMenuIndexDeauth, evil_esp_submenu_callback_attacks, app);
    submenu_add_item(app->submenu, "Evil Twin Attack", EvilEspAttacksMenuIndexDisassoc, evil_esp_submenu_callback_attacks, app);
    submenu_add_item(app->submenu, "WPA3 SAE Overflow", EvilEspAttacksMenuIndexRandom, evil_esp_submenu_callback_attacks, app);
    submenu_add_item(app->submenu, "Wardrive", EvilEspAttacksMenuIndexWardrive, evil_esp_submenu_callback_attacks, app);
    submenu_add_item(app->submenu, "Blackout", EvilEspAttacksMenuIndexBlackout, evil_esp_submenu_callback_attacks, app);
    submenu_add_item(app->submenu, "SnifferDog", EvilEspAttacksMenuIndexSnifferDog, evil_esp_submenu_callback_attacks, app);
    submenu_add_item(app->submenu, "Portal", EvilEspAttacksMenuIndexPortal, evil_esp_submenu_callback_attacks, app);
    //submenu_add_item(app->submenu, "Stop Attack", EvilEspAttacksMenuIndexStop, evil_esp_submenu_callback_attacks, app);

    view_dispatcher_switch_to_view(app->view_dispatcher, EvilEspViewMainMenu);
}

bool evil_esp_scene_on_event_attacks(void* context, SceneManagerEvent event) {
    EvilEspApp* app = context;

    if(event.type == SceneManagerEventTypeCustom) {
        switch(event.event) {
        case EvilEspAttacksMenuIndexDeauth:
            evil_esp_send_command(app, "start_deauth");
            app->attack_state.active = true;
            app->attack_state.mode = EvilEspAttackModeDeauth;
            scene_manager_set_scene_state(app->scene_manager, EvilEspSceneUartTerminal, 1);
            scene_manager_next_scene(app->scene_manager, EvilEspSceneUartTerminal);
            return true;

        case EvilEspAttacksMenuIndexDisassoc:
            evil_esp_send_command(app, "start_evil_twin");
            app->attack_state.active = true;
            app->attack_state.mode = EvilEspAttackModeDisassoc;
            scene_manager_set_scene_state(app->scene_manager, EvilEspSceneUartTerminal, 1);
            scene_manager_next_scene(app->scene_manager, EvilEspSceneUartTerminal);
            return true;

        case EvilEspAttacksMenuIndexRandom:
            evil_esp_send_command(app, "sae_overflow");
            app->attack_state.mode = EvilEspAttackModeRandom;
            scene_manager_set_scene_state(app->scene_manager, EvilEspSceneUartTerminal, 1);
            scene_manager_next_scene(app->scene_manager, EvilEspSceneUartTerminal);
            return true;

        case EvilEspAttacksMenuIndexWardrive:
            // Enable 5V power on GPIO pin 1 for external devices
            if(furi_hal_power_enable_otg()) {
                FURI_LOG_I("EvilEsp", "5V OTG power enabled for wardrive");
            } else {
                FURI_LOG_W("EvilEsp", "Failed to enable 5V OTG power");
            }
            evil_esp_send_command(app, "start_wardrive");
            scene_manager_set_scene_state(app->scene_manager, EvilEspSceneUartTerminal, 1);
            scene_manager_next_scene(app->scene_manager, EvilEspSceneUartTerminal);
            return true;

        case EvilEspAttacksMenuIndexBlackout:
            evil_esp_send_command(app, "start_blackout");
            app->attack_state.active = true;
            app->attack_state.mode = EvilEspAttackModeRandom; // Use existing mode for blackout
            scene_manager_set_scene_state(app->scene_manager, EvilEspSceneUartTerminal, 1);
            scene_manager_next_scene(app->scene_manager, EvilEspSceneUartTerminal);
            return true;

        case EvilEspAttacksMenuIndexSnifferDog:
            evil_esp_send_command(app, "start_sniffer_dog");
            app->attack_state.active = true;
            app->attack_state.mode = EvilEspAttackModeRandom; // Use existing mode for sniffer dog
            scene_manager_set_scene_state(app->scene_manager, EvilEspSceneUartTerminal, 1);
            scene_manager_next_scene(app->scene_manager, EvilEspSceneUartTerminal);
            return true;

        case EvilEspAttacksMenuIndexPortal:
            // Show text input for SSID
            strncpy(app->text_input_store, "", EVIL_ESP_TEXT_INPUT_STORE_SIZE - 1);
            text_input_reset(app->text_input);
            text_input_set_header_text(app->text_input, "Enter SSID:");
            text_input_set_result_callback(
                app->text_input,
                evil_esp_text_input_callback_portal,
                app,
                app->text_input_store,
                EVIL_ESP_TEXT_INPUT_STORE_SIZE,
                true
            );
            view_dispatcher_switch_to_view(app->view_dispatcher, EvilEspViewTextInput);
            return true;

        case EvilEspAttacksMenuIndexStop:
            // Disable 5V OTG power when stopping attacks
            if(furi_hal_power_is_otg_enabled()) {
                furi_hal_power_disable_otg();
                FURI_LOG_I("EvilEsp", "5V OTG power disabled on attack stop");
            }
            evil_esp_send_attack_stop(app);
            app->attack_state.active = false;
            scene_manager_set_scene_state(app->scene_manager, EvilEspSceneUartTerminal, 1);
            scene_manager_next_scene(app->scene_manager, EvilEspSceneUartTerminal);
            return true;
        }
    }

    return false;
}

void evil_esp_scene_on_exit_attacks(void* context) {
    EvilEspApp* app = context;
    submenu_reset(app->submenu);
}

// Scene: Attack Config
void evil_esp_scene_on_enter_attack_config(void* context) {
    EvilEspApp* app = context;

    furi_string_reset(app->text_box_string);
    furi_string_printf(app->text_box_string, "Attack Configuration\n\n");

    // Show current targets
    if(app->attack_state.num_targets > 0) {
        furi_string_cat_printf(app->text_box_string, "Current targets:\n");
        for(uint8_t i = 0; i < app->attack_state.num_targets; i++) {
            uint8_t idx = app->attack_state.target_indices[i];
            if(idx < app->network_count) {
                furi_string_cat_printf(app->text_box_string, "[%02d] %s\n", idx + 1, app->networks[idx].ssid);
            }
        }
    } else {
        furi_string_cat_printf(app->text_box_string, "No targets selected.\n");
    }

    furi_string_cat_printf(app->text_box_string, "\nPress OK to configure targets");

    text_box_set_text(app->text_box, furi_string_get_cstr(app->text_box_string));
    view_dispatcher_switch_to_view(app->view_dispatcher, EvilEspViewTextBox);
}

bool evil_esp_scene_on_event_attack_config(void* context, SceneManagerEvent event) {
    UNUSED(context);
    UNUSED(event);
    return false;
}

void evil_esp_scene_on_exit_attack_config(void* context) {
    EvilEspApp* app = context;
    text_box_reset(app->text_box);
}

// Scene: Sniffer (Set Targets)
enum EvilEspTargetMenuIndex {
    EvilEspTargetMenuIndexClearAll = 100,
    EvilEspTargetMenuIndexSelectAll = 101,
    EvilEspTargetMenuIndexConfirm = 102,
};

void evil_esp_scene_on_enter_sniffer(void* context) {
    EvilEspApp* app = context;

    submenu_reset(app->submenu);
    submenu_set_header(app->submenu, "Set Attack Targets");

    if(app->network_count == 0) {
        submenu_add_item(app->submenu, "No Networks Found", 0, NULL, app);
        submenu_add_item(app->submenu, "Run WiFi Scan First", 0, NULL, app);
    } else {
        // Show all available networks with optimized formatting for maximum SSID visibility
        for(uint8_t i = 0; i < app->network_count; i++) {
            char menu_text[120];  // Increased buffer size
            
            /*char channel_auth_str[40]; // odpowiedni rozmiar bufora
            snprintf(channel_auth_str, sizeof(channel_auth_str), "%d,%s",
                    app->networks[i].channel,    // Channel
                    app->networks[i].auth        // Auth (np. "WPA/WPA2 Mixed", "Open")
            );*/    

            // Allow longer SSIDs with more compact format
            char ssid_display[40];  // Increased from 32 to 40
            if(strlen(app->networks[i].ssid) > 36) {  // Increased from 28 to 36
                strncpy(ssid_display, app->networks[i].ssid, 33);  // Show 33 chars instead of 25
                ssid_display[33] = '.';
                ssid_display[34] = '.';
                ssid_display[35] = '.';
                ssid_display[36] = '\0';
            } else {
                strcpy(ssid_display, app->networks[i].ssid);
            }

            // More compact format: "✓02:NetworkName (2G)" instead of "✓ [02] NetworkName (2.4G)"
            snprintf(menu_text, sizeof(menu_text), "%02d:%s",
                     i + 1,         // 02: (3 chars) 
                     ssid_display  // NetworkName (up to 36 chars)
                     );     

            submenu_add_item(app->submenu, menu_text, i, evil_esp_submenu_callback_sniffer, app);

            FURI_LOG_D("EvilEsp", "Menu[%d]: '%s' -> device_idx=%d", 
                       i, ssid_display, app->networks[i].device_index);
        }

        // Count selected targets for status display
        int selected_targets = 0;
        for(uint8_t i = 0; i < app->network_count; i++) {
            if(app->networks[i].selected) selected_targets++;
        }

        // Add control options with status
        submenu_add_item(app->submenu, "Clear All Targets", EvilEspTargetMenuIndexClearAll, evil_esp_submenu_callback_sniffer, app);
        submenu_add_item(app->submenu, "Select All Targets", EvilEspTargetMenuIndexSelectAll, evil_esp_submenu_callback_sniffer, app);

        char confirm_text[64];
        snprintf(confirm_text, sizeof(confirm_text), "Confirm Targets (%d selected)", selected_targets);
        submenu_add_item(app->submenu, confirm_text, EvilEspTargetMenuIndexConfirm, evil_esp_submenu_callback_sniffer, app);
    }

    view_dispatcher_switch_to_view(app->view_dispatcher, EvilEspViewMainMenu);
}

bool evil_esp_scene_on_event_sniffer(void* context, SceneManagerEvent event) {
    EvilEspApp* app = context;

    if(event.type == SceneManagerEventTypeCustom) {
        uint32_t selection = event.event;

        // Add debugging for selection issues
        FURI_LOG_I("EvilEsp", "Target selection: event=%lu, network_count=%d", selection, app->network_count);

        if(selection < app->network_count) {
            // Validate the network index before toggling
            if(app->networks[selection].ssid[0] != '\0') { // Ensure network exists
                bool was_selected = app->networks[selection].selected;
                app->networks[selection].selected = !was_selected;

                FURI_LOG_I("EvilEsp", "TOGGLE: User clicked menu[%lu] '%s' (device_idx=%d): %s -> %s", 
                           selection, 
                           app->networks[selection].ssid,
                           app->networks[selection].device_index,
                           was_selected ? "selected" : "unselected",
                           app->networks[selection].selected ? "selected" : "unselected");

                // Refresh the scene by re-entering it (without adding to stack)
                evil_esp_scene_on_exit_sniffer(app);
                evil_esp_scene_on_enter_sniffer(app);
                // Set cursor to "Confirm Targets" after selecting a network
                submenu_set_selected_item(app->submenu, EvilEspTargetMenuIndexConfirm);
                return true;
            } else {
                FURI_LOG_W("EvilEsp", "Invalid network selection: index %lu has empty SSID", selection);
            }
        }

        switch(selection) {
        case EvilEspTargetMenuIndexClearAll:
            // Clear all selections
            for(uint8_t i = 0; i < app->network_count; i++) {
                app->networks[i].selected = false;
            }
            // Refresh scene by re-entering it (without adding to stack)
            evil_esp_scene_on_exit_sniffer(app);
            evil_esp_scene_on_enter_sniffer(app);
            // Set cursor to "Confirm Targets" after clearing all selections
            submenu_set_selected_item(app->submenu, EvilEspTargetMenuIndexConfirm);
            return true;

        case EvilEspTargetMenuIndexSelectAll:
            // Select all networks
            for(uint8_t i = 0; i < app->network_count; i++) {
                app->networks[i].selected = true;
            }
            // Refresh scene by re-entering it (without adding to stack)
            evil_esp_scene_on_exit_sniffer(app);
            evil_esp_scene_on_enter_sniffer(app);
            // Set cursor to "Confirm Targets" after selecting all networks
            submenu_set_selected_item(app->submenu, EvilEspTargetMenuIndexConfirm);
            return true;

        case EvilEspTargetMenuIndexConfirm:
            // Build target list string and send to Arduino using device indices
            FuriString* target_string = furi_string_alloc();
            bool first = true;
            int selected_count = 0;

            for(uint8_t i = 0; i < app->network_count; i++) {
                if(app->networks[i].selected) {
                    if(!first) {
                        furi_string_cat_str(target_string, " ");
                    }
                    // FIX: ESP device uses 1-based indexing, so add 1 to our 0-based menu index
                    furi_string_cat_printf(target_string, "%d", i + 1);
                    first = false;
                    selected_count++;

                    FURI_LOG_I("EvilEsp", "CONFIRM: User selected menu[%d]: '%s' -> sending 1-based index=%d", 
                               i, app->networks[i].ssid, i + 1);
                }
            }

            if(furi_string_size(target_string) > 0) {
                // Send target command to Arduino
                FuriString* set_target_cmd = furi_string_alloc();
                furi_string_printf(set_target_cmd, "select_networks %s", furi_string_get_cstr(target_string));

                FURI_LOG_I("EvilEsp", "Sending target command: '%s' (%d targets)", 
                           furi_string_get_cstr(set_target_cmd), selected_count);

                evil_esp_send_command(app, furi_string_get_cstr(set_target_cmd));
                furi_string_free(set_target_cmd);

                // Show confirmation and go to terminal
                scene_manager_set_scene_state(app->scene_manager, EvilEspSceneUartTerminal, 1);
                scene_manager_next_scene(app->scene_manager, EvilEspSceneUartTerminal);
            } else {
                // No targets selected - show popup
                evil_esp_show_popup(app, "No Targets", "Please select at least one target network");
            }

            furi_string_free(target_string);
            return true;
        }
    }

    return false;
}

void evil_esp_scene_on_exit_sniffer(void* context) {
    EvilEspApp* app = context;
    submenu_reset(app->submenu);
}

// Scene: Sniffer Results
void evil_esp_scene_on_enter_sniffer_results(void* context) {
    EvilEspApp* app = context;

    evil_esp_clear_log(app);
    furi_string_printf(app->log_string, "Packet Sniffer Active\nMode: ");

    switch(app->sniffer_state.mode) {
    case EvilEspSniffModeAll:
        furi_string_cat_printf(app->log_string, "ALL");
        break;
    case EvilEspSniffModeBeacon:
        furi_string_cat_printf(app->log_string, "BEACON");
        break;
    case EvilEspSniffModeProbe:
        furi_string_cat_printf(app->log_string, "PROBE");
        break;
    case EvilEspSniffModeDeauth:
        furi_string_cat_printf(app->log_string, "DEAUTH");
        break;
    case EvilEspSniffModeEapol:
        furi_string_cat_printf(app->log_string, "EAPOL");
        break;
    case EvilEspSniffModePwnagotchi:
        furi_string_cat_printf(app->log_string, "PWNAGOTCHI");
        break;
    }

    furi_string_cat_printf(app->log_string, "\nChannel: %d\nHopping: %s\n\n", 
                          app->sniffer_state.channel,
                          app->sniffer_state.hopping ? "ON" : "OFF"
    );

    text_box_set_text(app->text_box, furi_string_get_cstr(app->log_string));
    text_box_set_focus(app->text_box, TextBoxFocusEnd);
    view_dispatcher_switch_to_view(app->view_dispatcher, EvilEspViewTextBox);
}

bool evil_esp_scene_on_event_sniffer_results(void* context, SceneManagerEvent event) {
    EvilEspApp* app = context;
    UNUSED(event);

    // For now, just show static content without reading UART
    static uint32_t last_update = 0;
    if(furi_get_tick() - last_update > 2000) { // Update every 2 seconds
        app->sniffer_state.packet_count++;
        evil_esp_append_log(app, "Packet capture simulation running...");
        text_box_set_text(app->text_box, furi_string_get_cstr(app->log_string));
        text_box_set_focus(app->text_box, TextBoxFocusEnd);
        last_update = furi_get_tick();
    }

    return false;
}

void evil_esp_scene_on_exit_sniffer_results(void* context) {
    EvilEspApp* app = context;
    text_box_reset(app->text_box);
}

// Scene: Config
void evil_esp_scene_on_enter_config(void* context) {
    EvilEspApp* app = context;

    submenu_reset(app->submenu);
    submenu_set_header(app->submenu, "Configuration Settings");

    char temp_str[64];

    snprintf(temp_str, sizeof(temp_str), "Cycle Delay: %lu ms", app->config.cycle_delay);
    submenu_add_item(app->submenu, temp_str, EvilEspConfigMenuIndexCycleDelay, evil_esp_submenu_callback_attacks, app);

    snprintf(temp_str, sizeof(temp_str), "Scan Time: %lu ms", app->config.scan_time);
    submenu_add_item(app->submenu, temp_str, EvilEspConfigMenuIndexScanTime, evil_esp_submenu_callback_attacks, app);

    snprintf(temp_str, sizeof(temp_str), "Frames per AP: %lu", app->config.num_frames);
    submenu_add_item(app->submenu, temp_str, EvilEspConfigMenuIndexFramesPerAP, evil_esp_submenu_callback_attacks, app);

    snprintf(temp_str, sizeof(temp_str), "Start Channel: %d", app->config.start_channel);
    submenu_add_item(app->submenu, temp_str, EvilEspConfigMenuIndexStartChannel, evil_esp_submenu_callback_attacks, app);

    snprintf(temp_str, sizeof(temp_str), "LED Enabled: %s", app->config.led_enabled ? "Yes" : "No");
    submenu_add_item(app->submenu, temp_str, EvilEspConfigMenuIndexLedEnabled, evil_esp_submenu_callback_attacks, app);

    snprintf(temp_str, sizeof(temp_str), "Debug Mode: %s", app->config.debug_mode ? "Yes" : "No");
    submenu_add_item(app->submenu, temp_str, EvilEspConfigMenuIndexDebugMode, evil_esp_submenu_callback_attacks, app);

    snprintf(temp_str, sizeof(temp_str), "GPIO Pins: %s", app->config.gpio_pins == EvilEspGpioPins13_14 ? "13/14" : "15/16");
    submenu_add_item(app->submenu, temp_str, EvilEspConfigMenuIndexGpioPins, evil_esp_submenu_callback_attacks, app);

    submenu_add_item(app->submenu, "Send Config to Device", EvilEspConfigMenuIndexSendToDevice, evil_esp_submenu_callback_attacks, app);

    view_dispatcher_switch_to_view(app->view_dispatcher, EvilEspViewMainMenu);
}

bool evil_esp_scene_on_event_config(void* context, SceneManagerEvent event) {
    EvilEspApp* app = context;

    if(event.type == SceneManagerEventTypeCustom) {
        switch(event.event) {
        case EvilEspConfigMenuIndexCycleDelay:
            // Set up text input for cycle delay
            strncpy(app->text_input_store, "2000", EVIL_ESP_TEXT_INPUT_STORE_SIZE - 1);
            text_input_reset(app->text_input);
            text_input_set_header_text(app->text_input, "Cycle Delay (ms):");
            text_input_set_result_callback(
                app->text_input,
                evil_esp_config_input_callback,
                app,
                app->text_input_store,
                EVIL_ESP_TEXT_INPUT_STORE_SIZE,
                true
            );
            app->selected_network_index = EvilEspConfigMenuIndexCycleDelay; // Store which config item we're editing
            view_dispatcher_switch_to_view(app->view_dispatcher, EvilEspViewTextInput);
            return true;

        case EvilEspConfigMenuIndexScanTime:
            strncpy(app->text_input_store, "5000", EVIL_ESP_TEXT_INPUT_STORE_SIZE - 1);
            text_input_reset(app->text_input);
            text_input_set_header_text(app->text_input, "Scan Time (ms):");
            text_input_set_result_callback(
                app->text_input,
                evil_esp_config_input_callback,
                app,
                app->text_input_store,
                EVIL_ESP_TEXT_INPUT_STORE_SIZE,
                true
            );
            app->selected_network_index = EvilEspConfigMenuIndexScanTime;
            view_dispatcher_switch_to_view(app->view_dispatcher, EvilEspViewTextInput);
            return true;

        case EvilEspConfigMenuIndexFramesPerAP:
            strncpy(app->text_input_store, "3", EVIL_ESP_TEXT_INPUT_STORE_SIZE - 1);
            text_input_reset(app->text_input);
            text_input_set_header_text(app->text_input, "Frames per AP:");
            text_input_set_result_callback(
                app->text_input,
                evil_esp_config_input_callback,
                app,
                app->text_input_store,
                EVIL_ESP_TEXT_INPUT_STORE_SIZE,
                true
            );
            app->selected_network_index = EvilEspConfigMenuIndexFramesPerAP;
            view_dispatcher_switch_to_view(app->view_dispatcher, EvilEspViewTextInput);
            return true;

        case EvilEspConfigMenuIndexStartChannel:
            strncpy(app->text_input_store, "1", EVIL_ESP_TEXT_INPUT_STORE_SIZE - 1);
            text_input_reset(app->text_input);
            text_input_set_header_text(app->text_input, "Start Channel (1-14):");
            text_input_set_result_callback(
                app->text_input,
                evil_esp_config_input_callback,
                app,
                app->text_input_store,
                EVIL_ESP_TEXT_INPUT_STORE_SIZE,
                true
            );
            app->selected_network_index = EvilEspConfigMenuIndexStartChannel;
            view_dispatcher_switch_to_view(app->view_dispatcher, EvilEspViewTextInput);
            return true;

        case EvilEspConfigMenuIndexLedEnabled:
            // Toggle LED setting
            app->config.led_enabled = !app->config.led_enabled;
            // Refresh menu to show updated value
            evil_esp_scene_on_exit_config(app);
            evil_esp_scene_on_enter_config(app);
            return true;

        case EvilEspConfigMenuIndexDebugMode:
            // Toggle debug mode
            app->config.debug_mode = !app->config.debug_mode;
            // Refresh menu to show updated value
            evil_esp_scene_on_exit_config(app);
            evil_esp_scene_on_enter_config(app);
            return true;

        case EvilEspConfigMenuIndexGpioPins:
            // Toggle GPIO pins setting
            app->config.gpio_pins = (app->config.gpio_pins == EvilEspGpioPins13_14) ? EvilEspGpioPins15_16 : EvilEspGpioPins13_14;

            // Show loading popup while restarting UART
            evil_esp_show_popup(app, "Switching GPIO", "Restarting UART...");

            // Restart UART worker with new GPIO configuration
            evil_esp_uart_restart(app);

            // Show success popup
            const char* pin_text = (app->config.gpio_pins == EvilEspGpioPins13_14) ? "13/14" : "15/16";
            char success_msg[64];
            snprintf(success_msg, sizeof(success_msg), "Switched to GPIO %s", pin_text);
            evil_esp_show_popup(app, "GPIO Changed", success_msg);

            // Refresh menu to show updated value
            evil_esp_scene_on_exit_config(app);
            evil_esp_scene_on_enter_config(app);
            return true;

        case EvilEspConfigMenuIndexSendToDevice:
            // Send all config settings to ESP
            evil_esp_send_config_to_device(app);
            evil_esp_show_popup(app, "Config Sent", "Configuration sent to ESP device");
            return true;
        }
    }

    return false;
}

void evil_esp_scene_on_exit_config(void* context) {
    EvilEspApp* app = context;
    submenu_reset(app->submenu);
}

// Scene: Help
void evil_esp_scene_on_enter_device_info(void* context) {
    EvilEspApp* app = context;

    furi_string_reset(app->text_box_string);
    furi_string_printf(app->text_box_string, "Evil ESP Controller Help\n\n");

    furi_string_cat_printf(app->text_box_string, "=== HARDWARE SETUP ===\n\n");
    furi_string_cat_printf(app->text_box_string, "ESP Module Connections:\n");
    furi_string_cat_printf(app->text_box_string, "Pin 1 (5V) -> ESP 5V\n");
    if(app->config.gpio_pins == EvilEspGpioPins13_14) {
        furi_string_cat_printf(app->text_box_string, "Pin 13 (TX) -> ESP GPIO3 (RX)\n");
        furi_string_cat_printf(app->text_box_string, "Pin 14 (RX) -> ESP GPIO1 (TX)\n");
    } else {
        furi_string_cat_printf(app->text_box_string, "Pin 15 (TX) -> ESP GPIO3 (RX)\n");
        furi_string_cat_printf(app->text_box_string, "Pin 16 (RX) -> ESP GPIO1 (TX)\n");
    }
    furi_string_cat_printf(app->text_box_string, "Pin 18 (GND) -> ESP GND\n\n");

    furi_string_cat_printf(app->text_box_string, "=== HOW TO USE ===\n\n");
    furi_string_cat_printf(app->text_box_string, "1. WiFi Scanner - Scan for networks\n");
    furi_string_cat_printf(app->text_box_string, "2. Set Targets - Choose networks to attack\n");
    furi_string_cat_printf(app->text_box_string, "3. Attack Mode - Launch deauth attacks\n");
    furi_string_cat_printf(app->text_box_string, "4. Configuration - Adjust settings\n");
    furi_string_cat_printf(app->text_box_string, "5. UART Terminal - Direct communication\n\n");

    furi_string_cat_printf(app->text_box_string, "=== FEATURES ===\n\n");
    furi_string_cat_printf(app->text_box_string, "- Dual-band WiFi (2.4GHz + 5GHz)\n");
    furi_string_cat_printf(app->text_box_string, "- Deauth/Disassoc attacks\n");
    furi_string_cat_printf(app->text_box_string, "- Real-time packet monitoring\n");
    furi_string_cat_printf(app->text_box_string, "- Multi-target selection\n\n");

    furi_string_cat_printf(app->text_box_string, "App developed by dag nazty\n");
    furi_string_cat_printf(app->text_box_string, "ESP firmware by 7h30th3r0n3");

    text_box_set_text(app->text_box, furi_string_get_cstr(app->text_box_string));
    view_dispatcher_switch_to_view(app->view_dispatcher, EvilEspViewTextBox);
}

bool evil_esp_scene_on_event_device_info(void* context, SceneManagerEvent event) {
    UNUSED(context);
    UNUSED(event);
    return false;
}

void evil_esp_scene_on_exit_device_info(void* context) {
    EvilEspApp* app = context;
    text_box_reset(app->text_box);
}

// Scene: UART Terminal
void evil_esp_scene_on_enter_uart_terminal(void* context) {
    EvilEspApp* app = context;

    uint32_t state = scene_manager_get_scene_state(app->scene_manager, EvilEspSceneUartTerminal);

    if(state == 0) {
        // Text input mode - let user type custom command
        text_input_reset(app->text_input);
        text_input_set_header_text(app->text_input, "Enter UART Command:");
        text_input_set_result_callback(
            app->text_input,
            evil_esp_text_input_callback_uart,
            app,
            app->text_input_store,
            EVIL_ESP_TEXT_INPUT_STORE_SIZE,
            true
        );
        view_dispatcher_switch_to_view(app->view_dispatcher, EvilEspViewTextInput);
    } else {
        // Terminal display mode - show UART communication
        // Initialize UART log with header
        furi_string_reset(app->uart_log_string);
        furi_string_printf(app->uart_log_string, "=== UART TERMINAL ===\n");
        const char* gpio_pins = (app->config.gpio_pins == EvilEspGpioPins13_14) ? "13↔14" : "15↔16";
        furi_string_cat_printf(app->uart_log_string, "115200 baud, GPIO %s\n", gpio_pins);
        furi_string_cat_printf(app->uart_log_string, "ESP GPIO1←TX GPIO3→RX\n");
        furi_string_cat_printf(app->uart_log_string, "Status: LISTENING...\n\n");

        // Immediately start displaying any existing log content
        if(furi_string_size(app->log_string) > 0) {
            furi_string_cat(app->uart_log_string, app->log_string);
        } else {
            furi_string_cat_printf(app->uart_log_string, "[Waiting for UART data...]\n");
        }

        text_box_set_text(app->text_box, furi_string_get_cstr(app->uart_log_string));
        text_box_set_focus(app->text_box, TextBoxFocusEnd);
        view_dispatcher_switch_to_view(app->view_dispatcher, EvilEspViewTextBox);

        // Force initial refresh to show any pending data
        view_dispatcher_send_custom_event(app->view_dispatcher, EvilEspEventUartTerminalRefresh);
    }
}

bool evil_esp_scene_on_event_uart_terminal(void* context, SceneManagerEvent event) {
    EvilEspApp* app = context;

    // Only handle in terminal display mode
    uint32_t state = scene_manager_get_scene_state(app->scene_manager, EvilEspSceneUartTerminal);
    if(state != 1) return false;

    // Handle refresh event - update display with current log content
    if(event.type == SceneManagerEventTypeCustom && event.event == EvilEspEventUartTerminalRefresh) {
        size_t current_log_size = furi_string_size(app->log_string);

        // ALWAYS update display to show new data immediately
        // Create display string with header + current log content
        furi_string_reset(app->uart_log_string);
        furi_string_printf(app->uart_log_string, "=== UART TERMINAL ===\n");
        const char* gpio_pins = (app->config.gpio_pins == EvilEspGpioPins13_14) ? "13↔14" : "15↔16";
        furi_string_cat_printf(app->uart_log_string, "115200 baud, GPIO %s\n", gpio_pins);
        furi_string_cat_printf(app->uart_log_string, "ESP GPIO1←TX GPIO3→RX\n");
        furi_string_cat_printf(app->uart_log_string, "Status: ACTIVE\n\n");

        // Add current log content (which is updated by UART worker)
        if(current_log_size > 0) {
            furi_string_cat(app->uart_log_string, app->log_string);
        } else {
            furi_string_cat_printf(app->uart_log_string, "[Waiting for UART data...]\n");
        }

        // Limit total size to prevent memory issues
        if(furi_string_size(app->uart_log_string) > EVIL_ESP_TEXT_BOX_STORE_SIZE - 512) {
            // Keep header and recent content
            const char* gpio_pins_str = (app->config.gpio_pins == EvilEspGpioPins13_14) ? "13↔14" : "15↔16";
            char header[256];
            snprintf(header, sizeof(header), "=== UART TERMINAL ===\n115200 baud, GPIO %s\nESP GPIO1←TX GPIO3→RX\nStatus: ACTIVE\n\n[...truncated...]\n", gpio_pins_str);
            size_t keep_size = EVIL_ESP_TEXT_BOX_STORE_SIZE / 2;

            // Get recent content from app->log_string
            if(current_log_size > keep_size) {
                furi_string_set_str(app->uart_log_string, header);
                const char* recent_content = furi_string_get_cstr(app->log_string) + (current_log_size - keep_size);
                furi_string_cat_str(app->uart_log_string, recent_content);
            }
        }

        // Update the display
        text_box_set_text(app->text_box, furi_string_get_cstr(app->uart_log_string));
        text_box_set_focus(app->text_box, TextBoxFocusEnd);

        return true;
    }
    
    // Handle back event - send stop command if coming from attack or sniffer, then return appropriately
    if(event.type == SceneManagerEventTypeBack) {
        // Check if we came from the Attacks scene by checking if it's in the scene stack
        if(scene_manager_has_previous_scene(app->scene_manager, EvilEspSceneAttacks)) {
            // We came from an attack - send stop command
            FURI_LOG_I("EvilEsp", "Stopping attack and returning to attacks menu");
            evil_esp_send_command(app, "stop");
            
            // Brief delay to let the command be sent
            furi_delay_ms(100);
            
            // Return to attacks menu
            scene_manager_search_and_switch_to_previous_scene(app->scene_manager, EvilEspSceneAttacks);
        } else if(scene_manager_has_previous_scene(app->scene_manager, EvilEspSceneSnifferMenu)) {
            // We came from Sniffer menu - send stop command
            FURI_LOG_I("EvilEsp", "Stopping sniffer and returning to sniffer menu");
            evil_esp_send_command(app, "stop");
            
            // Brief delay to let the command be sent
            furi_delay_ms(100);
            
            // Return to sniffer menu
            scene_manager_search_and_switch_to_previous_scene(app->scene_manager, EvilEspSceneSnifferMenu);
        } else if(scene_manager_has_previous_scene(app->scene_manager, EvilEspSceneMainMenu)) {
            // Return to main menu
            scene_manager_search_and_switch_to_previous_scene(app->scene_manager, EvilEspSceneMainMenu);
        } else {
            // Otherwise, go to main menu
            scene_manager_search_and_switch_to_previous_scene(app->scene_manager, EvilEspSceneMainMenu);
        }
        return true;
    }

    return false;
}

void evil_esp_scene_on_exit_uart_terminal(void* context) {
    EvilEspApp* app = context;
    text_box_reset(app->text_box);
}

// Scene: List Portals
static void evil_esp_submenu_callback_portals(void* context, uint32_t index) {
    EvilEspApp* app = context;
    view_dispatcher_send_custom_event(app->view_dispatcher, index);
}

void evil_esp_scene_on_enter_list_portals(void* context) {
    EvilEspApp* app = context;

    // Clear previous portal data
    app->portal_count = 0;
    memset(app->portals, 0, sizeof(app->portals));
    app->portal_scan_in_progress = true;

    FURI_LOG_I("EvilEsp", "Entering list portals scene, sending list_sd command");

    // Send list_sd command to get HTML files
    evil_esp_send_command(app, "list_sd");

    // Show loading popup while waiting for response
    evil_esp_show_loading(app, "Loading portals from SD...");
    
    // Store scene state to track timeout
    scene_manager_set_scene_state(app->scene_manager, EvilEspSceneListPortals, furi_get_tick());
}

bool evil_esp_scene_on_event_list_portals(void* context, SceneManagerEvent event) {
    EvilEspApp* app = context;
    
    // Log every event call for debugging
    static uint32_t event_counter = 0;
    event_counter++;
    
    uint32_t portal_scan_start = scene_manager_get_scene_state(app->scene_manager, EvilEspSceneListPortals);
    uint32_t elapsed = furi_get_tick() - portal_scan_start;

    // Log state every 10 events
    if(event_counter % 10 == 0) {
        FURI_LOG_I("EvilEsp", "[Portal Scene] Event #%lu: type=%u, event=%lu, scan_in_progress=%d, count=%u, elapsed=%lu ms",
                   event_counter, (unsigned)event.type, event.event, 
                   app->portal_scan_in_progress, app->portal_count, elapsed);
    }

    // Handle portal scan completion event
    if(event.type == SceneManagerEventTypeCustom) {
        FURI_LOG_I("EvilEsp", "[Portal Scene] Custom event: %lu (PortalScanComplete=%d)", 
                   event.event, EvilEspEventPortalScanComplete);
        
        if(event.event == EvilEspEventPortalScanComplete) {
            FURI_LOG_I("EvilEsp", "[Portal Scene] Portal scan complete! count=%u", app->portal_count);
            // Portals loaded - show menu
            evil_esp_hide_loading(app);
            
            if(app->portal_count == 0) {
                // No portals found
                FURI_LOG_W("EvilEsp", "[Portal Scene] No portals found, showing popup");
                evil_esp_show_popup(app, "No Portals", "No HTML files found on SD card");
                return true;
            }
            
            submenu_reset(app->submenu);
            submenu_set_header(app->submenu, "Select Portal");

            // Add portal items to menu
            for(uint8_t i = 0; i < app->portal_count; i++) {
                char menu_text[80];
                snprintf(menu_text, sizeof(menu_text), "%d. %s", 
                         app->portals[i].index, 
                         app->portals[i].filename);
                submenu_add_item(app->submenu, menu_text, i, evil_esp_submenu_callback_portals, app);
                FURI_LOG_I("EvilEsp", "[Portal Scene] Added menu item: %s", menu_text);
            }

            view_dispatcher_switch_to_view(app->view_dispatcher, EvilEspViewMainMenu);
            return true;
        }
        
        // Handle portal selection
        if(event.event < 100 && event.event < app->portal_count) {
            // Send select_html command with the portal index
            char cmd[64];
            snprintf(cmd, sizeof(cmd), "select_html %d", app->portals[event.event].index);
            evil_esp_send_command(app, cmd);
            
            FURI_LOG_I("EvilEsp", "[Portal Scene] Selected portal %lu, going to attacks", event.event);
            // Go to attacks menu
            scene_manager_next_scene(app->scene_manager, EvilEspSceneAttacks);
            return true;
        }
    }

    // Check timeout - this might not be called often when showing popup!
    if(app->portal_scan_in_progress && elapsed > 10000) {
        // Timeout - show error
        FURI_LOG_W("EvilEsp", "[Portal Scene] TIMEOUT after %lu ms! scan_in_progress=%d, count=%u", 
                   elapsed, app->portal_scan_in_progress, app->portal_count);
        evil_esp_hide_loading(app);
        evil_esp_show_popup(app, "Timeout", "No response from ESP32.\nCheck UART connection.");
        app->portal_scan_in_progress = false;
        return true;
    }

    return false;
}

void evil_esp_scene_on_exit_list_portals(void* context) {
    EvilEspApp* app = context;
    submenu_reset(app->submenu);
    evil_esp_hide_loading(app);
    
    // Reset portal scan state
    app->portal_scan_in_progress = false;
    app->portal_count = 0;
}
