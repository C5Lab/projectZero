#include <furi.h>
#include <gui/gui.h>
#include <input/input.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdint.h>
#include <furi_hal_light.h>
#include <furi_hal_power.h>
#include <furi_hal_serial.h>
#include <furi_hal_serial_control.h>
#include <notification/notification.h>
#include <notification/notification_messages.h>
#include <storage/storage.h>
#include <furi/core/stream_buffer.h>

typedef enum {
    ScreenMenu,
    ScreenSerial,
    ScreenResults,
    ScreenSetupScanner,
    ScreenConsole,
    ScreenConfirmBlackout,
    ScreenConfirmSnifferDos,
    ScreenEvilTwinMenu,
} AppScreen;

typedef enum {
    MenuStateSections,
    MenuStateItems,
} MenuState;
#define LAB_C5_VERSION_TEXT "0.9"

#define MAX_SCAN_RESULTS 64
#define SCAN_LINE_BUFFER_SIZE 192
#define SCAN_SSID_MAX_LEN 33
#define SCAN_CHANNEL_MAX_LEN 8
#define SCAN_TYPE_MAX_LEN 16
#define SCAN_FIELD_BUFFER_LEN 64
#define SCAN_POWER_MIN_DBM (-110)
#define SCAN_POWER_MAX_DBM 0
#define SCAN_POWER_STEP 1
#define BACKLIGHT_ON_LEVEL 255
#define BACKLIGHT_OFF_LEVEL 0

#define SERIAL_BUFFER_SIZE 4096
#define UART_STREAM_SIZE 1024
#define MENU_VISIBLE_COUNT 6
#define MENU_VISIBLE_COUNT_SNIFFERS 4
#define MENU_VISIBLE_COUNT_ATTACKS 4
#define MENU_TITLE_Y 12
#define MENU_ITEM_BASE_Y 24
#define MENU_ITEM_SPACING 12
#define MENU_SCROLL_TRACK_Y 14
#define SERIAL_VISIBLE_LINES 6
#define SERIAL_LINE_CHAR_LIMIT 22
#define SERIAL_TEXT_LINE_HEIGHT 10
#define DISPLAY_WIDTH 128
#define RESULT_DEFAULT_MAX_LINES 4
#define RESULT_DEFAULT_LINE_HEIGHT 12
#define RESULT_DEFAULT_CHAR_LIMIT (SERIAL_LINE_CHAR_LIMIT - 3)
#define RESULT_START_Y 12
#define RESULT_ENTRY_SPACING 0
#define RESULT_PREFIX_X 2
#define RESULT_TEXT_X 5
#define RESULT_SCROLL_WIDTH 3
#define RESULT_SCROLL_GAP 0
#define CONSOLE_VISIBLE_LINES 4
#define MENU_SECTION_SCANNER 0
#define MENU_SECTION_SNIFFERS 1
#define MENU_SECTION_TARGETS 2
#define MENU_SECTION_ATTACKS 3
#define MENU_SECTION_SETUP 4
#define SCANNER_FILTER_VISIBLE_COUNT 3
#define SCANNER_SCAN_COMMAND "scan_networks"
#define TARGETS_RESULTS_COMMAND "show_scan_results"
#define LAB_C5_CONFIG_DIR_PATH "apps_assets/labC5"
#define LAB_C5_CONFIG_FILE_PATH LAB_C5_CONFIG_DIR_PATH "/config.txt"

#define HINT_MAX_LINES 16
#define HINT_VISIBLE_LINES 3
#define HINT_LINE_CHAR_LIMIT 48
#define HINT_WRAP_LIMIT 21
#define HINT_LINE_HEIGHT 12
#define EVIL_TWIN_MAX_HTML_FILES 16
#define EVIL_TWIN_HTML_NAME_MAX 32
#define EVIL_TWIN_POPUP_VISIBLE_LINES 3
#define EVIL_TWIN_MENU_OPTION_COUNT 2
#define HELP_HINT_IDLE_MS 3000

typedef enum {
    MenuActionCommand,
    MenuActionCommandWithTargets,
    MenuActionResults,
    MenuActionToggleBacklight,
    MenuActionToggleOtgPower,
    MenuActionOpenScannerSetup,
    MenuActionOpenConsole,
    MenuActionConfirmBlackout,
    MenuActionConfirmSnifferDos,
    MenuActionOpenEvilTwinMenu,
} MenuAction;

typedef enum {
    ScannerOptionShowSSID,
    ScannerOptionShowBSSID,
    ScannerOptionShowChannel,
    ScannerOptionShowSecurity,
    ScannerOptionShowPower,
    ScannerOptionShowBand,
    ScannerOptionMinPower,
    ScannerOptionCount,
} ScannerOption;

typedef struct {
    uint16_t number;
    char ssid[SCAN_SSID_MAX_LEN];
    char bssid[SCAN_FIELD_BUFFER_LEN];
    char channel[SCAN_CHANNEL_MAX_LEN];
    char security[SCAN_TYPE_MAX_LEN];
    char power_display[SCAN_FIELD_BUFFER_LEN];
    char band[SCAN_TYPE_MAX_LEN];
    int16_t power_dbm;
    bool power_valid;
    bool selected;
} ScanResult;

typedef struct {
    uint8_t id;
    char name[EVIL_TWIN_HTML_NAME_MAX];
} EvilTwinHtmlEntry;

typedef struct {
    bool exit_app;
    MenuState menu_state;
    uint32_t section_index;
    uint32_t item_index;
    uint32_t item_offset;
    AppScreen screen;
    FuriHalSerialHandle* serial;
    FuriMutex* serial_mutex;
    FuriStreamBuffer* rx_stream;
    ViewPort* viewport;
    Gui* gui;
    char serial_buffer[SERIAL_BUFFER_SIZE];
    size_t serial_len;
    size_t serial_scroll;
    bool serial_follow_tail;
    bool serial_targets_hint;
    bool last_command_sent;
    bool confirm_blackout_yes;
    bool confirm_sniffer_dos_yes;
    uint32_t last_attack_index;
    size_t evil_twin_menu_index;
    EvilTwinHtmlEntry evil_twin_html_entries[EVIL_TWIN_MAX_HTML_FILES];
    size_t evil_twin_html_count;
    size_t evil_twin_html_popup_index;
    size_t evil_twin_html_popup_offset;
    bool evil_twin_popup_active;
    bool evil_twin_listing_active;
    bool evil_twin_list_header_seen;
    char evil_twin_list_buffer[64];
    size_t evil_twin_list_length;
    uint8_t evil_twin_selected_html_id;
    char evil_twin_selected_html_name[EVIL_TWIN_HTML_NAME_MAX];
    ScanResult scan_results[MAX_SCAN_RESULTS];
    size_t scan_result_count;
    size_t scan_result_index;
    size_t scan_result_offset;
    uint16_t scan_selected_numbers[MAX_SCAN_RESULTS];
    size_t scan_selected_count;
    bool scan_results_loading;
    char scan_line_buffer[SCAN_LINE_BUFFER_SIZE];
    size_t scan_line_len;
    uint16_t visible_result_indices[MAX_SCAN_RESULTS];
    size_t visible_result_count;
    bool scanner_show_ssid;
    bool scanner_show_bssid;
    bool scanner_show_channel;
    bool scanner_show_security;
    bool scanner_show_power;
    bool scanner_show_band;
    int16_t scanner_min_power;
    size_t scanner_setup_index;
    bool scanner_adjusting_power;
    bool otg_power_enabled;
    bool otg_power_initial_state;
    bool backlight_enabled;
    bool backlight_insomnia;
    size_t scanner_view_offset;
    uint8_t result_line_height;
    uint8_t result_char_limit;
    uint8_t result_max_lines;
    Font result_font;
    bool hint_active;
    char hint_title[24];
    char hint_lines[HINT_MAX_LINES][HINT_LINE_CHAR_LIMIT];
    size_t hint_line_count;
    size_t hint_scroll;
    NotificationApp* notifications;
    bool backlight_notification_enforced;
    bool config_dirty;
    char status_message[64];
    uint32_t status_message_until;
    bool status_message_fullscreen;
    uint32_t last_input_tick;
    bool help_hint_visible;
} SimpleApp;
static void simple_app_adjust_result_offset(SimpleApp* app);
static void simple_app_rebuild_visible_results(SimpleApp* app);
static bool simple_app_result_is_visible(const SimpleApp* app, const ScanResult* result);
static ScanResult* simple_app_visible_result(SimpleApp* app, size_t visible_index);
static const ScanResult* simple_app_visible_result_const(const SimpleApp* app, size_t visible_index);
static void simple_app_update_result_layout(SimpleApp* app);
static void simple_app_apply_backlight(SimpleApp* app);
static void simple_app_toggle_backlight(SimpleApp* app);
static void simple_app_update_otg_label(SimpleApp* app);
static void simple_app_apply_otg_power(SimpleApp* app);
static void simple_app_toggle_otg_power(SimpleApp* app);
static void simple_app_mark_config_dirty(SimpleApp* app);
static void simple_app_show_hint(SimpleApp* app, const char* title, const char* text);
static void simple_app_hide_hint(SimpleApp* app);
static void simple_app_handle_hint_event(SimpleApp* app, const InputEvent* event);
static void simple_app_draw_hint(SimpleApp* app, Canvas* canvas);
static void simple_app_prepare_hint_lines(SimpleApp* app, const char* text);
static void simple_app_hint_scroll(SimpleApp* app, int delta);
static size_t simple_app_hint_max_scroll(const SimpleApp* app);
static bool simple_app_try_show_hint(SimpleApp* app);
static void simple_app_draw_evil_twin_menu(SimpleApp* app, Canvas* canvas);
static void simple_app_handle_evil_twin_menu_input(SimpleApp* app, InputKey key);
static void simple_app_request_evil_twin_html_list(SimpleApp* app);
static void simple_app_start_evil_portal(SimpleApp* app);
static void simple_app_draw_evil_twin_popup(SimpleApp* app, Canvas* canvas);
static void simple_app_handle_evil_twin_popup_event(SimpleApp* app, const InputEvent* event);
static void simple_app_close_evil_twin_popup(SimpleApp* app);
static void simple_app_reset_evil_twin_listing(SimpleApp* app);
static void simple_app_finish_evil_twin_listing(SimpleApp* app);
static void simple_app_process_evil_twin_line(SimpleApp* app, const char* line);
static void simple_app_evil_twin_feed(SimpleApp* app, char ch);
static void simple_app_save_config_if_dirty(SimpleApp* app, const char* message, bool fullscreen);
static bool simple_app_save_config(SimpleApp* app, const char* success_message, bool fullscreen);
static void simple_app_load_config(SimpleApp* app);
static void simple_app_show_status_message(SimpleApp* app, const char* message, uint32_t duration_ms, bool fullscreen);
static void simple_app_clear_status_message(SimpleApp* app);
static bool simple_app_status_message_is_active(SimpleApp* app);
static void simple_app_send_command_with_targets(SimpleApp* app, const char* base_command);
static size_t simple_app_menu_visible_count(const SimpleApp* app, uint32_t section_index);
static size_t simple_app_render_display_lines(
    SimpleApp* app,
    size_t skip_lines,
    char dest[][64],
    size_t max_lines);

typedef struct {
    const char* label;
    const char* command;
    MenuAction action;
    const char* hint;
} MenuEntry;

typedef struct {
    const char* title;
    const char* hint;
    const MenuEntry* entries;
    size_t entry_count;
    uint8_t display_y;
    uint8_t display_height;
} MenuSection;

static const uint8_t image_icon_0_bits[] = {
    0xff, 0x03, 0xff, 0x03, 0xff, 0x03, 0x11, 0x03, 0xdd, 0x03,
    0x1d, 0x03, 0x71, 0x03, 0x1f, 0x03, 0xff, 0x03, 0xff, 0x03,
};

static const char hint_section_scanner[] =
    "Passively listens \nto network events collecting \ninfo about APs, STAs associated \nand Probe Requests.";
static const char hint_section_sniffers[] =
    "Passive Wi-Fi tools\nMonitor live clients\nAuto channel hopping\nReview captured data\nFrom the results tab.";
static const char hint_section_targets[] =
    "Selects targets \nfor Deauth, Evil Twin \nand SAE Overflow attacks.";
static const char hint_section_attacks[] =
    "Test features here\nUse only on own lab\nTargets come from\nSelected networks\nFollow local laws.";
static const char hint_section_setup[] =
    "General settings\nBacklight and OTG\nAdjust scanner view\nConsole with logs\nUseful for debug.";

static const char hint_sniffer_start[] =
    "Start passive sniffer\nCaptures frames live\nHops 2.4 and 5 GHz\nWatch status in log\nStop with Back/Stop.";
static const char hint_sniffer_results[] =
    "Display sniffer list\nAccess points sorted\nBy client activity\nUse to inspect who\nWas seen on air.";
static const char hint_sniffer_probes[] =
    "View probe requests\nSee devices searching\nFor nearby SSIDs\nGreat for finding\nHidden networks.";
static const char hint_sniffer_debug[] =
    "Enable verbose logs\nPrints frame details\nDecision reasoning\nHelpful diagnostics\nBut very noisy.";

static const char hint_attack_blackout[] =
    "Sends broadcast deauth \npackets to all networks \naround you.";
static const char hint_attack_deauth[] =
    "Disconnects clients \nof all selected networks.";
static const char hint_attack_evil_twin[] =
    "Creates fake network \nwith captive portal in the \nname of the first selected.";
static const char hint_attack_sae_overflow[] =
    "Sends SAE Commit frames \nto overflow WPA3 router.";
static const char hint_attack_sniffer_dog[] =
    "Listens to traffic \nbetween AP and STA \nand sends deauth packet \ndirectly to this STA";
static const char hint_attack_wardrive[] =
    "Logs networks around you \nwith GPS coordinates.";

static const char hint_setup_backlight[] =
    "Toggle screen light\nKeep brightness high\nOr allow auto dim\nGreat for console\nLong sessions.";
static const char hint_setup_otg[] =
    "Control USB OTG 5V\nPower external gear\nDisable to save\nBattery capacity\nWhen unused.";
static const char hint_setup_filters[] =
    "Choose visible fields\nSimplify result list\nHide unused data\nTailor display\nOK flips options.";
static const char hint_setup_console[] =
    "Open live console\nStream UART output\nWatch commands\nDebug operations\nClose with Back.";

static const MenuEntry menu_entries_sniffers[] = {
    {"Start Sniffer", "start_sniffer", MenuActionCommand, hint_sniffer_start},
    {"Show Sniffer Results", "show_sniffer_results", MenuActionCommand, hint_sniffer_results},
    {"Show Probes", "show_probes", MenuActionCommand, hint_sniffer_probes},
    {"Sniffer Debug", "sniffer_debug 1", MenuActionCommand, hint_sniffer_debug},
};

static const MenuEntry menu_entries_attacks[] = {
    {"Blackout", NULL, MenuActionConfirmBlackout, hint_attack_blackout},
    {"Deauth", "start_deauth", MenuActionCommandWithTargets, hint_attack_deauth},
    {"Evil Twin", NULL, MenuActionOpenEvilTwinMenu, hint_attack_evil_twin},
    {"SAE Overflow", "sae_overflow", MenuActionCommandWithTargets, hint_attack_sae_overflow},
    {"Sniffer Dog", NULL, MenuActionConfirmSnifferDos, hint_attack_sniffer_dog},
    {"Wardrive", "start_wardrive", MenuActionCommand, hint_attack_wardrive},
};

static char menu_label_backlight[24] = "Backlight: On";
static char menu_label_otg_power[24] = "5V Power: On";

static const MenuEntry menu_entries_setup[] = {
    {menu_label_backlight, NULL, MenuActionToggleBacklight, hint_setup_backlight},
    {menu_label_otg_power, NULL, MenuActionToggleOtgPower, hint_setup_otg},
    {"Scanner Filters", NULL, MenuActionOpenScannerSetup, hint_setup_filters},
    {"Console", NULL, MenuActionOpenConsole, hint_setup_console},
};

static const MenuSection menu_sections[] = {
    {"Scanner", hint_section_scanner, NULL, 0, 12, MENU_VISIBLE_COUNT * MENU_ITEM_SPACING},
    {"Sniffers", hint_section_sniffers, menu_entries_sniffers, sizeof(menu_entries_sniffers) / sizeof(menu_entries_sniffers[0]), 24, MENU_VISIBLE_COUNT_SNIFFERS * MENU_ITEM_SPACING},
    {"Targets", hint_section_targets, NULL, 0, 36, MENU_VISIBLE_COUNT * MENU_ITEM_SPACING},
    {"Attacks", hint_section_attacks, menu_entries_attacks, sizeof(menu_entries_attacks) / sizeof(menu_entries_attacks[0]), 48, MENU_VISIBLE_COUNT_ATTACKS * MENU_ITEM_SPACING},
    {"Setup", hint_section_setup, menu_entries_setup, sizeof(menu_entries_setup) / sizeof(menu_entries_setup[0]), 60, MENU_VISIBLE_COUNT * MENU_ITEM_SPACING},
};

static const size_t menu_section_count = sizeof(menu_sections) / sizeof(menu_sections[0]);

static size_t simple_app_menu_visible_count(const SimpleApp* app, uint32_t section_index) {
    UNUSED(app);
    if(section_index == MENU_SECTION_SNIFFERS) {
        return MENU_VISIBLE_COUNT_SNIFFERS;
    }
    if(section_index == MENU_SECTION_ATTACKS) {
        return MENU_VISIBLE_COUNT_ATTACKS;
    }
    return MENU_VISIBLE_COUNT;
}

static void simple_app_focus_attacks_menu(SimpleApp* app) {
    if(!app) return;
    app->screen = ScreenMenu;
    app->menu_state = MenuStateItems;
    app->section_index = MENU_SECTION_ATTACKS;
    const MenuSection* section = &menu_sections[MENU_SECTION_ATTACKS];
    if(section->entry_count == 0) {
        app->item_index = 0;
        app->item_offset = 0;
        return;
    }
    size_t entry_count = section->entry_count;
    if(app->last_attack_index >= entry_count) {
        app->last_attack_index = entry_count - 1;
    }
    app->item_index = app->last_attack_index;
    size_t visible_count = simple_app_menu_visible_count(app, MENU_SECTION_ATTACKS);
    if(visible_count == 0) visible_count = 1;
    if(app->item_index >= entry_count) {
        app->item_index = entry_count - 1;
    }
    if(entry_count <= visible_count) {
        app->item_offset = 0;
    } else {
        size_t max_offset = entry_count - visible_count;
        size_t desired_offset =
            (app->item_index >= visible_count) ? (app->item_index - visible_count + 1) : 0;
        if(desired_offset > max_offset) {
            desired_offset = max_offset;
        }
        app->item_offset = desired_offset;
    }
}

static void simple_app_truncate_text(char* text, size_t max_chars) {
    if(!text || max_chars == 0) return;
    size_t len = strlen(text);
    if(len <= max_chars) return;
    if(max_chars == 1) {
        text[0] = '\0';
        return;
    }
    text[max_chars - 1] = '.';
    text[max_chars] = '\0';
}

static void simple_app_copy_field(char* dest, size_t dest_size, const char* src, const char* fallback) {
    if(dest_size == 0 || !dest) return;
    const char* value = (src && src[0] != '\0') ? src : fallback;
    if(!value) value = "";
    size_t max_copy = dest_size - 1;
    if(max_copy == 0) {
        dest[0] = '\0';
        return;
    }
    strncpy(dest, value, max_copy);
    dest[max_copy] = '\0';
}

static void simple_app_reset_scan_results(SimpleApp* app) {
    if(!app) return;
    memset(app->scan_results, 0, sizeof(app->scan_results));
    memset(app->scan_selected_numbers, 0, sizeof(app->scan_selected_numbers));
    memset(app->scan_line_buffer, 0, sizeof(app->scan_line_buffer));
    memset(app->visible_result_indices, 0, sizeof(app->visible_result_indices));
    app->scan_result_count = 0;
    app->scan_result_index = 0;
    app->scan_result_offset = 0;
    app->scan_selected_count = 0;
    app->scan_line_len = 0;
    app->scan_results_loading = false;
    app->visible_result_count = 0;
}

static bool simple_app_result_is_visible(const SimpleApp* app, const ScanResult* result) {
    if(!app || !result) return false;
    if(result->power_valid && result->power_dbm < app->scanner_min_power) {
        return false;
    }
    return true;
}

static void simple_app_rebuild_visible_results(SimpleApp* app) {
    if(!app) return;
    app->visible_result_count = 0;
    for(size_t i = 0; i < app->scan_result_count && i < MAX_SCAN_RESULTS; i++) {
        if(simple_app_result_is_visible(app, &app->scan_results[i])) {
            app->visible_result_indices[app->visible_result_count++] = (uint16_t)i;
        }
    }
    if(app->scan_result_index >= app->visible_result_count) {
        app->scan_result_index =
            (app->visible_result_count > 0) ? app->visible_result_count - 1 : 0;
    }
    if(app->scan_result_offset >= app->visible_result_count) {
        app->scan_result_offset =
            (app->visible_result_count > 0) ? app->visible_result_count - 1 : 0;
    }
    if(app->scan_result_offset > app->scan_result_index) {
        app->scan_result_offset = app->scan_result_index;
    }
}

static void simple_app_modify_min_power(SimpleApp* app, int16_t delta) {
    if(!app) return;
    int32_t proposed = (int32_t)app->scanner_min_power + delta;
    if(proposed > SCAN_POWER_MAX_DBM) {
        proposed = SCAN_POWER_MAX_DBM;
    } else if(proposed < SCAN_POWER_MIN_DBM) {
        proposed = SCAN_POWER_MIN_DBM;
    }
    if(app->scanner_min_power != proposed) {
        app->scanner_min_power = (int16_t)proposed;
        simple_app_rebuild_visible_results(app);
        simple_app_adjust_result_offset(app);
        simple_app_mark_config_dirty(app);
    }
}

static size_t simple_app_enabled_field_count(const SimpleApp* app) {
    if(!app) return 0;
    size_t count = 0;
    if(app->scanner_show_ssid) count++;
    if(app->scanner_show_bssid) count++;
    if(app->scanner_show_channel) count++;
    if(app->scanner_show_security) count++;
    if(app->scanner_show_power) count++;
    if(app->scanner_show_band) count++;
    return count;
}

static bool* simple_app_scanner_option_flag(SimpleApp* app, ScannerOption option) {
    if(!app) return NULL;
    switch(option) {
    case ScannerOptionShowSSID:
        return &app->scanner_show_ssid;
    case ScannerOptionShowBSSID:
        return &app->scanner_show_bssid;
    case ScannerOptionShowChannel:
        return &app->scanner_show_channel;
    case ScannerOptionShowSecurity:
        return &app->scanner_show_security;
    case ScannerOptionShowPower:
        return &app->scanner_show_power;
    case ScannerOptionShowBand:
        return &app->scanner_show_band;
    default:
        return NULL;
    }
}

static ScanResult* simple_app_visible_result(SimpleApp* app, size_t visible_index) {
    if(!app || visible_index >= app->visible_result_count) return NULL;
    uint16_t actual_index = app->visible_result_indices[visible_index];
    if(actual_index >= MAX_SCAN_RESULTS) return NULL;
    return &app->scan_results[actual_index];
}

static const ScanResult* simple_app_visible_result_const(const SimpleApp* app, size_t visible_index) {
    if(!app || visible_index >= app->visible_result_count) return NULL;
    uint16_t actual_index = app->visible_result_indices[visible_index];
    if(actual_index >= MAX_SCAN_RESULTS) return NULL;
    return &app->scan_results[actual_index];
}

static void simple_app_update_backlight_label(SimpleApp* app) {
    if(!app) return;
    snprintf(
        menu_label_backlight,
        sizeof(menu_label_backlight),
        "Backlight: %s",
        app->backlight_enabled ? "On" : "Off");
}

static void simple_app_update_otg_label(SimpleApp* app) {
    if(!app) return;
    snprintf(
        menu_label_otg_power,
        sizeof(menu_label_otg_power),
        "5V Power: %s",
        app->otg_power_enabled ? "On" : "Off");
}

static void simple_app_apply_otg_power(SimpleApp* app) {
    if(!app) return;
    bool currently_enabled = furi_hal_power_is_otg_enabled();
    if(app->otg_power_enabled) {
        if(!currently_enabled) {
            bool enabled = furi_hal_power_enable_otg();
            currently_enabled = furi_hal_power_is_otg_enabled();
            if(!enabled && !currently_enabled) {
                float usb_voltage = furi_hal_power_get_usb_voltage();
                app->otg_power_enabled = false;
                simple_app_update_otg_label(app);
                if(usb_voltage < 1.0f) {
                    simple_app_show_status_message(app, "5V enable failed", 2000, false);
                }
                return;
            }
        } else {
            app->otg_power_enabled = true;
        }
    } else if(currently_enabled) {
        furi_hal_power_disable_otg();
    }
    simple_app_update_otg_label(app);
}

static void simple_app_toggle_otg_power(SimpleApp* app) {
    if(!app) return;
    app->otg_power_enabled = !app->otg_power_enabled;
    simple_app_apply_otg_power(app);
    simple_app_mark_config_dirty(app);
}

static void simple_app_update_result_layout(SimpleApp* app) {
    if(!app) return;
    size_t enabled_fields = simple_app_enabled_field_count(app);
    app->result_max_lines = RESULT_DEFAULT_MAX_LINES;
    if(enabled_fields <= 2) {
        app->result_font = FontPrimary;
        app->result_line_height = 14;
        app->result_max_lines = 3;
    } else if(enabled_fields <= 4) {
        app->result_font = FontSecondary;
        app->result_line_height = RESULT_DEFAULT_LINE_HEIGHT;
    } else {
        app->result_font = FontSecondary;
        app->result_line_height = RESULT_DEFAULT_LINE_HEIGHT;
    }

    uint8_t char_width = (app->result_font == FontPrimary) ? 7 : 6;
    uint8_t available_px = DISPLAY_WIDTH - RESULT_TEXT_X - RESULT_SCROLL_WIDTH - RESULT_SCROLL_GAP;
    uint8_t computed_limit = (char_width > 0) ? (available_px / char_width) : RESULT_DEFAULT_CHAR_LIMIT;
    if(computed_limit < 10) {
        computed_limit = 10;
    }
    app->result_char_limit = computed_limit;

    if(app->result_line_height == 0) {
        app->result_line_height = RESULT_DEFAULT_LINE_HEIGHT;
    }
    if(app->result_max_lines == 0) {
        app->result_max_lines = RESULT_DEFAULT_MAX_LINES;
    }
}

static void simple_app_line_append_token(
    char* line,
    size_t line_size,
    const char* label,
    const char* value) {
    if(!line || line_size == 0 || !value || value[0] == '\0') return;
    size_t current_len = strlen(line);
    if(current_len >= line_size - 1) return;
    size_t remaining = (line_size > current_len) ? (line_size - current_len - 1) : 0;
    if(remaining == 0) return;

    const char* separator = (current_len > 0) ? "  " : "";
    size_t sep_len = strlen(separator);
    if(sep_len > remaining) sep_len = remaining;
    if(sep_len > 0) {
        memcpy(line + current_len, separator, sep_len);
        current_len += sep_len;
        remaining -= sep_len;
    }

    if(label && label[0] != '\0' && remaining > 0) {
        size_t label_len = strlen(label);
        if(label_len > remaining) label_len = remaining;
        memcpy(line + current_len, label, label_len);
        current_len += label_len;
        remaining -= label_len;
    }

    if(remaining > 0) {
        size_t value_len = strlen(value);
        if(value_len > remaining) value_len = remaining;
        memcpy(line + current_len, value, value_len);
        current_len += value_len;
    }

    if(current_len < line_size) {
        line[current_len] = '\0';
    } else {
        line[line_size - 1] = '\0';
    }
}

static size_t simple_app_build_result_lines(
    const SimpleApp* app,
    const ScanResult* result,
    char lines[][64],
    size_t max_lines) {
    if(!app || !result || max_lines == 0) return 0;

    size_t char_limit = (app->result_char_limit > 0) ? app->result_char_limit : RESULT_DEFAULT_CHAR_LIMIT;
    if(char_limit == 0) char_limit = RESULT_DEFAULT_CHAR_LIMIT;
    if(char_limit >= 63) char_limit = 63;

    bool store_lines = (lines != NULL);
    if(max_lines > RESULT_DEFAULT_MAX_LINES) {
        max_lines = RESULT_DEFAULT_MAX_LINES;
    }

    size_t emitted = 0;
    const size_t line_cap = 64;
    size_t truncate_limit = (char_limit < (line_cap - 1)) ? char_limit : (line_cap - 1);
    if(truncate_limit < 1) truncate_limit = 1;

#define SIMPLE_APP_EMIT_LINE(buffer) \
    do { \
        if(emitted < max_lines) { \
            if(store_lines) { \
                strncpy(lines[emitted], buffer, line_cap - 1); \
                lines[emitted][line_cap - 1] = '\0'; \
                simple_app_truncate_text(lines[emitted], truncate_limit); \
            } \
            emitted++; \
        } \
    } while(0)

    char first_line[line_cap];
    memset(first_line, 0, sizeof(first_line));
    snprintf(first_line, sizeof(first_line), "%u%s", (unsigned)result->number, result->selected ? "*" : "");

    bool ssid_visible = app->scanner_show_ssid && result->ssid[0] != '\0';
    if(ssid_visible) {
        size_t len = strlen(first_line);
        if(len < sizeof(first_line) - 1) {
            size_t remaining = sizeof(first_line) - len - 1;
            if(remaining > 0) {
                first_line[len++] = ' ';
                size_t ssid_len = strlen(result->ssid);
                if(ssid_len > remaining) ssid_len = remaining;
                memcpy(first_line + len, result->ssid, ssid_len);
                len += ssid_len;
                first_line[len] = '\0';
            }
        }
    }

    bool bssid_in_first_line = false;
    if(!ssid_visible && app->scanner_show_bssid && result->bssid[0] != '\0') {
        size_t len = strlen(first_line);
        if(len < sizeof(first_line) - 1) {
            size_t remaining = sizeof(first_line) - len - 1;
            if(remaining > 0) {
                first_line[len++] = ' ';
                size_t bssid_len = strlen(result->bssid);
                if(bssid_len > remaining) bssid_len = remaining;
                memcpy(first_line + len, result->bssid, bssid_len);
                len += bssid_len;
                first_line[len] = '\0';
                bssid_in_first_line = true;
            }
        }
    }

    SIMPLE_APP_EMIT_LINE(first_line);

    if(emitted < max_lines && app->scanner_show_bssid && !bssid_in_first_line &&
       result->bssid[0] != '\0') {
        char bssid_line[line_cap];
        memset(bssid_line, 0, sizeof(bssid_line));
        size_t len = 0;
        bssid_line[len++] = ' ';
        if(len < sizeof(bssid_line) - 1) {
            size_t remaining = sizeof(bssid_line) - len - 1;
            size_t bssid_len = strlen(result->bssid);
            if(bssid_len > remaining) bssid_len = remaining;
            memcpy(bssid_line + len, result->bssid, bssid_len);
            len += bssid_len;
            bssid_line[len] = '\0';
        } else {
            bssid_line[sizeof(bssid_line) - 1] = '\0';
        }
        SIMPLE_APP_EMIT_LINE(bssid_line);
    }

    if(emitted < max_lines) {
        char info_line[line_cap];
        memset(info_line, 0, sizeof(info_line));
        if(app->scanner_show_channel && result->channel[0] != '\0') {
            simple_app_line_append_token(info_line, sizeof(info_line), NULL, result->channel);
        }
        if(app->scanner_show_band && result->band[0] != '\0') {
            simple_app_line_append_token(info_line, sizeof(info_line), NULL, result->band);
        }
        if(info_line[0] != '\0') {
            SIMPLE_APP_EMIT_LINE(info_line);
        }
    }

    if(emitted < max_lines) {
        char info_line[line_cap];
        memset(info_line, 0, sizeof(info_line));
        if(app->scanner_show_security && result->security[0] != '\0') {
            char security_value[SCAN_FIELD_BUFFER_LEN];
            memset(security_value, 0, sizeof(security_value));
            strncpy(security_value, result->security, sizeof(security_value) - 1);
            char* mixed_suffix = strstr(security_value, " Mixed");
            if(mixed_suffix) {
                *mixed_suffix = '\0';
                size_t trimmed_len = strlen(security_value);
                while(trimmed_len > 0 &&
                      (security_value[trimmed_len - 1] == ' ' || security_value[trimmed_len - 1] == '/')) {
                    security_value[trimmed_len - 1] = '\0';
                    trimmed_len--;
                }
            }
            simple_app_line_append_token(info_line, sizeof(info_line), NULL, security_value);
        }
        if(app->scanner_show_power && result->power_display[0] != '\0') {
            char power_value[SCAN_FIELD_BUFFER_LEN];
            memset(power_value, 0, sizeof(power_value));
            strncpy(power_value, result->power_display, sizeof(power_value) - 1);
            if(strstr(power_value, "dBm") == NULL) {
                size_t len = strlen(power_value);
                if(len < sizeof(power_value) - 4) {
                    strncpy(power_value + len, " dBm", sizeof(power_value) - len - 1);
                    power_value[sizeof(power_value) - 1] = '\0';
                }
            }
            simple_app_line_append_token(info_line, sizeof(info_line), NULL, power_value);
        }
        if(info_line[0] != '\0') {
            SIMPLE_APP_EMIT_LINE(info_line);
        }
    }

    if(emitted == 0) {
        char fallback_line[line_cap];
        strncpy(fallback_line, "-", sizeof(fallback_line) - 1);
        fallback_line[sizeof(fallback_line) - 1] = '\0';
        SIMPLE_APP_EMIT_LINE(fallback_line);
    }

#undef SIMPLE_APP_EMIT_LINE

    return emitted;
}

static void simple_app_show_status_message(
    SimpleApp* app,
    const char* message,
    uint32_t duration_ms,
    bool fullscreen) {
    if(!app) return;
    if(app->hint_active) {
        simple_app_hide_hint(app);
    }
    if(message && message[0] != '\0') {
        strncpy(app->status_message, message, sizeof(app->status_message) - 1);
        app->status_message[sizeof(app->status_message) - 1] = '\0';
        if(duration_ms == 0) {
            app->status_message_until = UINT32_MAX;
        } else {
            uint32_t timeout_ticks = furi_ms_to_ticks(duration_ms);
            app->status_message_until = furi_get_tick() + timeout_ticks;
        }
        app->status_message_fullscreen = fullscreen;
    } else {
        app->status_message[0] = '\0';
        app->status_message_until = 0;
        app->status_message_fullscreen = false;
    }
    if(app->viewport) {
        view_port_update(app->viewport);
    }
}

static void simple_app_clear_status_message(SimpleApp* app) {
    if(!app) return;
    app->status_message[0] = '\0';
    app->status_message_until = 0;
    app->status_message_fullscreen = false;
    if(app->viewport) {
        view_port_update(app->viewport);
    }
}

static bool simple_app_status_message_is_active(SimpleApp* app) {
    if(!app) return false;
    if(app->status_message_until == 0 || app->status_message[0] == '\0') return false;
    if(app->status_message_until != UINT32_MAX && furi_get_tick() >= app->status_message_until) {
        simple_app_clear_status_message(app);
        return false;
    }
    return true;
}

static void simple_app_mark_config_dirty(SimpleApp* app) {
    if(!app) return;
    app->config_dirty = true;
}

static bool simple_app_parse_bool_value(const char* value, bool current) {
    if(!value || value[0] == '\0') return current;
    if((value[0] == '1' && value[1] == '\0') || value[0] == 'Y' || value[0] == 'y' ||
       value[0] == 'T' || value[0] == 't') {
        return true;
    }
    if((value[0] == '0' && value[1] == '\0') || value[0] == 'N' || value[0] == 'n' ||
       value[0] == 'F' || value[0] == 'f') {
        return false;
    }
    return atoi(value) != 0;
}

static void simple_app_trim(char* text) {
    if(!text) return;
    char* start = text;
    while(*start && isspace((unsigned char)*start)) {
        start++;
    }
    char* end = start + strlen(start);
    while(end > start && isspace((unsigned char)end[-1])) {
        end--;
    }
    *end = '\0';
    if(start != text) {
        memmove(text, start, (size_t)(end - start) + 1);
    }
}

static void simple_app_parse_config_line(SimpleApp* app, char* line) {
    if(!app || !line) return;
    simple_app_trim(line);
    if(line[0] == '\0' || line[0] == '#') return;
    char* equals = strchr(line, '=');
    if(!equals) return;
    *equals = '\0';
    char* key = line;
    char* value = equals + 1;
    simple_app_trim(key);
    simple_app_trim(value);
    if(strcmp(key, "show_ssid") == 0) {
        app->scanner_show_ssid = simple_app_parse_bool_value(value, app->scanner_show_ssid);
    } else if(strcmp(key, "show_bssid") == 0) {
        app->scanner_show_bssid = simple_app_parse_bool_value(value, app->scanner_show_bssid);
    } else if(strcmp(key, "show_channel") == 0) {
        app->scanner_show_channel = simple_app_parse_bool_value(value, app->scanner_show_channel);
    } else if(strcmp(key, "show_security") == 0) {
        app->scanner_show_security = simple_app_parse_bool_value(value, app->scanner_show_security);
    } else if(strcmp(key, "show_power") == 0) {
        app->scanner_show_power = simple_app_parse_bool_value(value, app->scanner_show_power);
    } else if(strcmp(key, "show_band") == 0) {
        app->scanner_show_band = simple_app_parse_bool_value(value, app->scanner_show_band);
    } else if(strcmp(key, "min_power") == 0) {
        app->scanner_min_power = (int16_t)strtol(value, NULL, 10);
    } else if(strcmp(key, "backlight_enabled") == 0) {
        app->backlight_enabled = simple_app_parse_bool_value(value, app->backlight_enabled);
    } else if(strcmp(key, "otg_power_enabled") == 0) {
        app->otg_power_enabled = simple_app_parse_bool_value(value, app->otg_power_enabled);
    }
}

static bool simple_app_save_config(SimpleApp* app, const char* success_message, bool fullscreen) {
    if(!app) return false;
    Storage* storage = furi_record_open(RECORD_STORAGE);
    if(!storage) return false;
    storage_simply_mkdir(storage, EXT_PATH("apps_assets"));
    storage_simply_mkdir(storage, EXT_PATH(LAB_C5_CONFIG_DIR_PATH));
    File* file = storage_file_alloc(storage);
    bool success = false;
    if(storage_file_open(file, EXT_PATH(LAB_C5_CONFIG_FILE_PATH), FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        char buffer[256];
        int len = snprintf(
            buffer,
            sizeof(buffer),
            "show_ssid=%d\n"
            "show_bssid=%d\n"
            "show_channel=%d\n"
            "show_security=%d\n"
            "show_power=%d\n"
            "show_band=%d\n"
            "min_power=%d\n"
            "backlight_enabled=%d\n"
            "otg_power_enabled=%d\n",
            app->scanner_show_ssid ? 1 : 0,
            app->scanner_show_bssid ? 1 : 0,
            app->scanner_show_channel ? 1 : 0,
            app->scanner_show_security ? 1 : 0,
            app->scanner_show_power ? 1 : 0,
            app->scanner_show_band ? 1 : 0,
            (int)app->scanner_min_power,
            app->backlight_enabled ? 1 : 0,
            app->otg_power_enabled ? 1 : 0);
        if(len > 0 && len < (int)sizeof(buffer)) {
            size_t written = storage_file_write(file, buffer, (size_t)len);
            if(written == (size_t)len) {
                success = true;
            }
        }
        storage_file_close(file);
    }
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
    if(success) {
        app->config_dirty = false;
        if(success_message) {
            simple_app_show_status_message(app, success_message, 2000, fullscreen);
        }
    }
    return success;
}

static void simple_app_load_config(SimpleApp* app) {
    if(!app) return;
    Storage* storage = furi_record_open(RECORD_STORAGE);
    if(!storage) return;
    File* file = storage_file_alloc(storage);
    bool loaded = false;
    if(storage_file_open(file, EXT_PATH(LAB_C5_CONFIG_FILE_PATH), FSAM_READ, FSOM_OPEN_EXISTING)) {
        char line[96];
        size_t pos = 0;
        uint8_t ch = 0;
        while(storage_file_read(file, &ch, 1) == 1) {
            if(ch == '\r') continue;
            if(ch == '\n') {
                line[pos] = '\0';
                simple_app_parse_config_line(app, line);
                pos = 0;
                continue;
            }
            if(pos + 1 < sizeof(line)) {
                line[pos++] = (char)ch;
            }
        }
        if(pos > 0) {
            line[pos] = '\0';
            simple_app_parse_config_line(app, line);
        }
        storage_file_close(file);
        loaded = true;
    }
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
    if(loaded) {
        simple_app_show_status_message(app, "Config loaded", 1000, true);
        app->config_dirty = false;
    } else {
        simple_app_save_config(app, NULL, false);
        simple_app_show_status_message(app, "Config created", 1000, true);
    }
    if(app->scanner_min_power > SCAN_POWER_MAX_DBM) {
        app->scanner_min_power = SCAN_POWER_MAX_DBM;
    } else if(app->scanner_min_power < SCAN_POWER_MIN_DBM) {
        app->scanner_min_power = SCAN_POWER_MIN_DBM;
    }
    simple_app_update_result_layout(app);
    simple_app_rebuild_visible_results(app);
}

static void simple_app_save_config_if_dirty(SimpleApp* app, const char* message, bool fullscreen) {
    if(!app) return;
    if(app->config_dirty) {
        simple_app_save_config(app, message, fullscreen);
    }
}

static void simple_app_apply_backlight(SimpleApp* app) {
    if(!app) return;
    uint8_t level = app->backlight_enabled ? BACKLIGHT_ON_LEVEL : BACKLIGHT_OFF_LEVEL;
    furi_hal_light_set(LightBacklight, level);

    if(app->backlight_enabled) {
        if(!app->backlight_insomnia) {
            furi_hal_power_insomnia_enter();
            app->backlight_insomnia = true;
        }
        if(app->notifications && !app->backlight_notification_enforced) {
            notification_message_block(app->notifications, &sequence_display_backlight_enforce_on);
            app->backlight_notification_enforced = true;
        }
    } else {
        if(app->backlight_insomnia) {
            furi_hal_power_insomnia_exit();
            app->backlight_insomnia = false;
        }
        if(app->notifications && app->backlight_notification_enforced) {
            notification_message(app->notifications, &sequence_display_backlight_enforce_auto);
            app->backlight_notification_enforced = false;
        }
    }

    simple_app_update_backlight_label(app);
}

static void simple_app_toggle_backlight(SimpleApp* app) {
    if(!app) return;
    app->backlight_enabled = !app->backlight_enabled;
    simple_app_apply_backlight(app);
    simple_app_mark_config_dirty(app);
}

static size_t simple_app_parse_quoted_fields(const char* line, char fields[][SCAN_FIELD_BUFFER_LEN], size_t max_fields) {
    if(!line || !fields || max_fields == 0) return 0;

    size_t count = 0;
    const char* ptr = line;
    while(*ptr && count < max_fields) {
        while(*ptr && *ptr != '"') {
            ptr++;
        }
        if(*ptr != '"') break;
        ptr++;
        const char* start = ptr;
        while(*ptr && *ptr != '"') {
            ptr++;
        }
        size_t len = (size_t)(ptr - start);
        if(len >= SCAN_FIELD_BUFFER_LEN) {
            len = SCAN_FIELD_BUFFER_LEN - 1;
        }
        memcpy(fields[count], start, len);
        fields[count][len] = '\0';
        if(*ptr == '"') {
            ptr++;
        }
        while(*ptr && *ptr != '"') {
            ptr++;
        }
        count++;
    }
    return count;
}

static void simple_app_process_scan_line(SimpleApp* app, const char* line) {
    if(!app || !line) return;

    const char* cursor = line;
    while(*cursor == ' ' || *cursor == '\t') {
        cursor++;
    }

    if(strncmp(cursor, "Scan results", 12) == 0) {
        app->scan_results_loading = false;
        if(app->screen == ScreenResults) {
            view_port_update(app->viewport);
        }
        return;
    }

    if(cursor[0] != '"') return;
    if(app->scan_result_count >= MAX_SCAN_RESULTS) return;

    char fields[7][SCAN_FIELD_BUFFER_LEN];
    for(size_t i = 0; i < 7; i++) {
        memset(fields[i], 0, SCAN_FIELD_BUFFER_LEN);
    }

    size_t field_count = simple_app_parse_quoted_fields(cursor, fields, 7);
    if(field_count < 7) return;

    ScanResult* result = &app->scan_results[app->scan_result_count];
    memset(result, 0, sizeof(ScanResult));
    result->number = (uint16_t)strtoul(fields[0], NULL, 10);
    simple_app_copy_field(result->ssid, sizeof(result->ssid), fields[1], "<hidden>");
    simple_app_copy_field(result->bssid, sizeof(result->bssid), fields[2], "??:??:??:??:??:??");
    simple_app_copy_field(result->channel, sizeof(result->channel), fields[3], "?");
    simple_app_copy_field(result->security, sizeof(result->security), fields[4], "Unknown");
    simple_app_copy_field(result->power_display, sizeof(result->power_display), fields[5], "?");
    simple_app_copy_field(result->band, sizeof(result->band), fields[6], "?");

    const char* power_str = fields[5];
    char* power_end = NULL;
    long power_value = strtol(power_str, &power_end, 10);
    if(power_str[0] != '\0' && power_end && *power_end == '\0') {
        if(power_value < SCAN_POWER_MIN_DBM) {
            power_value = SCAN_POWER_MIN_DBM;
        } else if(power_value > SCAN_POWER_MAX_DBM) {
            power_value = SCAN_POWER_MAX_DBM;
        }
        result->power_dbm = (int16_t)power_value;
        result->power_valid = true;
    } else {
        result->power_dbm = 0;
        result->power_valid = false;
    }
    result->selected = false;

    app->scan_result_count++;
    simple_app_rebuild_visible_results(app);

    if(app->screen == ScreenResults) {
        simple_app_adjust_result_offset(app);
        view_port_update(app->viewport);
    }
}

static uint8_t simple_app_result_line_count(const SimpleApp* app, const ScanResult* result) {
    if(!app || !result) return 1;
    size_t max_lines = (app->result_max_lines > 0) ? app->result_max_lines : RESULT_DEFAULT_MAX_LINES;
    if(max_lines == 0) max_lines = RESULT_DEFAULT_MAX_LINES;
    if(max_lines > RESULT_DEFAULT_MAX_LINES) {
        max_lines = RESULT_DEFAULT_MAX_LINES;
    }
    size_t count = simple_app_build_result_lines(app, result, NULL, max_lines);
    if(count == 0) count = 1;
    return (uint8_t)count;
}

static size_t simple_app_total_result_lines(SimpleApp* app) {
    if(!app) return 0;
    size_t total = 0;
    for(size_t i = 0; i < app->visible_result_count; i++) {
        const ScanResult* result = simple_app_visible_result_const(app, i);
        if(!result) continue;
        total += simple_app_result_line_count(app, result);
    }
    return total;
}

static size_t simple_app_result_offset_lines(SimpleApp* app) {
    if(!app) return 0;
    size_t lines = 0;
    for(size_t i = 0; i < app->scan_result_offset && i < app->visible_result_count; i++) {
        const ScanResult* result = simple_app_visible_result_const(app, i);
        if(!result) continue;
        lines += simple_app_result_line_count(app, result);
    }
    return lines;
}

static void simple_app_scan_feed(SimpleApp* app, char ch) {
    if(!app || !app->scan_results_loading) return;

    if(ch == '\r') return;

    if(ch == '\n') {
        if(app->scan_line_len > 0) {
            app->scan_line_buffer[app->scan_line_len] = '\0';
            simple_app_process_scan_line(app, app->scan_line_buffer);
        }
        app->scan_line_len = 0;
        return;
    }

    if(app->scan_line_len + 1 >= sizeof(app->scan_line_buffer)) {
        app->scan_line_len = 0;
        return;
    }

    app->scan_line_buffer[app->scan_line_len++] = ch;
}

static void simple_app_update_selected_numbers(SimpleApp* app, const ScanResult* result) {
    if(!app || !result) return;
    if(result->selected) {
        for(size_t i = 0; i < app->scan_selected_count; i++) {
            if(app->scan_selected_numbers[i] == result->number) {
                return;
            }
        }
        if(app->scan_selected_count < MAX_SCAN_RESULTS) {
            app->scan_selected_numbers[app->scan_selected_count++] = result->number;
        }
    } else {
        for(size_t i = 0; i < app->scan_selected_count; i++) {
            if(app->scan_selected_numbers[i] == result->number) {
                for(size_t j = i; j + 1 < app->scan_selected_count; j++) {
                    app->scan_selected_numbers[j] = app->scan_selected_numbers[j + 1];
                }
                app->scan_selected_numbers[app->scan_selected_count - 1] = 0;
                if(app->scan_selected_count > 0) {
                    app->scan_selected_count--;
                }
                break;
            }
        }
    }
}

static void simple_app_toggle_scan_selection(SimpleApp* app, ScanResult* result) {
    if(!app || !result) return;
    result->selected = !result->selected;
    simple_app_update_selected_numbers(app, result);
}

static void simple_app_adjust_result_offset(SimpleApp* app) {
    if(!app) return;

    if(app->visible_result_count == 0) {
        app->scan_result_offset = 0;
        app->scan_result_index = 0;
        return;
    }

    if(app->scan_result_index >= app->visible_result_count) {
        app->scan_result_index = app->visible_result_count - 1;
    }

    if(app->scan_result_offset > app->scan_result_index) {
        app->scan_result_offset = app->scan_result_index;
    }

    while(app->scan_result_offset < app->visible_result_count) {
        size_t lines_used = 0;
        bool index_visible = false;
        size_t available_lines = (app->result_max_lines > 0) ? app->result_max_lines : 1;
        for(size_t i = app->scan_result_offset; i < app->visible_result_count; i++) {
            const ScanResult* result = simple_app_visible_result_const(app, i);
            if(!result) continue;
            uint8_t entry_lines = simple_app_result_line_count(app, result);
            if(entry_lines == 0) entry_lines = 1;
            if(lines_used + entry_lines > available_lines) break;
            lines_used += entry_lines;
            if(i == app->scan_result_index) {
                index_visible = true;
                break;
            }
        }
        if(index_visible) break;
        if(app->scan_result_offset >= app->scan_result_index) {
            break;
        }
        app->scan_result_offset++;
    }

    if(app->scan_result_offset >= app->visible_result_count) {
        app->scan_result_offset =
            (app->visible_result_count > 0) ? app->visible_result_count - 1 : 0;
    }
}

static size_t simple_app_trim_oldest_line(SimpleApp* app) {
    if(!app || app->serial_len == 0) return 0;
    size_t drop = 0;
    size_t removed_lines = 0;

    while(drop < app->serial_len && app->serial_buffer[drop] != '\n') {
        drop++;
    }

    if(drop < app->serial_len) {
        drop++;
        removed_lines = 1;
    } else if(app->serial_len > 0) {
        removed_lines = 1;
    } else {
        drop = app->serial_len;
    }

    if(drop > 0) {
        memmove(app->serial_buffer, app->serial_buffer + drop, app->serial_len - drop);
        app->serial_len -= drop;
        app->serial_buffer[app->serial_len] = '\0';
    }

    return removed_lines;
}

static size_t simple_app_count_display_lines(const char* buffer, size_t length) {
    size_t lines = 0;
    size_t col = 0;

    for(size_t i = 0; i < length; i++) {
        char ch = buffer[i];
        if(ch == '\r') continue;
        if(ch == '\n') {
            lines++;
            col = 0;
            continue;
        }
        if(col >= SERIAL_LINE_CHAR_LIMIT) {
            lines++;
            col = 0;
        }
        col++;
    }

    if(col > 0) {
        lines++;
    }

    return lines;
}

static size_t simple_app_total_display_lines(SimpleApp* app) {
    if(!app->serial_mutex) return 0;
    furi_mutex_acquire(app->serial_mutex, FuriWaitForever);
    size_t total = simple_app_count_display_lines(app->serial_buffer, app->serial_len);
    furi_mutex_release(app->serial_mutex);
    return total;
}

static size_t simple_app_max_scroll(SimpleApp* app) {
    size_t total = simple_app_total_display_lines(app);
    if(total <= SERIAL_VISIBLE_LINES) return 0;
    return total - SERIAL_VISIBLE_LINES;
}

static void simple_app_update_scroll(SimpleApp* app) {
    if(!app) return;
    size_t max_scroll = simple_app_max_scroll(app);
    if(app->serial_follow_tail) {
        app->serial_scroll = max_scroll;
    } else if(app->serial_scroll > max_scroll) {
        app->serial_scroll = max_scroll;
    }
    if(max_scroll == 0) {
        app->serial_follow_tail = true;
    }
}

static void simple_app_reset_serial_log(SimpleApp* app, const char* status) {
    if(!app || !app->serial_mutex) return;
    furi_mutex_acquire(app->serial_mutex, FuriWaitForever);
    int written = snprintf(
        app->serial_buffer,
        SERIAL_BUFFER_SIZE,
        "=== UART TERMINAL ===\n115200 baud\nStatus: %s\n\n",
        status ? status : "READY");
    if(written < 0) {
        written = 0;
    } else if(written >= (int)SERIAL_BUFFER_SIZE) {
        written = SERIAL_BUFFER_SIZE - 1;
    }
    app->serial_len = (size_t)written;
    app->serial_buffer[app->serial_len] = '\0';
    furi_mutex_release(app->serial_mutex);
    app->serial_scroll = 0;
    app->serial_follow_tail = true;
    app->serial_targets_hint = false;
    simple_app_update_scroll(app);
}

static void simple_app_append_serial_data(SimpleApp* app, const uint8_t* data, size_t length) {
    if(!app || !data || length == 0 || !app->serial_mutex) return;

    bool trimmed_any = false;

    furi_mutex_acquire(app->serial_mutex, FuriWaitForever);
    for(size_t i = 0; i < length; i++) {
        while(app->serial_len >= SERIAL_BUFFER_SIZE - 1) {
            trimmed_any = simple_app_trim_oldest_line(app) > 0 || trimmed_any;
        }
        app->serial_buffer[app->serial_len++] = (char)data[i];
    }
    app->serial_buffer[app->serial_len] = '\0';

    if(!app->serial_targets_hint) {
        static const char hint_phrase[] = "Scan results printed.";
        size_t phrase_len = strlen(hint_phrase);
        if(app->serial_len >= phrase_len) {
            size_t search_window = phrase_len + 64;
            if(search_window > app->serial_len) {
                search_window = app->serial_len;
            }
            const char* start = app->serial_buffer + (app->serial_len - search_window);
            if(strstr(start, hint_phrase) != NULL) {
                app->serial_targets_hint = true;
            }
        }
    }

    furi_mutex_release(app->serial_mutex);

    for(size_t i = 0; i < length; i++) {
        char ch = (char)data[i];
        simple_app_scan_feed(app, ch);
        simple_app_evil_twin_feed(app, ch);
    }

    if(trimmed_any && !app->serial_follow_tail) {
        size_t max_scroll = simple_app_max_scroll(app);
        if(app->serial_scroll > max_scroll) {
            app->serial_scroll = max_scroll;
        }
    }

    simple_app_update_scroll(app);
}

static void simple_app_send_command(SimpleApp* app, const char* command, bool go_to_serial) {
    if(!app || !command || command[0] == '\0') return;

    app->serial_targets_hint = false;

    char cmd[64];
    snprintf(cmd, sizeof(cmd), "%s\n", command);

    furi_hal_serial_tx(app->serial, (const uint8_t*)cmd, strlen(cmd));
    furi_hal_serial_tx_wait_complete(app->serial);

    furi_stream_buffer_reset(app->rx_stream);
    simple_app_reset_serial_log(app, "COMMAND SENT");

    char log_line[96];
    int log_len = snprintf(log_line, sizeof(log_line), "TX: %s\n", command);
    if(log_len > 0) {
        simple_app_append_serial_data(app, (const uint8_t*)log_line, (size_t)log_len);
    }

    app->last_command_sent = true;
    if(go_to_serial) {
        app->screen = ScreenSerial;
        app->serial_follow_tail = true;
        simple_app_update_scroll(app);
    }
}

static void simple_app_send_command_with_targets(SimpleApp* app, const char* base_command) {
    if(!app || !base_command || base_command[0] == '\0') return;
    if(app->scan_selected_count == 0) {
        simple_app_show_status_message(app, "Please select\nnetwork first", 1500, true);
        if(app->viewport) {
            view_port_update(app->viewport);
        }
        return;
    }

    if(strcmp(base_command, "start_deauth") == 0 || strcmp(base_command, "start_evil_twin") == 0) {
        char select_command[160];
        size_t written = snprintf(select_command, sizeof(select_command), "select_networks");
        if(written >= sizeof(select_command)) {
            select_command[sizeof(select_command) - 1] = '\0';
            written = strlen(select_command);
        }

        for(size_t i = 0; i < app->scan_selected_count && written < sizeof(select_command) - 1; i++) {
            int added = snprintf(
                select_command + written,
                sizeof(select_command) - written,
                " %u",
                (unsigned)app->scan_selected_numbers[i]);
            if(added < 0) {
                break;
            }
            written += (size_t)added;
            if(written >= sizeof(select_command)) {
                written = sizeof(select_command) - 1;
                select_command[written] = '\0';
                break;
            }
        }

        char combined_command[256];
        int combined_written =
            snprintf(combined_command, sizeof(combined_command), "%s\n%s", select_command, base_command);
        if(combined_written < 0) {
            simple_app_send_command(app, base_command, true);
        } else {
            if((size_t)combined_written >= sizeof(combined_command)) {
                combined_command[sizeof(combined_command) - 1] = '\0';
            }
            simple_app_send_command(app, combined_command, true);
        }
        return;
    }

    char command[96];
    size_t written = snprintf(command, sizeof(command), "%s", base_command);
    if(written >= sizeof(command)) {
        command[sizeof(command) - 1] = '\0';
        written = strlen(command);
    }

    for(size_t i = 0; i < app->scan_selected_count && written < sizeof(command) - 1; i++) {
        int added = snprintf(
            command + written,
            sizeof(command) - written,
            " %u",
            (unsigned)app->scan_selected_numbers[i]);
        if(added < 0) {
            break;
        }
        written += (size_t)added;
        if(written >= sizeof(command)) {
            written = sizeof(command) - 1;
            command[written] = '\0';
            break;
        }
    }

    simple_app_send_command(app, command, true);
}

static void simple_app_send_stop_if_needed(SimpleApp* app) {
    if(!app || !app->last_command_sent) return;
    simple_app_send_command(app, "stop", false);
    app->last_command_sent = false;
}

static void simple_app_request_scan_results(SimpleApp* app, const char* command) {
    if(!app) return;
    simple_app_reset_scan_results(app);
    app->scan_results_loading = true;
    app->serial_targets_hint = false;
    if(command && command[0] != '\0') {
        simple_app_send_command(app, command, false);
    }
    app->screen = ScreenResults;
    view_port_update(app->viewport);
}

static void simple_app_console_enter(SimpleApp* app) {
    if(!app) return;
    app->screen = ScreenConsole;
    app->serial_follow_tail = true;
    simple_app_update_scroll(app);
    view_port_update(app->viewport);
}

static void simple_app_console_leave(SimpleApp* app) {
    if(!app) return;
    app->screen = ScreenMenu;
    app->menu_state = MenuStateItems;
    app->section_index = MENU_SECTION_SETUP;
    app->item_index = menu_sections[MENU_SECTION_SETUP].entry_count - 1;
    size_t visible_count = simple_app_menu_visible_count(app, MENU_SECTION_SETUP);
    if(visible_count == 0) visible_count = 1;
    if(menu_sections[MENU_SECTION_SETUP].entry_count > visible_count) {
        size_t max_offset = menu_sections[MENU_SECTION_SETUP].entry_count - visible_count;
        app->item_offset = max_offset;
    } else {
        app->item_offset = 0;
    }
    app->serial_follow_tail = true;
    simple_app_update_scroll(app);
    view_port_update(app->viewport);
}

static void simple_app_draw_console(SimpleApp* app, Canvas* canvas) {
    if(!app) return;
    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontSecondary);

    char display_lines[CONSOLE_VISIBLE_LINES][64];
    size_t lines_filled =
        simple_app_render_display_lines(app, app->serial_scroll, display_lines, CONSOLE_VISIBLE_LINES);
    uint8_t y = 8;
    for(size_t i = 0; i < CONSOLE_VISIBLE_LINES; i++) {
        const char* line = (i < lines_filled) ? display_lines[i] : "";
        if(lines_filled == 0 && i == 0) {
            canvas_draw_str(canvas, 2, y, "No UART data");
        } else {
            canvas_draw_str(canvas, 2, y, line[0] ? line : " ");
        }
        y += SERIAL_TEXT_LINE_HEIGHT;
    }

    size_t total_lines = simple_app_total_display_lines(app);
    if(total_lines > CONSOLE_VISIBLE_LINES) {
        const uint8_t track_width = 3;
        const uint8_t track_x = DISPLAY_WIDTH - track_width;
        const uint8_t track_y = 4;
        const uint8_t track_height = 56;

        canvas_draw_frame(canvas, track_x, track_y, track_width, track_height);
        canvas_draw_box(canvas, track_x + 1, track_y + 1, 1, 1);
        canvas_draw_box(canvas, track_x + 1, track_y + track_height - 2, 1, 1);

        size_t max_scroll = simple_app_max_scroll(app);
        uint8_t thumb_height =
            (uint8_t)(((uint32_t)CONSOLE_VISIBLE_LINES * track_height) / total_lines);
        if(thumb_height < 4) thumb_height = 4;
        if(thumb_height > track_height) thumb_height = track_height;

        uint8_t thumb_track_top = track_y;
        uint8_t thumb_track_height = track_height;
        uint8_t thumb_width = (track_width > 2) ? (track_width - 2) : 1;
        uint8_t thumb_x = (track_width > 2) ? (track_x + 1) : track_x;

        if(track_width > 2 && track_height > 2) {
            thumb_track_top = track_y + 1;
            thumb_track_height = track_height - 2;
        }

        if(thumb_height > thumb_track_height) {
            thumb_height = thumb_track_height;
        }

        uint8_t max_thumb_offset =
            (thumb_track_height > thumb_height) ? (thumb_track_height - thumb_height) : 0;
        uint8_t thumb_offset = 0;
        if(max_scroll > 0 && max_thumb_offset > 0) {
            thumb_offset = (uint8_t)(((uint32_t)app->serial_scroll * max_thumb_offset) / max_scroll);
        }

        uint8_t thumb_y = thumb_track_top + thumb_offset;
        canvas_draw_box(canvas, thumb_x, thumb_y, thumb_width, thumb_height);
    }

    if(simple_app_status_message_is_active(app) && !app->status_message_fullscreen) {
        canvas_draw_str(canvas, 2, 52, app->status_message);
    }

    canvas_draw_str(canvas, 2, 62, "Back=Exit  Up/Down scroll");
}

static void simple_app_draw_confirm_blackout(SimpleApp* app, Canvas* canvas) {
    if(!app) return;
    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str_aligned(
        canvas,
        DISPLAY_WIDTH / 2,
        12,
        AlignCenter,
        AlignCenter,
        "Blackout will disconnect");
    canvas_draw_str_aligned(
        canvas,
        DISPLAY_WIDTH / 2,
        24,
        AlignCenter,
        AlignCenter,
        "all clients on scanned APs");

    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, 38, AlignCenter, AlignCenter, "Confirm?");

    canvas_set_font(canvas, FontSecondary);
    const char* option_line = app->confirm_blackout_yes ? "No        > Yes" : "> No        Yes";
    canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, 50, AlignCenter, AlignCenter, option_line);
}

static void simple_app_draw_confirm_sniffer_dos(SimpleApp* app, Canvas* canvas) {
    if(!app) return;
    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str_aligned(
        canvas, DISPLAY_WIDTH / 2, 12, AlignCenter, AlignCenter, "Sniffer Dog will flood");
    canvas_draw_str_aligned(
        canvas, DISPLAY_WIDTH / 2, 24, AlignCenter, AlignCenter, "clients found by sniffer");

    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, 38, AlignCenter, AlignCenter, "Confirm?");

    canvas_set_font(canvas, FontSecondary);
    const char* option_line =
        app->confirm_sniffer_dos_yes ? "No        > Yes" : "> No        Yes";
    canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, 50, AlignCenter, AlignCenter, option_line);
}

static void simple_app_handle_console_input(SimpleApp* app, InputKey key) {
    if(!app) return;
    if(key == InputKeyBack) {
        simple_app_send_stop_if_needed(app);
        simple_app_console_leave(app);
        return;
    }

    if(key == InputKeyUp) {
        if(app->serial_scroll > 0) {
            app->serial_scroll--;
            app->serial_follow_tail = false;
            view_port_update(app->viewport);
        }
        return;
    }

    if(key == InputKeyLeft) {
        size_t step = CONSOLE_VISIBLE_LINES;
        if(app->serial_scroll > 0) {
            if(app->serial_scroll > step) {
                app->serial_scroll -= step;
            } else {
                app->serial_scroll = 0;
            }
            app->serial_follow_tail = false;
        }
        view_port_update(app->viewport);
        return;
    } else if(key == InputKeyRight) {
        size_t step = CONSOLE_VISIBLE_LINES;
        size_t max_scroll = simple_app_max_scroll(app);
        if(app->serial_scroll < max_scroll) {
            app->serial_scroll =
                (app->serial_scroll + step < max_scroll) ? app->serial_scroll + step : max_scroll;
            app->serial_follow_tail = (app->serial_scroll == max_scroll);
        } else {
            app->serial_follow_tail = true;
            simple_app_update_scroll(app);
        }
        view_port_update(app->viewport);
        return;
    } else if(key == InputKeyDown) {
        size_t max_scroll = simple_app_max_scroll(app);
        if(app->serial_scroll < max_scroll) {
            app->serial_scroll++;
            app->serial_follow_tail = (app->serial_scroll == max_scroll);
            view_port_update(app->viewport);
        } else {
            app->serial_follow_tail = true;
            simple_app_update_scroll(app);
            view_port_update(app->viewport);
        }
        return;
    } else if(key == InputKeyOk) {
        app->serial_follow_tail = true;
        simple_app_update_scroll(app);
        view_port_update(app->viewport);
    }
}

static void simple_app_handle_confirm_blackout_input(SimpleApp* app, InputKey key) {
    if(!app) return;
    if(key == InputKeyBack) {
        simple_app_send_stop_if_needed(app);
        app->confirm_blackout_yes = false;
        simple_app_focus_attacks_menu(app);
        view_port_update(app->viewport);
        return;
    }

    if(key == InputKeyLeft || key == InputKeyRight) {
        app->confirm_blackout_yes = !app->confirm_blackout_yes;
        view_port_update(app->viewport);
        return;
    }

    if(key == InputKeyOk) {
        if(app->confirm_blackout_yes) {
            app->confirm_blackout_yes = false;
            simple_app_send_command(app, "start_blackout", true);
        } else {
            simple_app_focus_attacks_menu(app);
            view_port_update(app->viewport);
        }
    }
}

static void simple_app_handle_confirm_sniffer_dos_input(SimpleApp* app, InputKey key) {
    if(!app) return;
    if(key == InputKeyBack) {
        simple_app_send_stop_if_needed(app);
        app->confirm_sniffer_dos_yes = false;
        simple_app_focus_attacks_menu(app);
        view_port_update(app->viewport);
        return;
    }

    if(key == InputKeyLeft || key == InputKeyRight) {
        app->confirm_sniffer_dos_yes = !app->confirm_sniffer_dos_yes;
        view_port_update(app->viewport);
        return;
    }

    if(key == InputKeyOk) {
        if(app->confirm_sniffer_dos_yes) {
            app->confirm_sniffer_dos_yes = false;
            simple_app_send_command(app, "start_sniffer_dog", true);
        } else {
            simple_app_focus_attacks_menu(app);
            view_port_update(app->viewport);
        }
    }
}

static size_t simple_app_hint_max_scroll(const SimpleApp* app) {
    if(!app || app->hint_line_count <= HINT_VISIBLE_LINES) {
        return 0;
    }
    return app->hint_line_count - HINT_VISIBLE_LINES;
}

static void simple_app_prepare_hint_lines(SimpleApp* app, const char* text) {
    if(!app) return;
    app->hint_line_count = 0;
    if(!text) return;

    const char* ptr = text;
    while(*ptr && app->hint_line_count < HINT_MAX_LINES) {
        if(*ptr == '\n') {
            app->hint_lines[app->hint_line_count][0] = '\0';
            app->hint_line_count++;
            ptr++;
            continue;
        }

        size_t line_len = 0;
        while(ptr[line_len] && ptr[line_len] != '\n') {
            line_len++;
        }

        size_t consumed = 0;
        while(consumed < line_len && app->hint_line_count < HINT_MAX_LINES) {
            size_t remaining = line_len - consumed;
            size_t block = remaining > HINT_WRAP_LIMIT ? HINT_WRAP_LIMIT : remaining;

            size_t copy_len = block;
            if(block == HINT_WRAP_LIMIT && consumed + block < line_len) {
                size_t adjust = block;
                while(adjust > 0 &&
                      ptr[consumed + adjust - 1] != ' ' &&
                      ptr[consumed + adjust - 1] != '-') {
                    adjust--;
                }
                if(adjust > 0) {
                    copy_len = adjust;
                }
            }

            if(copy_len == 0) {
                copy_len = block;
            }
            if(copy_len >= HINT_LINE_CHAR_LIMIT) {
                copy_len = HINT_LINE_CHAR_LIMIT - 1;
            }

            memcpy(app->hint_lines[app->hint_line_count], ptr + consumed, copy_len);
            app->hint_lines[app->hint_line_count][copy_len] = '\0';

            size_t trim = copy_len;
            while(trim > 0 && app->hint_lines[app->hint_line_count][trim - 1] == ' ') {
                app->hint_lines[app->hint_line_count][--trim] = '\0';
            }

            app->hint_line_count++;
            if(app->hint_line_count >= HINT_MAX_LINES) {
                break;
            }

            consumed += copy_len;
            while(consumed < line_len && ptr[consumed] == ' ') {
                consumed++;
            }
        }

        ptr += line_len;
        if(*ptr == '\n') {
            ptr++;
        }
    }
}

static void simple_app_show_hint(SimpleApp* app, const char* title, const char* text) {
    if(!app || !title || !text) return;

    memset(app->hint_title, 0, sizeof(app->hint_title));
    strncpy(app->hint_title, title, sizeof(app->hint_title) - 1);
    simple_app_prepare_hint_lines(app, text);

    if(app->hint_line_count == 0) {
        strncpy(app->hint_lines[0], text, HINT_LINE_CHAR_LIMIT - 1);
        app->hint_lines[0][HINT_LINE_CHAR_LIMIT - 1] = '\0';
        app->hint_line_count = 1;
    }

    app->hint_scroll = 0;
    app->hint_active = true;
    if(app->viewport) {
        view_port_update(app->viewport);
    }
}

static void simple_app_hide_hint(SimpleApp* app) {
    if(!app || !app->hint_active) return;
    app->hint_active = false;
    app->hint_line_count = 0;
    app->hint_scroll = 0;
    if(app->viewport) {
        view_port_update(app->viewport);
    }
}

static void simple_app_hint_scroll(SimpleApp* app, int delta) {
    if(!app || !app->hint_active || delta == 0) return;
    size_t max_scroll = simple_app_hint_max_scroll(app);
    int32_t new_value = (int32_t)app->hint_scroll + delta;
    if(new_value < 0) {
        new_value = 0;
    }
    if(new_value > (int32_t)max_scroll) {
        new_value = (int32_t)max_scroll;
    }
    if((size_t)new_value != app->hint_scroll) {
        app->hint_scroll = (size_t)new_value;
        if(app->viewport) {
            view_port_update(app->viewport);
        }
    }
}

static void simple_app_handle_hint_event(SimpleApp* app, const InputEvent* event) {
    if(!app || !event) return;

    if(event->type == InputTypeShort && event->key == InputKeyBack) {
        simple_app_send_stop_if_needed(app);
        simple_app_hide_hint(app);
        return;
    }

    if((event->type == InputTypeShort || event->type == InputTypeRepeat)) {
        if(event->key == InputKeyUp) {
            simple_app_hint_scroll(app, -1);
        } else if(event->key == InputKeyDown) {
            simple_app_hint_scroll(app, 1);
        }
    }
}

static void simple_app_draw_hint(SimpleApp* app, Canvas* canvas) {
    if(!app || !canvas || !app->hint_active) return;

    const uint8_t bubble_x = 6;
    const uint8_t bubble_y = 6;
    const uint8_t bubble_w = DISPLAY_WIDTH - (bubble_x * 2);
    const uint8_t bubble_h = 56;
    const uint8_t radius = 8;

    canvas_set_color(canvas, ColorWhite);
    canvas_draw_rbox(canvas, bubble_x, bubble_y, bubble_w, bubble_h, radius);
    canvas_set_color(canvas, ColorBlack);
    canvas_draw_rframe(canvas, bubble_x, bubble_y, bubble_w, bubble_h, radius);

    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, bubble_x + 7, bubble_y + 16, app->hint_title);

    canvas_set_font(canvas, FontSecondary);
    uint8_t text_x = bubble_x + 7;
    uint8_t text_y = bubble_y + 28;

    if(app->hint_line_count > 0) {
        size_t visible = app->hint_line_count - app->hint_scroll;
        if(visible > HINT_VISIBLE_LINES) {
            visible = HINT_VISIBLE_LINES;
        }
        for(size_t i = 0; i < visible; i++) {
            size_t line_index = app->hint_scroll + i;
            if(line_index >= app->hint_line_count) break;
            canvas_draw_str(
                canvas, text_x, (uint8_t)(text_y + i * HINT_LINE_HEIGHT), app->hint_lines[line_index]);
        }
    }

    if(app->hint_line_count > HINT_VISIBLE_LINES) {
        const uint8_t track_width = 5;
        const uint8_t track_height = (uint8_t)(HINT_VISIBLE_LINES * HINT_LINE_HEIGHT);
        const uint8_t track_x = bubble_x + bubble_w - track_width - 4;
        int16_t desired_track_y =
            bubble_y + ((int16_t)bubble_h - (int16_t)track_height) / 2;
        int16_t track_min = bubble_y + 2;
        int16_t track_max = bubble_y + bubble_h - track_height - 2;
        if(track_max < track_min) track_max = track_min;
        if(desired_track_y < track_min) desired_track_y = track_min;
        if(desired_track_y > track_max) desired_track_y = track_max;
        uint8_t track_y = (uint8_t)desired_track_y;

        canvas_draw_frame(canvas, track_x, track_y, track_width, track_height);

        size_t max_scroll = simple_app_hint_max_scroll(app);
        uint8_t thumb_height =
            (uint8_t)(((uint32_t)HINT_VISIBLE_LINES * track_height) / app->hint_line_count);
        if(thumb_height < 4) thumb_height = 4;
        if(thumb_height > track_height) thumb_height = track_height;

        uint8_t max_thumb_offset =
            (track_height > thumb_height) ? (uint8_t)(track_height - thumb_height) : 0;
        uint8_t thumb_offset = 0;
        if(max_scroll > 0 && max_thumb_offset > 0) {
            thumb_offset =
                (uint8_t)(((uint32_t)app->hint_scroll * max_thumb_offset) / max_scroll);
        }
        uint8_t thumb_x = track_x + 1;
        uint8_t thumb_y = (uint8_t)(track_y + 1 + thumb_offset);
        uint8_t thumb_inner_height = (thumb_height > 2) ? (uint8_t)(thumb_height - 2) : thumb_height;
        if(thumb_inner_height == 0) thumb_inner_height = thumb_height;
        uint8_t thumb_width = (track_width > 2) ? (uint8_t)(track_width - 2) : 1;
        canvas_draw_box(canvas, thumb_x, thumb_y, thumb_width, thumb_inner_height);

        uint8_t arrow_top_center = (uint8_t)(track_y + 2);
        canvas_draw_line(canvas, track_x + track_width / 2, arrow_top_center - 2, track_x + 1, arrow_top_center);
        canvas_draw_line(
            canvas, track_x + track_width / 2, arrow_top_center - 2, track_x + track_width - 2, arrow_top_center);

        uint8_t arrow_bottom_center = (uint8_t)(track_y + track_height - 3);
        canvas_draw_line(canvas, track_x + 1, arrow_bottom_center, track_x + track_width / 2, arrow_bottom_center + 2);
        canvas_draw_line(
            canvas,
            track_x + track_width - 2,
            arrow_bottom_center,
            track_x + track_width / 2,
            arrow_bottom_center + 2);
    }
}

static bool simple_app_try_show_hint(SimpleApp* app) {
    if(!app) return false;
    if(app->screen != ScreenMenu) return false;
    if(app->section_index >= menu_section_count) return false;

    const MenuSection* section = &menu_sections[app->section_index];

    if(app->menu_state == MenuStateSections) {
        if(!section->hint) return false;
        simple_app_show_hint(app, section->title, section->hint);
        return true;
    }

    if(section->entry_count == 0) {
        if(!section->hint) return false;
        simple_app_show_hint(app, section->title, section->hint);
        return true;
    }

    if(app->item_index >= section->entry_count) return false;

    const MenuEntry* entry = &section->entries[app->item_index];
    const char* hint_text = entry->hint ? entry->hint : section->hint;
    if(!hint_text) return false;

    simple_app_show_hint(app, entry->label, hint_text);
    return true;
}

static void simple_app_draw_evil_twin_menu(SimpleApp* app, Canvas* canvas) {
    if(!app || !canvas) return;

    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 4, 14, "Evil Twin");

    canvas_set_font(canvas, FontSecondary);
    uint8_t y = 30;

    for(size_t idx = 0; idx < EVIL_TWIN_MENU_OPTION_COUNT; idx++) {
        const char* label = (idx == 0) ? "Select HTML" : "Start Evil Twin";
        if(app->evil_twin_menu_index == idx) {
            canvas_draw_str(canvas, 2, y, ">");
        }
        canvas_draw_str(canvas, 14, y, label);
        if(idx == 0) {
            char status[48];
            if(app->evil_twin_selected_html_id > 0 &&
               app->evil_twin_selected_html_name[0] != '\0') {
                snprintf(status, sizeof(status), "Current: %s", app->evil_twin_selected_html_name);
            } else {
                snprintf(status, sizeof(status), "Current: <none>");
            }
            simple_app_truncate_text(status, 26);
            canvas_draw_str(canvas, 14, y + 10, status);
            y += 10;
        }
        y += 12;
    }

    canvas_draw_str(canvas, 2, 62, "OK choose, Back menu");
}

static void simple_app_draw_evil_twin_popup(SimpleApp* app, Canvas* canvas) {
    if(!app || !canvas || !app->evil_twin_popup_active) return;

    const uint8_t bubble_x = 4;
    const uint8_t bubble_y = 4;
    const uint8_t bubble_w = DISPLAY_WIDTH - (bubble_x * 2);
    const uint8_t bubble_h = 56;
    const uint8_t radius = 9;

    canvas_set_color(canvas, ColorWhite);
    canvas_draw_rbox(canvas, bubble_x, bubble_y, bubble_w, bubble_h, radius);
    canvas_set_color(canvas, ColorBlack);
    canvas_draw_rframe(canvas, bubble_x, bubble_y, bubble_w, bubble_h, radius);

    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, bubble_x + 8, bubble_y + 16, "Select HTML");

    canvas_set_font(canvas, FontSecondary);
    uint8_t list_y = bubble_y + 28;

    if(app->evil_twin_html_count == 0) {
        canvas_draw_str(canvas, bubble_x + 10, list_y, "No HTML files");
        canvas_draw_str(canvas, bubble_x + 10, (uint8_t)(list_y + HINT_LINE_HEIGHT), "Back returns to menu");
        return;
    }

    size_t visible = app->evil_twin_html_count;
    if(visible > EVIL_TWIN_POPUP_VISIBLE_LINES) {
        visible = EVIL_TWIN_POPUP_VISIBLE_LINES;
    }

    if(app->evil_twin_html_popup_offset >= app->evil_twin_html_count) {
        app->evil_twin_html_popup_offset =
            (app->evil_twin_html_count > visible) ? (app->evil_twin_html_count - visible) : 0;
    }

    for(size_t i = 0; i < visible; i++) {
        size_t idx = app->evil_twin_html_popup_offset + i;
        if(idx >= app->evil_twin_html_count) break;
        const EvilTwinHtmlEntry* entry = &app->evil_twin_html_entries[idx];
        char line[48];
        snprintf(line, sizeof(line), "%u %s", (unsigned)entry->id, entry->name);
        simple_app_truncate_text(line, 28);
        uint8_t line_y = (uint8_t)(list_y + i * HINT_LINE_HEIGHT);
        if(idx == app->evil_twin_html_popup_index) {
            canvas_draw_str(canvas, bubble_x + 4, line_y, ">");
        }
        canvas_draw_str(canvas, bubble_x + 8, line_y, line);
    }

    if(app->evil_twin_html_count > EVIL_TWIN_POPUP_VISIBLE_LINES) {
        const uint8_t track_width = 3;
        uint8_t track_height = (uint8_t)(EVIL_TWIN_POPUP_VISIBLE_LINES * HINT_LINE_HEIGHT);
        const uint8_t track_x = bubble_x + bubble_w - track_width - 6;
        int16_t desired_track_y =
            bubble_y + ((int16_t)bubble_h - (int16_t)track_height) / 2;
        int16_t track_min = bubble_y + 2;
        int16_t track_max = bubble_y + bubble_h - track_height - 2;
        if(track_max < track_min) track_max = track_min;
        if(desired_track_y < track_min) desired_track_y = track_min;
        if(desired_track_y > track_max) desired_track_y = track_max;
        uint8_t track_y = (uint8_t)desired_track_y;

        canvas_draw_frame(canvas, track_x, track_y, track_width, track_height);

        size_t max_offset = app->evil_twin_html_count - EVIL_TWIN_POPUP_VISIBLE_LINES;
        uint8_t thumb_height =
            (uint8_t)(((uint32_t)EVIL_TWIN_POPUP_VISIBLE_LINES * track_height) / app->evil_twin_html_count);
        if(thumb_height < 4) thumb_height = 4;
        if(thumb_height > track_height) thumb_height = track_height;

        uint8_t max_thumb_offset =
            (track_height > thumb_height) ? (uint8_t)(track_height - thumb_height) : 0;
        uint8_t thumb_offset = 0;
        if(max_offset > 0 && max_thumb_offset > 0) {
            size_t offset = app->evil_twin_html_popup_offset;
            if(offset > max_offset) offset = max_offset;
            thumb_offset = (uint8_t)(((uint32_t)offset * max_thumb_offset) / max_offset);
        }

        uint8_t thumb_width = (track_width > 2) ? (uint8_t)(track_width - 2) : 1;
        uint8_t thumb_inner_height =
            (thumb_height > 2) ? (uint8_t)(thumb_height - 2) : thumb_height;
        if(thumb_inner_height == 0) thumb_inner_height = thumb_height;

        canvas_draw_box(
            canvas,
            (track_width > 2) ? (uint8_t)(track_x + 1) : track_x,
            (uint8_t)(track_y + 1 + thumb_offset),
            thumb_width,
            thumb_inner_height);
    }
}

static void simple_app_draw_menu(SimpleApp* app, Canvas* canvas) {
    canvas_set_color(canvas, ColorBlack);

    if(app->section_index >= menu_section_count) {
        app->section_index = 0;
    }

    bool show_setup_branding =
        (app->menu_state == MenuStateItems) && (app->section_index == MENU_SECTION_SETUP);

    if(show_setup_branding) {
        canvas_set_bitmap_mode(canvas, true);
        canvas_draw_xbm(canvas, 115, 2, 10, 10, image_icon_0_bits);
    }
    canvas_set_bitmap_mode(canvas, false);

    canvas_set_font(canvas, FontSecondary);

    if(app->help_hint_visible) {
        const uint8_t help_text_x = DISPLAY_WIDTH - 2;
        const uint8_t help_text_y = 63;
        canvas_draw_str_aligned(canvas, help_text_x, (int16_t)help_text_y - 8, AlignRight, AlignBottom, "Hold OK");
        canvas_draw_str_aligned(canvas, help_text_x, help_text_y, AlignRight, AlignBottom, "for Help");
    }

    if(simple_app_status_message_is_active(app) && !app->status_message_fullscreen) {
        canvas_draw_str(canvas, 2, 52, app->status_message);
    }
    if(show_setup_branding) {
        char version_text[24];
        snprintf(version_text, sizeof(version_text), "v.%s", LAB_C5_VERSION_TEXT);
        canvas_draw_str_aligned(canvas, DISPLAY_WIDTH - 1, 63, AlignRight, AlignBottom, version_text);
    }

    if(app->menu_state == MenuStateSections) {
        canvas_set_font(canvas, FontPrimary);
        for(size_t i = 0; i < menu_section_count; i++) {
            uint8_t y = menu_sections[i].display_y;
            if(app->section_index == i) {
                canvas_draw_str(canvas, 0, y, ">");
                canvas_draw_str(canvas, 12, y, menu_sections[i].title);
            } else {
                canvas_draw_str(canvas, 6, y, menu_sections[i].title);
            }
        }
        return;
    }

    if(app->section_index >= menu_section_count) {
        app->section_index = 0;
    }

    const MenuSection* section = &menu_sections[app->section_index];

    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 3, MENU_TITLE_Y, section->title);

    canvas_set_font(canvas, FontSecondary);

    size_t visible_count = simple_app_menu_visible_count(app, app->section_index);
    if(visible_count == 0) {
        visible_count = 1;
    }

    if(section->entry_count == 0) {
        const char* hint = "No options";
        if(app->section_index == MENU_SECTION_SCANNER) {
            hint = "OK: Scan networks";
        } else if(app->section_index == MENU_SECTION_TARGETS) {
            hint = "OK: Show results";
        }
        canvas_draw_str(canvas, 3, MENU_ITEM_BASE_Y + (MENU_ITEM_SPACING / 2), hint);
        return;
    }

    if(app->item_index >= section->entry_count) {
        app->item_index = section->entry_count - 1;
    }

    size_t max_offset = 0;
    if(section->entry_count > visible_count) {
        max_offset = section->entry_count - visible_count;
    }
    if(app->item_offset > max_offset) {
        app->item_offset = max_offset;
    }
    if(app->item_index < app->item_offset) {
        app->item_offset = app->item_index;
    } else if(app->item_index >= app->item_offset + visible_count) {
        app->item_offset = app->item_index - visible_count + 1;
    }

    for(uint32_t i = 0; i < visible_count; i++) {
        uint32_t idx = app->item_offset + i;
        if(idx >= section->entry_count) break;
        uint8_t y = MENU_ITEM_BASE_Y + i * MENU_ITEM_SPACING;

        if(idx == app->item_index) {
            canvas_draw_str(canvas, 2, y, ">");
            canvas_draw_str(canvas, 12, y, section->entries[idx].label);
        } else {
            canvas_draw_str(canvas, 8, y, section->entries[idx].label);
        }
    }

    if(section->entry_count > visible_count) {
        const uint8_t track_width = 3;
        uint8_t track_height = section->display_height ? section->display_height : (uint8_t)(visible_count * MENU_ITEM_SPACING);
        const uint8_t track_x = DISPLAY_WIDTH - track_width;
        const uint8_t track_y = MENU_SCROLL_TRACK_Y;
        canvas_draw_frame(canvas, track_x, track_y, track_width, track_height);
        uint8_t thumb_height =
            (uint8_t)(((uint32_t)visible_count * track_height) / section->entry_count);
        if(thumb_height < 4) thumb_height = 4;
        if(thumb_height > track_height) thumb_height = track_height;
        uint8_t max_thumb_offset =
            (track_height > thumb_height) ? (uint8_t)(track_height - thumb_height) : 0;
        uint8_t thumb_offset = 0;
        if(max_offset > 0 && max_thumb_offset > 0) {
            thumb_offset = (uint8_t)(((uint32_t)app->item_offset * max_thumb_offset) / max_offset);
        }
        uint8_t thumb_x = (track_width > 2) ? (track_x + 1) : track_x;
        uint8_t thumb_y = track_y + 1 + thumb_offset;
        uint8_t thumb_width = (track_width > 2) ? (uint8_t)(track_width - 2) : 1;
        if(track_width > 2) {
            uint8_t draw_height = thumb_height;
            uint8_t draw_y = thumb_y;
            if(draw_height > 2) {
                draw_height = (uint8_t)(draw_height - 2);
                draw_y = thumb_y;
            }
            if(draw_height == 0) draw_height = 1;
            canvas_draw_box(canvas, thumb_x, draw_y, thumb_width, draw_height);
        } else {
            canvas_draw_box(canvas, thumb_x, thumb_y, thumb_width, thumb_height);
        }
    }
}

static size_t simple_app_render_display_lines(SimpleApp* app, size_t skip_lines, char dest[][64], size_t max_lines) {
    memset(dest, 0, max_lines * 64);
    if(!app->serial_mutex) return 0;

    furi_mutex_acquire(app->serial_mutex, FuriWaitForever);
    const char* buffer = app->serial_buffer;
    size_t length = app->serial_len;
    size_t line_index = 0;
    size_t col = 0;
    size_t lines_filled = 0;

    for(size_t idx = 0; idx < length; idx++) {
        char ch = buffer[idx];
        if(ch == '\r') continue;

        if(ch == '\n') {
            if(line_index >= skip_lines && lines_filled < max_lines) {
                dest[lines_filled][col] = '\0';
                lines_filled++;
            }
            line_index++;
            col = 0;
            if(line_index >= skip_lines + max_lines) break;
            continue;
        }

        if(col >= SERIAL_LINE_CHAR_LIMIT) {
            if(line_index >= skip_lines && lines_filled < max_lines) {
                dest[lines_filled][col] = '\0';
                lines_filled++;
            }
            line_index++;
            col = 0;
            if(line_index >= skip_lines + max_lines) {
                continue;
            }
        }

        if(line_index >= skip_lines && lines_filled < max_lines) {
            dest[lines_filled][col] = ch;
        }
        col++;
    }

    if(col > 0) {
        if(line_index >= skip_lines && lines_filled < max_lines) {
            dest[lines_filled][col] = '\0';
            lines_filled++;
        }
    }

    furi_mutex_release(app->serial_mutex);
    return lines_filled;
}

static void simple_app_draw_serial(SimpleApp* app, Canvas* canvas) {
    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontSecondary);
    char display_lines[SERIAL_VISIBLE_LINES][64];
    size_t lines_filled =
        simple_app_render_display_lines(app, app->serial_scroll, display_lines, SERIAL_VISIBLE_LINES);

    uint8_t y = 8;
    if(lines_filled == 0) {
        canvas_draw_str(canvas, 2, y, "No UART data");
    } else {
        for(size_t i = 0; i < lines_filled; i++) {
            canvas_draw_str(canvas, 2, y, display_lines[i][0] ? display_lines[i] : " ");
            y += SERIAL_TEXT_LINE_HEIGHT;
        }
    }

    size_t total_lines = simple_app_total_display_lines(app);
    if(total_lines > SERIAL_VISIBLE_LINES) {
        const uint8_t track_width = 3;
        const uint8_t track_x = DISPLAY_WIDTH - track_width;
        const uint8_t track_y = 4;
        const uint8_t track_height = 56;

        canvas_draw_frame(canvas, track_x, track_y, track_width, track_height);
        canvas_draw_box(canvas, track_x + 1, track_y + 1, 1, 1);
        canvas_draw_box(canvas, track_x + 1, track_y + track_height - 2, 1, 1);

        size_t max_scroll = simple_app_max_scroll(app);
        uint8_t thumb_height =
            (uint8_t)(((uint32_t)SERIAL_VISIBLE_LINES * track_height) / total_lines);
        if(thumb_height < 4) thumb_height = 4;
        if(thumb_height > track_height) thumb_height = track_height;

        uint8_t thumb_track_top = track_y;
        uint8_t thumb_track_height = track_height;
        uint8_t thumb_width = (track_width > 2) ? (track_width - 2) : 1;
        uint8_t thumb_x = (track_width > 2) ? (track_x + 1) : track_x;

        if(track_width > 2 && track_height > 2) {
            thumb_track_top = track_y + 1;
            thumb_track_height = track_height - 2;
        }

        if(thumb_height > thumb_track_height) {
            thumb_height = thumb_track_height;
        }

        uint8_t max_thumb_offset =
            (thumb_track_height > thumb_height) ? (thumb_track_height - thumb_height) : 0;
        uint8_t thumb_offset = 0;
        if(max_scroll > 0 && max_thumb_offset > 0) {
            thumb_offset = (uint8_t)(((uint32_t)app->serial_scroll * max_thumb_offset) / max_scroll);
        }

        uint8_t thumb_y = thumb_track_top + thumb_offset;
        canvas_draw_box(canvas, thumb_x, thumb_y, thumb_width, thumb_height);
    }

    if(app->serial_targets_hint) {
        canvas_draw_str(canvas, DISPLAY_WIDTH - 14, 62, "->");
    }
}

static void simple_app_draw_results(SimpleApp* app, Canvas* canvas) {
    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, app->result_font);

    if(app->scan_results_loading && app->visible_result_count == 0) {
        canvas_draw_str(canvas, 2, 20, "Loading...");
        canvas_draw_str(canvas, 2, 62, "[Results] Selected: 0");
        return;
    }

    if(app->visible_result_count == 0) {
        canvas_draw_str(canvas, 2, 20, "No results");
        canvas_draw_str(canvas, 2, 62, "[Results] Selected: 0");
        return;
    }

    simple_app_adjust_result_offset(app);

    uint8_t y = RESULT_START_Y;
    size_t visible_line_budget = (app->result_max_lines > 0) ? app->result_max_lines : 1;
    size_t lines_left = visible_line_budget;
    size_t entry_line_capacity =
        (app->result_max_lines > 0) ? app->result_max_lines : RESULT_DEFAULT_MAX_LINES;
    if(entry_line_capacity == 0) entry_line_capacity = RESULT_DEFAULT_MAX_LINES;
    if(entry_line_capacity > RESULT_DEFAULT_MAX_LINES) {
        entry_line_capacity = RESULT_DEFAULT_MAX_LINES;
    }

    for(size_t idx = app->scan_result_offset; idx < app->visible_result_count && lines_left > 0; idx++) {
        const ScanResult* result = simple_app_visible_result_const(app, idx);
        if(!result) continue;

        char segments[RESULT_DEFAULT_MAX_LINES][64];
        memset(segments, 0, sizeof(segments));
        size_t segments_available =
            simple_app_build_result_lines(app, result, segments, entry_line_capacity);
        if(segments_available == 0) {
            strncpy(segments[0], "-", sizeof(segments[0]) - 1);
            segments[0][sizeof(segments[0]) - 1] = '\0';
            segments_available = 1;
        }
        if(segments_available > lines_left) {
            segments_available = lines_left;
        }

        for(size_t segment = 0; segment < segments_available && lines_left > 0; segment++) {
            if(segment == 0) {
                if(idx == app->scan_result_index) {
                    canvas_draw_str(canvas, RESULT_PREFIX_X, y, ">");
                } else {
                    canvas_draw_str(canvas, RESULT_PREFIX_X, y, " ");
                }
            }
            canvas_draw_str(canvas, RESULT_TEXT_X, y, segments[segment]);
            y += app->result_line_height;
            lines_left--;
            if(lines_left == 0) break;
        }

        if(lines_left > 0) {
            bool more_entries = false;
            for(size_t next = idx + 1; next < app->visible_result_count; next++) {
                const ScanResult* next_result = simple_app_visible_result_const(app, next);
                if(!next_result) continue;
                uint8_t next_lines = simple_app_result_line_count(app, next_result);
                if(next_lines == 0) next_lines = 1;
                if(next_lines <= lines_left) {
                    more_entries = true;
                    break;
                }
            }
            if(more_entries) {
                y += RESULT_ENTRY_SPACING;
            }
        }
    }

    size_t total_lines = simple_app_total_result_lines(app);
    size_t offset_lines = simple_app_result_offset_lines(app);
    if(total_lines > visible_line_budget) {
        const uint8_t track_width = RESULT_SCROLL_WIDTH;
        const uint8_t track_height = (uint8_t)(app->result_line_height * visible_line_budget);
        const uint8_t track_x = DISPLAY_WIDTH - track_width;
        const uint8_t track_y = (RESULT_START_Y > 5) ? (RESULT_START_Y - 5) : 0;

        canvas_draw_frame(canvas, track_x, track_y, track_width, track_height);

        size_t max_scroll = total_lines - visible_line_budget;
        uint8_t thumb_height =
            (uint8_t)(((uint32_t)visible_line_budget * track_height) / total_lines);
        if(thumb_height < 4) thumb_height = 4;
        if(thumb_height > track_height) thumb_height = track_height;

        uint8_t max_thumb_offset =
            (track_height > thumb_height) ? (uint8_t)(track_height - thumb_height) : 0;
        uint8_t thumb_offset = 0;
        if(max_scroll > 0 && max_thumb_offset > 0) {
            if(offset_lines > max_scroll) offset_lines = max_scroll;
            thumb_offset = (uint8_t)(((uint32_t)offset_lines * max_thumb_offset) / max_scroll);
        }

        uint8_t thumb_x = track_x + 1;
        uint8_t thumb_y = track_y + 1 + thumb_offset;
        uint8_t thumb_inner_height = (thumb_height > 2) ? (uint8_t)(thumb_height - 2) : thumb_height;
        uint8_t thumb_width = (track_width > 2) ? (uint8_t)(track_width - 2) : 1;
        if(thumb_inner_height == 0) thumb_inner_height = thumb_height;
        canvas_draw_box(canvas, thumb_x, thumb_y, thumb_width, thumb_inner_height);
    }

    char footer[48];
    snprintf(footer, sizeof(footer), "[Results] Selected: %u", (unsigned)app->scan_selected_count);
    simple_app_truncate_text(footer, SERIAL_LINE_CHAR_LIMIT);
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str(canvas, 2, 62, footer);
    if(app->scan_selected_count > 0) {
        canvas_draw_str(canvas, DISPLAY_WIDTH - 10, 62, "->");
    }
}

static void simple_app_draw_setup_scanner(SimpleApp* app, Canvas* canvas) {
    if(!app) return;

    static const char* option_labels[] = {"SSID", "BSSID", "Channel", "Security", "Power", "Band"};

    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 4, 12, "Scanner Filters");

    canvas_set_font(canvas, FontSecondary);
    size_t option_count = ScannerOptionCount;
    if(app->scanner_view_offset >= option_count) {
        app->scanner_view_offset = (option_count > 0 && option_count > SCANNER_FILTER_VISIBLE_COUNT)
                                       ? option_count - SCANNER_FILTER_VISIBLE_COUNT
                                       : 0;
    }

    uint8_t y = 26;
    for(size_t i = 0; i < SCANNER_FILTER_VISIBLE_COUNT; i++) {
        size_t option_index = app->scanner_view_offset + i;
        if(option_index >= option_count) break;

        char line[48];
        memset(line, 0, sizeof(line));

        if(option_index == ScannerOptionMinPower) {
            const char* fmt =
                (app->scanner_adjusting_power && app->scanner_setup_index == ScannerOptionMinPower)
                    ? "Min power*: %d dBm"
                    : "Min power: %d dBm";
            snprintf(line, sizeof(line), fmt, (int)app->scanner_min_power);
        } else {
            bool enabled = false;
            switch(option_index) {
            case ScannerOptionShowSSID:
                enabled = app->scanner_show_ssid;
                break;
            case ScannerOptionShowBSSID:
                enabled = app->scanner_show_bssid;
                break;
            case ScannerOptionShowChannel:
                enabled = app->scanner_show_channel;
                break;
            case ScannerOptionShowSecurity:
                enabled = app->scanner_show_security;
                break;
            case ScannerOptionShowPower:
                enabled = app->scanner_show_power;
                break;
            case ScannerOptionShowBand:
                enabled = app->scanner_show_band;
                break;
            default:
                break;
            }
            snprintf(line, sizeof(line), "[%c] %s", enabled ? 'x' : ' ', option_labels[option_index]);
        }

        simple_app_truncate_text(line, 20);

        if(app->scanner_setup_index == option_index) {
            canvas_draw_str(canvas, 2, y, ">");
        }
        canvas_draw_str(canvas, 12, y, line);
        y += 10;
    }

    if(option_count > SCANNER_FILTER_VISIBLE_COUNT) {
        const uint8_t track_width = 3;
        const uint8_t track_height = (uint8_t)(SCANNER_FILTER_VISIBLE_COUNT * 10);
        const uint8_t track_x = DISPLAY_WIDTH - track_width;
        const uint8_t track_y = 24;

        canvas_draw_frame(canvas, track_x, track_y, track_width, track_height);

        size_t max_offset = option_count - SCANNER_FILTER_VISIBLE_COUNT;
        uint8_t thumb_height =
            (uint8_t)(((uint32_t)SCANNER_FILTER_VISIBLE_COUNT * track_height) / option_count);
        if(thumb_height < 4) thumb_height = 4;
        if(thumb_height > track_height) thumb_height = track_height;

        uint8_t max_thumb_offset =
            (track_height > thumb_height) ? (uint8_t)(track_height - thumb_height) : 0;
        uint8_t thumb_offset = 0;
        if(max_offset > 0 && max_thumb_offset > 0) {
            if(app->scanner_view_offset > max_offset) {
                app->scanner_view_offset = max_offset;
            }
            thumb_offset =
                (uint8_t)(((uint32_t)app->scanner_view_offset * max_thumb_offset) / max_offset);
        }
        uint8_t thumb_x = track_x + 1;
        uint8_t thumb_y = track_y + 1 + thumb_offset;
        uint8_t thumb_inner_height = (thumb_height > 2) ? (uint8_t)(thumb_height - 2) : thumb_height;
        if(thumb_inner_height == 0) thumb_inner_height = thumb_height;
        uint8_t thumb_width = (track_width > 2) ? (uint8_t)(track_width - 2) : 1;
        canvas_draw_box(canvas, thumb_x, thumb_y, thumb_width, thumb_inner_height);
    }

    const char* footer = "OK toggle, Back exit";
    if(app->scanner_setup_index == ScannerOptionMinPower) {
        footer = app->scanner_adjusting_power ? "Up/Down adjust, OK" : "OK edit, Back exit";
    }
    canvas_draw_str(canvas, 2, 62, footer);
}

static void simple_app_draw(Canvas* canvas, void* context) {
    SimpleApp* app = context;
    canvas_clear(canvas);
    bool status_active = simple_app_status_message_is_active(app);
    if(status_active && app->status_message_fullscreen) {
        canvas_set_color(canvas, ColorBlack);
        canvas_set_font(canvas, FontPrimary);
        const char* message = app->status_message;
        size_t line_count = 1;
        for(const char* ptr = message; *ptr; ptr++) {
            if(*ptr == '\n') {
                line_count++;
            }
        }
        const uint8_t line_height = 16;
        int16_t first_line_y = 32;
        if(line_count > 1) {
            first_line_y -= (int16_t)((line_count - 1) * line_height) / 2;
        }
        const char* line_ptr = message;
        char line_buffer[64];
        for(size_t line_index = 0; line_index < line_count; line_index++) {
            const char* next_break = strchr(line_ptr, '\n');
            size_t line_length = next_break ? (size_t)(next_break - line_ptr) : strlen(line_ptr);
            if(line_length >= sizeof(line_buffer)) {
                line_length = sizeof(line_buffer) - 1;
            }
            memcpy(line_buffer, line_ptr, line_length);
            line_buffer[line_length] = '\0';
            canvas_draw_str_aligned(
                canvas,
                DISPLAY_WIDTH / 2,
                first_line_y + (int16_t)(line_index * line_height),
                AlignCenter,
                AlignCenter,
                line_buffer);
            if(!next_break) break;
            line_ptr = next_break + 1;
        }
        return;
    }
    switch(app->screen) {
    case ScreenMenu:
        simple_app_draw_menu(app, canvas);
        break;
    case ScreenSerial:
        simple_app_draw_serial(app, canvas);
        break;
    case ScreenResults:
        simple_app_draw_results(app, canvas);
        break;
    case ScreenSetupScanner:
        simple_app_draw_setup_scanner(app, canvas);
        break;
    case ScreenConsole:
        simple_app_draw_console(app, canvas);
        break;
    case ScreenConfirmBlackout:
        simple_app_draw_confirm_blackout(app, canvas);
        break;
    case ScreenConfirmSnifferDos:
        simple_app_draw_confirm_sniffer_dos(app, canvas);
        break;
    case ScreenEvilTwinMenu:
        simple_app_draw_evil_twin_menu(app, canvas);
        break;
    default:
        simple_app_draw_results(app, canvas);
        break;
    }

    if(app->evil_twin_popup_active) {
        simple_app_draw_evil_twin_popup(app, canvas);
    } else if(app->hint_active) {
        simple_app_draw_hint(app, canvas);
    }
}

static void simple_app_handle_menu_input(SimpleApp* app, InputKey key) {
    if(key == InputKeyUp) {
        if(app->menu_state == MenuStateSections) {
            if(app->section_index > 0) {
                app->section_index--;
                view_port_update(app->viewport);
            }
        } else {
            const MenuSection* section = &menu_sections[app->section_index];
            if(section->entry_count == 0) return;
            if(app->item_index > 0) {
                app->item_index--;
                if(app->section_index == MENU_SECTION_ATTACKS) {
                    app->last_attack_index = app->item_index;
                }
                if(app->item_index < app->item_offset) {
                    app->item_offset = app->item_index;
                }
                view_port_update(app->viewport);
            }
        }
    } else if(key == InputKeyDown) {
        if(app->menu_state == MenuStateSections) {
            if(app->section_index + 1 < menu_section_count) {
                app->section_index++;
                view_port_update(app->viewport);
            }
        } else {
            const MenuSection* section = &menu_sections[app->section_index];
            if(section->entry_count == 0) return;
            if(app->item_index + 1 < section->entry_count) {
                app->item_index++;
                if(app->section_index == MENU_SECTION_ATTACKS) {
                    app->last_attack_index = app->item_index;
                }
                size_t visible_count = simple_app_menu_visible_count(app, app->section_index);
                if(visible_count == 0) visible_count = 1;
                if(app->item_index >= app->item_offset + visible_count) {
                    app->item_offset = app->item_index - visible_count + 1;
                }
                view_port_update(app->viewport);
            }
        }
    } else if(key == InputKeyOk) {
        if(app->menu_state == MenuStateSections) {
            if(app->section_index == MENU_SECTION_SCANNER) {
                simple_app_send_command(app, SCANNER_SCAN_COMMAND, true);
                view_port_update(app->viewport);
                return;
            } else if(app->section_index == MENU_SECTION_TARGETS) {
                simple_app_request_scan_results(app, TARGETS_RESULTS_COMMAND);
                return;
            }
            app->menu_state = MenuStateItems;
            if(app->section_index == MENU_SECTION_ATTACKS) {
                simple_app_focus_attacks_menu(app);
                app->last_attack_index = app->item_index;
                view_port_update(app->viewport);
                return;
            }
            app->item_index = 0;
            app->item_offset = 0;
            size_t visible_count = simple_app_menu_visible_count(app, app->section_index);
            if(visible_count == 0) visible_count = 1;
            if(menu_sections[app->section_index].entry_count > visible_count) {
                size_t max_offset = menu_sections[app->section_index].entry_count - visible_count;
                if(app->item_offset > max_offset) {
                    app->item_offset = max_offset;
                }
            }
            view_port_update(app->viewport);
            return;
        }

        const MenuSection* section = &menu_sections[app->section_index];
        if(section->entry_count == 0) return;
        if(app->item_index >= section->entry_count) {
            app->item_index = section->entry_count - 1;
        }
        if(app->section_index == MENU_SECTION_ATTACKS) {
            app->last_attack_index = app->item_index;
        }

        const MenuEntry* entry = &section->entries[app->item_index];
        if(entry->action == MenuActionResults) {
            simple_app_request_scan_results(app, entry->command);
        } else if(entry->action == MenuActionCommandWithTargets) {
            simple_app_send_command_with_targets(app, entry->command);
        } else if(entry->action == MenuActionCommand) {
            if(entry->command && entry->command[0] != '\0') {
                simple_app_send_command(app, entry->command, true);
            }
        } else if(entry->action == MenuActionOpenEvilTwinMenu) {
            app->screen = ScreenEvilTwinMenu;
            app->evil_twin_menu_index = 0;
            view_port_update(app->viewport);
        } else if(entry->action == MenuActionToggleBacklight) {
            simple_app_toggle_backlight(app);
        } else if(entry->action == MenuActionToggleOtgPower) {
            simple_app_toggle_otg_power(app);
        } else if(entry->action == MenuActionOpenScannerSetup) {
            app->screen = ScreenSetupScanner;
            app->scanner_setup_index = 0;
            app->scanner_adjusting_power = false;
            app->scanner_view_offset = 0;
        } else if(entry->action == MenuActionOpenConsole) {
            simple_app_console_enter(app);
        } else if(entry->action == MenuActionConfirmBlackout) {
            app->confirm_blackout_yes = false;
            app->screen = ScreenConfirmBlackout;
        } else if(entry->action == MenuActionConfirmSnifferDos) {
            app->confirm_sniffer_dos_yes = false;
            app->screen = ScreenConfirmSnifferDos;
        }

        view_port_update(app->viewport);
    } else if(key == InputKeyBack) {
        simple_app_send_stop_if_needed(app);
        if(app->menu_state == MenuStateItems) {
            app->menu_state = MenuStateSections;
            view_port_update(app->viewport);
        } else {
            simple_app_save_config_if_dirty(app, NULL, false);
            app->exit_app = true;
        }
    }
}

static void simple_app_handle_evil_twin_menu_input(SimpleApp* app, InputKey key) {
    if(!app) return;

    if(key == InputKeyBack || key == InputKeyLeft) {
        if(app->evil_twin_listing_active) {
            simple_app_send_stop_if_needed(app);
            simple_app_reset_evil_twin_listing(app);
            simple_app_clear_status_message(app);
        }
        simple_app_close_evil_twin_popup(app);
        simple_app_focus_attacks_menu(app);
        if(app->viewport) {
            view_port_update(app->viewport);
        }
        return;
    }

    if(key == InputKeyUp) {
        if(app->evil_twin_menu_index > 0) {
            app->evil_twin_menu_index--;
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
    } else if(key == InputKeyDown) {
        if(app->evil_twin_menu_index + 1 < EVIL_TWIN_MENU_OPTION_COUNT) {
            app->evil_twin_menu_index++;
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
    } else if(key == InputKeyOk) {
        if(app->evil_twin_menu_index == 0) {
            if(app->evil_twin_listing_active) {
                simple_app_show_status_message(app, "Listing already\nin progress", 1200, true);
                return;
            }
            simple_app_request_evil_twin_html_list(app);
        } else {
            simple_app_start_evil_portal(app);
        }
    }
}

static void simple_app_request_evil_twin_html_list(SimpleApp* app) {
    if(!app) return;
    simple_app_close_evil_twin_popup(app);
    simple_app_reset_evil_twin_listing(app);
    app->evil_twin_listing_active = true;
    simple_app_show_status_message(app, "Listing HTML...", 0, false);
    simple_app_send_command(app, "list_sd", true);
}

static void simple_app_start_evil_portal(SimpleApp* app) {
    if(!app) return;
    if(app->evil_twin_listing_active) {
        simple_app_show_status_message(app, "Wait for list\ncompletion", 1200, true);
        return;
    }
    if(app->evil_twin_selected_html_id == 0) {
        simple_app_show_status_message(app, "Select HTML file\nbefore starting", 1500, true);
        return;
    }
    char select_command[48];
    snprintf(
        select_command,
        sizeof(select_command),
        "select_html %u",
        (unsigned)app->evil_twin_selected_html_id);
    simple_app_send_command(app, select_command, false);
    app->last_command_sent = false;
    simple_app_send_command_with_targets(app, "start_evil_twin");
    if(app->viewport) {
        view_port_update(app->viewport);
    }
}

static void simple_app_close_evil_twin_popup(SimpleApp* app) {
    if(!app) return;
    app->evil_twin_popup_active = false;
}

static void simple_app_reset_evil_twin_listing(SimpleApp* app) {
    if(!app) return;
    app->evil_twin_listing_active = false;
    app->evil_twin_list_header_seen = false;
    app->evil_twin_list_length = 0;
    app->evil_twin_html_count = 0;
    app->evil_twin_html_popup_index = 0;
    app->evil_twin_html_popup_offset = 0;
}

static void simple_app_finish_evil_twin_listing(SimpleApp* app) {
    if(!app || !app->evil_twin_listing_active) return;
    app->evil_twin_listing_active = false;
    app->evil_twin_list_length = 0;
    app->evil_twin_list_header_seen = false;
    app->evil_twin_popup_active = false;
    app->last_command_sent = false;
    app->screen = ScreenEvilTwinMenu;
    simple_app_clear_status_message(app);

    if(app->evil_twin_html_count == 0) {
        simple_app_show_status_message(app, "No HTML files\nfound on SD", 1500, true);
        return;
    }

    size_t target_index = 0;
    if(app->evil_twin_selected_html_id != 0) {
        for(size_t i = 0; i < app->evil_twin_html_count; i++) {
            if(app->evil_twin_html_entries[i].id == app->evil_twin_selected_html_id) {
                target_index = i;
                break;
            }
        }
        if(target_index >= app->evil_twin_html_count) {
            target_index = 0;
        }
    }

    app->evil_twin_html_popup_index = target_index;
    size_t visible = (app->evil_twin_html_count > EVIL_TWIN_POPUP_VISIBLE_LINES)
                         ? EVIL_TWIN_POPUP_VISIBLE_LINES
                         : app->evil_twin_html_count;
    if(visible == 0) visible = 1;
    if(app->evil_twin_html_count <= visible ||
       app->evil_twin_html_popup_index < visible) {
        app->evil_twin_html_popup_offset = 0;
    } else {
        app->evil_twin_html_popup_offset =
            app->evil_twin_html_popup_index - visible + 1;
    }
    size_t max_offset =
        (app->evil_twin_html_count > visible) ? (app->evil_twin_html_count - visible) : 0;
    if(app->evil_twin_html_popup_offset > max_offset) {
        app->evil_twin_html_popup_offset = max_offset;
    }

    app->evil_twin_popup_active = true;
    if(app->viewport) {
        view_port_update(app->viewport);
    }
}

static void simple_app_process_evil_twin_line(SimpleApp* app, const char* line) {
    if(!app || !line || !app->evil_twin_listing_active) return;

    const char* cursor = line;
    while(*cursor == ' ' || *cursor == '\t') {
        cursor++;
    }
    if(*cursor == '\0') {
        if(app->evil_twin_html_count > 0) {
            simple_app_finish_evil_twin_listing(app);
        }
        return;
    }

    if(strncmp(cursor, "HTML files", 10) == 0) {
        app->evil_twin_list_header_seen = true;
        return;
    }

    if(strncmp(cursor, "No HTML", 7) == 0 || strncmp(cursor, "No html", 7) == 0) {
        app->evil_twin_html_count = 0;
        simple_app_finish_evil_twin_listing(app);
        return;
    }

    if(!isdigit((unsigned char)cursor[0])) {
        if(app->evil_twin_html_count > 0) {
            simple_app_finish_evil_twin_listing(app);
        }
        return;
    }

    char* endptr = NULL;
    long id = strtol(cursor, &endptr, 10);
    if(id <= 0 || id > 255 || !endptr) {
        return;
    }
    while(*endptr == ' ' || *endptr == '\t') {
        endptr++;
    }
    if(*endptr == '\0') {
        return;
    }

    if(app->evil_twin_html_count >= EVIL_TWIN_MAX_HTML_FILES) {
        return;
    }

    EvilTwinHtmlEntry* entry = &app->evil_twin_html_entries[app->evil_twin_html_count++];
    entry->id = (uint8_t)id;
    strncpy(entry->name, endptr, EVIL_TWIN_HTML_NAME_MAX - 1);
    entry->name[EVIL_TWIN_HTML_NAME_MAX - 1] = '\0';
    app->evil_twin_list_header_seen = true;

    size_t len = strlen(entry->name);
    while(len > 0 &&
          (entry->name[len - 1] == '\r' || entry->name[len - 1] == '\n' ||
           entry->name[len - 1] == ' ')) {
        entry->name[--len] = '\0';
    }
}

static void simple_app_evil_twin_feed(SimpleApp* app, char ch) {
    if(!app || !app->evil_twin_listing_active) return;
    if(ch == '\r') return;

    if(ch == '>') {
        if(app->evil_twin_list_length > 0) {
            app->evil_twin_list_buffer[app->evil_twin_list_length] = '\0';
            simple_app_process_evil_twin_line(app, app->evil_twin_list_buffer);
            app->evil_twin_list_length = 0;
        }
        if(app->evil_twin_html_count > 0 || app->evil_twin_list_header_seen) {
            simple_app_finish_evil_twin_listing(app);
        }
        return;
    }

    if(ch == '\n') {
        if(app->evil_twin_list_length > 0) {
            app->evil_twin_list_buffer[app->evil_twin_list_length] = '\0';
            simple_app_process_evil_twin_line(app, app->evil_twin_list_buffer);
        } else if(app->evil_twin_list_header_seen) {
            simple_app_finish_evil_twin_listing(app);
        }
        app->evil_twin_list_length = 0;
        return;
    }

    if(app->evil_twin_list_length + 1 >= sizeof(app->evil_twin_list_buffer)) {
        app->evil_twin_list_length = 0;
        return;
    }

    app->evil_twin_list_buffer[app->evil_twin_list_length++] = ch;
}

static void simple_app_handle_evil_twin_popup_event(SimpleApp* app, const InputEvent* event) {
    if(!app || !event || !app->evil_twin_popup_active) return;

    if(event->type != InputTypeShort && event->type != InputTypeRepeat) return;

    InputKey key = event->key;
    if(event->type == InputTypeShort && key == InputKeyBack) {
        simple_app_close_evil_twin_popup(app);
        if(app->viewport) {
            view_port_update(app->viewport);
        }
        return;
    }

    if(app->evil_twin_html_count == 0) {
        if(event->type == InputTypeShort && key == InputKeyOk) {
            simple_app_close_evil_twin_popup(app);
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
        return;
    }

    size_t visible = (app->evil_twin_html_count > EVIL_TWIN_POPUP_VISIBLE_LINES)
                         ? EVIL_TWIN_POPUP_VISIBLE_LINES
                         : app->evil_twin_html_count;
    if(visible == 0) visible = 1;

    if(key == InputKeyUp) {
        if(app->evil_twin_html_popup_index > 0) {
            app->evil_twin_html_popup_index--;
            if(app->evil_twin_html_popup_index < app->evil_twin_html_popup_offset) {
                app->evil_twin_html_popup_offset = app->evil_twin_html_popup_index;
            }
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
    } else if(key == InputKeyDown) {
        if(app->evil_twin_html_popup_index + 1 < app->evil_twin_html_count) {
            app->evil_twin_html_popup_index++;
            if(app->evil_twin_html_count > visible &&
               app->evil_twin_html_popup_index >=
                   app->evil_twin_html_popup_offset + visible) {
                app->evil_twin_html_popup_offset =
                    app->evil_twin_html_popup_index - visible + 1;
            }
            size_t max_offset =
                (app->evil_twin_html_count > visible) ? (app->evil_twin_html_count - visible) : 0;
            if(app->evil_twin_html_popup_offset > max_offset) {
                app->evil_twin_html_popup_offset = max_offset;
            }
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
    } else if(event->type == InputTypeShort && key == InputKeyOk) {
        if(app->evil_twin_html_popup_index < app->evil_twin_html_count) {
            const EvilTwinHtmlEntry* entry =
                &app->evil_twin_html_entries[app->evil_twin_html_popup_index];
            app->evil_twin_selected_html_id = entry->id;
            strncpy(
                app->evil_twin_selected_html_name,
                entry->name,
                EVIL_TWIN_HTML_NAME_MAX - 1);
            app->evil_twin_selected_html_name[EVIL_TWIN_HTML_NAME_MAX - 1] = '\0';

            char command[48];
            snprintf(command, sizeof(command), "select_html %u", (unsigned)entry->id);
            simple_app_send_command(app, command, false);
            app->last_command_sent = false;

            char message[64];
            snprintf(message, sizeof(message), "HTML set:\n%s", entry->name);
            simple_app_show_status_message(app, message, 1500, true);

            simple_app_close_evil_twin_popup(app);
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
    }
}

static void simple_app_handle_setup_scanner_input(SimpleApp* app, InputKey key) {
    if(!app) return;

    if(key == InputKeyBack) {
        simple_app_send_stop_if_needed(app);
        if(app->scanner_adjusting_power) {
            app->scanner_adjusting_power = false;
            view_port_update(app->viewport);
        } else {
            simple_app_save_config_if_dirty(app, "Config saved", true);
            app->screen = ScreenMenu;
            view_port_update(app->viewport);
        }
        return;
    }

    if(app->scanner_adjusting_power && app->scanner_setup_index == ScannerOptionMinPower) {
        if(key == InputKeyUp || key == InputKeyRight) {
            simple_app_modify_min_power(app, SCAN_POWER_STEP);
            view_port_update(app->viewport);
            return;
        } else if(key == InputKeyDown || key == InputKeyLeft) {
            simple_app_modify_min_power(app, -SCAN_POWER_STEP);
            view_port_update(app->viewport);
            return;
        }
    }

    if(key == InputKeyUp) {
        if(app->scanner_setup_index > 0) {
            app->scanner_setup_index--;
            if(app->scanner_setup_index != ScannerOptionMinPower) {
                app->scanner_adjusting_power = false;
            }
            if(app->scanner_setup_index < app->scanner_view_offset) {
                app->scanner_view_offset = app->scanner_setup_index;
            }
            view_port_update(app->viewport);
        }
    } else if(key == InputKeyDown) {
        if(app->scanner_setup_index + 1 < ScannerOptionCount) {
            app->scanner_setup_index++;
            if(app->scanner_setup_index != ScannerOptionMinPower) {
                app->scanner_adjusting_power = false;
            }
            if(app->scanner_setup_index >=
               app->scanner_view_offset + SCANNER_FILTER_VISIBLE_COUNT) {
                app->scanner_view_offset =
                    app->scanner_setup_index - SCANNER_FILTER_VISIBLE_COUNT + 1;
            }
            view_port_update(app->viewport);
        }
    } else if(key == InputKeyOk) {
        if(app->scanner_setup_index == ScannerOptionMinPower) {
            app->scanner_adjusting_power = !app->scanner_adjusting_power;
            view_port_update(app->viewport);
        } else {
            bool* flag =
                simple_app_scanner_option_flag(app, (ScannerOption)app->scanner_setup_index);
            if(flag) {
                if(*flag && simple_app_enabled_field_count(app) <= 1) {
                    view_port_update(app->viewport);
                } else {
                    *flag = !(*flag);
                    simple_app_mark_config_dirty(app);
                    simple_app_update_result_layout(app);
                    simple_app_rebuild_visible_results(app);
                    simple_app_adjust_result_offset(app);
                    view_port_update(app->viewport);
                }
            }
        }
    }
}

static void simple_app_handle_serial_input(SimpleApp* app, InputKey key) {
    if(key == InputKeyBack) {
        simple_app_send_stop_if_needed(app);
        app->serial_targets_hint = false;
        app->screen = ScreenMenu;
        app->serial_follow_tail = true;
        simple_app_update_scroll(app);
        view_port_update(app->viewport);
    } else if(key == InputKeyUp) {
        if(app->serial_scroll > 0) {
            app->serial_scroll--;
            app->serial_follow_tail = false;
            view_port_update(app->viewport);
        }
    } else if(key == InputKeyDown) {
        size_t max_scroll = simple_app_max_scroll(app);
        if(app->serial_scroll < max_scroll) {
            app->serial_scroll++;
            app->serial_follow_tail = (app->serial_scroll == max_scroll);
            view_port_update(app->viewport);
        } else {
            app->serial_follow_tail = true;
            simple_app_update_scroll(app);
            view_port_update(app->viewport);
        }
    } else if(key == InputKeyLeft) {
        size_t step = SERIAL_VISIBLE_LINES;
        if(app->serial_scroll > 0) {
            if(app->serial_scroll > step) {
                app->serial_scroll -= step;
            } else {
                app->serial_scroll = 0;
            }
            app->serial_follow_tail = false;
            view_port_update(app->viewport);
        }
    } else if(key == InputKeyRight) {
        if(app->serial_targets_hint) {
            app->serial_targets_hint = false;
            simple_app_request_scan_results(app, TARGETS_RESULTS_COMMAND);
            return;
        }

        size_t step = SERIAL_VISIBLE_LINES;
        size_t max_scroll = simple_app_max_scroll(app);
        if(app->serial_scroll < max_scroll) {
            app->serial_scroll =
                (app->serial_scroll + step < max_scroll) ? app->serial_scroll + step : max_scroll;
            app->serial_follow_tail = (app->serial_scroll == max_scroll);
            view_port_update(app->viewport);
        } else {
            app->serial_follow_tail = true;
            simple_app_update_scroll(app);
            view_port_update(app->viewport);
        }
    } else if(key == InputKeyOk) {
        app->serial_follow_tail = true;
        simple_app_update_scroll(app);
        view_port_update(app->viewport);
    }
}

static void simple_app_handle_results_input(SimpleApp* app, InputKey key) {
    if(key == InputKeyBack || key == InputKeyLeft) {
        simple_app_send_stop_if_needed(app);
        app->screen = ScreenMenu;
        view_port_update(app->viewport);
        return;
    }

    if(app->visible_result_count == 0) return;

    if(key == InputKeyUp) {
        if(app->scan_result_index > 0) {
            app->scan_result_index--;
            simple_app_adjust_result_offset(app);
            view_port_update(app->viewport);
        }
    } else if(key == InputKeyDown) {
        if(app->scan_result_index + 1 < app->visible_result_count) {
            app->scan_result_index++;
            simple_app_adjust_result_offset(app);
            view_port_update(app->viewport);
        }
    } else if(key == InputKeyOk) {
        if(app->scan_result_index < app->visible_result_count) {
            ScanResult* result = simple_app_visible_result(app, app->scan_result_index);
            if(result) {
                simple_app_toggle_scan_selection(app, result);
                simple_app_adjust_result_offset(app);
                view_port_update(app->viewport);
            }
        }
    } else if(key == InputKeyRight) {
        if(app->scan_selected_count > 0) {
            app->screen = ScreenMenu;
            app->menu_state = MenuStateItems;
            app->section_index = MENU_SECTION_ATTACKS;
            app->item_index = 0;
            app->item_offset = 0;
            app->last_attack_index = 0;
            view_port_update(app->viewport);
        }
    }
}

static bool simple_app_is_direction_key(InputKey key) {
    return (key == InputKeyUp || key == InputKeyDown || key == InputKeyLeft || key == InputKeyRight);
}

static void simple_app_input(InputEvent* event, void* context) {
    SimpleApp* app = context;
    if(!app || !event) return;

    uint32_t now = furi_get_tick();
    app->last_input_tick = now;
    if(app->help_hint_visible) {
        app->help_hint_visible = false;
        if(app->viewport) {
            view_port_update(app->viewport);
        }
    }

    if(simple_app_status_message_is_active(app) && app->status_message_fullscreen) {
        if(event->type == InputTypeShort &&
           (event->key == InputKeyOk || event->key == InputKeyBack)) {
            if(event->key == InputKeyBack) {
                simple_app_send_stop_if_needed(app);
            }
            simple_app_clear_status_message(app);
        }
        return;
    }

    if(app->evil_twin_popup_active) {
        simple_app_handle_evil_twin_popup_event(app, event);
        return;
    }

    if(app->hint_active) {
        simple_app_handle_hint_event(app, event);
        return;
    }

    if(event->type == InputTypeLong && event->key == InputKeyOk) {
        if(simple_app_try_show_hint(app)) {
            return;
        }
    }

    bool allow_event = false;
    if(event->type == InputTypeShort) {
        allow_event = true;
    } else if((event->type == InputTypeRepeat || event->type == InputTypeLong) &&
              simple_app_is_direction_key(event->key)) {
        allow_event = true;
    }

    if(!allow_event) return;

    switch(app->screen) {
    case ScreenMenu:
        simple_app_handle_menu_input(app, event->key);
        break;
    case ScreenSerial:
        simple_app_handle_serial_input(app, event->key);
        break;
    case ScreenResults:
        simple_app_handle_results_input(app, event->key);
        break;
    case ScreenSetupScanner:
        simple_app_handle_setup_scanner_input(app, event->key);
        break;
    case ScreenConsole:
        simple_app_handle_console_input(app, event->key);
        break;
    case ScreenConfirmBlackout:
        simple_app_handle_confirm_blackout_input(app, event->key);
        break;
    case ScreenConfirmSnifferDos:
        simple_app_handle_confirm_sniffer_dos_input(app, event->key);
        break;
    case ScreenEvilTwinMenu:
        simple_app_handle_evil_twin_menu_input(app, event->key);
        break;
    default:
        simple_app_handle_results_input(app, event->key);
        break;
    }
}

static void simple_app_process_stream(SimpleApp* app) {
    if(!app || !app->rx_stream) return;

    uint8_t chunk[64];
    bool updated = false;

    while(true) {
        size_t received = furi_stream_buffer_receive(app->rx_stream, chunk, sizeof(chunk), 0);
        if(received == 0) break;
        simple_app_append_serial_data(app, chunk, received);
        updated = true;
    }

    if(updated && (app->screen == ScreenSerial || app->screen == ScreenConsole)) {
        view_port_update(app->viewport);
    }
}

static void simple_app_serial_irq(FuriHalSerialHandle* handle, FuriHalSerialRxEvent event, void* context) {
    SimpleApp* app = context;
    if(!app || !app->rx_stream || !(event & FuriHalSerialRxEventData)) return;

    do {
        uint8_t byte = furi_hal_serial_async_rx(handle);
        furi_stream_buffer_send(app->rx_stream, &byte, 1, 0);
    } while(furi_hal_serial_async_rx_available(handle));
}

int32_t Lab_C5_app(void* p) {
    UNUSED(p);

    SimpleApp* app = malloc(sizeof(SimpleApp));
    if(!app) {
        return 0;
    }
    memset(app, 0, sizeof(SimpleApp));
    app->scanner_show_ssid = true;
    app->scanner_show_bssid = true;
    app->scanner_show_channel = true;
    app->scanner_show_security = true;
    app->scanner_show_power = true;
    app->scanner_show_band = true;
    app->scanner_min_power = SCAN_POWER_MIN_DBM;
    app->scanner_setup_index = 0;
    app->scanner_adjusting_power = false;
    app->otg_power_initial_state = furi_hal_power_is_otg_enabled();
    app->otg_power_enabled = app->otg_power_initial_state;
    app->backlight_enabled = true;
    app->scanner_view_offset = 0;
    simple_app_update_result_layout(app);
    simple_app_update_backlight_label(app);
    simple_app_update_otg_label(app);
    simple_app_apply_otg_power(app);
    app->notifications = furi_record_open(RECORD_NOTIFICATION);
    simple_app_load_config(app);
    simple_app_update_backlight_label(app);
    simple_app_apply_backlight(app);
    simple_app_update_otg_label(app);
    simple_app_apply_otg_power(app);
    app->menu_state = MenuStateSections;
    app->screen = ScreenMenu;
    app->serial_follow_tail = true;
    simple_app_reset_scan_results(app);
    app->last_input_tick = furi_get_tick();
    app->help_hint_visible = false;

    app->serial = furi_hal_serial_control_acquire(FuriHalSerialIdUsart);
    if(!app->serial) {
        free(app);
        return 0;
    }

    furi_hal_serial_init(app->serial, 115200);

    app->serial_mutex = furi_mutex_alloc(FuriMutexTypeNormal);
    if(!app->serial_mutex) {
        furi_hal_serial_deinit(app->serial);
        furi_hal_serial_control_release(app->serial);
        free(app);
        return 0;
    }

    app->rx_stream = furi_stream_buffer_alloc(UART_STREAM_SIZE, 1);
    if(!app->rx_stream) {
        furi_mutex_free(app->serial_mutex);
        furi_hal_serial_deinit(app->serial);
        furi_hal_serial_control_release(app->serial);
        free(app);
        return 0;
    }

    furi_stream_buffer_reset(app->rx_stream);
    simple_app_reset_serial_log(app, "READY");

    furi_hal_serial_async_rx_start(app->serial, simple_app_serial_irq, app, false);

    app->gui = furi_record_open(RECORD_GUI);
    app->viewport = view_port_alloc();
    view_port_draw_callback_set(app->viewport, simple_app_draw, app);
    view_port_input_callback_set(app->viewport, simple_app_input, app);
    gui_add_view_port(app->gui, app->viewport, GuiLayerFullscreen);

    while(!app->exit_app) {
        simple_app_process_stream(app);

        bool previous_help_hint = app->help_hint_visible;
        bool can_show_help_hint = (app->screen == ScreenMenu) && (app->menu_state == MenuStateSections) &&
                                  !app->hint_active && !app->evil_twin_popup_active &&
                                  !simple_app_status_message_is_active(app);

        if(can_show_help_hint) {
            uint32_t now = furi_get_tick();
            if(!app->help_hint_visible &&
               (now - app->last_input_tick) >= furi_ms_to_ticks(HELP_HINT_IDLE_MS)) {
                app->help_hint_visible = true;
            }
        } else {
            app->help_hint_visible = false;
        }

        if(app->help_hint_visible != previous_help_hint && app->viewport) {
            view_port_update(app->viewport);
        }

        furi_delay_ms(20);
    }

    simple_app_save_config_if_dirty(app, NULL, false);

    gui_remove_view_port(app->gui, app->viewport);
    view_port_free(app->viewport);
    furi_record_close(RECORD_GUI);

    furi_hal_serial_async_rx_stop(app->serial);
    furi_stream_buffer_free(app->rx_stream);
    furi_hal_serial_deinit(app->serial);
    furi_hal_serial_control_release(app->serial);
    furi_mutex_free(app->serial_mutex);
    if(app->notifications) {
        if(app->backlight_notification_enforced) {
            notification_message(app->notifications, &sequence_display_backlight_enforce_auto);
            app->backlight_notification_enforced = false;
        }
        furi_record_close(RECORD_NOTIFICATION);
        app->notifications = NULL;
    }
    if(app->backlight_insomnia) {
        furi_hal_power_insomnia_exit();
        app->backlight_insomnia = false;
    }
    bool current_otg_state = furi_hal_power_is_otg_enabled();
    if(current_otg_state != app->otg_power_initial_state) {
        if(app->otg_power_initial_state) {
            furi_hal_power_enable_otg();
        } else {
            furi_hal_power_disable_otg();
        }
    }
    furi_hal_light_set(LightBacklight, BACKLIGHT_ON_LEVEL);
    free(app);

    return 0;
}
