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
#include <gui/view_dispatcher.h>
#include <gui/modules/text_input.h>
#include <furi_hal_usb.h>
#include <furi_hal_usb_cdc.h>
#include <usb_cdc.h>

#define TAG "Lab_C5"

static size_t simple_app_bounded_strlen(const char* s, size_t max_len) {
    size_t len = 0;
    while(len < max_len && s[len] != '\0') {
        len++;
    }
    return len;
}

typedef enum {
    ScreenMenu,
    ScreenSerial,
    ScreenResults,
    ScreenSetupScanner,
    ScreenSetupKarma,
    ScreenSetupLed,
    ScreenSetupBoot,
    ScreenSetupSdManager,
    ScreenConsole,
    ScreenPackageMonitor,
    ScreenChannelView,
    ScreenConfirmBlackout,
    ScreenConfirmSnifferDos,
    ScreenKarmaMenu,
    ScreenEvilTwinMenu,
    ScreenPortalMenu,
    ScreenDownloadBridge,
} AppScreen;

typedef enum {
    MenuStateSections,
    MenuStateItems,
} MenuState;
#define LAB_C5_VERSION_TEXT "0.26"

#define MAX_SCAN_RESULTS 64
#define SCAN_LINE_BUFFER_SIZE 192
#define SCAN_SSID_MAX_LEN 33
#define SCAN_CHANNEL_MAX_LEN 8
#define SCAN_TYPE_MAX_LEN 16
#define SCAN_FIELD_BUFFER_LEN 64
#define SCAN_VENDOR_MAX_LEN 64
#define SCAN_POWER_MIN_DBM (-110)
#define SCAN_POWER_MAX_DBM 0
#define SCAN_POWER_STEP 1
#define BACKLIGHT_ON_LEVEL 255
#define BACKLIGHT_OFF_LEVEL 0

#define SERIAL_BUFFER_SIZE 4096
#define UART_STREAM_SIZE 4096
#define MENU_VISIBLE_COUNT 6
#define MENU_VISIBLE_COUNT_SNIFFERS 4
#define MENU_VISIBLE_COUNT_ATTACKS 4
#define MENU_VISIBLE_COUNT_SETUP 4
#define PACKAGE_MONITOR_MAX_HISTORY 96
#define MENU_TITLE_Y 12
#define MENU_ITEM_BASE_Y 24
#define MENU_ITEM_SPACING 12
#define MENU_SCROLL_TRACK_Y 14
#define SERIAL_VISIBLE_LINES 6
#define SERIAL_LINE_CHAR_LIMIT 22
#define SERIAL_TEXT_LINE_HEIGHT 10
#define DISPLAY_WIDTH 128
#define DISPLAY_HEIGHT 64
#define WARD_DRIVE_CONSOLE_LINES 3
#define RESULT_DEFAULT_MAX_LINES 4
#define RESULT_DEFAULT_LINE_HEIGHT 12
#define RESULT_DEFAULT_CHAR_LIMIT (SERIAL_LINE_CHAR_LIMIT - 3)
#define RESULT_START_Y 12
#define RESULT_ENTRY_SPACING 0
#define RESULT_PREFIX_X 2
#define RESULT_TEXT_X 5
#define RESULT_SCROLL_WIDTH 3
#define RESULT_SCROLL_GAP 0
#define RESULT_SCROLL_INTERVAL_MS 200
#define RESULT_SCROLL_EDGE_PAUSE_STEPS 3
#define CONSOLE_VISIBLE_LINES 4
#define MENU_SECTION_SCANNER 0
#define MENU_SECTION_SNIFFERS 1
#define MENU_SECTION_TARGETS 2
#define MENU_SECTION_ATTACKS 3
#define MENU_SECTION_MONITORING 4
#define MENU_SECTION_SETUP 5
#define SCANNER_FILTER_VISIBLE_COUNT 3
#define SCANNER_SCAN_COMMAND "scan_networks"
#define TARGETS_RESULTS_COMMAND "show_scan_results"
#define LAB_C5_CONFIG_DIR_PATH "apps_assets/labC5"
#define LAB_C5_CONFIG_FILE_PATH LAB_C5_CONFIG_DIR_PATH "/config.txt"

#define BOARD_PING_INTERVAL_MS 4000
#define BOARD_PING_TIMEOUT_MS 3000

#define PACKAGE_MONITOR_CHANNELS_24GHZ 14
#define PACKAGE_MONITOR_CHANNELS_5GHZ 23
#define PACKAGE_MONITOR_TOTAL_CHANNELS (PACKAGE_MONITOR_CHANNELS_24GHZ + PACKAGE_MONITOR_CHANNELS_5GHZ)
#define PACKAGE_MONITOR_DEFAULT_CHANNEL 1
#define PACKAGE_MONITOR_COMMAND "packet_monitor"
#define PACKAGE_MONITOR_BAR_SPACING 2
#define PACKAGE_MONITOR_CHANNEL_SWITCH_COOLDOWN_MS 200

#define CHANNEL_VIEW_COMMAND "channel_view"
#define CHANNEL_VIEW_LINE_BUFFER 64

static const uint8_t channel_view_channels_24ghz[] = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14};
static const uint8_t channel_view_channels_5ghz[] = {
    36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165};

#define CHANNEL_VIEW_24GHZ_CHANNEL_COUNT \
    (sizeof(channel_view_channels_24ghz) / sizeof(channel_view_channels_24ghz[0]))
#define CHANNEL_VIEW_5GHZ_CHANNEL_COUNT \
    (sizeof(channel_view_channels_5ghz) / sizeof(channel_view_channels_5ghz[0]))

#define CHANNEL_VIEW_VISIBLE_COLUMNS_24 6
#define CHANNEL_VIEW_VISIBLE_COLUMNS_5 5

#define BOOT_COMMAND_OPTION_COUNT 7
static const char* boot_command_options[BOOT_COMMAND_OPTION_COUNT] = {
    "start_blackout",
    "start_sniffer_dog",
    "channel_view",
    "packet_monitor",
    "start_sniffer",
    "scan_networks",
    "start_wardrive",
};

#define HINT_MAX_LINES 16
#define HINT_VISIBLE_LINES 3
#define HINT_LINE_CHAR_LIMIT 48
#define HINT_WRAP_LIMIT 21
#define HINT_LINE_HEIGHT 12
#define EVIL_TWIN_MAX_HTML_FILES 16
#define EVIL_TWIN_HTML_NAME_MAX 32
#define EVIL_TWIN_POPUP_VISIBLE_LINES 3
#define EVIL_TWIN_MENU_OPTION_COUNT 2
#define KARMA_MAX_PROBES 32
#define KARMA_PROBE_NAME_MAX 48
#define KARMA_POPUP_VISIBLE_LINES 3
#define KARMA_MENU_OPTION_COUNT 5
#define PORTAL_MENU_OPTION_COUNT 3
#define PORTAL_VISIBLE_COUNT 2
#define PORTAL_MAX_SSID_PRESETS 48
#define PORTAL_SSID_POPUP_VISIBLE_LINES 3
#define KARMA_MAX_HTML_FILES EVIL_TWIN_MAX_HTML_FILES
#define KARMA_HTML_NAME_MAX EVIL_TWIN_HTML_NAME_MAX
#define KARMA_SNIFFER_DURATION_MIN_SEC 5
#define KARMA_SNIFFER_DURATION_MAX_SEC 180
#define KARMA_SNIFFER_DURATION_STEP 5
#define KARMA_AUTO_LIST_DELAY_MS 500
#define HELP_HINT_IDLE_MS 3000
#define SD_MANAGER_MAX_FILES 64
#define SD_MANAGER_FILE_NAME_MAX 64
#define SD_MANAGER_POPUP_VISIBLE_LINES 3
#define SD_MANAGER_FOLDER_LABEL_MAX 24
#define SD_MANAGER_PATH_MAX 160

typedef enum {
    MenuActionCommand,
    MenuActionCommandWithTargets,
    MenuActionResults,
    MenuActionToggleBacklight,
    MenuActionToggleOtgPower,
    MenuActionOpenScannerSetup,
    MenuActionOpenLedSetup,
    MenuActionOpenBootSetup,
    MenuActionOpenDownload,
    MenuActionOpenSdManager,

    MenuActionOpenConsole,
    MenuActionOpenPackageMonitor,
    MenuActionOpenChannelView,
    MenuActionConfirmBlackout,
    MenuActionConfirmSnifferDos,
    MenuActionOpenEvilTwinMenu,
    MenuActionOpenKarmaMenu,
    MenuActionOpenPortalMenu,
} MenuAction;

typedef enum {
    ChannelViewBand24,
    ChannelViewBand5,
} ChannelViewBand;

typedef enum {
    ChannelViewSectionNone,
    ChannelViewSection24,
    ChannelViewSection5,
} ChannelViewSection;

typedef enum {
    ScannerOptionShowSSID,
    ScannerOptionShowBSSID,
    ScannerOptionShowChannel,
    ScannerOptionShowSecurity,
    ScannerOptionShowPower,
    ScannerOptionShowBand,
    ScannerOptionShowVendor,
    ScannerOptionMinPower,
    ScannerOptionCount,
} ScannerOption;

typedef struct {
    uint16_t number;
    char ssid[SCAN_SSID_MAX_LEN];
    char vendor[SCAN_VENDOR_MAX_LEN];
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
    uint8_t id;
    char name[KARMA_PROBE_NAME_MAX];
} KarmaProbeEntry;

typedef struct {
    uint8_t id;
    char name[KARMA_HTML_NAME_MAX];
} KarmaHtmlEntry;

typedef struct {
    uint8_t id;
    char ssid[SCAN_SSID_MAX_LEN];
} PortalSsidEntry;

typedef struct {
    const char* label;
    const char* path;
} SdFolderOption;

typedef struct {
    char name[SD_MANAGER_FILE_NAME_MAX];
} SdFileEntry;

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
    bool blackout_view_active;
    bool wardrive_view_active;
    bool wardrive_status_is_numeric;
    char wardrive_status_text[32];
    char wardrive_line_buffer[96];
    size_t wardrive_line_length;
    bool wardrive_otg_forced;
    bool wardrive_otg_previous_state;
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
    size_t portal_menu_index;
    char portal_ssid[SCAN_SSID_MAX_LEN];
    size_t portal_menu_offset;
    bool portal_input_requested;
    bool portal_input_active;
    PortalSsidEntry portal_ssid_entries[PORTAL_MAX_SSID_PRESETS];
    size_t portal_ssid_count;
    size_t portal_ssid_popup_index;
    size_t portal_ssid_popup_offset;
    bool portal_ssid_popup_active;
    bool portal_ssid_listing_active;
    bool portal_ssid_list_header_seen;
    char portal_ssid_list_buffer[64];
    size_t portal_ssid_list_length;
    bool portal_ssid_missing;
    size_t sd_folder_index;
    size_t sd_folder_offset;
    bool sd_folder_popup_active;
    SdFileEntry sd_files[SD_MANAGER_MAX_FILES];
    size_t sd_file_count;
    size_t sd_file_popup_index;
    size_t sd_file_popup_offset;
    bool sd_file_popup_active;
    bool sd_listing_active;
    bool sd_list_header_seen;
    char sd_list_buffer[160];
    size_t sd_list_length;
    char sd_current_folder_label[SD_MANAGER_FOLDER_LABEL_MAX];
    char sd_current_folder_path[SD_MANAGER_PATH_MAX];
    char sd_delete_target_name[SD_MANAGER_FILE_NAME_MAX];
    char sd_delete_target_path[SD_MANAGER_PATH_MAX];
    bool sd_delete_confirm_active;
    bool sd_delete_confirm_yes;
    bool sd_refresh_pending;
    uint32_t sd_refresh_tick;
    uint8_t sd_scroll_offset;
    int8_t sd_scroll_direction;
    uint8_t sd_scroll_hold;
    uint32_t sd_scroll_last_tick;
    uint8_t sd_scroll_char_limit;
    char sd_scroll_text[SD_MANAGER_FILE_NAME_MAX];
    size_t karma_menu_index;
    size_t karma_menu_offset;
    KarmaProbeEntry karma_probes[KARMA_MAX_PROBES];
    size_t karma_probe_count;
    size_t karma_probe_popup_index;
    size_t karma_probe_popup_offset;
    bool karma_probe_popup_active;
    bool karma_probe_listing_active;
    bool karma_probe_list_header_seen;
    char karma_probe_list_buffer[64];
    size_t karma_probe_list_length;
    uint8_t karma_selected_probe_id;
    char karma_selected_probe_name[KARMA_PROBE_NAME_MAX];
    KarmaHtmlEntry karma_html_entries[KARMA_MAX_HTML_FILES];
    size_t karma_html_count;
    size_t karma_html_popup_index;
    size_t karma_html_popup_offset;
    bool karma_html_popup_active;
    bool karma_html_listing_active;
    bool karma_html_list_header_seen;
    char karma_html_list_buffer[64];
    size_t karma_html_list_length;
    uint8_t karma_selected_html_id;
    char karma_selected_html_name[KARMA_HTML_NAME_MAX];
    bool karma_sniffer_running;
    uint32_t karma_sniffer_stop_tick;
    uint32_t karma_sniffer_duration_sec;
    bool karma_pending_probe_refresh;
    uint32_t karma_pending_probe_tick;
    bool karma_status_active;
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
    bool scanner_show_vendor;
    bool vendor_scan_enabled;
    bool vendor_read_pending;
    char vendor_read_buffer[32];
    size_t vendor_read_length;
    int16_t scanner_min_power;
    size_t scanner_setup_index;
    bool scanner_adjusting_power;
    bool otg_power_enabled;
    bool otg_power_initial_state;
    bool backlight_enabled;
    bool backlight_insomnia;
    bool led_enabled;
    uint8_t led_level;
    size_t led_setup_index;
    bool boot_short_enabled;
    bool boot_long_enabled;
    uint8_t boot_short_command_index;
    uint8_t boot_long_command_index;
    bool boot_setup_long;
    size_t boot_setup_index;
    bool led_read_pending;
    char led_read_buffer[64];
    size_t led_read_length;
    size_t scanner_view_offset;
    uint8_t result_line_height;
    uint8_t result_char_limit;
    uint8_t result_max_lines;
    Font result_font;
    uint8_t result_scroll_offset;
    int8_t result_scroll_direction;
    uint8_t result_scroll_hold;
    uint32_t result_scroll_last_tick;
    char result_scroll_text[64];
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
    bool board_ready_seen;
    bool board_sync_pending;
    bool board_ping_outstanding;
    uint32_t board_last_ping_tick;
    uint32_t board_last_rx_tick;
    bool board_missing_shown;
    uint32_t last_input_tick;
    bool help_hint_visible;
    bool package_monitor_active;
    uint8_t package_monitor_channel;
    uint16_t package_monitor_history[PACKAGE_MONITOR_MAX_HISTORY];
    size_t package_monitor_history_count;
    uint16_t package_monitor_last_value;
    bool package_monitor_dirty;
    char package_monitor_line_buffer[64];
    size_t package_monitor_line_length;
    uint32_t package_monitor_last_channel_tick;
    bool channel_view_active;
    bool channel_view_dirty;
    bool channel_view_has_data;
    bool channel_view_dataset_active;
    bool channel_view_has_status;
    ChannelViewBand channel_view_band;
    ChannelViewSection channel_view_section;
    uint16_t channel_view_counts_24[CHANNEL_VIEW_24GHZ_CHANNEL_COUNT];
    uint16_t channel_view_counts_5[CHANNEL_VIEW_5GHZ_CHANNEL_COUNT];
    uint16_t channel_view_working_counts_24[CHANNEL_VIEW_24GHZ_CHANNEL_COUNT];
    uint16_t channel_view_working_counts_5[CHANNEL_VIEW_5GHZ_CHANNEL_COUNT];
    char channel_view_line_buffer[CHANNEL_VIEW_LINE_BUFFER];
    size_t channel_view_line_length;
    char channel_view_status_text[32];
    uint8_t channel_view_offset_24;
    uint8_t channel_view_offset_5;
    // Download/bridge state
    bool download_bridge_active;
    uint8_t download_cdc_if;
    FuriHalUsbInterface* download_usb_prev;
    FuriThread* download_thread;
    uint32_t download_baud;
    uint32_t download_baud_new;
    uint32_t download_uart_to_usb;
    uint32_t download_usb_to_uart;
} SimpleApp;
static void simple_app_reset_result_scroll(SimpleApp* app);
static void simple_app_update_result_scroll(SimpleApp* app);
static void simple_app_adjust_result_offset(SimpleApp* app);
static void simple_app_rebuild_visible_results(SimpleApp* app);
static bool simple_app_result_is_visible(const SimpleApp* app, const ScanResult* result);
static ScanResult* simple_app_visible_result(SimpleApp* app, size_t visible_index);
static const ScanResult* simple_app_visible_result_const(const SimpleApp* app, size_t visible_index);
static void simple_app_update_result_layout(SimpleApp* app);
static void simple_app_update_karma_duration_label(SimpleApp* app);
static bool simple_app_parse_bool_value(const char* value, bool current);
static void simple_app_apply_backlight(SimpleApp* app);
static void simple_app_toggle_backlight(SimpleApp* app);
static void simple_app_update_led_label(SimpleApp* app);
static void simple_app_send_led_power_command(SimpleApp* app);
static void simple_app_send_led_level_command(SimpleApp* app);
static void simple_app_send_command_quiet(SimpleApp* app, const char* command);
static void simple_app_request_led_status(SimpleApp* app);
static bool simple_app_handle_led_status_line(SimpleApp* app, const char* line);
static void simple_app_led_feed(SimpleApp* app, char ch);
static void simple_app_update_boot_labels(SimpleApp* app);
static void simple_app_send_boot_status(SimpleApp* app, bool is_short, bool enabled);
static void simple_app_send_boot_command(SimpleApp* app, bool is_short, uint8_t command_index);
static void simple_app_request_boot_status(SimpleApp* app);
static bool simple_app_handle_boot_status_line(SimpleApp* app, const char* line);
static void simple_app_boot_feed(SimpleApp* app, char ch);
static void simple_app_serial_irq(
    FuriHalSerialHandle* handle, FuriHalSerialRxEvent event, void* context);
static void simple_app_draw_download_bridge(SimpleApp* app, Canvas* canvas);
static bool simple_app_download_bridge_start(SimpleApp* app);
static void simple_app_download_bridge_stop(SimpleApp* app);
static void simple_app_handle_boot_trigger(SimpleApp* app, bool is_long);
static void simple_app_handle_board_ready(SimpleApp* app);
static void simple_app_draw_sync_status(const SimpleApp* app, Canvas* canvas);
static void simple_app_send_vendor_command(SimpleApp* app, bool enable);
static void simple_app_request_vendor_status(SimpleApp* app);
static bool simple_app_handle_vendor_status_line(SimpleApp* app, const char* line);
static void simple_app_vendor_feed(SimpleApp* app, char ch);
static void simple_app_reset_wardrive_status(SimpleApp* app);
static void simple_app_process_wardrive_line(SimpleApp* app, const char* line);
static void simple_app_wardrive_feed(SimpleApp* app, char ch);
static void simple_app_force_otg_for_wardrive(SimpleApp* app);
static void simple_app_restore_otg_after_wardrive(SimpleApp* app);
static void simple_app_send_command(SimpleApp* app, const char* command, bool go_to_serial);
static void simple_app_append_serial_data(SimpleApp* app, const uint8_t* data, size_t length);
static void simple_app_draw_wardrive_serial(SimpleApp* app, Canvas* canvas);
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
static void simple_app_package_monitor_enter(SimpleApp* app);
static void simple_app_package_monitor_start(SimpleApp* app, uint8_t channel, bool reset_history);
static void simple_app_package_monitor_stop(SimpleApp* app);
static void simple_app_package_monitor_reset(SimpleApp* app);
static void simple_app_package_monitor_process_line(SimpleApp* app, const char* line);
static void simple_app_package_monitor_feed(SimpleApp* app, char ch);
static void simple_app_draw_package_monitor(SimpleApp* app, Canvas* canvas);
static void simple_app_handle_package_monitor_input(SimpleApp* app, InputKey key);
static void simple_app_channel_view_enter(SimpleApp* app);
static void simple_app_channel_view_start(SimpleApp* app);
static void simple_app_channel_view_stop(SimpleApp* app);
static void simple_app_channel_view_reset(SimpleApp* app);
static void simple_app_channel_view_begin_dataset(SimpleApp* app);
static void simple_app_channel_view_commit_dataset(SimpleApp* app);
static void simple_app_channel_view_process_line(SimpleApp* app, const char* line);
static void simple_app_channel_view_feed(SimpleApp* app, char ch);
static void simple_app_draw_channel_view(SimpleApp* app, Canvas* canvas);
static void simple_app_handle_channel_view_input(SimpleApp* app, InputKey key);
static void simple_app_channel_view_show_status(SimpleApp* app, const char* status);
static int simple_app_channel_view_find_channel_index(const uint8_t* list, size_t count, uint8_t channel);
static size_t simple_app_channel_view_visible_columns(ChannelViewBand band);
static uint8_t simple_app_channel_view_max_offset(ChannelViewBand band);
static uint8_t* simple_app_channel_view_offset_ptr(SimpleApp* app, ChannelViewBand band);
static bool simple_app_channel_view_adjust_offset(SimpleApp* app, ChannelViewBand band, int delta);
static bool simple_app_try_show_hint(SimpleApp* app);
static void simple_app_draw_portal_menu(SimpleApp* app, Canvas* canvas);
static void simple_app_handle_portal_menu_input(SimpleApp* app, InputKey key);
static void simple_app_reset_portal_ssid_listing(SimpleApp* app);
static void simple_app_request_portal_ssid_list(SimpleApp* app);
static void simple_app_copy_portal_ssid(SimpleApp* app, const char* source);
static void simple_app_portal_prompt_ssid(SimpleApp* app);
static void simple_app_portal_sync_offset(SimpleApp* app);
static void simple_app_open_portal_ssid_popup(SimpleApp* app);
static void simple_app_finish_portal_ssid_listing(SimpleApp* app);
static void simple_app_process_portal_ssid_line(SimpleApp* app, const char* line);
static void simple_app_portal_ssid_feed(SimpleApp* app, char ch);
static void simple_app_draw_portal_ssid_popup(SimpleApp* app, Canvas* canvas);
static void simple_app_handle_portal_ssid_popup_event(SimpleApp* app, const InputEvent* event);
static bool simple_app_portal_run_text_input(SimpleApp* app);
static void simple_app_portal_text_input_result(void* context);
static bool simple_app_portal_text_input_navigation(void* context);
static void simple_app_start_portal(SimpleApp* app);
static void simple_app_open_sd_manager(SimpleApp* app);
static void simple_app_copy_sd_folder(SimpleApp* app, const SdFolderOption* folder);
static void simple_app_draw_setup_sd_manager(SimpleApp* app, Canvas* canvas);
static void simple_app_handle_setup_sd_manager_input(SimpleApp* app, InputKey key);
static void simple_app_draw_sd_folder_popup(SimpleApp* app, Canvas* canvas);
static void simple_app_handle_sd_folder_popup_event(SimpleApp* app, const InputEvent* event);
static void simple_app_request_sd_listing(SimpleApp* app, const SdFolderOption* folder);
static void simple_app_reset_sd_listing(SimpleApp* app);
static void simple_app_finish_sd_listing(SimpleApp* app);
static void simple_app_process_sd_line(SimpleApp* app, const char* line);
static void simple_app_sd_feed(SimpleApp* app, char ch);
static void simple_app_draw_sd_file_popup(SimpleApp* app, Canvas* canvas);
static void simple_app_handle_sd_file_popup_event(SimpleApp* app, const InputEvent* event);
static void simple_app_draw_sd_delete_confirm(SimpleApp* app, Canvas* canvas);
static void simple_app_handle_sd_delete_confirm_event(SimpleApp* app, const InputEvent* event);
static void simple_app_reset_sd_scroll(SimpleApp* app);
static void simple_app_sd_scroll_buffer(
    SimpleApp* app, const char* text, size_t char_limit, char* out, size_t out_size);
static void simple_app_update_sd_scroll(SimpleApp* app);
static void simple_app_draw_evil_twin_menu(SimpleApp* app, Canvas* canvas);
static void simple_app_handle_evil_twin_menu_input(SimpleApp* app, InputKey key);
static void simple_app_draw_scroll_arrow(Canvas* canvas, uint8_t base_left_x, int16_t base_y, bool upwards);
static void simple_app_draw_scroll_hints(
    Canvas* canvas,
    uint8_t base_left_x,
    int16_t content_top_y,
    int16_t content_bottom_y,
    bool show_up,
    bool show_down);
static void simple_app_draw_scroll_hints_clamped(
    Canvas* canvas,
    uint8_t base_left_x,
    int16_t content_top_y,
    int16_t content_bottom_y,
    bool show_up,
    bool show_down,
    int16_t min_base_y,
    int16_t max_base_y);
static void simple_app_request_evil_twin_html_list(SimpleApp* app);
static void simple_app_start_evil_portal(SimpleApp* app);
static void simple_app_draw_evil_twin_popup(SimpleApp* app, Canvas* canvas);
static void simple_app_handle_evil_twin_popup_event(SimpleApp* app, const InputEvent* event);
static void simple_app_close_evil_twin_popup(SimpleApp* app);
static void simple_app_reset_evil_twin_listing(SimpleApp* app);
static void simple_app_finish_evil_twin_listing(SimpleApp* app);
static void simple_app_process_evil_twin_line(SimpleApp* app, const char* line);
static void simple_app_evil_twin_feed(SimpleApp* app, char ch);
static void simple_app_draw_karma_menu(SimpleApp* app, Canvas* canvas);
static void simple_app_handle_karma_menu_input(SimpleApp* app, InputKey key);
static void simple_app_start_karma_sniffer(SimpleApp* app);
static void simple_app_start_karma_attack(SimpleApp* app);
static void simple_app_request_karma_probe_list(SimpleApp* app);
static void simple_app_reset_karma_probe_listing(SimpleApp* app);
static void simple_app_finish_karma_probe_listing(SimpleApp* app);
static void simple_app_process_karma_probe_line(SimpleApp* app, const char* line);
static void simple_app_karma_probe_feed(SimpleApp* app, char ch);
static void simple_app_draw_karma_probe_popup(SimpleApp* app, Canvas* canvas);
static void simple_app_handle_karma_probe_popup_event(SimpleApp* app, const InputEvent* event);
static void simple_app_request_karma_html_list(SimpleApp* app);
static void simple_app_reset_karma_html_listing(SimpleApp* app);
static void simple_app_finish_karma_html_listing(SimpleApp* app);
static void simple_app_process_karma_html_line(SimpleApp* app, const char* line);
static void simple_app_karma_html_feed(SimpleApp* app, char ch);
static void simple_app_draw_karma_html_popup(SimpleApp* app, Canvas* canvas);
static void simple_app_handle_karma_html_popup_event(SimpleApp* app, const InputEvent* event);
static void simple_app_update_karma_sniffer(SimpleApp* app);
static void simple_app_draw_setup_karma(SimpleApp* app, Canvas* canvas);
static void simple_app_handle_setup_karma_input(SimpleApp* app, InputKey key);
static void simple_app_draw_setup_led(SimpleApp* app, Canvas* canvas);
static void simple_app_handle_setup_led_input(SimpleApp* app, InputKey key);
static void simple_app_modify_karma_duration(SimpleApp* app, int32_t delta);
static void simple_app_save_config_if_dirty(SimpleApp* app, const char* message, bool fullscreen);
static bool simple_app_save_config(SimpleApp* app, const char* success_message, bool fullscreen);
static void simple_app_load_config(SimpleApp* app);
static void simple_app_show_status_message(SimpleApp* app, const char* message, uint32_t duration_ms, bool fullscreen);
static void simple_app_clear_status_message(SimpleApp* app);
static bool simple_app_status_message_is_active(SimpleApp* app);
static void simple_app_send_command_with_targets(SimpleApp* app, const char* base_command);
static size_t simple_app_menu_visible_count(const SimpleApp* app, uint32_t section_index);
static void simple_app_update_scroll(SimpleApp* app);
static size_t simple_app_render_display_lines(
    SimpleApp* app,
    size_t skip_lines,
    char dest[][64],
    size_t max_lines);
static void simple_app_send_ping(SimpleApp* app);
static void simple_app_handle_pong(SimpleApp* app);
static void simple_app_ping_watchdog(SimpleApp* app);

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
static const char hint_section_monitoring[] =
    "Monitoring tools\nPacket rates +\nChannel analyzer\nSwitch views with\nUp/Down buttons.";
static const char hint_section_setup[] =
    "General settings\nBacklight, 5V, LED\nAdjust scanner view\nConsole with logs\nUseful for debug.";

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
static const char hint_attack_handshaker[] =
    "Collect WPA handshakes\nWorks with or without\nselected networks.\nNo selection grabs\nall in the air.";
static const char hint_attack_evil_twin[] =
    "Creates fake network \nwith captive portal in the \nname of the first selected.";
static const char hint_attack_portal[] =
    "Custom captive portal\nSet SSID manually\nUse keyboard input\nStart when ready\nLab testing only.";
static const char hint_attack_karma[] =
    "Collect probe SSIDs\nPick captive portal\nStart Karma beacon\nSniffer auto stops\nLab use only.";
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
static const char hint_setup_led[] =
    "Control status LED\nLeft/Right toggles\nSends CLI command\nAdjust brightness\nRange 1 to 100.";
static const char hint_setup_boot[] =
    "Assign boot button\nShort/Long actions\nToggle on/off\nPick command\nSaved in device.";
static const char hint_setup_filters[] =
    "Choose visible fields\nSimplify result list\nHide unused data\nTailor display\nOK flips options.";
static const char hint_setup_console[] =
    "Open live console\nStream UART output\nWatch commands\nDebug operations\nClose with Back.";
static const char hint_setup_download[] =
    "Send download cmd\nThen open UART GPIO\nbridge manually and\nreconnect USB to PC\nfor flashing.";
static const char hint_setup_sd_manager[] =
    "Browse SD folders\nPick lab captures\nDelete safely\nDefault: handshakes.";

static const SdFolderOption sd_folder_options[] = {
    {"Handshakes", "lab/handshakes"},
    {"HTML portals", "lab/htmls"},
    {"Wardrives", "lab/wardrives"},
};

static const size_t sd_folder_option_count = sizeof(sd_folder_options) / sizeof(sd_folder_options[0]);

static const MenuEntry menu_entries_sniffers[] = {
    {"Start Sniffer", "start_sniffer", MenuActionCommand, hint_sniffer_start},
    {"Show Sniffer Results", "show_sniffer_results", MenuActionCommand, hint_sniffer_results},
    {"Show Probes", "show_probes", MenuActionCommand, hint_sniffer_probes},
    {"Sniffer Debug", "sniffer_debug 1", MenuActionCommand, hint_sniffer_debug},
};

static const MenuEntry menu_entries_attacks[] = {
    {"Blackout", NULL, MenuActionConfirmBlackout, hint_attack_blackout},
    {"Deauth", "start_deauth", MenuActionCommandWithTargets, hint_attack_deauth},
    {"Handshaker", "start_handshake", MenuActionCommandWithTargets, hint_attack_handshaker},
    {"Evil Twin", NULL, MenuActionOpenEvilTwinMenu, hint_attack_evil_twin},
    {"Portal", NULL, MenuActionOpenPortalMenu, hint_attack_portal},
    {"Karma", NULL, MenuActionOpenKarmaMenu, hint_attack_karma},
    {"SAE Overflow", "sae_overflow", MenuActionCommandWithTargets, hint_attack_sae_overflow},
    {"Sniffer Dog", NULL, MenuActionConfirmSnifferDos, hint_attack_sniffer_dog},
    {"Wardrive", "start_wardrive", MenuActionCommand, hint_attack_wardrive},
};

static const char hint_monitor_package[] =
    "Live packet count\nShows vertical bars\nBack stops monitor\nUp/Down change ch.";
static const char hint_monitor_channel[] =
    "Channel usage view\nAuto scans both bands\nUp/Down swap band\nLeft/Right scroll\nOK restarts scan.";

static const MenuEntry menu_entries_monitoring[] = {
    {"Package Monitor", NULL, MenuActionOpenPackageMonitor, hint_monitor_package},
    {"Channel View", NULL, MenuActionOpenChannelView, hint_monitor_channel},
};

static char menu_label_backlight[24] = "Backlight: On";
static char menu_label_otg_power[24] = "5V Power: On";
static char menu_label_led[24] = "LED: On (10)";
static char menu_label_boot_short[40] = "Boot short: Off";
static char menu_label_boot_long[40] = "Boot long: Off";

static const MenuEntry menu_entries_setup[] = {
    {menu_label_backlight, NULL, MenuActionToggleBacklight, hint_setup_backlight},
    {menu_label_otg_power, NULL, MenuActionToggleOtgPower, hint_setup_otg},
    {menu_label_led, NULL, MenuActionOpenLedSetup, hint_setup_led},
    {menu_label_boot_short, NULL, MenuActionOpenBootSetup, hint_setup_boot},
    {menu_label_boot_long, NULL, MenuActionOpenBootSetup, hint_setup_boot},
    {"Scanner Filters", NULL, MenuActionOpenScannerSetup, hint_setup_filters},
    {"SD Manager", NULL, MenuActionOpenSdManager, hint_setup_sd_manager},
    {"Download Mode", NULL, MenuActionOpenDownload, hint_setup_download},
    {"Console", NULL, MenuActionOpenConsole, hint_setup_console},
};

static const MenuSection menu_sections[] = {
    {"Scanner", hint_section_scanner, NULL, 0, 12, MENU_VISIBLE_COUNT * MENU_ITEM_SPACING},
    {"Sniffers", hint_section_sniffers, menu_entries_sniffers, sizeof(menu_entries_sniffers) / sizeof(menu_entries_sniffers[0]), 22, MENU_VISIBLE_COUNT_SNIFFERS * MENU_ITEM_SPACING},
    {"Targets", hint_section_targets, NULL, 0, 32, MENU_VISIBLE_COUNT * MENU_ITEM_SPACING},
    {"Attacks", hint_section_attacks, menu_entries_attacks, sizeof(menu_entries_attacks) / sizeof(menu_entries_attacks[0]), 42, MENU_VISIBLE_COUNT_ATTACKS * MENU_ITEM_SPACING},
    {"Monitoring", hint_section_monitoring, menu_entries_monitoring, sizeof(menu_entries_monitoring) / sizeof(menu_entries_monitoring[0]), 52, MENU_VISIBLE_COUNT * MENU_ITEM_SPACING},
    {"Setup", hint_section_setup, menu_entries_setup, sizeof(menu_entries_setup) / sizeof(menu_entries_setup[0]), 62, MENU_VISIBLE_COUNT_SETUP * MENU_ITEM_SPACING},
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
    if(section_index == MENU_SECTION_SETUP) {
        return MENU_VISIBLE_COUNT_SETUP;
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

static void simple_app_draw_scroll_arrow(Canvas* canvas, uint8_t base_left_x, int16_t base_y, bool upwards) {
    if(!canvas) return;

    if(upwards) {
        if(base_y < 2) base_y = 2;
    } else {
        if(base_y > 61) base_y = 61;
    }

    if(base_y < 0) base_y = 0;
    if(base_y > 63) base_y = 63;

    uint8_t base = (uint8_t)base_y;
    uint8_t base_right_x = (uint8_t)(base_left_x + 4);
    uint8_t apex_x = (uint8_t)(base_left_x + 2);
    uint8_t apex_y = upwards ? (uint8_t)(base - 2) : (uint8_t)(base + 2);

    canvas_draw_line(canvas, base_left_x, base, base_right_x, base);
    canvas_draw_line(canvas, base_left_x, base, apex_x, apex_y);
    canvas_draw_line(canvas, base_right_x, base, apex_x, apex_y);
}

static void simple_app_draw_scroll_hints_clamped(
    Canvas* canvas,
    uint8_t base_left_x,
    int16_t content_top_y,
    int16_t content_bottom_y,
    bool show_up,
    bool show_down,
    int16_t min_base_y,
    int16_t max_base_y) {
    if(!canvas || (!show_up && !show_down)) return;

    if(min_base_y > max_base_y) {
        int16_t tmp = min_base_y;
        min_base_y = max_base_y;
        max_base_y = tmp;
    }

    int16_t up_base = content_top_y - 4;
    int16_t down_base = content_bottom_y + 4;

    if(up_base < min_base_y) up_base = min_base_y;
    if(up_base > max_base_y) up_base = max_base_y;

    if(down_base < min_base_y) down_base = min_base_y;
    if(down_base > max_base_y) down_base = max_base_y;

    if(show_up) {
        simple_app_draw_scroll_arrow(canvas, base_left_x, up_base, true);
    }

    if(show_down) {
        if(show_up && down_base <= up_base) {
            down_base = up_base + 4;
            if(down_base > max_base_y) down_base = max_base_y;
        }
        if(!show_up && down_base < min_base_y) {
            down_base = min_base_y;
        }
        simple_app_draw_scroll_arrow(canvas, base_left_x, down_base, false);
    }
}

static void simple_app_draw_scroll_hints(
    Canvas* canvas,
    uint8_t base_left_x,
    int16_t content_top_y,
    int16_t content_bottom_y,
    bool show_up,
    bool show_down) {
    simple_app_draw_scroll_hints_clamped(
        canvas, base_left_x, content_top_y, content_bottom_y, show_up, show_down, 10, 60);
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
    simple_app_reset_result_scroll(app);
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
    simple_app_reset_result_scroll(app);
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
    if(app->scanner_show_vendor) count++;
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
    case ScannerOptionShowVendor:
        return &app->scanner_show_vendor;
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

static void simple_app_update_led_label(SimpleApp* app) {
    if(!app) return;
    uint32_t level = app->led_level;
    if(level < 1) level = 1;
    if(level > 100) level = 100;
    snprintf(
        menu_label_led,
        sizeof(menu_label_led),
        "LED: %s (%lu)",
        app->led_enabled ? "On" : "Off",
        (unsigned long)level);
}

static void simple_app_update_boot_labels(SimpleApp* app) {
    if(!app) return;
    snprintf(
        menu_label_boot_short,
        sizeof(menu_label_boot_short),
        "Boot short: %s",
        app->boot_short_enabled ? "On" : "Off");
    snprintf(
        menu_label_boot_long,
        sizeof(menu_label_boot_long),
        "Boot long: %s",
        app->boot_long_enabled ? "On" : "Off");
}

static void simple_app_send_led_power_command(SimpleApp* app) {
    if(!app || !app->serial) return;
    const char* state = app->led_enabled ? "on" : "off";
    char command[24];
    snprintf(command, sizeof(command), "led set %s", state);
    simple_app_send_command_quiet(app, command);
}

static void simple_app_send_led_level_command(SimpleApp* app) {
    if(!app || !app->serial) return;
    uint32_t level = app->led_level;
    if(level < 1) level = 1;
    if(level > 100) level = 100;
    char command[24];
    snprintf(command, sizeof(command), "led level %lu", (unsigned long)level);
    simple_app_send_command_quiet(app, command);
}

static void simple_app_send_boot_status(SimpleApp* app, bool is_short, bool enabled) {
    if(!app || !app->serial) return;
    char command[48];
    snprintf(command, sizeof(command), "boot_button status %s %s", is_short ? "short" : "long", enabled ? "on" : "off");
    simple_app_send_command_quiet(app, command);
}

static void simple_app_send_boot_command(SimpleApp* app, bool is_short, uint8_t command_index) {
    if(!app || !app->serial) return;
    if(command_index >= BOOT_COMMAND_OPTION_COUNT) {
        command_index = 0;
    }
    char command[48];
    snprintf(
        command,
        sizeof(command),
        "boot_button set %s %s",
        is_short ? "short" : "long",
        boot_command_options[command_index]);
    simple_app_send_command_quiet(app, command);
}

static void simple_app_request_boot_status(SimpleApp* app) {
    if(!app || !app->serial) return;
    simple_app_send_command_quiet(app, "boot_button read");
}

static bool simple_app_handle_boot_status_line(SimpleApp* app, const char* line) {
    if(!app || !line) return false;
    const char* short_status = "boot_short_status=";
    const char* short_cmd = "boot_short=";
    const char* long_status = "boot_long_status=";
    const char* long_cmd = "boot_long=";

    if(strncmp(line, short_status, strlen(short_status)) == 0) {
        app->boot_short_enabled =
            simple_app_parse_bool_value(line + strlen(short_status), app->boot_short_enabled);
        simple_app_update_boot_labels(app);
        return true;
    }
    if(strncmp(line, long_status, strlen(long_status)) == 0) {
        app->boot_long_enabled =
            simple_app_parse_bool_value(line + strlen(long_status), app->boot_long_enabled);
        simple_app_update_boot_labels(app);
        return true;
    }
    if(strncmp(line, short_cmd, strlen(short_cmd)) == 0) {
        const char* value = line + strlen(short_cmd);
        for(uint8_t i = 0; i < BOOT_COMMAND_OPTION_COUNT; i++) {
            if(strcmp(value, boot_command_options[i]) == 0) {
                app->boot_short_command_index = i;
                simple_app_update_boot_labels(app);
                return true;
            }
        }
        return true;
    }
    if(strncmp(line, long_cmd, strlen(long_cmd)) == 0) {
        const char* value = line + strlen(long_cmd);
        for(uint8_t i = 0; i < BOOT_COMMAND_OPTION_COUNT; i++) {
            if(strcmp(value, boot_command_options[i]) == 0) {
                app->boot_long_command_index = i;
                simple_app_update_boot_labels(app);
                return true;
            }
        }
        return true;
    }
    return false;
}

static void simple_app_boot_feed(SimpleApp* app, char ch) {
    static char line_buffer[96];
    static size_t line_len = 0;
    if(ch == '\r') return;
    if(ch == '\n') {
        if(line_len > 0) {
            line_buffer[line_len] = '\0';
            // Skip prompt markers and leading spaces
            const char* line_ptr = line_buffer;
            while(*line_ptr == '>' || *line_ptr == ' ' || *line_ptr == '\t') {
                line_ptr++;
            }

            if(simple_app_handle_boot_status_line(app, line_ptr)) {
                if(app->viewport) {
                    view_port_update(app->viewport);
                }
            } else if(strcmp(line_ptr, "Boot Pressed") == 0) {
                simple_app_handle_boot_trigger(app, false);
            } else if(strcmp(line_ptr, "Boot Long Pressed") == 0) {
                simple_app_handle_boot_trigger(app, true);
            } else if(strcmp(line_ptr, "BOARD READY") == 0) {
                simple_app_handle_board_ready(app);
            }
        }
        line_len = 0;
        return;
    }
    if(line_len + 1 >= sizeof(line_buffer)) {
        line_len = 0;
        return;
    }
    line_buffer[line_len++] = ch;
}

static void simple_app_handle_boot_trigger(SimpleApp* app, bool is_long) {
    if(!app) return;

    const char* cmd = NULL;
    bool enabled = false;
    if(is_long) {
        enabled = app->boot_long_enabled;
        if(app->boot_long_command_index < BOOT_COMMAND_OPTION_COUNT) {
            cmd = boot_command_options[app->boot_long_command_index];
        }
    } else {
        enabled = app->boot_short_enabled;
        if(app->boot_short_command_index < BOOT_COMMAND_OPTION_COUNT) {
            cmd = boot_command_options[app->boot_short_command_index];
        }
    }

    char message[64];
    if(!enabled) {
        snprintf(message, sizeof(message), "Boot %s:\ndisabled", is_long ? "long" : "short");
    } else if(cmd) {
        snprintf(message, sizeof(message), "Boot %s:\n%s", is_long ? "long" : "short", cmd);
    } else {
        snprintf(message, sizeof(message), "Boot %s\npressed", is_long ? "long" : "short");
    }

    simple_app_show_status_message(app, message, 1500, true);

    if(enabled) {
        app->screen = ScreenSerial;
        app->serial_follow_tail = true;
        app->last_command_sent = true; // allow Back to send stop for boot-triggered actions
        simple_app_update_scroll(app);
        if(app->viewport) {
            view_port_update(app->viewport);
        }
    }
}

static void simple_app_handle_board_ready(SimpleApp* app) {
    if(!app) return;

    bool was_ready = app->board_ready_seen;
    app->board_ready_seen = true;
    app->board_sync_pending = false;
    app->board_ping_outstanding = false;
    app->board_last_rx_tick = furi_get_tick();
    app->board_missing_shown = false;

    if(!was_ready) {
        simple_app_show_status_message(app, "Board found", 1000, true);
        if(app->viewport) {
            view_port_update(app->viewport);
        }
    }
}

static void simple_app_draw_sync_status(const SimpleApp* app, Canvas* canvas) {
    if(!app || !canvas) return;
    const char* text = "Sync...";
    if(app->board_missing_shown) {
        text = "No board";
    } else if(app->board_ready_seen) {
        text = "Sync OK";
    }
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str_aligned(
        canvas,
        DISPLAY_WIDTH - 2,
        8,
        AlignRight,
        AlignBottom,
        text);
}

static void simple_app_handle_pong(SimpleApp* app) {
    if(!app) return;
    bool was_ready = app->board_ready_seen;
    app->board_ready_seen = true;
    app->board_sync_pending = false;
    app->board_ping_outstanding = false;
    app->board_last_rx_tick = furi_get_tick();
    app->board_missing_shown = false;
    if(!was_ready) {
        simple_app_show_status_message(app, "Board found", 1000, true);
        if(app->viewport) {
            view_port_update(app->viewport);
        }
    }
}

static void simple_app_send_ping(SimpleApp* app) {
    if(!app || !app->serial) return;
    const char* cmd = "ping\n";
    furi_hal_serial_tx(app->serial, (const uint8_t*)cmd, strlen(cmd));
    furi_hal_serial_tx_wait_complete(app->serial);
    app->board_ping_outstanding = true;
    app->board_last_ping_tick = furi_get_tick();
}

static void simple_app_ping_watchdog(SimpleApp* app) {
    if(!app) return;
    uint32_t now = furi_get_tick();

    // Only ping when idle on main menu (section list) and no modal status
    bool idle_menu = (app->screen == ScreenMenu) && (app->menu_state == MenuStateSections) &&
                     !simple_app_status_message_is_active(app);

    if(idle_menu && !app->board_ping_outstanding &&
       (now - app->board_last_ping_tick) >= BOARD_PING_INTERVAL_MS) {
        simple_app_send_ping(app);
    }

    if(app->board_ping_outstanding &&
       (now - app->board_last_ping_tick) >= BOARD_PING_TIMEOUT_MS) {
        app->board_ping_outstanding = false;
        app->board_ready_seen = false;
        if(!app->board_missing_shown) {
            app->board_missing_shown = true;
            simple_app_show_status_message(app, "No board", 1500, true);
        }
    }
}

static void simple_app_send_command_quiet(SimpleApp* app, const char* command) {
    if(!app || !command || !app->serial) return;

    // Block commands until board reports ready (except reboot which triggers sync)
    if(!app->board_ready_seen) {
        // Allow reboot to kick off sync
        if(strncmp(command, "reboot", 6) != 0 && strncmp(command, "ping", 4) != 0) {
            simple_app_show_status_message(app, "Waiting for board...", 1000, true);
            return;
        }
    }
    app->board_ping_outstanding = false;

    char cmd[64];
    int len = snprintf(cmd, sizeof(cmd), "%s\n", command);
    if(len <= 0) return;
    if(app->rx_stream) {
        furi_stream_buffer_reset(app->rx_stream);
    }
    furi_hal_serial_tx(app->serial, (const uint8_t*)cmd, (size_t)len);
    furi_hal_serial_tx_wait_complete(app->serial);
    char log_line[96];
    int log_len = snprintf(log_line, sizeof(log_line), "TX: %s\n", command);
    if(log_len > 0) {
        simple_app_append_serial_data(app, (const uint8_t*)log_line, (size_t)log_len);
    }
}

static void simple_app_request_led_status(SimpleApp* app) {
    if(!app || !app->serial) return;
    app->led_read_pending = true;
    app->led_read_length = 0;
    app->led_read_buffer[0] = '\0';
    simple_app_send_command_quiet(app, "led read");
}

static bool simple_app_handle_led_status_line(SimpleApp* app, const char* line) {
    if(!app || !line) return false;
    const char* status_marker = "LED status:";
    const char* status_ptr = strstr(line, status_marker);
    if(!status_ptr) return false;
    status_ptr += strlen(status_marker);
    while(*status_ptr == ' ' || *status_ptr == '\t') {
        status_ptr++;
    }
    bool enabled = app->led_enabled;
    if(status_ptr[0] != '\0') {
        if((status_ptr[0] == 'o' || status_ptr[0] == 'O') &&
           (status_ptr[1] == 'n' || status_ptr[1] == 'N')) {
            enabled = true;
        } else if((status_ptr[0] == 'o' || status_ptr[0] == 'O') &&
                  (status_ptr[1] == 'f' || status_ptr[1] == 'F')) {
            enabled = false;
        }
    }

    uint32_t level = app->led_level;
    const char* brightness_marker = "brightness";
    const char* brightness_ptr = strstr(line, brightness_marker);
    if(brightness_ptr) {
        brightness_ptr += strlen(brightness_marker);
        while(*brightness_ptr == ' ' || *brightness_ptr == ':' || *brightness_ptr == ',' ||
              *brightness_ptr == '\t') {
            brightness_ptr++;
        }
        char digits[6] = {0};
        size_t idx = 0;
        while(brightness_ptr[idx] && idx < sizeof(digits) - 1) {
            if(isdigit((unsigned char)brightness_ptr[idx])) {
                digits[idx] = brightness_ptr[idx];
            } else {
                break;
            }
            idx++;
        }
        if(idx > 0) {
            digits[idx] = '\0';
            long parsed = strtol(digits, NULL, 10);
            if(parsed >= 0) {
                level = (uint32_t)parsed;
            }
        }
    }

    if(level < 1) level = 1;
    if(level > 100) level = 100;

    app->led_enabled = enabled;
    app->led_level = (uint8_t)level;
    simple_app_update_led_label(app);

    if(app->screen == ScreenMenu && app->menu_state == MenuStateItems &&
       app->section_index == MENU_SECTION_SETUP && app->viewport) {
        view_port_update(app->viewport);
    } else if(app->screen == ScreenSetupLed && app->viewport) {
        view_port_update(app->viewport);
    }
    return true;
}

static void simple_app_led_feed(SimpleApp* app, char ch) {
    if(!app || !app->led_read_pending) return;
    if(ch == '\r') return;
    if(ch == '\n') {
        app->led_read_buffer[app->led_read_length] = '\0';
        if(simple_app_handle_led_status_line(app, app->led_read_buffer)) {
            app->led_read_pending = false;
        }
        app->led_read_length = 0;
        return;
    }
    if(app->led_read_length + 1 >= sizeof(app->led_read_buffer)) {
        app->led_read_length = 0;
        return;
    }
    app->led_read_buffer[app->led_read_length++] = ch;
}

static void simple_app_send_vendor_command(SimpleApp* app, bool enable) {
    if(!app || !app->serial) return;
    app->vendor_read_pending = true;
    app->vendor_read_length = 0;
    app->vendor_read_buffer[0] = '\0';
    char command[24];
    snprintf(command, sizeof(command), "vendor set %s", enable ? "on" : "off");
    simple_app_send_command_quiet(app, command);
}

static void simple_app_request_vendor_status(SimpleApp* app) {
    if(!app || !app->serial) return;
    app->vendor_read_pending = true;
    app->vendor_read_length = 0;
    app->vendor_read_buffer[0] = '\0';
    simple_app_send_command_quiet(app, "vendor read");
}

static bool simple_app_handle_vendor_status_line(SimpleApp* app, const char* line) {
    if(!app || !line) return false;
    static const char prefix[] = "Vendor scan:";
    size_t prefix_len = sizeof(prefix) - 1;
    if(strncmp(line, prefix, prefix_len) != 0) {
        return false;
    }

    const char* status = line + prefix_len;
    while(*status == ' ' || *status == '\t') {
        status++;
    }

    bool enabled = app->vendor_scan_enabled;
    if((status[0] == 'o' || status[0] == 'O') && (status[1] == 'n' || status[1] == 'N')) {
        enabled = true;
    } else if((status[0] == 'o' || status[0] == 'O') && (status[1] == 'f' || status[1] == 'F')) {
        enabled = false;
    } else if(status[0] == '1' || status[0] == 'Y' || status[0] == 'y' || status[0] == 'T' ||
              status[0] == 't') {
        enabled = true;
    } else if(status[0] == '0' || status[0] == 'N' || status[0] == 'n' || status[0] == 'F' ||
              status[0] == 'f') {
        enabled = false;
    }

    app->vendor_scan_enabled = enabled;
    bool changed = (app->scanner_show_vendor != enabled);
    app->scanner_show_vendor = enabled;
    if(changed) {
        simple_app_update_result_layout(app);
        simple_app_rebuild_visible_results(app);
        simple_app_adjust_result_offset(app);
        if(app->viewport && app->screen == ScreenSetupScanner) {
            view_port_update(app->viewport);
        }
    }
    return true;
}

static void simple_app_vendor_feed(SimpleApp* app, char ch) {
    if(!app || !app->vendor_read_pending) return;
    if(ch == '\r') return;
    if(ch == '\n') {
        if(app->vendor_read_length > 0) {
            app->vendor_read_buffer[app->vendor_read_length] = '\0';
            if(simple_app_handle_vendor_status_line(app, app->vendor_read_buffer)) {
                app->vendor_read_pending = false;
            }
        }
        app->vendor_read_length = 0;
        return;
    }
    if(app->vendor_read_length + 1 >= sizeof(app->vendor_read_buffer)) {
        app->vendor_read_length = 0;
        return;
    }
    app->vendor_read_buffer[app->vendor_read_length++] = ch;
}

static void simple_app_set_wardrive_status(SimpleApp* app, const char* text, bool numeric) {
    if(!app || !text) return;
    snprintf(app->wardrive_status_text, sizeof(app->wardrive_status_text), "%s", text);
    app->wardrive_status_is_numeric = numeric;
}

static void simple_app_reset_wardrive_status(SimpleApp* app) {
    if(!app) return;
    simple_app_set_wardrive_status(app, "0", true);
    app->wardrive_line_length = 0;
}

static void simple_app_process_wardrive_line(SimpleApp* app, const char* line) {
    if(!app || !line || !app->wardrive_view_active) return;

    if(strstr(line, "Wardrive task started") != NULL) {
        simple_app_set_wardrive_status(app, "Starting", false);
        return;
    }

    if(strstr(line, "Waiting for GPS fix") != NULL) {
        simple_app_set_wardrive_status(app, "waiting for GPS signal", false);
        return;
    }

    const char* logged_ptr = strstr(line, "Logged ");
    if(!logged_ptr) return;
    logged_ptr += strlen("Logged ");
    while(*logged_ptr == ' ') {
        logged_ptr++;
    }

    char digits[12];
    size_t idx = 0;
    while(isdigit((unsigned char)logged_ptr[idx]) && idx < sizeof(digits) - 1) {
        digits[idx] = logged_ptr[idx];
        idx++;
    }
    if(idx == 0) return;
    digits[idx] = '\0';

    if(strstr(line, "networks to") != NULL) {
        simple_app_set_wardrive_status(app, digits, true);
    }
}

static void simple_app_wardrive_feed(SimpleApp* app, char ch) {
    if(!app) return;
    if(!app->wardrive_view_active) {
        app->wardrive_line_length = 0;
        return;
    }
    if(ch == '\r') return;
    if(ch == '\n') {
        if(app->wardrive_line_length > 0) {
            app->wardrive_line_buffer[app->wardrive_line_length] = '\0';
            simple_app_process_wardrive_line(app, app->wardrive_line_buffer);
        }
        app->wardrive_line_length = 0;
        return;
    }
    if(app->wardrive_line_length + 1 >= sizeof(app->wardrive_line_buffer)) {
        app->wardrive_line_length = 0;
        return;
    }
    app->wardrive_line_buffer[app->wardrive_line_length++] = ch;
}

static void simple_app_force_otg_for_wardrive(SimpleApp* app) {
    if(!app) return;
    if(!app->wardrive_otg_forced) {
        app->wardrive_otg_forced = true;
        app->wardrive_otg_previous_state = app->otg_power_enabled;
    }
    if(!app->otg_power_enabled) {
        app->otg_power_enabled = true;
    }
    simple_app_apply_otg_power(app);
}

static void simple_app_restore_otg_after_wardrive(SimpleApp* app) {
    if(!app || !app->wardrive_otg_forced) return;
    app->wardrive_otg_forced = false;
    bool desired_state = app->wardrive_otg_previous_state;
    if(app->otg_power_enabled != desired_state) {
        app->otg_power_enabled = desired_state;
    }
    simple_app_apply_otg_power(app);
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

#define SIMPLE_APP_EMIT_LINE(buffer, allow_truncate) \
    do { \
        if(emitted < max_lines) { \
            if(store_lines) { \
                strncpy(lines[emitted], buffer, line_cap - 1); \
                lines[emitted][line_cap - 1] = '\0'; \
                if(allow_truncate) { \
                    simple_app_truncate_text(lines[emitted], truncate_limit); \
                } \
            } \
            emitted++; \
        } \
    } while(0)

    char first_line[line_cap];
    memset(first_line, 0, sizeof(first_line));
    snprintf(first_line, sizeof(first_line), "%u%s", (unsigned)result->number, result->selected ? "*" : "");

    bool vendor_visible = app->scanner_show_vendor && result->vendor[0] != '\0';
    bool vendor_in_first_line = false;
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
        if(vendor_visible) {
            size_t len_after_ssid = strlen(first_line);
            if(len_after_ssid < sizeof(first_line) - 1) {
                size_t remaining = sizeof(first_line) - len_after_ssid - 1;
                if(remaining > 3) {
                    size_t vendor_len = strlen(result->vendor);
                    if(vendor_len > remaining - 1) vendor_len = remaining - 1;
                    if(vendor_len > 0) {
                        first_line[len_after_ssid++] = ' ';
                        first_line[len_after_ssid++] = '(';
                        memcpy(first_line + len_after_ssid, result->vendor, vendor_len);
                        len_after_ssid += vendor_len;
                        if(len_after_ssid < sizeof(first_line) - 1) {
                            first_line[len_after_ssid++] = ')';
                            first_line[len_after_ssid] = '\0';
                            vendor_in_first_line = true;
                        } else {
                            first_line[sizeof(first_line) - 1] = '\0';
                        }
                    }
                }
            }
        }
    } else if(vendor_visible) {
        size_t len = strlen(first_line);
        if(len < sizeof(first_line) - 1) {
            size_t remaining = sizeof(first_line) - len - 1;
            if(remaining > 0) {
                first_line[len++] = ' ';
                size_t vendor_len = strlen(result->vendor);
                if(vendor_len > remaining) vendor_len = remaining;
                memcpy(first_line + len, result->vendor, vendor_len);
                len += vendor_len;
                first_line[len] = '\0';
                vendor_in_first_line = true;
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

    SIMPLE_APP_EMIT_LINE(first_line, false);

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
        SIMPLE_APP_EMIT_LINE(bssid_line, true);
    }

    if(emitted < max_lines && vendor_visible && !vendor_in_first_line) {
        char vendor_line[line_cap];
        memset(vendor_line, 0, sizeof(vendor_line));
        size_t len = 0;
        vendor_line[len++] = ' ';
        if(len < sizeof(vendor_line) - 1) {
            size_t remaining = sizeof(vendor_line) - len - 1;
            size_t vendor_len = strlen(result->vendor);
            if(vendor_len > remaining) vendor_len = remaining;
            memcpy(vendor_line + len, result->vendor, vendor_len);
            len += vendor_len;
            vendor_line[len] = '\0';
        } else {
            vendor_line[sizeof(vendor_line) - 1] = '\0';
        }
        SIMPLE_APP_EMIT_LINE(vendor_line, true);
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
            SIMPLE_APP_EMIT_LINE(info_line, true);
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
            SIMPLE_APP_EMIT_LINE(info_line, true);
        }
    }

    if(emitted == 0) {
        char fallback_line[line_cap];
        strncpy(fallback_line, "-", sizeof(fallback_line) - 1);
        fallback_line[sizeof(fallback_line) - 1] = '\0';
        SIMPLE_APP_EMIT_LINE(fallback_line, true);
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
    app->karma_status_active = false;
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
    if(!value) return current;
    size_t len = strlen(value);
    if(len == 0) return current;

    char c0 = (char)tolower((unsigned char)value[0]);
    char c1 = (len > 1) ? (char)tolower((unsigned char)value[1]) : '\0';

    // Textual checks: on/yes/true, off/no/false
    if((c0 == 'o' && c1 == 'n') || (c0 == 'y' && c1 == 'e') || (c0 == 't' && c1 == 'r')) {
        return true;
    }
    if((c0 == 'o' && c1 == 'f') || (c0 == 'n' && c1 == 'o') || (c0 == 'f' && c1 == 'a')) {
        return false;
    }

    // Single digit shortcuts
    if(c0 == '1') return true;
    if(c0 == '0') return false;

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
    } else if(strcmp(key, "show_vendor") == 0) {
        app->scanner_show_vendor = simple_app_parse_bool_value(value, app->scanner_show_vendor);
    } else if(strcmp(key, "min_power") == 0) {
        app->scanner_min_power = (int16_t)strtol(value, NULL, 10);
    } else if(strcmp(key, "backlight_enabled") == 0) {
        app->backlight_enabled = simple_app_parse_bool_value(value, app->backlight_enabled);
    } else if(strcmp(key, "otg_power_enabled") == 0) {
        app->otg_power_enabled = simple_app_parse_bool_value(value, app->otg_power_enabled);
    } else if(strcmp(key, "karma_duration") == 0) {
        app->karma_sniffer_duration_sec = (uint32_t)strtoul(value, NULL, 10);
    } else if(strcmp(key, "led_enabled") == 0) {
        app->led_enabled = simple_app_parse_bool_value(value, app->led_enabled);
    } else if(strcmp(key, "led_level") == 0) {
        long parsed = strtol(value, NULL, 10);
        if(parsed >= 0) {
            if(parsed > 255) {
                parsed = 255;
            }
            app->led_level = (uint8_t)parsed;
        }
    } else if(strcmp(key, "boot_short_status") == 0) {
        app->boot_short_enabled = simple_app_parse_bool_value(value, app->boot_short_enabled);
    } else if(strcmp(key, "boot_long_status") == 0) {
        app->boot_long_enabled = simple_app_parse_bool_value(value, app->boot_long_enabled);
    } else if(strcmp(key, "boot_short") == 0) {
        for(uint8_t i = 0; i < BOOT_COMMAND_OPTION_COUNT; i++) {
            if(strcmp(value, boot_command_options[i]) == 0) {
                app->boot_short_command_index = i;
                break;
            }
        }
    } else if(strcmp(key, "boot_long") == 0) {
        for(uint8_t i = 0; i < BOOT_COMMAND_OPTION_COUNT; i++) {
            if(strcmp(value, boot_command_options[i]) == 0) {
                app->boot_long_command_index = i;
                break;
            }
        }
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
    if(storage_file_open(file, EXT_PATH(LAB_C5_CONFIG_FILE_PATH), FSAM_READ_WRITE, FSOM_CREATE_ALWAYS)) {
        char buffer[512];
        uint8_t short_idx = (app->boot_short_command_index < BOOT_COMMAND_OPTION_COUNT)
                                ? app->boot_short_command_index
                                : 0;
        uint8_t long_idx = (app->boot_long_command_index < BOOT_COMMAND_OPTION_COUNT)
                               ? app->boot_long_command_index
                               : 0;
        int len = snprintf(
            buffer,
            sizeof(buffer),
            "show_ssid=%d\n"
            "show_bssid=%d\n"
            "show_channel=%d\n"
            "show_security=%d\n"
            "show_power=%d\n"
            "show_band=%d\n"
            "show_vendor=%d\n"
            "min_power=%d\n"
            "backlight_enabled=%d\n"
            "otg_power_enabled=%d\n"
            "karma_duration=%lu\n"
            "boot_short_status=%d\n"
            "boot_short=%s\n"
            "boot_long_status=%d\n"
            "boot_long=%s\n",
            app->scanner_show_ssid ? 1 : 0,
            app->scanner_show_bssid ? 1 : 0,
            app->scanner_show_channel ? 1 : 0,
            app->scanner_show_security ? 1 : 0,
            app->scanner_show_power ? 1 : 0,
            app->scanner_show_band ? 1 : 0,
            app->scanner_show_vendor ? 1 : 0,
            (int)app->scanner_min_power,
            app->backlight_enabled ? 1 : 0,
            app->otg_power_enabled ? 1 : 0,
            (unsigned long)app->karma_sniffer_duration_sec,
            app->boot_short_enabled ? 1 : 0,
            boot_command_options[short_idx],
            app->boot_long_enabled ? 1 : 0,
            boot_command_options[long_idx]);
        if(len > 0 && len < (int)sizeof(buffer)) {
            size_t written = storage_file_write(file, buffer, (size_t)len);
            if(written == (size_t)len) {
                success = true;
            } else {
                FURI_LOG_E(TAG, "Config write short (%u/%u)", (unsigned)written, (unsigned)len);
            }
        } else {
            FURI_LOG_E(TAG, "Config buffer overflow (%d)", len);
        }
        storage_file_close(file);
    } else {
        FURI_LOG_E(TAG, "Config open for write failed");
    }
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
    if(success) {
        app->config_dirty = false;
        if(success_message) {
            simple_app_show_status_message(app, success_message, 2000, fullscreen);
        }
    } else if(success_message) {
        simple_app_show_status_message(app, "Config save failed", 2000, true);
    }
    return success;
}

static void simple_app_load_config(SimpleApp* app) {
    if(!app) return;
    Storage* storage = furi_record_open(RECORD_STORAGE);
    if(!storage) return;
    storage_simply_mkdir(storage, EXT_PATH("apps_assets"));
    storage_simply_mkdir(storage, EXT_PATH(LAB_C5_CONFIG_DIR_PATH));
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
        simple_app_show_status_message(app, "Config loaded", 2500, true);
        app->config_dirty = false;
    } else {
        bool created = simple_app_save_config(app, NULL, false);
        if(created) {
            simple_app_show_status_message(app, "Config created", 2500, true);
            app->config_dirty = false;
        } else {
            simple_app_show_status_message(app, "Config write failed", 2000, true);
            simple_app_mark_config_dirty(app);
        }
    }
    if(app->scanner_min_power > SCAN_POWER_MAX_DBM) {
        app->scanner_min_power = SCAN_POWER_MAX_DBM;
    } else if(app->scanner_min_power < SCAN_POWER_MIN_DBM) {
        app->scanner_min_power = SCAN_POWER_MIN_DBM;
    }
    if(app->karma_sniffer_duration_sec < KARMA_SNIFFER_DURATION_MIN_SEC) {
        app->karma_sniffer_duration_sec = KARMA_SNIFFER_DURATION_MIN_SEC;
    } else if(app->karma_sniffer_duration_sec > KARMA_SNIFFER_DURATION_MAX_SEC) {
        app->karma_sniffer_duration_sec = KARMA_SNIFFER_DURATION_MAX_SEC;
    }
    if(app->led_level < 1) {
        app->led_level = 1;
    } else if(app->led_level > 100) {
        app->led_level = 100;
    }
    if(app->boot_short_command_index >= BOOT_COMMAND_OPTION_COUNT) {
        app->boot_short_command_index = 1;
    }
    if(app->boot_long_command_index >= BOOT_COMMAND_OPTION_COUNT) {
        app->boot_long_command_index = 0;
    }
    simple_app_reset_karma_probe_listing(app);
    simple_app_reset_karma_probe_listing(app);
    simple_app_update_karma_duration_label(app);
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

    char fields[8][SCAN_FIELD_BUFFER_LEN];
    for(size_t i = 0; i < 8; i++) {
        memset(fields[i], 0, SCAN_FIELD_BUFFER_LEN);
    }

    size_t field_count = simple_app_parse_quoted_fields(cursor, fields, 8);
    if(field_count < 8) return;

    ScanResult* result = &app->scan_results[app->scan_result_count];
    memset(result, 0, sizeof(ScanResult));
    result->number = (uint16_t)strtoul(fields[0], NULL, 10);
    simple_app_copy_field(result->ssid, sizeof(result->ssid), fields[1], "<hidden>");
    simple_app_copy_field(result->vendor, sizeof(result->vendor), fields[2], "");
    simple_app_copy_field(result->bssid, sizeof(result->bssid), fields[3], "??:??:??:??:??:??");
    simple_app_copy_field(result->channel, sizeof(result->channel), fields[4], "?");
    simple_app_copy_field(result->security, sizeof(result->security), fields[5], "Unknown");
    simple_app_copy_field(result->power_display, sizeof(result->power_display), fields[6], "?");
    simple_app_copy_field(result->band, sizeof(result->band), fields[7], "?");

    const char* power_str = fields[6];
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

static void simple_app_reset_result_scroll(SimpleApp* app) {
    if(!app) return;
    app->result_scroll_offset = 0;
    app->result_scroll_direction = 1;
    app->result_scroll_hold = RESULT_SCROLL_EDGE_PAUSE_STEPS;
    app->result_scroll_last_tick = furi_get_tick();
    app->result_scroll_text[0] = '\0';
}

static void simple_app_reset_sd_scroll(SimpleApp* app) {
    if(!app) return;
    app->sd_scroll_offset = 0;
    app->sd_scroll_direction = 1;
    app->sd_scroll_hold = RESULT_SCROLL_EDGE_PAUSE_STEPS;
    app->sd_scroll_last_tick = furi_get_tick();
    app->sd_scroll_char_limit = 0;
    app->sd_scroll_text[0] = '\0';
}

static void simple_app_update_result_scroll(SimpleApp* app) {
    if(!app) return;

    if(app->screen != ScreenResults) {
        if(app->result_scroll_text[0] != '\0' || app->result_scroll_offset != 0) {
            simple_app_reset_result_scroll(app);
        }
        return;
    }

    if(app->visible_result_count == 0) {
        if(app->result_scroll_text[0] != '\0' || app->result_scroll_offset != 0) {
            simple_app_reset_result_scroll(app);
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
        return;
    }

    const ScanResult* result = simple_app_visible_result_const(app, app->scan_result_index);
    if(!result) {
        if(app->result_scroll_text[0] != '\0' || app->result_scroll_offset != 0) {
            simple_app_reset_result_scroll(app);
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
        return;
    }

    char first_line_buffer[1][64];
    memset(first_line_buffer, 0, sizeof(first_line_buffer));
    size_t produced = simple_app_build_result_lines(app, result, first_line_buffer, 1);
    if(produced == 0) {
        if(app->result_scroll_text[0] != '\0' || app->result_scroll_offset != 0) {
            simple_app_reset_result_scroll(app);
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
        return;
    }

    const char* full_line = first_line_buffer[0];
    if(strncmp(full_line, app->result_scroll_text, sizeof(app->result_scroll_text)) != 0) {
        strncpy(app->result_scroll_text, full_line, sizeof(app->result_scroll_text) - 1);
        app->result_scroll_text[sizeof(app->result_scroll_text) - 1] = '\0';
        app->result_scroll_offset = 0;
        app->result_scroll_direction = 1;
        app->result_scroll_hold = RESULT_SCROLL_EDGE_PAUSE_STEPS;
        app->result_scroll_last_tick = furi_get_tick();
        if(app->viewport) {
            view_port_update(app->viewport);
        }
        return;
    }

    size_t char_limit = (app->result_char_limit > 0) ? app->result_char_limit : RESULT_DEFAULT_CHAR_LIMIT;
    if(char_limit == 0) char_limit = 1;
    if(char_limit >= sizeof(first_line_buffer[0])) {
        char_limit = sizeof(first_line_buffer[0]) - 1;
        if(char_limit == 0) char_limit = 1;
    }

    size_t line_length = strlen(app->result_scroll_text);
    if(line_length <= char_limit) {
        if(app->result_scroll_offset != 0) {
            app->result_scroll_offset = 0;
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
        return;
    }

    size_t max_offset = line_length - char_limit;
    uint32_t now = furi_get_tick();
    uint32_t interval_ticks = furi_ms_to_ticks(RESULT_SCROLL_INTERVAL_MS);
    if(interval_ticks == 0) interval_ticks = 1;
    if((now - app->result_scroll_last_tick) < interval_ticks) {
        return;
    }
    app->result_scroll_last_tick = now;

    if(app->result_scroll_hold > 0) {
        app->result_scroll_hold--;
        return;
    }

    bool changed = false;
    if(app->result_scroll_direction > 0) {
        if(app->result_scroll_offset < max_offset) {
            app->result_scroll_offset++;
            changed = true;
            if(app->result_scroll_offset >= max_offset) {
                app->result_scroll_direction = -1;
                app->result_scroll_hold = RESULT_SCROLL_EDGE_PAUSE_STEPS;
            }
        } else {
            app->result_scroll_direction = -1;
            app->result_scroll_hold = RESULT_SCROLL_EDGE_PAUSE_STEPS;
        }
    } else {
        if(app->result_scroll_offset > 0) {
            app->result_scroll_offset--;
            changed = true;
            if(app->result_scroll_offset == 0) {
                app->result_scroll_direction = 1;
                app->result_scroll_hold = RESULT_SCROLL_EDGE_PAUSE_STEPS;
            }
        } else {
            app->result_scroll_direction = 1;
            app->result_scroll_hold = RESULT_SCROLL_EDGE_PAUSE_STEPS;
        }
    }

    if(changed && app->viewport) {
        view_port_update(app->viewport);
    }
}

static void simple_app_update_sd_scroll(SimpleApp* app) {
    if(!app) return;

    bool sd_popup_active =
        app->sd_folder_popup_active || app->sd_file_popup_active || app->sd_delete_confirm_active;

    if(!sd_popup_active || app->sd_scroll_char_limit == 0 || app->sd_scroll_text[0] == '\0') {
        if(app->sd_scroll_text[0] != '\0' || app->sd_scroll_offset != 0) {
            simple_app_reset_sd_scroll(app);
        }
        return;
    }

    size_t len = strlen(app->sd_scroll_text);
    size_t char_limit = app->sd_scroll_char_limit;
    if(char_limit == 0) char_limit = 1;
    if(len <= char_limit) {
        if(app->sd_scroll_offset != 0) {
            simple_app_reset_sd_scroll(app);
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
        return;
    }

    size_t max_offset = len - char_limit;
    uint32_t now = furi_get_tick();
    uint32_t interval_ticks = furi_ms_to_ticks(RESULT_SCROLL_INTERVAL_MS);
    if(interval_ticks == 0) interval_ticks = 1;
    if((now - app->sd_scroll_last_tick) < interval_ticks) {
        return;
    }
    app->sd_scroll_last_tick = now;

    if(app->sd_scroll_hold > 0) {
        app->sd_scroll_hold--;
        return;
    }

    bool changed = false;
    if(app->sd_scroll_direction > 0) {
        if(app->sd_scroll_offset < max_offset) {
            app->sd_scroll_offset++;
            changed = true;
            if(app->sd_scroll_offset >= max_offset) {
                app->sd_scroll_direction = -1;
                app->sd_scroll_hold = RESULT_SCROLL_EDGE_PAUSE_STEPS;
            }
        } else {
            app->sd_scroll_direction = -1;
            app->sd_scroll_hold = RESULT_SCROLL_EDGE_PAUSE_STEPS;
        }
    } else {
        if(app->sd_scroll_offset > 0) {
            app->sd_scroll_offset--;
            changed = true;
            if(app->sd_scroll_offset == 0) {
                app->sd_scroll_direction = 1;
                app->sd_scroll_hold = RESULT_SCROLL_EDGE_PAUSE_STEPS;
            }
        } else {
            app->sd_scroll_direction = 1;
            app->sd_scroll_hold = RESULT_SCROLL_EDGE_PAUSE_STEPS;
        }
    }

    if(changed && app->viewport) {
        view_port_update(app->viewport);
    }
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
    simple_app_reset_result_scroll(app);
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

static size_t simple_app_visible_serial_lines(const SimpleApp* app) {
    if(!app) return SERIAL_VISIBLE_LINES;
    if(app->screen == ScreenConsole) {
        return CONSOLE_VISIBLE_LINES;
    }
    if(app->screen == ScreenSerial && app->wardrive_view_active) {
        return WARD_DRIVE_CONSOLE_LINES;
    }
    return SERIAL_VISIBLE_LINES;
}

static size_t simple_app_max_scroll(SimpleApp* app) {
    size_t total = simple_app_total_display_lines(app);
    size_t visible_lines = simple_app_visible_serial_lines(app);
    if(total <= visible_lines) return 0;
    return total - visible_lines;
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

    if(!app->serial_targets_hint && !app->blackout_view_active) {
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
        simple_app_package_monitor_feed(app, ch);
        simple_app_channel_view_feed(app, ch);
        simple_app_portal_ssid_feed(app, ch);
        simple_app_sd_feed(app, ch);
        simple_app_evil_twin_feed(app, ch);
        simple_app_karma_probe_feed(app, ch);
        simple_app_karma_html_feed(app, ch);
        simple_app_led_feed(app, ch);
        simple_app_boot_feed(app, ch);
        simple_app_vendor_feed(app, ch);
        simple_app_wardrive_feed(app, ch);
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

    bool is_wardrive_command = strstr(command, "start_wardrive") != NULL;
    bool is_stop_command = strcmp(command, "stop") == 0;
    if(is_wardrive_command) {
        app->wardrive_view_active = true;
        simple_app_reset_wardrive_status(app);
        simple_app_force_otg_for_wardrive(app);
    } else if(app->wardrive_view_active) {
        app->wardrive_view_active = false;
        simple_app_reset_wardrive_status(app);
    }
    if(is_stop_command) {
        simple_app_restore_otg_after_wardrive(app);
    }

    app->serial_targets_hint = false;
    if(strcmp(command, "start_blackout") != 0) {
        app->blackout_view_active = false;
    }

    char cmd[160];
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

static bool simple_app_command_requires_select_networks(const char* base_command) {
    if(!base_command || base_command[0] == '\0') return false;
    return (strcmp(base_command, "start_deauth") == 0 || strcmp(base_command, "start_evil_twin") == 0 ||
            strcmp(base_command, "sae_overflow") == 0);
}

static void simple_app_send_command_with_targets(SimpleApp* app, const char* base_command) {
    if(!app || !base_command || base_command[0] == '\0') return;
    bool requires_select_networks = simple_app_command_requires_select_networks(base_command);
    if(app->scan_selected_count == 0 && requires_select_networks) {
        simple_app_show_status_message(app, "Please select\nnetwork first", 1500, true);
        if(app->viewport) {
            view_port_update(app->viewport);
        }
        return;
    }

    if(requires_select_networks) {
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
    app->blackout_view_active = false;
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
        size_t max_scroll = simple_app_max_scroll(app);
        bool show_up = (app->serial_scroll > 0);
        bool show_down = (app->serial_scroll < max_scroll);
        if(show_up || show_down) {
            uint8_t arrow_x = DISPLAY_WIDTH - 6;
            int16_t content_top = 8;
            int16_t visible_rows =
                (CONSOLE_VISIBLE_LINES > 0) ? (CONSOLE_VISIBLE_LINES - 1) : 0;
            int16_t content_bottom = 8 + (int16_t)(visible_rows * SERIAL_TEXT_LINE_HEIGHT);
            simple_app_draw_scroll_hints(canvas, arrow_x, content_top, content_bottom, show_up, show_down);
        }
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
            app->blackout_view_active = true;
            app->serial_targets_hint = false;
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

static void simple_app_package_monitor_reset(SimpleApp* app) {
    if(!app) return;
    memset(app->package_monitor_history, 0, sizeof(app->package_monitor_history));
    app->package_monitor_history_count = 0;
    app->package_monitor_last_value = 0;
    app->package_monitor_line_length = 0;
    app->package_monitor_dirty = true;
    app->package_monitor_last_channel_tick = 0;
}

static void simple_app_package_monitor_process_line(SimpleApp* app, const char* line) {
    if(!app || !line) return;

    while(*line == '>' || *line == ' ') {
        line++;
    }
    if(*line == '\0') return;

    if(strstr(line, "monitor started on channel") != NULL) {
        const char* digits = line;
        while(*digits && !isdigit((unsigned char)*digits)) {
            digits++;
        }
        if(*digits) {
            unsigned long channel = strtoul(digits, NULL, 10);
            if(channel == 0 || channel > PACKAGE_MONITOR_TOTAL_CHANNELS) {
                channel = PACKAGE_MONITOR_DEFAULT_CHANNEL;
            }
            app->package_monitor_channel = (uint8_t)channel;
        }
        app->package_monitor_active = true;
        app->package_monitor_dirty = true;
        return;
    }

    if(strstr(line, "monitor stopped") != NULL) {
        app->package_monitor_active = false;
        app->package_monitor_dirty = true;
        return;
    }

    size_t len = strlen(line);
    if(len < 4) return;

    if(strcmp(line + len - 4, "pkts") == 0) {
        const char* digits = line;
        while(*digits && !isdigit((unsigned char)*digits)) {
            digits++;
        }
        if(!*digits) return;

        unsigned long value = strtoul(digits, NULL, 10);
        if(value > UINT16_MAX) {
            value = UINT16_MAX;
        }
        app->package_monitor_last_value = (uint16_t)value;

        if(app->package_monitor_history_count < PACKAGE_MONITOR_MAX_HISTORY) {
            app->package_monitor_history[app->package_monitor_history_count++] = (uint16_t)value;
        } else {
            memmove(
                app->package_monitor_history,
                app->package_monitor_history + 1,
                (PACKAGE_MONITOR_MAX_HISTORY - 1) *
                    sizeof(app->package_monitor_history[0]));
            app->package_monitor_history[PACKAGE_MONITOR_MAX_HISTORY - 1] = (uint16_t)value;
        }
        app->package_monitor_dirty = true;
    }
}

static void simple_app_package_monitor_feed(SimpleApp* app, char ch) {
    if(!app) return;

    if(ch == '\r') return;

    if(ch == '\n') {
        if(app->package_monitor_line_length > 0) {
            app->package_monitor_line_buffer[app->package_monitor_line_length] = '\0';
            simple_app_package_monitor_process_line(app, app->package_monitor_line_buffer);
        }
        app->package_monitor_line_length = 0;
        return;
    }

    if(app->package_monitor_line_length + 1 >= sizeof(app->package_monitor_line_buffer)) {
        app->package_monitor_line_length = 0;
        return;
    }

    app->package_monitor_line_buffer[app->package_monitor_line_length++] = ch;
}

static void simple_app_package_monitor_start(SimpleApp* app, uint8_t channel, bool reset_history) {
    if(!app) return;

    if(channel < 1) {
        channel = PACKAGE_MONITOR_DEFAULT_CHANNEL;
    }
    if(channel > PACKAGE_MONITOR_TOTAL_CHANNELS) {
        channel = PACKAGE_MONITOR_TOTAL_CHANNELS;
    }

    if(reset_history) {
        simple_app_package_monitor_reset(app);
    }

    simple_app_send_stop_if_needed(app);

    char command[32];
    snprintf(command, sizeof(command), "%s %u", PACKAGE_MONITOR_COMMAND, (unsigned)channel);
    simple_app_send_command(app, command, false);

    app->package_monitor_channel = channel;
    app->package_monitor_active = true;
    app->package_monitor_dirty = true;
    uint32_t now = furi_get_tick();
    if(reset_history) {
        uint32_t cooldown = furi_ms_to_ticks(PACKAGE_MONITOR_CHANNEL_SWITCH_COOLDOWN_MS);
        app->package_monitor_last_channel_tick = (now > cooldown) ? (now - cooldown) : 0;
    } else {
        app->package_monitor_last_channel_tick = now;
    }
}

static void simple_app_package_monitor_stop(SimpleApp* app) {
    if(!app) return;
    if(app->package_monitor_active || app->last_command_sent) {
        simple_app_send_stop_if_needed(app);
    }
    app->package_monitor_active = false;
    app->package_monitor_dirty = true;
}

static void simple_app_package_monitor_enter(SimpleApp* app) {
    if(!app) return;
    if(app->package_monitor_channel < 1 || app->package_monitor_channel > PACKAGE_MONITOR_TOTAL_CHANNELS) {
        app->package_monitor_channel = PACKAGE_MONITOR_DEFAULT_CHANNEL;
    }
    app->screen = ScreenPackageMonitor;
    simple_app_package_monitor_start(app, app->package_monitor_channel, true);
    if(app->viewport) {
        view_port_update(app->viewport);
    }
}

static void simple_app_draw_package_monitor(SimpleApp* app, Canvas* canvas) {
    if(!app || !canvas) return;

    canvas_set_color(canvas, ColorBlack);

    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 4, 12, "Package Monitor");

    uint8_t channel = app->package_monitor_channel;
    if(channel < 1 || channel > PACKAGE_MONITOR_TOTAL_CHANNELS) {
        channel = PACKAGE_MONITOR_DEFAULT_CHANNEL;
    }

    char channel_text[32];
    snprintf(
        channel_text,
        sizeof(channel_text),
        "Ch %02u/%02u",
        (unsigned)channel,
        (unsigned)PACKAGE_MONITOR_TOTAL_CHANNELS);
    char value_text[24];
    snprintf(value_text, sizeof(value_text), "%upkts", (unsigned)app->package_monitor_last_value);

    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str(canvas, 4, 24, channel_text);
    canvas_draw_str_aligned(canvas, DISPLAY_WIDTH - 2, 24, AlignRight, AlignBottom, value_text);

    const int16_t frame_x = 2;
    const int16_t frame_y = 28;
    const int16_t frame_w = DISPLAY_WIDTH - 4;
    const int16_t frame_h = 34;

    canvas_draw_line(canvas, frame_x, frame_y, frame_x + frame_w, frame_y);
    canvas_draw_line(canvas, frame_x, frame_y + frame_h, frame_x + frame_w, frame_y + frame_h);
    canvas_draw_line(canvas, frame_x, frame_y, frame_x, frame_y + frame_h);
    canvas_draw_line(canvas, frame_x + frame_w, frame_y, frame_x + frame_w, frame_y + frame_h);

    const int16_t graph_left = frame_x + 1;
    const int16_t graph_right = frame_x + frame_w - 1;
    const int16_t graph_top = frame_y + 1;
    const int16_t graph_bottom = frame_y + frame_h - 1;
    const int16_t graph_width_px = graph_right - graph_left + 1;
    const int16_t graph_height_px = graph_bottom - graph_top + 1;

    if(graph_width_px <= 0 || graph_height_px <= 0) {
        app->package_monitor_dirty = false;
        return;
    }

    if(app->package_monitor_history_count == 0) {
        const char* message = app->package_monitor_active ? "Waiting for data" : "Press OK to restart";
        canvas_draw_str_aligned(
            canvas,
            graph_left + graph_width_px / 2,
            graph_top + graph_height_px / 2,
            AlignCenter,
            AlignCenter,
            message);
        app->package_monitor_dirty = false;
        return;
    }

    uint16_t max_value = 0;
    for(size_t i = 0; i < app->package_monitor_history_count; i++) {
        if(app->package_monitor_history[i] > max_value) {
            max_value = app->package_monitor_history[i];
        }
    }
    if(max_value == 0) {
        max_value = 1;
    }

    size_t sample_count = app->package_monitor_history_count;
    size_t slot_capacity = (PACKAGE_MONITOR_BAR_SPACING > 0)
                               ? ((size_t)(graph_width_px - 1) / PACKAGE_MONITOR_BAR_SPACING) + 1
                               : (size_t)graph_width_px;
    if(slot_capacity == 0) {
        slot_capacity = 1;
    }
    size_t visible_samples = (sample_count < slot_capacity) ? sample_count : slot_capacity;
    size_t start_index = (sample_count > visible_samples) ? (sample_count - visible_samples) : 0;

    for(size_t idx = start_index; idx < sample_count; idx++) {
        size_t relative = idx - start_index;
        int16_t x = graph_right - (int16_t)(relative * PACKAGE_MONITOR_BAR_SPACING);
        if(x < graph_left) {
            break;
        }

        uint16_t value = app->package_monitor_history[idx];
        int16_t bar_height = 0;
        if(value > 0) {
            bar_height = (int16_t)((value * (uint32_t)(graph_height_px - 1)) / max_value);
            if(bar_height == 0) {
                bar_height = 1;
            }
        }
        int16_t bar_top = graph_bottom - bar_height;
        if(bar_top < graph_top) {
            bar_top = graph_top;
        }
        canvas_draw_line(canvas, x, graph_bottom, x, bar_top);
    }

    app->package_monitor_dirty = false;
}

static void simple_app_handle_package_monitor_input(SimpleApp* app, InputKey key) {
    if(!app) return;

    if(key == InputKeyBack) {
        simple_app_package_monitor_stop(app);
        app->menu_state = MenuStateItems;
        app->section_index = MENU_SECTION_MONITORING;
        app->item_index = 0;
        app->item_offset = 0;
        app->screen = ScreenMenu;
        app->package_monitor_dirty = false;
        if(app->viewport) {
            view_port_update(app->viewport);
        }
        return;
    }

    uint32_t now = furi_get_tick();
    uint32_t cooldown_ticks = furi_ms_to_ticks(PACKAGE_MONITOR_CHANNEL_SWITCH_COOLDOWN_MS);
    bool can_switch =
        (app->package_monitor_last_channel_tick == 0) ||
        ((now - app->package_monitor_last_channel_tick) >= cooldown_ticks);

    if(key == InputKeyUp) {
        if(!can_switch) {
            return;
        }
        if(app->package_monitor_channel < PACKAGE_MONITOR_TOTAL_CHANNELS) {
            uint8_t next_channel = app->package_monitor_channel + 1;
            simple_app_package_monitor_reset(app);
            simple_app_package_monitor_start(app, next_channel, false);
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
    } else if(key == InputKeyDown) {
        if(!can_switch) {
            return;
        }
        if(app->package_monitor_channel > 1) {
            uint8_t prev_channel = app->package_monitor_channel - 1;
            simple_app_package_monitor_reset(app);
            simple_app_package_monitor_start(app, prev_channel, false);
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
    } else if(key == InputKeyOk) {
        simple_app_package_monitor_start(app, app->package_monitor_channel, true);
        if(app->viewport) {
            view_port_update(app->viewport);
        }
    }
}

static int simple_app_channel_view_find_channel_index(const uint8_t* list, size_t count, uint8_t channel) {
    if(!list || count == 0) return -1;
    for(size_t i = 0; i < count; i++) {
        if(list[i] == channel) {
            return (int)i;
        }
    }
    return -1;
}

static size_t simple_app_channel_view_visible_columns(ChannelViewBand band) {
    return (band == ChannelViewBand5) ? CHANNEL_VIEW_VISIBLE_COLUMNS_5 : CHANNEL_VIEW_VISIBLE_COLUMNS_24;
}

static uint8_t simple_app_channel_view_max_offset(ChannelViewBand band) {
    size_t total = (band == ChannelViewBand5) ? CHANNEL_VIEW_5GHZ_CHANNEL_COUNT : CHANNEL_VIEW_24GHZ_CHANNEL_COUNT;
    size_t visible = simple_app_channel_view_visible_columns(band);
    if(total <= visible) {
        return 0;
    }
    return (uint8_t)(total - visible);
}

static uint8_t* simple_app_channel_view_offset_ptr(SimpleApp* app, ChannelViewBand band) {
    return (band == ChannelViewBand5) ? &app->channel_view_offset_5 : &app->channel_view_offset_24;
}

static bool simple_app_channel_view_adjust_offset(SimpleApp* app, ChannelViewBand band, int delta) {
    if(!app || delta == 0) return false;
    uint8_t* offset = simple_app_channel_view_offset_ptr(app, band);
    uint8_t max_offset = simple_app_channel_view_max_offset(band);
    int new_offset = (int)*offset + delta;
    if(new_offset < 0) {
        new_offset = 0;
    } else if(new_offset > (int)max_offset) {
        new_offset = (int)max_offset;
    }
    if(new_offset == (int)*offset) {
        return false;
    }
    *offset = (uint8_t)new_offset;
    app->channel_view_dirty = true;
    return true;
}

static void simple_app_channel_view_show_status(SimpleApp* app, const char* status) {
    if(!app) return;
    if(status && status[0] != '\0') {
        strncpy(app->channel_view_status_text, status, sizeof(app->channel_view_status_text) - 1);
        app->channel_view_status_text[sizeof(app->channel_view_status_text) - 1] = '\0';
        app->channel_view_has_status = true;
    } else {
        app->channel_view_status_text[0] = '\0';
        app->channel_view_has_status = false;
    }
    app->channel_view_dirty = true;
}

static void simple_app_channel_view_reset(SimpleApp* app) {
    if(!app) return;
    memset(app->channel_view_counts_24, 0, sizeof(app->channel_view_counts_24));
    memset(app->channel_view_counts_5, 0, sizeof(app->channel_view_counts_5));
    memset(app->channel_view_working_counts_24, 0, sizeof(app->channel_view_working_counts_24));
    memset(app->channel_view_working_counts_5, 0, sizeof(app->channel_view_working_counts_5));
    app->channel_view_line_length = 0;
    app->channel_view_section = ChannelViewSectionNone;
    app->channel_view_dataset_active = false;
    app->channel_view_has_data = false;
    app->channel_view_has_status = false;
    app->channel_view_status_text[0] = '\0';
    app->channel_view_dirty = true;
}

static void simple_app_channel_view_begin_dataset(SimpleApp* app) {
    if(!app) return;
    memset(app->channel_view_working_counts_24, 0, sizeof(app->channel_view_working_counts_24));
    memset(app->channel_view_working_counts_5, 0, sizeof(app->channel_view_working_counts_5));
    app->channel_view_section = ChannelViewSectionNone;
    app->channel_view_dataset_active = true;
}

static void simple_app_channel_view_commit_dataset(SimpleApp* app) {
    if(!app) return;
    memcpy(app->channel_view_counts_24, app->channel_view_working_counts_24, sizeof(app->channel_view_counts_24));
    memcpy(app->channel_view_counts_5, app->channel_view_working_counts_5, sizeof(app->channel_view_counts_5));
    app->channel_view_dataset_active = false;
    app->channel_view_has_data = true;
    app->channel_view_dirty = true;
}

static void simple_app_channel_view_start(SimpleApp* app) {
    if(!app) return;
    simple_app_send_stop_if_needed(app);
    simple_app_channel_view_reset(app);
    app->channel_view_active = true;
    simple_app_send_command(app, CHANNEL_VIEW_COMMAND, false);
    simple_app_channel_view_show_status(app, "Scanning...");
}

static void simple_app_channel_view_stop(SimpleApp* app) {
    if(!app) return;
    if(app->channel_view_active) {
        app->channel_view_active = false;
    }
    app->channel_view_dataset_active = false;
    simple_app_send_stop_if_needed(app);
    app->channel_view_dirty = true;
}

static void simple_app_channel_view_enter(SimpleApp* app) {
    if(!app) return;
    if(app->channel_view_band != ChannelViewBand24 && app->channel_view_band != ChannelViewBand5) {
        app->channel_view_band = ChannelViewBand24;
    }
    uint8_t* offset_ptr = simple_app_channel_view_offset_ptr(app, app->channel_view_band);
    uint8_t max_offset = simple_app_channel_view_max_offset(app->channel_view_band);
    if(*offset_ptr > max_offset) {
        *offset_ptr = max_offset;
    }
    app->screen = ScreenChannelView;
    simple_app_channel_view_start(app);
    if(app->viewport) {
        view_port_update(app->viewport);
    }
}

static void simple_app_channel_view_process_line(SimpleApp* app, const char* line) {
    if(!app || !line) return;

    while(*line == '>' || *line == ' ') {
        line++;
    }
    if(*line == '\0') return;

    if(strncmp(line, "channel_view_start", 18) == 0) {
        simple_app_channel_view_begin_dataset(app);
        simple_app_channel_view_show_status(app, "Scanning...");
        return;
    }

    if(strncmp(line, "channel_view_end", 16) == 0) {
        simple_app_channel_view_commit_dataset(app);
        simple_app_channel_view_show_status(app, "");
        return;
    }

    if(strncmp(line, "channel_view_error:", 19) == 0) {
        simple_app_channel_view_show_status(app, line + 19);
        return;
    }

    if(strncmp(line, "band:", 5) == 0) {
        unsigned long band_value = strtoul(line + 5, NULL, 10);
        if(band_value >= 10) {
            app->channel_view_section = ChannelViewSection24;
        } else {
            app->channel_view_section = ChannelViewSection5;
        }
        return;
    }

    if(strncmp(line, "ch", 2) == 0) {
        const char* colon = strchr(line, ':');
        if(!colon) return;
        unsigned long channel = strtoul(line + 2, NULL, 10);
        unsigned long count = strtoul(colon + 1, NULL, 10);
        if(count > UINT16_MAX) {
            count = UINT16_MAX;
        }
        if(app->channel_view_section == ChannelViewSection24) {
            int idx = simple_app_channel_view_find_channel_index(
                channel_view_channels_24ghz, CHANNEL_VIEW_24GHZ_CHANNEL_COUNT, (uint8_t)channel);
            if(idx >= 0) {
                app->channel_view_working_counts_24[idx] = (uint16_t)count;
            }
        } else if(app->channel_view_section == ChannelViewSection5) {
            int idx = simple_app_channel_view_find_channel_index(
                channel_view_channels_5ghz, CHANNEL_VIEW_5GHZ_CHANNEL_COUNT, (uint8_t)channel);
            if(idx >= 0) {
                app->channel_view_working_counts_5[idx] = (uint16_t)count;
            }
        }
        return;
    }
}

static void simple_app_channel_view_feed(SimpleApp* app, char ch) {
    if(!app) return;

    if(ch == '\r') return;

    if(ch == '\n') {
        if(app->channel_view_line_length > 0) {
            app->channel_view_line_buffer[app->channel_view_line_length] = '\0';
            simple_app_channel_view_process_line(app, app->channel_view_line_buffer);
        }
        app->channel_view_line_length = 0;
        return;
    }

    if(app->channel_view_line_length + 1 >= sizeof(app->channel_view_line_buffer)) {
        app->channel_view_line_length = 0;
        return;
    }

    app->channel_view_line_buffer[app->channel_view_line_length++] = ch;
}

static void simple_app_draw_channel_view(SimpleApp* app, Canvas* canvas) {
    if(!app || !canvas) return;

    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 4, 12, "Channel View");

    const bool showing_5ghz = (app->channel_view_band == ChannelViewBand5);
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str_aligned(
        canvas, DISPLAY_WIDTH - 4, 12, AlignRight, AlignBottom, showing_5ghz ? "5G" : "2.4G");

    const int16_t frame_x = 2;
    const int16_t frame_y = 18;
    const int16_t frame_w = DISPLAY_WIDTH - 4;
    const int16_t frame_h = DISPLAY_HEIGHT - frame_y - 4;
    const int16_t bar_top = frame_y + 10;
    const int16_t bar_bottom = frame_y + frame_h - 12;

    canvas_draw_frame(canvas, frame_x, frame_y, frame_w, frame_h);

    const char* overlay_text = NULL;
    if(app->channel_view_has_status && app->channel_view_status_text[0] != '\0') {
        overlay_text = app->channel_view_status_text;
    } else if(!app->channel_view_has_data) {
        overlay_text = app->channel_view_active ? "Scanning..." : "Press OK to restart";
    }

    if(!app->channel_view_has_data) {
        const char* message = overlay_text;
        if(!message) {
            message = app->channel_view_active ? "Waiting for data..." : "Press OK to restart";
        }
        canvas_draw_str_aligned(
            canvas,
            frame_x + frame_w / 2,
            frame_y + frame_h / 2,
            AlignCenter,
            AlignCenter,
            message);
        app->channel_view_dirty = false;
        return;
    }

    const uint16_t* counts = showing_5ghz ? app->channel_view_counts_5 : app->channel_view_counts_24;
    const uint8_t* channel_map =
        showing_5ghz ? channel_view_channels_5ghz : channel_view_channels_24ghz;
    const size_t channel_count =
        showing_5ghz ? CHANNEL_VIEW_5GHZ_CHANNEL_COUNT : CHANNEL_VIEW_24GHZ_CHANNEL_COUNT;
    const size_t visible_columns = simple_app_channel_view_visible_columns(app->channel_view_band);
    const uint8_t offset = *simple_app_channel_view_offset_ptr(app, app->channel_view_band);

    uint16_t max_count = 0;
    for(size_t i = 0; i < channel_count; i++) {
        if(counts[i] > max_count) {
            max_count = counts[i];
        }
    }
    if(max_count == 0) {
        max_count = 1;
    }

    const int16_t column_width = (frame_w - 8) / (int16_t)visible_columns;
    const int16_t column_gap = 2;
    size_t drawn_columns = 0;
    const int16_t label_padding = 8;
    int16_t max_bar_height = bar_bottom - (bar_top + label_padding);
    if(max_bar_height < 2) {
        max_bar_height = 2;
    }
    for(size_t column = 0; column < visible_columns; column++) {
        size_t index = offset + column;
        if(index >= channel_count) break;
        drawn_columns++;
        uint16_t value = counts[index];
        uint8_t channel = channel_map[index];

        int16_t x0 = frame_x + 4 + (int16_t)column * column_width;
        int16_t x_center = x0 + column_width / 2;
        int16_t column_inner_width = column_width - column_gap;
        if(column_inner_width < 2) {
            column_inner_width = 2;
        }

        int16_t bar_height = 0;
        if(value > 0) {
            bar_height = (int16_t)((value * (uint32_t)max_bar_height) / max_count);
            if(bar_height == 0) {
                bar_height = 1;
            }
        }
        int16_t column_bar_top = bar_bottom - bar_height;
        if(bar_height > 0) {
            canvas_draw_box(canvas, x_center - column_inner_width / 2, column_bar_top, column_inner_width, bar_height);
        }

        char value_label[6];
        snprintf(value_label, sizeof(value_label), "%u", (unsigned)value);
        int16_t value_y = column_bar_top - 2;
        int16_t min_value_y = frame_y + 12;
        if(value_y < min_value_y) {
            value_y = min_value_y;
        }
        canvas_draw_str_aligned(canvas, x_center, value_y, AlignCenter, AlignBottom, value_label);

        char channel_label[6];
        snprintf(channel_label, sizeof(channel_label), "%u", (unsigned)channel);
        canvas_draw_str_aligned(
            canvas,
            x_center,
            frame_y + frame_h - 2,
            AlignCenter,
            AlignBottom,
            channel_label);
    }

    if(offset > 0) {
        canvas_draw_str(canvas, frame_x + 1, frame_y + frame_h / 2, "<");
    }
    size_t max_offset = simple_app_channel_view_max_offset(app->channel_view_band);
    if(offset < max_offset) {
        canvas_draw_str(canvas, frame_x + frame_w - 4, frame_y + frame_h / 2, ">");
    }

    app->channel_view_dirty = false;
}

static void simple_app_handle_channel_view_input(SimpleApp* app, InputKey key) {
    if(!app) return;

    if(key == InputKeyBack) {
        simple_app_channel_view_stop(app);
        app->menu_state = MenuStateItems;
        app->section_index = MENU_SECTION_MONITORING;
        app->item_index = 0;
        app->item_offset = 0;
        app->screen = ScreenMenu;
        if(app->viewport) {
            view_port_update(app->viewport);
        }
        return;
    }

    if(key == InputKeyUp || key == InputKeyDown) {
        ChannelViewBand new_band =
            (app->channel_view_band == ChannelViewBand24) ? ChannelViewBand5 : ChannelViewBand24;
        app->channel_view_band = new_band;
        uint8_t* offset_ptr = simple_app_channel_view_offset_ptr(app, app->channel_view_band);
        uint8_t max_offset = simple_app_channel_view_max_offset(app->channel_view_band);
        if(*offset_ptr > max_offset) {
            *offset_ptr = max_offset;
        }
        app->channel_view_dirty = true;
        if(app->viewport) {
            view_port_update(app->viewport);
        }
        return;
    }

    if(key == InputKeyOk) {
        simple_app_channel_view_stop(app);
        simple_app_channel_view_start(app);
        if(app->viewport) {
            view_port_update(app->viewport);
        }
        return;
    }

    if(key == InputKeyLeft) {
        if(simple_app_channel_view_adjust_offset(app, app->channel_view_band, -1) && app->viewport) {
            view_port_update(app->viewport);
        }
        return;
    }

    if(key == InputKeyRight) {
        if(simple_app_channel_view_adjust_offset(app, app->channel_view_band, 1) && app->viewport) {
            view_port_update(app->viewport);
        }
        return;
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
        size_t max_scroll = simple_app_hint_max_scroll(app);
        bool show_up = (app->hint_scroll > 0);
        bool show_down = (app->hint_scroll < max_scroll);
        if(show_up || show_down) {
            uint8_t arrow_x = (uint8_t)(bubble_x + bubble_w - 10);
            int16_t content_top = text_y;
            int16_t content_bottom =
                text_y + (int16_t)((HINT_VISIBLE_LINES > 0 ? (HINT_VISIBLE_LINES - 1) : 0) * HINT_LINE_HEIGHT);
            int16_t min_base = bubble_y + 12;
            int16_t max_base = bubble_y + bubble_h - 12;
            simple_app_draw_scroll_hints_clamped(
                canvas, arrow_x, content_top, content_bottom, show_up, show_down, min_base, max_base);
        }
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

static void simple_app_draw_portal_menu(SimpleApp* app, Canvas* canvas) {
    if(!app || !canvas) return;

    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 4, 14, "Portal");

    canvas_set_font(canvas, FontSecondary);
    simple_app_portal_sync_offset(app);

    size_t offset = app->portal_menu_offset;
    size_t visible = PORTAL_VISIBLE_COUNT;
    if(visible == 0) visible = 1;
    if(visible > PORTAL_MENU_OPTION_COUNT) {
        visible = PORTAL_MENU_OPTION_COUNT;
    }

    uint8_t base_y = 30;
    uint8_t y = base_y;
    uint8_t list_bottom_y = base_y;

    for(size_t pos = 0; pos < visible; pos++) {
        size_t idx = offset + pos;
        if(idx >= PORTAL_MENU_OPTION_COUNT) break;

        const char* label = "Start Portal";
        char detail[48];
        char detail_extra[48];
        detail[0] = '\0';
        detail_extra[0] = '\0';
        bool show_detail_line = false;
        bool show_detail_extra = false;

        switch(idx) {
        case 0:
            label = "SSID";
            snprintf(detail, sizeof(detail), "Current:");
            show_detail_line = true;
            if(app->portal_ssid[0] != '\0') {
                strncpy(detail_extra, app->portal_ssid, sizeof(detail_extra) - 1);
                detail_extra[sizeof(detail_extra) - 1] = '\0';
            } else {
                snprintf(detail_extra, sizeof(detail_extra), "<none>");
            }
            simple_app_truncate_text(detail_extra, 28);
            show_detail_extra = true;
            break;
        case 1:
            label = "Select HTML";
            if(app->karma_selected_html_id != 0 && app->karma_selected_html_name[0] != '\0') {
                snprintf(detail, sizeof(detail), "Current: %s", app->karma_selected_html_name);
            } else {
                snprintf(detail, sizeof(detail), "Current: <none>");
            }
            simple_app_truncate_text(detail, 26);
            show_detail_line = true;
            break;
        default:
            label = "Start Portal";
            if(app->portal_ssid[0] == '\0') {
                snprintf(detail, sizeof(detail), "Need SSID");
            } else if(app->karma_selected_html_id == 0) {
                snprintf(detail, sizeof(detail), "Need HTML");
            } else {
                detail[0] = '\0';
            }
            simple_app_truncate_text(detail, 20);
            break;
        }

        if(app->portal_menu_index == idx) {
            canvas_draw_str(canvas, 2, y, ">");
        }
        canvas_draw_str(canvas, 14, y, label);

        uint8_t item_height = 12;
        if(show_detail_line || detail[0] != '\0') {
            canvas_draw_str(canvas, 14, (uint8_t)(y + 10), detail);
            item_height += 10;
        }
        if(show_detail_extra) {
            canvas_draw_str(canvas, 14, (uint8_t)(y + item_height), detail_extra);
            item_height += 10;
        }
        y = (uint8_t)(y + item_height);
        list_bottom_y = y;
    }

    uint8_t arrow_x = DISPLAY_WIDTH - 6;
    if(offset > 0) {
        int16_t arrow_y = (int16_t)(base_y - 6);
        if(arrow_y < 12) arrow_y = 12;
        simple_app_draw_scroll_arrow(canvas, arrow_x, arrow_y, true);
    }
    if(offset + visible < PORTAL_MENU_OPTION_COUNT) {
        int16_t arrow_y = (int16_t)(list_bottom_y - 6);
        if(arrow_y > 60) arrow_y = 60;
        if(arrow_y < 16) arrow_y = 16;
        simple_app_draw_scroll_arrow(canvas, arrow_x, arrow_y, false);
    }
}

static void simple_app_handle_portal_menu_input(SimpleApp* app, InputKey key) {
    if(!app) return;

    if(key == InputKeyBack || key == InputKeyLeft) {
        if(app->portal_ssid_listing_active) {
            simple_app_reset_portal_ssid_listing(app);
        }
        app->portal_ssid_popup_active = false;
        if(app->karma_html_listing_active) {
            simple_app_reset_karma_html_listing(app);
        }
        app->karma_html_popup_active = false;
        simple_app_clear_status_message(app);
        app->karma_status_active = false;
        app->portal_menu_offset = 0;
        simple_app_focus_attacks_menu(app);
        if(app->viewport) {
            view_port_update(app->viewport);
        }
        return;
    }

    if(key == InputKeyUp) {
        if(app->portal_menu_index > 0) {
            app->portal_menu_index--;
            simple_app_portal_sync_offset(app);
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
    } else if(key == InputKeyDown) {
        if(app->portal_menu_index + 1 < PORTAL_MENU_OPTION_COUNT) {
            app->portal_menu_index++;
            simple_app_portal_sync_offset(app);
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
    } else if(key == InputKeyOk) {
        if(app->portal_menu_index == 0) {
            if(app->portal_ssid_listing_active) {
                simple_app_show_status_message(app, "Listing already\nin progress", 1200, true);
                if(app->viewport) {
                    view_port_update(app->viewport);
                }
                return;
            }
            if(app->portal_ssid_count > 0 && !app->portal_ssid_missing) {
                simple_app_open_portal_ssid_popup(app);
            } else if(app->portal_ssid_missing) {
                simple_app_portal_prompt_ssid(app);
            } else {
                simple_app_request_portal_ssid_list(app);
            }
        } else if(app->portal_menu_index == 1) {
            if(app->karma_html_listing_active || app->karma_html_count == 0) {
                simple_app_request_karma_html_list(app);
            } else {
                simple_app_clear_status_message(app);
                app->karma_status_active = false;
                if(app->karma_html_popup_index >= app->karma_html_count) {
                    app->karma_html_popup_index = 0;
                }
                if(app->karma_html_popup_offset >= app->karma_html_count) {
                    app->karma_html_popup_offset = 0;
                }
                app->karma_html_popup_active = true;
                if(app->viewport) {
                    view_port_update(app->viewport);
                }
            }
        } else {
            simple_app_start_portal(app);
        }
    }
}

static void simple_app_reset_portal_ssid_listing(SimpleApp* app) {
    if(!app) return;
    app->portal_ssid_listing_active = false;
    app->portal_ssid_list_header_seen = false;
    app->portal_ssid_list_length = 0;
    app->portal_ssid_count = 0;
    app->portal_ssid_popup_index = 0;
    app->portal_ssid_popup_offset = 0;
    app->portal_ssid_popup_active = false;
    app->portal_ssid_missing = false;
}

static void simple_app_open_portal_ssid_popup(SimpleApp* app) {
    if(!app || app->portal_ssid_count == 0) return;

    size_t total_options = app->portal_ssid_count + 1; // +1 for manual entry
    size_t target_index = 0; // manual by default
    if(app->portal_ssid[0] != '\0') {
        for(size_t i = 0; i < app->portal_ssid_count; i++) {
            if(strncmp(app->portal_ssid_entries[i].ssid, app->portal_ssid, SCAN_SSID_MAX_LEN - 1) == 0) {
                target_index = i + 1;
                break;
            }
        }
    }

    app->portal_ssid_popup_index = target_index;
    size_t visible = total_options;
    if(visible > PORTAL_SSID_POPUP_VISIBLE_LINES) {
        visible = PORTAL_SSID_POPUP_VISIBLE_LINES;
    }
    if(visible == 0) visible = 1;

    if(total_options > visible && target_index >= visible) {
        app->portal_ssid_popup_offset = target_index - visible + 1;
    } else {
        app->portal_ssid_popup_offset = 0;
    }
    size_t max_offset = (total_options > visible) ? (total_options - visible) : 0;
    if(app->portal_ssid_popup_offset > max_offset) {
        app->portal_ssid_popup_offset = max_offset;
    }

    app->portal_ssid_popup_active = true;
    simple_app_clear_status_message(app);
    if(app->viewport) {
        view_port_update(app->viewport);
    }
}

static void simple_app_finish_portal_ssid_listing(SimpleApp* app) {
    if(!app || !app->portal_ssid_listing_active) return;
    app->portal_ssid_listing_active = false;
    app->portal_ssid_list_length = 0;
    app->portal_ssid_list_header_seen = false;
    app->last_command_sent = false;
    simple_app_clear_status_message(app);

    if(app->portal_ssid_count == 0) {
        app->portal_ssid_popup_active = false;
        if(app->screen == ScreenPortalMenu) {
            simple_app_show_status_message(app, "SSID presets\nnot available", 1500, true);
            simple_app_portal_prompt_ssid(app);
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
        return;
    }

    app->portal_ssid_missing = false;
    if(app->screen == ScreenPortalMenu) {
        simple_app_open_portal_ssid_popup(app);
    }
}

static void simple_app_process_portal_ssid_line(SimpleApp* app, const char* line) {
    if(!app || !line || !app->portal_ssid_listing_active) return;

    const char* cursor = line;
    while(*cursor == ' ' || *cursor == '\t') {
        cursor++;
    }

    if(*cursor == '\0') {
        if(app->portal_ssid_count > 0) {
            simple_app_finish_portal_ssid_listing(app);
        }
        return;
    }

    if(strncmp(cursor, "ssid.txt not found", 19) == 0 ||
       strncmp(cursor, "ssid.txt is empty", 18) == 0 ||
       strncmp(cursor, "No SSID", 7) == 0) {
        app->portal_ssid_missing = true;
        app->portal_ssid_count = 0;
        simple_app_finish_portal_ssid_listing(app);
        return;
    }

    if(strncmp(cursor, "SSID presets", 12) == 0) {
        app->portal_ssid_list_header_seen = true;
        return;
    }

    if(!isdigit((unsigned char)cursor[0])) {
        if(app->portal_ssid_count > 0) {
            simple_app_finish_portal_ssid_listing(app);
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

    if(app->portal_ssid_count >= PORTAL_MAX_SSID_PRESETS) {
        return;
    }

    PortalSsidEntry* entry = &app->portal_ssid_entries[app->portal_ssid_count++];
    entry->id = (uint8_t)id;
    strncpy(entry->ssid, endptr, SCAN_SSID_MAX_LEN - 1);
    entry->ssid[SCAN_SSID_MAX_LEN - 1] = '\0';

    size_t len = strlen(entry->ssid);
    while(len > 0 &&
          (entry->ssid[len - 1] == '\r' || entry->ssid[len - 1] == '\n' ||
           entry->ssid[len - 1] == ' ' || entry->ssid[len - 1] == '\t')) {
        entry->ssid[--len] = '\0';
    }

    app->portal_ssid_list_header_seen = true;
}

static void simple_app_portal_ssid_feed(SimpleApp* app, char ch) {
    if(!app || !app->portal_ssid_listing_active) return;
    if(ch == '\r') return;

    if(ch == '>') {
        if(app->portal_ssid_list_length > 0) {
            app->portal_ssid_list_buffer[app->portal_ssid_list_length] = '\0';
            simple_app_process_portal_ssid_line(app, app->portal_ssid_list_buffer);
            app->portal_ssid_list_length = 0;
        }
        simple_app_finish_portal_ssid_listing(app);
        return;
    }

    if(ch == '\n') {
        if(app->portal_ssid_list_length > 0) {
            app->portal_ssid_list_buffer[app->portal_ssid_list_length] = '\0';
            simple_app_process_portal_ssid_line(app, app->portal_ssid_list_buffer);
        } else if(app->portal_ssid_list_header_seen || app->portal_ssid_missing) {
            simple_app_finish_portal_ssid_listing(app);
        }
        app->portal_ssid_list_length = 0;
        return;
    }

    if(app->portal_ssid_list_length + 1 >= sizeof(app->portal_ssid_list_buffer)) {
        app->portal_ssid_list_length = 0;
        return;
    }

    app->portal_ssid_list_buffer[app->portal_ssid_list_length++] = ch;
}

static void simple_app_request_portal_ssid_list(SimpleApp* app) {
    if(!app) return;
    simple_app_reset_portal_ssid_listing(app);
    app->portal_ssid_listing_active = true;
    simple_app_show_status_message(app, "Listing SSID...", 0, false);
    simple_app_send_command(app, "list_ssid", false);
    if(app->viewport) {
        view_port_update(app->viewport);
    }
}

static void simple_app_copy_portal_ssid(SimpleApp* app, const char* source) {
    if(!app) return;
    if(!source) {
        app->portal_ssid[0] = '\0';
        return;
    }

    size_t dst = 0;
    size_t max_len = sizeof(app->portal_ssid);
    for(size_t i = 0; source[i] != '\0' && dst + 1 < max_len; i++) {
        char ch = source[i];
        if((unsigned char)ch < 32) {
            continue;
        }
        if(ch == '"') {
            ch = '\'';
        }
        app->portal_ssid[dst++] = ch;
    }
    app->portal_ssid[dst] = '\0';
    simple_app_trim(app->portal_ssid);
}

static void simple_app_portal_prompt_ssid(SimpleApp* app) {
    if(!app) return;
    if(app->portal_input_active) return;
    app->portal_input_requested = true;
}

static void simple_app_portal_sync_offset(SimpleApp* app) {
    if(!app) return;
    size_t total = PORTAL_MENU_OPTION_COUNT;
    size_t visible = PORTAL_VISIBLE_COUNT;
    if(visible == 0) visible = 1;
    if(visible > total) visible = total;
    if(total == 0) {
        app->portal_menu_index = 0;
        app->portal_menu_offset = 0;
        return;
    }
    if(app->portal_menu_index >= total) {
        app->portal_menu_index = total - 1;
    }
    size_t max_offset = (total > visible) ? (total - visible) : 0;
    if(app->portal_menu_offset > max_offset) {
        app->portal_menu_offset = max_offset;
    }
    if(app->portal_menu_index < app->portal_menu_offset) {
        app->portal_menu_offset = app->portal_menu_index;
    } else if(app->portal_menu_index >= app->portal_menu_offset + visible) {
        app->portal_menu_offset = app->portal_menu_index - visible + 1;
    }
    if(app->portal_menu_offset > max_offset) {
        app->portal_menu_offset = max_offset;
    }
}

typedef struct {
    ViewDispatcher* dispatcher;
    bool accepted;
} SimpleAppPortalInputContext;

static void simple_app_portal_text_input_result(void* context) {
    SimpleAppPortalInputContext* ctx = context;
    if(!ctx || !ctx->dispatcher) return;
    ctx->accepted = true;
    view_dispatcher_stop(ctx->dispatcher);
}

static bool simple_app_portal_text_input_navigation(void* context) {
    SimpleAppPortalInputContext* ctx = context;
    if(!ctx || !ctx->dispatcher) return false;
    ctx->accepted = false;
    view_dispatcher_stop(ctx->dispatcher);
    return true;
}

static bool simple_app_portal_run_text_input(SimpleApp* app) {
    if(!app || !app->gui || !app->viewport) return false;

    bool accepted = false;
    bool viewport_detached = false;

    char buffer[SCAN_SSID_MAX_LEN];
    strncpy(buffer, app->portal_ssid, sizeof(buffer));
    buffer[sizeof(buffer) - 1] = '\0';

    ViewDispatcher* dispatcher = view_dispatcher_alloc();
    if(!dispatcher) return false;

    TextInput* text_input = text_input_alloc();
    if(!text_input) {
        view_dispatcher_free(dispatcher);
        return false;
    }

    SimpleAppPortalInputContext ctx = {
        .dispatcher = dispatcher,
        .accepted = false,
    };

    view_dispatcher_set_event_callback_context(dispatcher, &ctx);
    view_dispatcher_set_navigation_event_callback(dispatcher, simple_app_portal_text_input_navigation);

    text_input_set_header_text(text_input, "Portal SSID");
    text_input_set_result_callback(
        text_input,
        simple_app_portal_text_input_result,
        &ctx,
        buffer,
        sizeof(buffer),
        false);
    text_input_set_minimum_length(text_input, 1);

    view_dispatcher_add_view(dispatcher, 0, text_input_get_view(text_input));

    gui_remove_view_port(app->gui, app->viewport);
    viewport_detached = true;
    app->portal_input_active = true;

    view_dispatcher_attach_to_gui(dispatcher, app->gui, ViewDispatcherTypeFullscreen);
    view_dispatcher_switch_to_view(dispatcher, 0);
    view_dispatcher_run(dispatcher);

    view_dispatcher_remove_view(dispatcher, 0);
    view_dispatcher_free(dispatcher);
    text_input_free(text_input);

    if(viewport_detached) {
        gui_add_view_port(app->gui, app->viewport, GuiLayerFullscreen);
        view_port_update(app->viewport);
    }
    app->portal_input_active = false;

    if(ctx.accepted) {
        simple_app_copy_portal_ssid(app, buffer);
        accepted = true;
    }

    return accepted;
}

static void simple_app_draw_portal_ssid_popup(SimpleApp* app, Canvas* canvas) {
    if(!app || !canvas || !app->portal_ssid_popup_active) return;

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
    canvas_draw_str(canvas, bubble_x + 8, bubble_y + 16, "Select SSID");

    canvas_set_font(canvas, FontSecondary);
    uint8_t list_y = bubble_y + 28;

    if(app->portal_ssid_count == 0) {
        canvas_draw_str(canvas, bubble_x + 10, list_y, "No presets found");
        canvas_draw_str(canvas, bubble_x + 10, (uint8_t)(list_y + HINT_LINE_HEIGHT), "Back returns");
        return;
    }

    size_t total_options = app->portal_ssid_count + 1; // manual option first
    size_t visible = total_options;
    if(visible > PORTAL_SSID_POPUP_VISIBLE_LINES) {
        visible = PORTAL_SSID_POPUP_VISIBLE_LINES;
    }

    if(app->portal_ssid_popup_offset >= total_options) {
        app->portal_ssid_popup_offset =
            (total_options > visible) ? (total_options - visible) : 0;
    }

    for(size_t i = 0; i < visible; i++) {
        size_t idx = app->portal_ssid_popup_offset + i;
        if(idx >= total_options) break;
        char line[48];
        if(idx == 0) {
            strncpy(line, "Manual select", sizeof(line) - 1);
            line[sizeof(line) - 1] = '\0';
        } else {
            const PortalSsidEntry* entry = &app->portal_ssid_entries[idx - 1];
            snprintf(line, sizeof(line), "%u %s", (unsigned)entry->id, entry->ssid);
        }
        simple_app_truncate_text(line, 28);
        uint8_t line_y = (uint8_t)(list_y + i * HINT_LINE_HEIGHT);
        if(idx == app->portal_ssid_popup_index) {
            canvas_draw_str(canvas, bubble_x + 4, line_y, ">");
        }
        canvas_draw_str(canvas, bubble_x + 14, line_y, line);
    }

    if(total_options > visible) {
        bool show_up = (app->portal_ssid_popup_offset > 0);
        bool show_down = (app->portal_ssid_popup_offset + visible < total_options);
        if(show_up || show_down) {
            uint8_t arrow_x = (uint8_t)(bubble_x + bubble_w - 10);
            int16_t content_top = list_y;
            int16_t content_bottom =
                list_y + (int16_t)((visible > 0 ? (visible - 1) : 0) * HINT_LINE_HEIGHT);
            int16_t min_base = bubble_y + 12;
            int16_t max_base = bubble_y + bubble_h - 12;
            simple_app_draw_scroll_hints_clamped(
                canvas, arrow_x, content_top, content_bottom, show_up, show_down, min_base, max_base);
        }
    }
}

static void simple_app_handle_portal_ssid_popup_event(SimpleApp* app, const InputEvent* event) {
    if(!app || !event || !app->portal_ssid_popup_active) return;
    if(event->type != InputTypeShort && event->type != InputTypeRepeat && event->type != InputTypeLong) return;

    InputKey key = event->key;
    bool is_short = (event->type == InputTypeShort);

    size_t total_options = app->portal_ssid_count + 1;
    size_t visible = total_options;
    if(visible > PORTAL_SSID_POPUP_VISIBLE_LINES) {
        visible = PORTAL_SSID_POPUP_VISIBLE_LINES;
    }
    if(visible == 0) visible = 1;

    if(is_short && key == InputKeyBack) {
        app->portal_ssid_popup_active = false;
        if(app->viewport) {
            view_port_update(app->viewport);
        }
        return;
    }

    if(total_options == 0) {
        return;
    }

    if(key == InputKeyUp) {
        if(app->portal_ssid_popup_index > 0) {
            app->portal_ssid_popup_index--;
            if(app->portal_ssid_popup_index < app->portal_ssid_popup_offset) {
                app->portal_ssid_popup_offset = app->portal_ssid_popup_index;
            }
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
    } else if(key == InputKeyDown) {
        if(app->portal_ssid_popup_index + 1 < total_options) {
            app->portal_ssid_popup_index++;
            if(total_options > visible &&
               app->portal_ssid_popup_index >= app->portal_ssid_popup_offset + visible) {
                app->portal_ssid_popup_offset =
                    app->portal_ssid_popup_index - visible + 1;
            }
            size_t max_offset = (total_options > visible) ? (total_options - visible) : 0;
            if(app->portal_ssid_popup_offset > max_offset) {
                app->portal_ssid_popup_offset = max_offset;
            }
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
    } else if(is_short && key == InputKeyOk) {
        size_t idx = app->portal_ssid_popup_index;
        if(idx == 0) {
            app->portal_ssid_popup_active = false;
            simple_app_portal_prompt_ssid(app);
        } else if(idx - 1 < app->portal_ssid_count) {
            const PortalSsidEntry* entry = &app->portal_ssid_entries[idx - 1];
            simple_app_copy_portal_ssid(app, entry->ssid);
            char message[64];
            snprintf(message, sizeof(message), "SSID set:\n%s", entry->ssid);
            simple_app_show_status_message(app, message, 1200, true);
            app->portal_menu_index = 1;
            simple_app_portal_sync_offset(app);
            app->portal_ssid_popup_active = false;
        }
        if(app->viewport) {
            view_port_update(app->viewport);
        }
    }
}

static void simple_app_start_portal(SimpleApp* app) {
    if(!app) return;

    if(app->portal_ssid_listing_active) {
        simple_app_show_status_message(app, "Wait for list\ncompletion", 1500, true);
        if(app->viewport) {
            view_port_update(app->viewport);
        }
        return;
    }

    if(app->karma_html_listing_active) {
        simple_app_show_status_message(app, "Wait for list\ncompletion", 1500, true);
        if(app->viewport) {
            view_port_update(app->viewport);
        }
        return;
    }

    if(app->portal_ssid[0] == '\0') {
        simple_app_show_status_message(app, "Set SSID first", 1200, true);
        if(app->viewport) {
            view_port_update(app->viewport);
        }
        return;
    }

    if(app->karma_selected_html_id == 0) {
        simple_app_show_status_message(app, "Select HTML file\nbefore starting", 1500, true);
        if(app->viewport) {
            view_port_update(app->viewport);
        }
        return;
    }

    char select_command[48];
    snprintf(select_command, sizeof(select_command), "select_html %u", (unsigned)app->karma_selected_html_id);
    simple_app_send_command(app, select_command, false);
    app->last_command_sent = false;

    char command[128];
    snprintf(command, sizeof(command), "start_portal \"%s\"", app->portal_ssid);
    simple_app_send_command(app, command, true);
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
        bool show_up = (app->evil_twin_html_popup_offset > 0);
        bool show_down =
            (app->evil_twin_html_popup_offset + visible < app->evil_twin_html_count);
        if(show_up || show_down) {
            uint8_t arrow_x = (uint8_t)(bubble_x + bubble_w - 10);
            int16_t content_top = list_y;
            int16_t content_bottom =
                list_y + (int16_t)((visible > 0 ? (visible - 1) : 0) * HINT_LINE_HEIGHT);
            int16_t min_base = bubble_y + 12;
            int16_t max_base = bubble_y + bubble_h - 12;
            simple_app_draw_scroll_hints_clamped(
                canvas, arrow_x, content_top, content_bottom, show_up, show_down, min_base, max_base);
        }
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
        canvas_draw_str_aligned(canvas, DISPLAY_WIDTH - 15, 11, AlignRight, AlignBottom, version_text);
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
        bool show_up = (app->item_offset > 0);
        bool show_down = (app->item_offset + visible_count < section->entry_count);
        if(show_up || show_down) {
            uint8_t arrow_x = DISPLAY_WIDTH - 6;
            uint8_t max_rows =
                (section->entry_count < visible_count) ? section->entry_count : visible_count;
            if(max_rows == 0) max_rows = 1;
            int16_t content_top = MENU_ITEM_BASE_Y;
            int16_t content_bottom = MENU_ITEM_BASE_Y + (int16_t)((max_rows - 1) * MENU_ITEM_SPACING);
            simple_app_draw_scroll_hints(canvas, arrow_x, content_top, content_bottom, show_up, show_down);
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

static void simple_app_draw_wardrive_serial(SimpleApp* app, Canvas* canvas) {
    if(!app || !canvas) return;
    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontSecondary);
    char display_lines[WARD_DRIVE_CONSOLE_LINES][64];
    size_t lines_filled = simple_app_render_display_lines(
        app, app->serial_scroll, display_lines, WARD_DRIVE_CONSOLE_LINES);

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
    if(total_lines > WARD_DRIVE_CONSOLE_LINES) {
        size_t max_scroll = simple_app_max_scroll(app);
        bool show_up = (app->serial_scroll > 0);
        bool show_down = (app->serial_scroll < max_scroll);
        if(show_up || show_down) {
            uint8_t arrow_x = DISPLAY_WIDTH - 6;
            int16_t content_top = 8;
            int16_t visible_rows =
                (WARD_DRIVE_CONSOLE_LINES > 0) ? (WARD_DRIVE_CONSOLE_LINES - 1) : 0;
            int16_t content_bottom = 8 + (int16_t)(visible_rows * SERIAL_TEXT_LINE_HEIGHT);
            simple_app_draw_scroll_hints(canvas, arrow_x, content_top, content_bottom, show_up, show_down);
        }
    }

    int16_t divider_y =
        8 + (int16_t)(WARD_DRIVE_CONSOLE_LINES * SERIAL_TEXT_LINE_HEIGHT) + 2;
    if(divider_y >= DISPLAY_HEIGHT) {
        divider_y = DISPLAY_HEIGHT - 2;
    }
    canvas_draw_line(canvas, 0, divider_y, DISPLAY_WIDTH - 1, divider_y);

    const char* status = app->wardrive_status_text[0] ? app->wardrive_status_text : "0";
    bool numeric = app->wardrive_status_is_numeric;
    int16_t bottom_center = divider_y + ((DISPLAY_HEIGHT - divider_y) / 2);
    if(bottom_center >= DISPLAY_HEIGHT) {
        bottom_center = DISPLAY_HEIGHT - 2;
    }

    if(!numeric) {
        size_t len = strlen(status);
        if(len > 12) {
            const char* split_ptr = NULL;
            size_t mid = len / 2;
            for(size_t i = mid; i > 0; i--) {
                if(status[i] == ' ') {
                    split_ptr = status + i;
                    break;
                }
            }
            if(!split_ptr) {
                for(size_t i = mid; i < len; i++) {
                    if(status[i] == ' ') {
                        split_ptr = status + i;
                        break;
                    }
                }
            }
            if(split_ptr) {
                size_t first_len = (size_t)(split_ptr - status);
                while(first_len > 0 && status[first_len - 1] == ' ') {
                    first_len--;
                }
                char first_line[32];
                if(first_len >= sizeof(first_line)) {
                    first_len = sizeof(first_line) - 1;
                }
                memcpy(first_line, status, first_len);
                first_line[first_len] = '\0';
                const char* second_start = split_ptr + 1;
                while(*second_start == ' ') {
                    second_start++;
                }
                char second_line[32];
                snprintf(second_line, sizeof(second_line), "%s", second_start);
                if(first_line[0] != '\0' && second_line[0] != '\0') {
                    canvas_set_font(canvas, FontSecondary);
                    int16_t first_y = bottom_center - 4;
                    int16_t second_y = bottom_center + 8;
                    if(second_y >= DISPLAY_HEIGHT) {
                        second_y = DISPLAY_HEIGHT - 2;
                        first_y = second_y - 12;
                    }
                    canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, first_y, AlignCenter, AlignCenter, first_line);
                    canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, second_y, AlignCenter, AlignCenter, second_line);
                    return;
                }
            }
        }
    }

    Font display_font = FontPrimary;
    if(!numeric) {
        size_t len = strlen(status);
        if(len > 10) {
            display_font = FontSecondary;
        }
    }
    canvas_set_font(canvas, display_font);
    canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, bottom_center, AlignCenter, AlignCenter, status);
}

static void simple_app_draw_serial(SimpleApp* app, Canvas* canvas) {
    if(app && app->wardrive_view_active) {
        simple_app_draw_wardrive_serial(app, canvas);
        return;
    }

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
        size_t max_scroll = simple_app_max_scroll(app);
        bool show_up = (app->serial_scroll > 0);
        bool show_down = (app->serial_scroll < max_scroll);
        if(show_up || show_down) {
            uint8_t arrow_x = DISPLAY_WIDTH - 6;
            int16_t content_top = 8;
            int16_t content_bottom =
                8 + (int16_t)((SERIAL_VISIBLE_LINES > 0 ? (SERIAL_VISIBLE_LINES - 1) : 0) * SERIAL_TEXT_LINE_HEIGHT);
            simple_app_draw_scroll_hints(canvas, arrow_x, content_top, content_bottom, show_up, show_down);
        }
    }

    if(app->serial_targets_hint && !app->blackout_view_active) {
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
    size_t char_limit = (app->result_char_limit > 0) ? app->result_char_limit : RESULT_DEFAULT_CHAR_LIMIT;
    if(char_limit == 0) char_limit = RESULT_DEFAULT_CHAR_LIMIT;
    if(char_limit == 0) char_limit = 1;
    if(char_limit > 63) char_limit = 63;

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

                char display_line[64];
                memset(display_line, 0, sizeof(display_line));
                const char* source_line = segments[0];
                size_t source_len = strlen(source_line);
                size_t local_limit = char_limit;
                if(local_limit >= sizeof(display_line)) {
                    local_limit = sizeof(display_line) - 1;
                }
                if(local_limit == 0) {
                    local_limit = 1;
                }

                if(idx == app->scan_result_index) {
                    if(source_len <= local_limit) {
                        strncpy(display_line, source_line, sizeof(display_line) - 1);
                        display_line[sizeof(display_line) - 1] = '\0';
                    } else {
                        size_t offset = app->result_scroll_offset;
                        size_t max_offset = source_len - local_limit;
                        if(offset > max_offset) {
                            offset = max_offset;
                        }
                        size_t copy_len = local_limit;
                        if(offset + copy_len > source_len) {
                            copy_len = source_len - offset;
                        }
                        if(copy_len > sizeof(display_line) - 1) {
                            copy_len = sizeof(display_line) - 1;
                        }
                        memcpy(display_line, source_line + offset, copy_len);
                        display_line[copy_len] = '\0';
                    }
                } else {
                    strncpy(display_line, source_line, sizeof(display_line) - 1);
                    display_line[sizeof(display_line) - 1] = '\0';
                    if(source_len > local_limit) {
                        size_t truncate_limit = local_limit;
                        if(truncate_limit >= sizeof(display_line)) {
                            truncate_limit = sizeof(display_line) - 1;
                        }
                        if(truncate_limit == 0) {
                            truncate_limit = 1;
                        }
                        simple_app_truncate_text(display_line, truncate_limit);
                    }
                }

                const char* render_line = (display_line[0] != '\0') ? display_line : " ";
                canvas_draw_str(canvas, RESULT_TEXT_X, y, render_line);
            } else {
                const char* render_line = (segments[segment][0] != '\0') ? segments[segment] : " ";
                canvas_draw_str(canvas, RESULT_TEXT_X, y, render_line);
            }
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
        size_t max_scroll = total_lines - visible_line_budget;
        if(offset_lines > max_scroll) offset_lines = max_scroll;
        bool show_up = (offset_lines > 0);
        bool show_down = (offset_lines < max_scroll);
        if(show_up || show_down) {
            uint8_t arrow_x = DISPLAY_WIDTH - 6;
            int16_t content_top = RESULT_START_Y;
            int16_t visible_rows =
                (visible_line_budget > 0) ? (int16_t)(visible_line_budget - 1) : 0;
            int16_t content_bottom =
                RESULT_START_Y + (int16_t)(visible_rows * app->result_line_height);
            simple_app_draw_scroll_hints(canvas, arrow_x, content_top, content_bottom, show_up, show_down);
        }
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

static void simple_app_draw_setup_led(SimpleApp* app, Canvas* canvas) {
    if(!app || !canvas) return;

    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 16, 14, "LED Settings");

    canvas_set_font(canvas, FontSecondary);
    uint8_t y = 32;
    const char* state = app->led_enabled ? "On" : "Off";
    char line[32];
    snprintf(line, sizeof(line), "State: %s", state);
    if(app->led_setup_index == 0) {
        canvas_draw_str(canvas, 2, y, ">");
    }
    canvas_draw_str(canvas, 16, y, line);

    y += 14;
    uint32_t level = app->led_level;
    if(level < 1) level = 1;
    if(level > 100) level = 100;
    snprintf(line, sizeof(line), "Brightness: %lu", (unsigned long)level);
    if(app->led_setup_index == 1) {
        canvas_draw_str(canvas, 2, y, ">");
    }
    canvas_draw_str(canvas, 16, y, line);

    const char* footer =
        (app->led_setup_index == 0) ? "Left/Right toggle, Back exit" : "Left/Right adjust, Back exit";
    canvas_draw_str(canvas, 2, 62, footer);
}

static void simple_app_draw_setup_boot(SimpleApp* app, Canvas* canvas) {
    if(!app || !canvas) return;

    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 10, 14, app->boot_setup_long ? "Boot Long" : "Boot Short");

    canvas_set_font(canvas, FontSecondary);
    uint8_t y = 32;
    const char* status = app->boot_setup_long ? (app->boot_long_enabled ? "On" : "Off")
                                              : (app->boot_short_enabled ? "On" : "Off");
    char line[48];
    snprintf(line, sizeof(line), "Status: %s", status);
    if(app->boot_setup_index == 0) {
        canvas_draw_str(canvas, 2, y, ">");
    }
    canvas_draw_str(canvas, 16, y, line);

    y += 14;
    uint8_t cmd_index = app->boot_setup_long ? app->boot_long_command_index : app->boot_short_command_index;
    if(cmd_index >= BOOT_COMMAND_OPTION_COUNT) {
        cmd_index = 0;
    }
    snprintf(line, sizeof(line), "Command:");
    if(app->boot_setup_index == 1) {
        canvas_draw_str(canvas, 2, y, ">");
    }
    canvas_draw_str(canvas, 16, y, line);

    // Draw command value on its own line to keep it within screen width
    y += 12;
    canvas_draw_str(canvas, 16, y, boot_command_options[cmd_index]);
}

static void simple_app_reset_sd_listing(SimpleApp* app) {
    if(!app) return;
    app->sd_listing_active = false;
    app->sd_list_header_seen = false;
    app->sd_list_length = 0;
    app->sd_file_count = 0;
    app->sd_file_popup_index = 0;
    app->sd_file_popup_offset = 0;
    app->sd_file_popup_active = false;
    app->sd_delete_confirm_active = false;
    app->sd_delete_confirm_yes = false;
    app->sd_delete_target_name[0] = '\0';
    app->sd_delete_target_path[0] = '\0';
    simple_app_reset_sd_scroll(app);
}

static void simple_app_copy_sd_folder(SimpleApp* app, const SdFolderOption* folder) {
    if(!app) return;
    if(folder) {
        strncpy(app->sd_current_folder_label, folder->label, SD_MANAGER_FOLDER_LABEL_MAX - 1);
        app->sd_current_folder_label[SD_MANAGER_FOLDER_LABEL_MAX - 1] = '\0';
        strncpy(app->sd_current_folder_path, folder->path, SD_MANAGER_PATH_MAX - 1);
        app->sd_current_folder_path[SD_MANAGER_PATH_MAX - 1] = '\0';
    } else {
        app->sd_current_folder_label[0] = '\0';
        app->sd_current_folder_path[0] = '\0';
    }

    size_t len = strlen(app->sd_current_folder_path);
    while(len > 0 && app->sd_current_folder_path[len - 1] == '/') {
        app->sd_current_folder_path[--len] = '\0';
    }
}

static void simple_app_open_sd_manager(SimpleApp* app) {
    if(!app) return;

    app->screen = ScreenSetupSdManager;
    simple_app_reset_sd_scroll(app);
    if(app->sd_folder_index >= sd_folder_option_count) {
        app->sd_folder_index = 0;
    }
    app->sd_folder_offset = 0;
    simple_app_reset_sd_listing(app);
    app->sd_refresh_pending = false;

    if(sd_folder_option_count > 0) {
        simple_app_copy_sd_folder(app, &sd_folder_options[app->sd_folder_index]);
    } else {
        simple_app_copy_sd_folder(app, NULL);
    }

    app->sd_folder_popup_active = (sd_folder_option_count > 0);
    if(app->viewport) {
        view_port_update(app->viewport);
    }
}

static void simple_app_request_sd_listing(SimpleApp* app, const SdFolderOption* folder) {
    if(!app || !folder) return;

    app->sd_folder_popup_active = false;
    simple_app_reset_sd_listing(app);
    simple_app_copy_sd_folder(app, folder);
    app->sd_listing_active = true;
    app->sd_refresh_pending = false;

    simple_app_show_status_message(app, "Listing files...", 0, false);

    char command[200];
    if(app->sd_current_folder_path[0] != '\0') {
        snprintf(command, sizeof(command), "list_dir \"%s\"", app->sd_current_folder_path);
    } else {
        snprintf(command, sizeof(command), "list_dir");
    }
    simple_app_send_command(app, command, false);
    if(app->viewport) {
        view_port_update(app->viewport);
    }
}

static void simple_app_finish_sd_listing(SimpleApp* app) {
    if(!app || !app->sd_listing_active) return;

    app->sd_listing_active = false;
    app->sd_list_length = 0;
    app->sd_list_header_seen = false;
    app->last_command_sent = false;
    simple_app_clear_status_message(app);

    if(app->sd_file_count == 0) {
        simple_app_show_status_message(app, "No files in\nselected folder", 1500, true);
        if(app->viewport) {
            view_port_update(app->viewport);
        }
        return;
    }

    app->sd_file_popup_index = 0;
    size_t visible = app->sd_file_count;
    if(visible > SD_MANAGER_POPUP_VISIBLE_LINES) {
        visible = SD_MANAGER_POPUP_VISIBLE_LINES;
    }
        app->sd_file_popup_offset = 0;
        if(app->sd_file_popup_index >= app->sd_file_count) {
            app->sd_file_popup_index = app->sd_file_count - 1;
        }

        app->sd_file_popup_active = true;
        simple_app_reset_sd_scroll(app);
        if(app->viewport) {
            view_port_update(app->viewport);
        }
    }

static void simple_app_sd_scroll_buffer(
    SimpleApp* app, const char* text, size_t char_limit, char* out, size_t out_size) {
    if(!app || !text || !out || out_size == 0) return;
    if(char_limit == 0) char_limit = 1;
    if(char_limit >= out_size) {
        char_limit = out_size - 1;
    }
    size_t len = strlen(text);
    if(len <= char_limit) {
        simple_app_reset_sd_scroll(app);
        strncpy(out, text, out_size - 1);
        out[out_size - 1] = '\0';
        return;
    }

    if(strncmp(text, app->sd_scroll_text, sizeof(app->sd_scroll_text)) != 0 ||
       app->sd_scroll_char_limit != char_limit) {
        strncpy(app->sd_scroll_text, text, sizeof(app->sd_scroll_text) - 1);
        app->sd_scroll_text[sizeof(app->sd_scroll_text) - 1] = '\0';
        app->sd_scroll_char_limit = (uint8_t)char_limit;
        app->sd_scroll_offset = 0;
        app->sd_scroll_direction = 1;
        app->sd_scroll_hold = RESULT_SCROLL_EDGE_PAUSE_STEPS;
        app->sd_scroll_last_tick = furi_get_tick();
    }

    size_t max_offset = len - char_limit;
    if(app->sd_scroll_offset > max_offset) {
        app->sd_scroll_offset = max_offset;
    }

    const char* start = text + app->sd_scroll_offset;
    strncpy(out, start, char_limit);
    out[char_limit] = '\0';
}

static void simple_app_process_sd_line(SimpleApp* app, const char* line) {
    if(!app || !line || !app->sd_listing_active) return;

    const char* cursor = line;
    while(*cursor == ' ' || *cursor == '\t') {
        cursor++;
    }

    if(*cursor == '\0') {
        if(app->sd_list_header_seen || app->sd_file_count > 0) {
            simple_app_finish_sd_listing(app);
        }
        return;
    }

    if(strncmp(cursor, "Files in", 8) == 0 || strncmp(cursor, "Found", 5) == 0) {
        app->sd_list_header_seen = true;
        return;
    }

    if(strncmp(cursor, "No files", 8) == 0) {
        app->sd_file_count = 0;
        simple_app_finish_sd_listing(app);
        return;
    }

    if(strncmp(cursor, "Failed", 6) == 0 || strncmp(cursor, "Invalid", 7) == 0) {
        simple_app_reset_sd_listing(app);
        app->last_command_sent = false;
        simple_app_show_status_message(app, "SD listing failed", 1500, true);
        if(app->viewport) {
            view_port_update(app->viewport);
        }
        return;
    }

    if(!isdigit((unsigned char)cursor[0])) {
        return;
    }

    char* endptr = NULL;
    long id = strtol(cursor, &endptr, 10);
    if(id <= 0 || !endptr) {
        return;
    }
    while(*endptr == ' ' || *endptr == '\t') {
        endptr++;
    }
    if(*endptr == '\0') {
        return;
    }
    if(app->sd_file_count >= SD_MANAGER_MAX_FILES) {
        return;
    }

    SdFileEntry* entry = &app->sd_files[app->sd_file_count++];
    strncpy(entry->name, endptr, SD_MANAGER_FILE_NAME_MAX - 1);
    entry->name[SD_MANAGER_FILE_NAME_MAX - 1] = '\0';

    size_t len = strlen(entry->name);
    while(len > 0 &&
          (entry->name[len - 1] == '\r' || entry->name[len - 1] == '\n' || entry->name[len - 1] == ' ')) {
        entry->name[--len] = '\0';
    }

    app->sd_list_header_seen = true;
}

static void simple_app_sd_feed(SimpleApp* app, char ch) {
    if(!app || !app->sd_listing_active) return;
    if(ch == '\r') return;

    if(ch == '>') {
        if(app->sd_list_length > 0) {
            app->sd_list_buffer[app->sd_list_length] = '\0';
            simple_app_process_sd_line(app, app->sd_list_buffer);
            app->sd_list_length = 0;
        }
        if(app->sd_file_count > 0 || app->sd_list_header_seen) {
            simple_app_finish_sd_listing(app);
        }
        return;
    }

    if(ch == '\n') {
        if(app->sd_list_length > 0) {
            app->sd_list_buffer[app->sd_list_length] = '\0';
            simple_app_process_sd_line(app, app->sd_list_buffer);
        } else if(app->sd_list_header_seen) {
            simple_app_finish_sd_listing(app);
        }
        app->sd_list_length = 0;
        return;
    }

    if(app->sd_list_length + 1 >= sizeof(app->sd_list_buffer)) {
        app->sd_list_length = 0;
        return;
    }

    app->sd_list_buffer[app->sd_list_length++] = ch;
}

static void simple_app_draw_sd_folder_popup(SimpleApp* app, Canvas* canvas) {
    if(!app || !canvas || !app->sd_folder_popup_active) return;

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
    canvas_draw_str(canvas, bubble_x + 8, bubble_y + 16, "Select folder");

    canvas_set_font(canvas, FontSecondary);
    uint8_t list_y = bubble_y + 28;

    if(sd_folder_option_count == 0) {
        canvas_draw_str(canvas, bubble_x + 8, list_y, "No folders configured");
        return;
    }

    size_t visible = sd_folder_option_count;
    if(visible > SD_MANAGER_POPUP_VISIBLE_LINES) {
        visible = SD_MANAGER_POPUP_VISIBLE_LINES;
    }

    if(app->sd_folder_index >= sd_folder_option_count) {
        app->sd_folder_index = sd_folder_option_count - 1;
    }
    if(app->sd_folder_offset + visible <= app->sd_folder_index) {
        app->sd_folder_offset = app->sd_folder_index - visible + 1;
    }
    if(app->sd_folder_offset >= sd_folder_option_count) {
        app->sd_folder_offset = 0;
    }

    for(size_t i = 0; i < visible; i++) {
        size_t idx = app->sd_folder_offset + i;
        if(idx >= sd_folder_option_count) break;
        const SdFolderOption* option = &sd_folder_options[idx];
        char full_line[64];
        snprintf(full_line, sizeof(full_line), "%s (%s)", option->label, option->path);

        char line[32];
        if(idx == app->sd_folder_index) {
            simple_app_sd_scroll_buffer(app, full_line, 23, line, sizeof(line));
        } else {
            strncpy(line, full_line, sizeof(line) - 1);
            line[sizeof(line) - 1] = '\0';
            simple_app_truncate_text(line, 23);
        }

        uint8_t line_y = (uint8_t)(list_y + i * HINT_LINE_HEIGHT);
        if(idx == app->sd_folder_index) {
            canvas_draw_str(canvas, bubble_x + 4, line_y, ">");
        }
        canvas_draw_str(canvas, bubble_x + 8, line_y, line);
    }

    if(sd_folder_option_count > SD_MANAGER_POPUP_VISIBLE_LINES) {
        bool show_up = (app->sd_folder_offset > 0);
        bool show_down = (app->sd_folder_offset + visible < sd_folder_option_count);
        if(show_up || show_down) {
            uint8_t arrow_x = (uint8_t)(bubble_x + bubble_w - 10);
            int16_t content_top = list_y;
            int16_t content_bottom =
                list_y + (int16_t)((visible > 0 ? (visible - 1) : 0) * HINT_LINE_HEIGHT);
            int16_t min_base = bubble_y + 12;
            int16_t max_base = bubble_y + bubble_h - 12;
            simple_app_draw_scroll_hints_clamped(
                canvas, arrow_x, content_top, content_bottom, show_up, show_down, min_base, max_base);
        }
    }
}

static void simple_app_draw_sd_file_popup(SimpleApp* app, Canvas* canvas) {
    if(!app || !canvas || !app->sd_file_popup_active) return;

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
    char title[48];
    snprintf(
        title,
        sizeof(title),
        "Files: %s",
        (app->sd_current_folder_label[0] != '\0') ? app->sd_current_folder_label : "Unknown");
    simple_app_truncate_text(title, 28);
    canvas_draw_str(canvas, bubble_x + 8, bubble_y + 16, title);

    canvas_set_font(canvas, FontSecondary);
    uint8_t list_y = bubble_y + 28;

    if(app->sd_file_count == 0) {
        canvas_draw_str(canvas, bubble_x + 8, list_y, "No files found");
        return;
    }

    size_t visible = app->sd_file_count;
    if(visible > SD_MANAGER_POPUP_VISIBLE_LINES) {
        visible = SD_MANAGER_POPUP_VISIBLE_LINES;
    }

    if(app->sd_file_popup_index >= app->sd_file_count) {
        app->sd_file_popup_index = (app->sd_file_count > 0) ? (app->sd_file_count - 1) : 0;
    }

    if(app->sd_file_count > visible &&
       app->sd_file_popup_index >= app->sd_file_popup_offset + visible) {
        app->sd_file_popup_offset = app->sd_file_popup_index - visible + 1;
    }

    size_t max_offset = (app->sd_file_count > visible) ? (app->sd_file_count - visible) : 0;
    if(app->sd_file_popup_offset > max_offset) {
        app->sd_file_popup_offset = max_offset;
    }

    for(size_t i = 0; i < visible; i++) {
        size_t idx = app->sd_file_popup_offset + i;
        if(idx >= app->sd_file_count) break;
        const SdFileEntry* entry = &app->sd_files[idx];
        char line[48];
        if(idx == app->sd_file_popup_index) {
            simple_app_sd_scroll_buffer(app, entry->name, 20, line, sizeof(line));
        } else {
            strncpy(line, entry->name, sizeof(line) - 1);
            line[sizeof(line) - 1] = '\0';
            simple_app_truncate_text(line, 20);
        }
        uint8_t line_y = (uint8_t)(list_y + i * HINT_LINE_HEIGHT);
        if(idx == app->sd_file_popup_index) {
            canvas_draw_str(canvas, bubble_x + 4, line_y, ">");
        }
        canvas_draw_str(canvas, bubble_x + 8, line_y, line);
    }

    if(app->sd_file_count > SD_MANAGER_POPUP_VISIBLE_LINES) {
        bool show_up = (app->sd_file_popup_offset > 0);
        bool show_down = (app->sd_file_popup_offset + visible < app->sd_file_count);
        if(show_up || show_down) {
            uint8_t arrow_x = (uint8_t)(bubble_x + bubble_w - 10);
            int16_t content_top = list_y;
            int16_t content_bottom =
                list_y + (int16_t)((visible > 0 ? (visible - 1) : 0) * HINT_LINE_HEIGHT);
            int16_t min_base = bubble_y + 12;
            int16_t max_base = bubble_y + bubble_h - 12;
            simple_app_draw_scroll_hints_clamped(
                canvas, arrow_x, content_top, content_bottom, show_up, show_down, min_base, max_base);
        }
    }
}

static void simple_app_draw_sd_delete_confirm(SimpleApp* app, Canvas* canvas) {
    if(!app || !canvas || !app->sd_delete_confirm_active) return;

    const uint8_t bubble_x = 4;
    const uint8_t bubble_y = 8;
    const uint8_t bubble_w = DISPLAY_WIDTH - (bubble_x * 2);
    const uint8_t bubble_h = 48;
    const uint8_t radius = 9;

    canvas_set_color(canvas, ColorWhite);
    canvas_draw_rbox(canvas, bubble_x, bubble_y, bubble_w, bubble_h, radius);
    canvas_set_color(canvas, ColorBlack);
    canvas_draw_rframe(canvas, bubble_x, bubble_y, bubble_w, bubble_h, radius);

    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, bubble_x + 10, bubble_y + 14, "Delete file?");

    canvas_set_font(canvas, FontSecondary);
    char name_line[48];
    simple_app_sd_scroll_buffer(app, app->sd_delete_target_name, 18, name_line, sizeof(name_line));
    canvas_draw_str(canvas, bubble_x + 10, bubble_y + 28, name_line);

    const char* options =
        app->sd_delete_confirm_yes ? "No        > Yes" : "> No        Yes";
    canvas_draw_str(canvas, bubble_x + 18, bubble_y + 44, options);
}

static void simple_app_draw_setup_sd_manager(SimpleApp* app, Canvas* canvas) {
    if(!app || !canvas) return;

    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 10, 14, "SD Manager");

    canvas_set_font(canvas, FontSecondary);
    char line[64];
    if(app->sd_current_folder_label[0] != '\0') {
        snprintf(line, sizeof(line), "Folder: %s", app->sd_current_folder_label);
    } else {
        snprintf(line, sizeof(line), "Folder: <select>");
    }
    simple_app_truncate_text(line, 30);
    canvas_draw_str(canvas, 8, 30, line);

    if(app->sd_current_folder_path[0] != '\0') {
        snprintf(
            line,
            sizeof(line),
            "Path: %.54s",
            app->sd_current_folder_path);
    } else {
        snprintf(line, sizeof(line), "Path: <not set>");
    }
    simple_app_truncate_text(line, 30);
    canvas_draw_str(canvas, 8, 42, line);

    if(app->sd_listing_active) {
        canvas_draw_str(canvas, 8, 54, "Listing files...");
    } else {
        snprintf(
            line,
            sizeof(line),
            "Cached files: %u",
            (unsigned)((app->sd_file_count > 0) ? app->sd_file_count : 0));
        simple_app_truncate_text(line, 28);
        canvas_draw_str(canvas, 8, 54, line);
    }

    canvas_draw_str(canvas, 8, 62, "OK=folders  Right=refresh");
}

static void simple_app_handle_sd_folder_popup_event(SimpleApp* app, const InputEvent* event) {
    if(!app || !event || !app->sd_folder_popup_active) return;

    if(event->type != InputTypeShort && event->type != InputTypeRepeat) return;

    InputKey key = event->key;
    if(event->type == InputTypeShort && key == InputKeyBack) {
        app->sd_folder_popup_active = false;
        simple_app_reset_sd_scroll(app);
        if(app->viewport) {
            view_port_update(app->viewport);
        }
        return;
    }

    if(sd_folder_option_count == 0) {
        if(event->type == InputTypeShort && key == InputKeyOk) {
            app->sd_folder_popup_active = false;
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
        return;
    }

    size_t visible = sd_folder_option_count;
    if(visible > SD_MANAGER_POPUP_VISIBLE_LINES) {
        visible = SD_MANAGER_POPUP_VISIBLE_LINES;
    }

    if(key == InputKeyUp) {
        if(app->sd_folder_index > 0) {
            app->sd_folder_index--;
            simple_app_reset_sd_scroll(app);
            if(app->sd_folder_index < app->sd_folder_offset) {
                app->sd_folder_offset = app->sd_folder_index;
            }
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
    } else if(key == InputKeyDown) {
        if(app->sd_folder_index + 1 < sd_folder_option_count) {
            app->sd_folder_index++;
            simple_app_reset_sd_scroll(app);
            if(sd_folder_option_count > visible &&
               app->sd_folder_index >= app->sd_folder_offset + visible) {
                app->sd_folder_offset = app->sd_folder_index - visible + 1;
            }
            size_t max_offset =
                (sd_folder_option_count > visible) ? (sd_folder_option_count - visible) : 0;
            if(app->sd_folder_offset > max_offset) {
                app->sd_folder_offset = max_offset;
            }
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
    } else if(event->type == InputTypeShort && key == InputKeyOk) {
        if(app->sd_folder_index < sd_folder_option_count) {
            const SdFolderOption* folder = &sd_folder_options[app->sd_folder_index];
            simple_app_request_sd_listing(app, folder);
        }
    }
}

static void simple_app_handle_sd_file_popup_event(SimpleApp* app, const InputEvent* event) {
    if(!app || !event || !app->sd_file_popup_active) return;
    if(event->type != InputTypeShort && event->type != InputTypeRepeat) return;

    InputKey key = event->key;
    if(event->type == InputTypeShort && key == InputKeyBack) {
        app->sd_file_popup_active = false;
        simple_app_reset_sd_scroll(app);
        if(app->viewport) {
            view_port_update(app->viewport);
        }
        return;
    }

    if(app->sd_file_count == 0) {
        if(event->type == InputTypeShort && key == InputKeyOk) {
            app->sd_file_popup_active = false;
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
        return;
    }

    size_t visible = app->sd_file_count;
    if(visible > SD_MANAGER_POPUP_VISIBLE_LINES) {
        visible = SD_MANAGER_POPUP_VISIBLE_LINES;
    }

    if(key == InputKeyUp) {
        if(app->sd_file_popup_index > 0) {
            app->sd_file_popup_index--;
            simple_app_reset_sd_scroll(app);
            if(app->sd_file_popup_index < app->sd_file_popup_offset) {
                app->sd_file_popup_offset = app->sd_file_popup_index;
            }
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
    } else if(key == InputKeyDown) {
        if(app->sd_file_popup_index + 1 < app->sd_file_count) {
            app->sd_file_popup_index++;
            simple_app_reset_sd_scroll(app);
            if(app->sd_file_count > visible &&
               app->sd_file_popup_index >= app->sd_file_popup_offset + visible) {
                app->sd_file_popup_offset = app->sd_file_popup_index - visible + 1;
            }
            size_t max_offset =
                (app->sd_file_count > visible) ? (app->sd_file_count - visible) : 0;
            if(app->sd_file_popup_offset > max_offset) {
                app->sd_file_popup_offset = max_offset;
            }
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
    } else if(event->type == InputTypeShort && key == InputKeyOk) {
        if(app->sd_file_popup_index < app->sd_file_count) {
            const SdFileEntry* entry = &app->sd_files[app->sd_file_popup_index];
            simple_app_reset_sd_scroll(app);
            strncpy(app->sd_delete_target_name, entry->name, SD_MANAGER_FILE_NAME_MAX - 1);
            app->sd_delete_target_name[SD_MANAGER_FILE_NAME_MAX - 1] = '\0';

            if(app->sd_current_folder_path[0] != '\0') {
                size_t max_total = sizeof(app->sd_delete_target_path) - 1;
                size_t folder_len = simple_app_bounded_strlen(app->sd_current_folder_path, max_total);
                size_t remaining = (folder_len < max_total) ? (max_total - folder_len - 1) : 0; // minus slash
                size_t name_len = simple_app_bounded_strlen(entry->name, remaining);
                snprintf(
                    app->sd_delete_target_path,
                    sizeof(app->sd_delete_target_path),
                    "%.*s/%.*s",
                    (int)folder_len,
                    app->sd_current_folder_path,
                    (int)name_len,
                    entry->name);
            } else {
                strncpy(
                    app->sd_delete_target_path,
                    entry->name,
                    sizeof(app->sd_delete_target_path) - 1);
                app->sd_delete_target_path[sizeof(app->sd_delete_target_path) - 1] = '\0';
            }

            app->sd_delete_confirm_yes = false;
            app->sd_delete_confirm_active = true;
            app->sd_file_popup_active = false;
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
    }
}

static void simple_app_handle_sd_delete_confirm_event(SimpleApp* app, const InputEvent* event) {
    if(!app || !event || !app->sd_delete_confirm_active) return;
    if(event->type != InputTypeShort && event->type != InputTypeRepeat) return;

    InputKey key = event->key;
    if(event->type == InputTypeShort && key == InputKeyBack) {
        app->sd_delete_confirm_active = false;
        app->sd_delete_confirm_yes = false;
        app->sd_file_popup_active = true;
        simple_app_reset_sd_scroll(app);
        if(app->viewport) {
            view_port_update(app->viewport);
        }
        return;
    }

    if(key == InputKeyLeft || key == InputKeyRight) {
        app->sd_delete_confirm_yes = !app->sd_delete_confirm_yes;
        if(app->viewport) {
            view_port_update(app->viewport);
        }
        return;
    }

    if(event->type == InputTypeShort && key == InputKeyOk) {
        if(app->sd_delete_confirm_yes) {
            char command[220];
            snprintf(command, sizeof(command), "file_delete \"%s\"", app->sd_delete_target_path);
            simple_app_send_command(app, command, false);
            simple_app_show_status_message(app, "Deleting...", 800, false);
            app->sd_refresh_pending = true;
            app->sd_refresh_tick = furi_get_tick() + furi_ms_to_ticks(400);
            simple_app_reset_sd_listing(app);
        } else {
            app->sd_file_popup_active = true;
        }
        app->sd_delete_confirm_active = false;
        app->sd_delete_confirm_yes = false;
        simple_app_reset_sd_scroll(app);
        if(app->viewport) {
            view_port_update(app->viewport);
        }
    }
}

static void simple_app_handle_setup_sd_manager_input(SimpleApp* app, InputKey key) {
    if(!app) return;

    if(key == InputKeyBack) {
        app->sd_folder_popup_active = false;
        app->sd_file_popup_active = false;
        app->sd_delete_confirm_active = false;
        app->sd_refresh_pending = false;
        simple_app_reset_sd_listing(app);
        simple_app_reset_sd_scroll(app);
        app->screen = ScreenMenu;
        app->menu_state = MenuStateItems;
        app->section_index = MENU_SECTION_SETUP;
        if(app->viewport) {
            view_port_update(app->viewport);
        }
        return;
    }

    if(key == InputKeyOk) {
        app->sd_folder_popup_active = true;
        app->sd_file_popup_active = false;
        app->sd_delete_confirm_active = false;
        if(app->viewport) {
            view_port_update(app->viewport);
        }
        return;
    }

    if(key == InputKeyDown) {
        if(app->sd_file_count > 0 && !app->sd_listing_active) {
            app->sd_file_popup_active = true;
            app->sd_file_popup_index = 0;
            app->sd_file_popup_offset = 0;
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
        return;
    }

    if(key == InputKeyRight) {
        if(!app->sd_listing_active && sd_folder_option_count > 0 &&
           app->sd_folder_index < sd_folder_option_count) {
            simple_app_request_sd_listing(app, &sd_folder_options[app->sd_folder_index]);
        }
        return;
    }
}

static void simple_app_draw_setup_scanner(SimpleApp* app, Canvas* canvas) {
    if(!app) return;

    static const char* option_labels[] = {"SSID", "BSSID", "Channel", "Security", "Power", "Band", "Vendor"};

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
            case ScannerOptionShowVendor:
                enabled = app->scanner_show_vendor;
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
        size_t max_offset = option_count - SCANNER_FILTER_VISIBLE_COUNT;
        if(app->scanner_view_offset > max_offset) {
            app->scanner_view_offset = max_offset;
        }
        bool show_up = (app->scanner_view_offset > 0);
        bool show_down = (app->scanner_view_offset < max_offset);
        if(show_up || show_down) {
            uint8_t arrow_x = DISPLAY_WIDTH - 6;
            int16_t content_top = 26;
            int16_t content_bottom =
                26 + (int16_t)((SCANNER_FILTER_VISIBLE_COUNT > 0 ? (SCANNER_FILTER_VISIBLE_COUNT - 1) : 0) * 10);
            simple_app_draw_scroll_hints(canvas, arrow_x, content_top, content_bottom, show_up, show_down);
        }
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

    if(app->screen == ScreenMenu && app->menu_state == MenuStateSections) {
        simple_app_draw_sync_status(app, canvas);
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
    case ScreenSetupLed:
        simple_app_draw_setup_led(app, canvas);
        break;
    case ScreenSetupBoot:
        simple_app_draw_setup_boot(app, canvas);
        break;
    case ScreenSetupSdManager:
        simple_app_draw_setup_sd_manager(app, canvas);
        break;
    case ScreenSetupKarma:
        simple_app_draw_setup_karma(app, canvas);
        break;
    case ScreenConsole:
        simple_app_draw_console(app, canvas);
        break;
    case ScreenPackageMonitor:
        simple_app_draw_package_monitor(app, canvas);
        break;
    case ScreenChannelView:
        simple_app_draw_channel_view(app, canvas);
        break;
    case ScreenConfirmBlackout:
        simple_app_draw_confirm_blackout(app, canvas);
        break;
    case ScreenConfirmSnifferDos:
        simple_app_draw_confirm_sniffer_dos(app, canvas);
        break;
    case ScreenKarmaMenu:
        simple_app_draw_karma_menu(app, canvas);
        break;
    case ScreenEvilTwinMenu:
        simple_app_draw_evil_twin_menu(app, canvas);
        break;
    case ScreenPortalMenu:
        simple_app_draw_portal_menu(app, canvas);
        break;
    case ScreenDownloadBridge:
        simple_app_draw_download_bridge(app, canvas);
        break;
    default:
        simple_app_draw_results(app, canvas);
        break;
    }

    if(app->sd_delete_confirm_active) {
        simple_app_draw_sd_delete_confirm(app, canvas);
    } else if(app->sd_file_popup_active) {
        simple_app_draw_sd_file_popup(app, canvas);
    } else if(app->sd_folder_popup_active) {
        simple_app_draw_sd_folder_popup(app, canvas);
    } else if(app->portal_ssid_popup_active) {
        simple_app_draw_portal_ssid_popup(app, canvas);
    } else if(app->karma_probe_popup_active) {
        simple_app_draw_karma_probe_popup(app, canvas);
    } else if(app->karma_html_popup_active) {
        simple_app_draw_karma_html_popup(app, canvas);
    } else if(app->evil_twin_popup_active) {
        simple_app_draw_evil_twin_popup(app, canvas);
    } else if(app->hint_active) {
        simple_app_draw_hint(app, canvas);
    }
}

static void simple_app_handle_menu_input(SimpleApp* app, InputKey key) {
    if(key == InputKeyUp) {
        if(app->menu_state == MenuStateSections) {
            size_t section_count = menu_section_count;
            if(section_count == 0) return;
            if(app->section_index > 0) {
                app->section_index--;
            } else {
                app->section_index = section_count - 1;
            }
            view_port_update(app->viewport);
        } else {
            const MenuSection* section = &menu_sections[app->section_index];
            size_t entry_count = section->entry_count;
            if(entry_count == 0) return;
            if(app->item_index > 0) {
                app->item_index--;
                if(app->item_index < app->item_offset) {
                    app->item_offset = app->item_index;
                }
            } else {
                app->item_index = entry_count - 1;
                size_t visible_count = simple_app_menu_visible_count(app, app->section_index);
                if(visible_count == 0) visible_count = 1;
                if(app->item_index >= visible_count) {
                    app->item_offset = app->item_index - visible_count + 1;
                } else {
                    app->item_offset = 0;
                }
            }
            if(app->section_index == MENU_SECTION_ATTACKS) {
                app->last_attack_index = app->item_index;
            }
            view_port_update(app->viewport);
        }
    } else if(key == InputKeyDown) {
        if(app->menu_state == MenuStateSections) {
            size_t section_count = menu_section_count;
            if(section_count == 0) return;
            if(app->section_index + 1 < section_count) {
                app->section_index++;
            } else {
                app->section_index = 0;
            }
            view_port_update(app->viewport);
        } else {
            const MenuSection* section = &menu_sections[app->section_index];
            size_t entry_count = section->entry_count;
            if(entry_count == 0) return;
            if(app->item_index + 1 < entry_count) {
                app->item_index++;
                size_t visible_count = simple_app_menu_visible_count(app, app->section_index);
                if(visible_count == 0) visible_count = 1;
                if(app->item_index >= app->item_offset + visible_count) {
                    app->item_offset = app->item_index - visible_count + 1;
                }
            } else {
                app->item_index = 0;
                app->item_offset = 0;
            }
            if(app->section_index == MENU_SECTION_ATTACKS) {
                app->last_attack_index = app->item_index;
            }
            view_port_update(app->viewport);
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
            if(app->section_index == MENU_SECTION_SETUP) {
                simple_app_request_led_status(app);
                simple_app_request_boot_status(app);
                simple_app_request_vendor_status(app);
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
        } else if(entry->action == MenuActionOpenKarmaMenu) {
            app->screen = ScreenKarmaMenu;
            app->karma_menu_index = 0;
            app->karma_menu_offset = 0;
            view_port_update(app->viewport);
        } else if(entry->action == MenuActionOpenEvilTwinMenu) {
            app->screen = ScreenEvilTwinMenu;
            app->evil_twin_menu_index = 0;
            view_port_update(app->viewport);
        } else if(entry->action == MenuActionOpenPortalMenu) {
            app->screen = ScreenPortalMenu;
            app->portal_menu_index = 0;
            app->portal_menu_offset = 0;
            simple_app_portal_sync_offset(app);
            view_port_update(app->viewport);
        } else if(entry->action == MenuActionToggleBacklight) {
            simple_app_toggle_backlight(app);
        } else if(entry->action == MenuActionToggleOtgPower) {
            simple_app_toggle_otg_power(app);
        } else if(entry->action == MenuActionOpenLedSetup) {
            app->screen = ScreenSetupLed;
            app->led_setup_index = 0;
            simple_app_request_led_status(app);
        } else if(entry->action == MenuActionOpenBootSetup) {
            app->screen = ScreenSetupBoot;
            app->boot_setup_index = 0;
            app->boot_setup_long = (entry->label == menu_label_boot_long);
            simple_app_request_boot_status(app);
        } else if(entry->action == MenuActionOpenSdManager) {
            simple_app_open_sd_manager(app);
            return;
        } else if(entry->action == MenuActionOpenDownload) {
            simple_app_download_bridge_start(app);
        } else if(entry->action == MenuActionOpenScannerSetup) {
            app->screen = ScreenSetupScanner;
            app->scanner_setup_index = 0;
            app->scanner_adjusting_power = false;
            app->scanner_view_offset = 0;
            simple_app_request_vendor_status(app);
        } else if(entry->action == MenuActionOpenPackageMonitor) {
            simple_app_package_monitor_enter(app);
            return;
        } else if(entry->action == MenuActionOpenChannelView) {
            simple_app_channel_view_enter(app);
            return;
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

            app->karma_selected_html_id = entry->id;
            strncpy(
                app->karma_selected_html_name,
                entry->name,
                KARMA_HTML_NAME_MAX - 1);
            app->karma_selected_html_name[KARMA_HTML_NAME_MAX - 1] = '\0';

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

static void simple_app_update_karma_duration_label(SimpleApp* app) {
    if(!app) return;
    if(app->karma_sniffer_duration_sec < KARMA_SNIFFER_DURATION_MIN_SEC) {
        app->karma_sniffer_duration_sec = KARMA_SNIFFER_DURATION_MIN_SEC;
    } else if(app->karma_sniffer_duration_sec > KARMA_SNIFFER_DURATION_MAX_SEC) {
        app->karma_sniffer_duration_sec = KARMA_SNIFFER_DURATION_MAX_SEC;
    }
}

static void simple_app_modify_karma_duration(SimpleApp* app, int32_t delta) {
    if(!app || delta == 0) return;
    int32_t value = (int32_t)app->karma_sniffer_duration_sec + delta;
    if(value < (int32_t)KARMA_SNIFFER_DURATION_MIN_SEC) {
        value = (int32_t)KARMA_SNIFFER_DURATION_MIN_SEC;
    }
    if(value > (int32_t)KARMA_SNIFFER_DURATION_MAX_SEC) {
        value = (int32_t)KARMA_SNIFFER_DURATION_MAX_SEC;
    }
    if((uint32_t)value != app->karma_sniffer_duration_sec) {
        app->karma_sniffer_duration_sec = (uint32_t)value;
        simple_app_update_karma_duration_label(app);
        simple_app_mark_config_dirty(app);
    }
}

static void simple_app_reset_karma_probe_listing(SimpleApp* app) {
    if(!app) return;
    app->karma_probe_listing_active = false;
    app->karma_probe_list_header_seen = false;
    app->karma_probe_list_length = 0;
    app->karma_probe_count = 0;
    app->karma_probe_popup_index = 0;
    app->karma_probe_popup_offset = 0;
    app->karma_probe_popup_active = false;
}

static void simple_app_finish_karma_probe_listing(SimpleApp* app) {
    if(!app || !app->karma_probe_listing_active) return;
    app->karma_probe_listing_active = false;
    app->karma_probe_list_length = 0;
    app->karma_probe_list_header_seen = false;
    app->last_command_sent = false;
    bool on_karma_screen = (app->screen == ScreenKarmaMenu);
    if(app->karma_status_active) {
        simple_app_clear_status_message(app);
        app->karma_status_active = false;
    }

    if(app->karma_probe_count == 0) {
        if(on_karma_screen) {
            simple_app_show_status_message(app, "No probes found", 1500, true);
            app->karma_probe_popup_active = false;
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
        return;
    }

    if(!on_karma_screen) {
        app->karma_probe_popup_active = false;
        return;
    }

    size_t target_index = 0;
    if(app->karma_selected_probe_id != 0) {
        for(size_t i = 0; i < app->karma_probe_count; i++) {
            if(app->karma_probes[i].id == app->karma_selected_probe_id) {
                target_index = i;
                break;
            }
        }
        if(target_index >= app->karma_probe_count) {
            target_index = 0;
        }
    }

    app->karma_probe_popup_index = target_index;
    size_t visible = (app->karma_probe_count > KARMA_POPUP_VISIBLE_LINES)
                         ? KARMA_POPUP_VISIBLE_LINES
                         : app->karma_probe_count;
    if(visible == 0) visible = 1;

    if(app->karma_probe_count <= visible ||
       app->karma_probe_popup_index < visible) {
        app->karma_probe_popup_offset = 0;
    } else {
        app->karma_probe_popup_offset = app->karma_probe_popup_index - visible + 1;
    }
    size_t max_offset =
        (app->karma_probe_count > visible) ? (app->karma_probe_count - visible) : 0;
    if(app->karma_probe_popup_offset > max_offset) {
        app->karma_probe_popup_offset = max_offset;
    }

    app->karma_probe_popup_active = true;
    if(app->viewport) {
        view_port_update(app->viewport);
    }
}

static void simple_app_process_karma_probe_line(SimpleApp* app, const char* line) {
    if(!app || !line || !app->karma_probe_listing_active) return;

    const char* cursor = line;
    while(*cursor == ' ' || *cursor == '\t') {
        cursor++;
    }

    if(*cursor == '\0') {
        if(app->karma_probe_count > 0) {
            simple_app_finish_karma_probe_listing(app);
        }
        return;
    }

    if(strncmp(cursor, "Probes", 6) == 0 || strncmp(cursor, "Probe", 5) == 0) {
        app->karma_probe_list_header_seen = true;
        return;
    }

    if(strncmp(cursor, "No probes", 9) == 0 || strncmp(cursor, "No Probes", 9) == 0) {
        app->karma_probe_count = 0;
        simple_app_finish_karma_probe_listing(app);
        return;
    }

    if(!isdigit((unsigned char)cursor[0])) {
        if(app->karma_probe_count > 0) {
            simple_app_finish_karma_probe_listing(app);
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

    if(app->karma_probe_count >= KARMA_MAX_PROBES) {
        return;
    }

    KarmaProbeEntry* entry = &app->karma_probes[app->karma_probe_count++];
    entry->id = (uint8_t)id;
    strncpy(entry->name, endptr, KARMA_PROBE_NAME_MAX - 1);
    entry->name[KARMA_PROBE_NAME_MAX - 1] = '\0';

    size_t len = strlen(entry->name);
    while(len > 0 &&
          (entry->name[len - 1] == '\r' || entry->name[len - 1] == '\n' ||
           entry->name[len - 1] == ' ' || entry->name[len - 1] == '\t')) {
        entry->name[--len] = '\0';
    }

    app->karma_probe_list_header_seen = true;
}

static void simple_app_karma_probe_feed(SimpleApp* app, char ch) {
    if(!app || !app->karma_probe_listing_active) return;
    if(ch == '\r') return;

    if(ch == '>') {
        if(app->karma_probe_list_length > 0) {
            app->karma_probe_list_buffer[app->karma_probe_list_length] = '\0';
            simple_app_process_karma_probe_line(app, app->karma_probe_list_buffer);
            app->karma_probe_list_length = 0;
        }
        if(app->karma_probe_count > 0 || app->karma_probe_list_header_seen) {
            simple_app_finish_karma_probe_listing(app);
        }
        return;
    }

    if(ch == '\n') {
        if(app->karma_probe_list_length > 0) {
            app->karma_probe_list_buffer[app->karma_probe_list_length] = '\0';
            simple_app_process_karma_probe_line(app, app->karma_probe_list_buffer);
        } else if(app->karma_probe_list_header_seen) {
            simple_app_finish_karma_probe_listing(app);
        }
        app->karma_probe_list_length = 0;
        return;
    }

    if(app->karma_probe_list_length + 1 >= sizeof(app->karma_probe_list_buffer)) {
        app->karma_probe_list_length = 0;
        return;
    }

    app->karma_probe_list_buffer[app->karma_probe_list_length++] = ch;
}

static void simple_app_draw_karma_probe_popup(SimpleApp* app, Canvas* canvas) {
    if(!app || !canvas || !app->karma_probe_popup_active) return;

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
    canvas_draw_str(canvas, bubble_x + 8, bubble_y + 16, "Select Probe");

    canvas_set_font(canvas, FontSecondary);
    uint8_t list_y = bubble_y + 28;

    if(app->karma_probe_count == 0) {
        canvas_draw_str(canvas, bubble_x + 10, list_y, "No probes found");
        canvas_draw_str(canvas, bubble_x + 10, (uint8_t)(list_y + HINT_LINE_HEIGHT), "Back returns");
        return;
    }

    size_t visible = app->karma_probe_count;
    if(visible > KARMA_POPUP_VISIBLE_LINES) {
        visible = KARMA_POPUP_VISIBLE_LINES;
    }

    if(app->karma_probe_popup_offset >= app->karma_probe_count) {
        app->karma_probe_popup_offset =
            (app->karma_probe_count > visible) ? (app->karma_probe_count - visible) : 0;
    }

    for(size_t i = 0; i < visible; i++) {
        size_t idx = app->karma_probe_popup_offset + i;
        if(idx >= app->karma_probe_count) break;
        const KarmaProbeEntry* entry = &app->karma_probes[idx];
        char line[64];
        snprintf(line, sizeof(line), "%u %s", (unsigned)entry->id, entry->name);
        simple_app_truncate_text(line, 28);
        uint8_t line_y = (uint8_t)(list_y + i * HINT_LINE_HEIGHT);
        if(idx == app->karma_probe_popup_index) {
            canvas_draw_str(canvas, bubble_x + 4, line_y, ">");
        }
        canvas_draw_str(canvas, bubble_x + 8, line_y, line);
    }

    if(app->karma_probe_count > KARMA_POPUP_VISIBLE_LINES) {
        bool show_up = (app->karma_probe_popup_offset > 0);
        bool show_down =
            (app->karma_probe_popup_offset + visible < app->karma_probe_count);
        if(show_up || show_down) {
            uint8_t arrow_x = (uint8_t)(bubble_x + bubble_w - 10);
            int16_t content_top = list_y;
            int16_t content_bottom =
                list_y + (int16_t)((visible > 0 ? (visible - 1) : 0) * HINT_LINE_HEIGHT);
            int16_t min_base = bubble_y + 12;
            int16_t max_base = bubble_y + bubble_h - 12;
            simple_app_draw_scroll_hints_clamped(
                canvas, arrow_x, content_top, content_bottom, show_up, show_down, min_base, max_base);
        }
    }
}

static void simple_app_handle_karma_probe_popup_event(SimpleApp* app, const InputEvent* event) {
    if(!app || !event || !app->karma_probe_popup_active) return;
    if(event->type != InputTypeShort && event->type != InputTypeRepeat) return;

    InputKey key = event->key;
    if(event->type == InputTypeShort && key == InputKeyBack) {
        app->karma_probe_popup_active = false;
        if(app->viewport) {
            view_port_update(app->viewport);
        }
        return;
    }

    if(app->karma_probe_count == 0) {
        if(event->type == InputTypeShort && key == InputKeyOk) {
            app->karma_probe_popup_active = false;
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
        return;
    }

    size_t visible = (app->karma_probe_count > KARMA_POPUP_VISIBLE_LINES)
                         ? KARMA_POPUP_VISIBLE_LINES
                         : app->karma_probe_count;
    if(visible == 0) visible = 1;

    if(key == InputKeyUp) {
        if(app->karma_probe_popup_index > 0) {
            app->karma_probe_popup_index--;
            if(app->karma_probe_popup_index < app->karma_probe_popup_offset) {
                app->karma_probe_popup_offset = app->karma_probe_popup_index;
            }
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
    } else if(key == InputKeyDown) {
        if(app->karma_probe_popup_index + 1 < app->karma_probe_count) {
            app->karma_probe_popup_index++;
            if(app->karma_probe_count > visible &&
               app->karma_probe_popup_index >= app->karma_probe_popup_offset + visible) {
                app->karma_probe_popup_offset =
                    app->karma_probe_popup_index - visible + 1;
            }
            size_t max_offset =
                (app->karma_probe_count > visible) ? (app->karma_probe_count - visible) : 0;
            if(app->karma_probe_popup_offset > max_offset) {
                app->karma_probe_popup_offset = max_offset;
            }
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
    } else if(event->type == InputTypeShort && key == InputKeyOk) {
        if(app->karma_probe_popup_index < app->karma_probe_count) {
            const KarmaProbeEntry* entry = &app->karma_probes[app->karma_probe_popup_index];
            app->karma_selected_probe_id = entry->id;
            strncpy(
                app->karma_selected_probe_name,
                entry->name,
                KARMA_PROBE_NAME_MAX - 1);
            app->karma_selected_probe_name[KARMA_PROBE_NAME_MAX - 1] = '\0';

            char message[64];
            snprintf(message, sizeof(message), "Probe selected:\n%s", entry->name);
            simple_app_show_status_message(app, message, 1500, true);

            app->karma_probe_popup_active = false;
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
    }
}

static void simple_app_request_karma_probe_list(SimpleApp* app) {
    if(!app) return;
    simple_app_reset_karma_probe_listing(app);
    app->karma_probe_listing_active = true;
    app->karma_pending_probe_refresh = false;
    bool show_status = (app->screen == ScreenKarmaMenu);
    if(show_status) {
        simple_app_show_status_message(app, "Listing probes...", 0, false);
        app->karma_status_active = true;
    } else {
        app->karma_status_active = false;
    }
    simple_app_send_command(app, "list_probes", false);
    if(show_status && app->viewport) {
        view_port_update(app->viewport);
    }
}

static void simple_app_reset_karma_html_listing(SimpleApp* app) {
    if(!app) return;
    app->karma_html_listing_active = false;
    app->karma_html_list_header_seen = false;
    app->karma_html_list_length = 0;
    app->karma_html_count = 0;
    app->karma_html_popup_index = 0;
    app->karma_html_popup_offset = 0;
    app->karma_html_popup_active = false;
}

static void simple_app_finish_karma_html_listing(SimpleApp* app) {
    if(!app || !app->karma_html_listing_active) return;
    app->karma_html_listing_active = false;
    app->karma_html_list_length = 0;
    app->karma_html_list_header_seen = false;
    app->last_command_sent = false;
    bool on_html_screen = (app->screen == ScreenKarmaMenu) || (app->screen == ScreenPortalMenu);
    if(app->karma_status_active) {
        simple_app_clear_status_message(app);
        app->karma_status_active = false;
    }

    if(app->karma_html_count == 0) {
        if(on_html_screen) {
            simple_app_show_status_message(app, "No HTML files\nfound on SD", 1500, true);
            app->karma_html_popup_active = false;
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
        return;
    }

    if(!on_html_screen) {
        app->karma_html_popup_active = false;
        return;
    }

    size_t target_index = 0;
    if(app->karma_selected_html_id != 0) {
        for(size_t i = 0; i < app->karma_html_count; i++) {
            if(app->karma_html_entries[i].id == app->karma_selected_html_id) {
                target_index = i;
                break;
            }
        }
        if(target_index >= app->karma_html_count) {
            target_index = 0;
        }
    }

    app->karma_html_popup_index = target_index;
    size_t visible = (app->karma_html_count > KARMA_POPUP_VISIBLE_LINES)
                         ? KARMA_POPUP_VISIBLE_LINES
                         : app->karma_html_count;
    if(visible == 0) visible = 1;

    if(app->karma_html_count <= visible ||
       app->karma_html_popup_index < visible) {
        app->karma_html_popup_offset = 0;
    } else {
        app->karma_html_popup_offset = app->karma_html_popup_index - visible + 1;
    }
    size_t max_offset =
        (app->karma_html_count > visible) ? (app->karma_html_count - visible) : 0;
    if(app->karma_html_popup_offset > max_offset) {
        app->karma_html_popup_offset = max_offset;
    }

    app->karma_html_popup_active = true;
    if(app->viewport) {
        view_port_update(app->viewport);
    }
}

static void simple_app_process_karma_html_line(SimpleApp* app, const char* line) {
    if(!app || !line || !app->karma_html_listing_active) return;

    const char* cursor = line;
    while(*cursor == ' ' || *cursor == '\t') {
        cursor++;
    }
    if(*cursor == '\0') {
        if(app->karma_html_count > 0) {
            simple_app_finish_karma_html_listing(app);
        }
        return;
    }

    if(strncmp(cursor, "HTML files", 10) == 0) {
        app->karma_html_list_header_seen = true;
        return;
    }

    if(strncmp(cursor, "No HTML", 7) == 0 || strncmp(cursor, "No html", 7) == 0) {
        app->karma_html_count = 0;
        simple_app_finish_karma_html_listing(app);
        return;
    }

    if(!isdigit((unsigned char)cursor[0])) {
        if(app->karma_html_count > 0) {
            simple_app_finish_karma_html_listing(app);
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

    if(app->karma_html_count >= KARMA_MAX_HTML_FILES) {
        return;
    }

    KarmaHtmlEntry* entry = &app->karma_html_entries[app->karma_html_count++];
    entry->id = (uint8_t)id;
    strncpy(entry->name, endptr, KARMA_HTML_NAME_MAX - 1);
    entry->name[KARMA_HTML_NAME_MAX - 1] = '\0';

    size_t len = strlen(entry->name);
    while(len > 0 &&
          (entry->name[len - 1] == '\r' || entry->name[len - 1] == '\n' ||
           entry->name[len - 1] == ' ' || entry->name[len - 1] == '\t')) {
        entry->name[--len] = '\0';
    }

    app->karma_html_list_header_seen = true;
}

static void simple_app_karma_html_feed(SimpleApp* app, char ch) {
    if(!app || !app->karma_html_listing_active) return;
    if(ch == '\r') return;

    if(ch == '>') {
        if(app->karma_html_list_length > 0) {
            app->karma_html_list_buffer[app->karma_html_list_length] = '\0';
            simple_app_process_karma_html_line(app, app->karma_html_list_buffer);
            app->karma_html_list_length = 0;
        }
        if(app->karma_html_count > 0 || app->karma_html_list_header_seen) {
            simple_app_finish_karma_html_listing(app);
        }
        return;
    }

    if(ch == '\n') {
        if(app->karma_html_list_length > 0) {
            app->karma_html_list_buffer[app->karma_html_list_length] = '\0';
            simple_app_process_karma_html_line(app, app->karma_html_list_buffer);
        } else if(app->karma_html_list_header_seen) {
            simple_app_finish_karma_html_listing(app);
        }
        app->karma_html_list_length = 0;
        return;
    }

    if(app->karma_html_list_length + 1 >= sizeof(app->karma_html_list_buffer)) {
        app->karma_html_list_length = 0;
        return;
    }

    app->karma_html_list_buffer[app->karma_html_list_length++] = ch;
}

static void simple_app_draw_karma_html_popup(SimpleApp* app, Canvas* canvas) {
    if(!app || !canvas || !app->karma_html_popup_active) return;

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

    if(app->karma_html_count == 0) {
        canvas_draw_str(canvas, bubble_x + 10, list_y, "No HTML files");
        canvas_draw_str(canvas, bubble_x + 10, (uint8_t)(list_y + HINT_LINE_HEIGHT), "Back returns");
        return;
    }

    size_t visible = app->karma_html_count;
    if(visible > KARMA_POPUP_VISIBLE_LINES) {
        visible = KARMA_POPUP_VISIBLE_LINES;
    }

    if(app->karma_html_popup_offset >= app->karma_html_count) {
        app->karma_html_popup_offset =
            (app->karma_html_count > visible) ? (app->karma_html_count - visible) : 0;
    }

    for(size_t i = 0; i < visible; i++) {
        size_t idx = app->karma_html_popup_offset + i;
        if(idx >= app->karma_html_count) break;
        const KarmaHtmlEntry* entry = &app->karma_html_entries[idx];
        char line[48];
        snprintf(line, sizeof(line), "%u %s", (unsigned)entry->id, entry->name);
        simple_app_truncate_text(line, 28);
        uint8_t line_y = (uint8_t)(list_y + i * HINT_LINE_HEIGHT);
        if(idx == app->karma_html_popup_index) {
            canvas_draw_str(canvas, bubble_x + 4, line_y, ">");
        }
        canvas_draw_str(canvas, bubble_x + 8, line_y, line);
    }

    if(app->karma_html_count > KARMA_POPUP_VISIBLE_LINES) {
        bool show_up = (app->karma_html_popup_offset > 0);
        bool show_down =
            (app->karma_html_popup_offset + visible < app->karma_html_count);
        if(show_up || show_down) {
            uint8_t arrow_x = (uint8_t)(bubble_x + bubble_w - 10);
            int16_t content_top = list_y;
            int16_t content_bottom =
                list_y + (int16_t)((visible > 0 ? (visible - 1) : 0) * HINT_LINE_HEIGHT);
            int16_t min_base = bubble_y + 12;
            int16_t max_base = bubble_y + bubble_h - 12;
            simple_app_draw_scroll_hints_clamped(
                canvas, arrow_x, content_top, content_bottom, show_up, show_down, min_base, max_base);
        }
    }
}

static void simple_app_handle_karma_html_popup_event(SimpleApp* app, const InputEvent* event) {
    if(!app || !event || !app->karma_html_popup_active) return;
    if(event->type != InputTypeShort && event->type != InputTypeRepeat && event->type != InputTypeLong) return;

    InputKey key = event->key;
    bool is_short = (event->type == InputTypeShort);

    if(is_short && key == InputKeyBack) {
        app->karma_html_popup_active = false;
        if(app->viewport) {
            view_port_update(app->viewport);
        }
        return;
    }

    if(app->karma_html_count == 0) {
        if(is_short && key == InputKeyOk) {
            app->karma_html_popup_active = false;
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
        return;
    }

    size_t visible = (app->karma_html_count > KARMA_POPUP_VISIBLE_LINES)
                         ? KARMA_POPUP_VISIBLE_LINES
                         : app->karma_html_count;
    if(visible == 0) visible = 1;

    if(key == InputKeyUp) {
        if(app->karma_html_popup_index > 0) {
            app->karma_html_popup_index--;
            if(app->karma_html_popup_index < app->karma_html_popup_offset) {
                app->karma_html_popup_offset = app->karma_html_popup_index;
            }
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
    } else if(key == InputKeyDown) {
        if(app->karma_html_popup_index + 1 < app->karma_html_count) {
            app->karma_html_popup_index++;
            if(app->karma_html_count > visible &&
               app->karma_html_popup_index >= app->karma_html_popup_offset + visible) {
                app->karma_html_popup_offset =
                    app->karma_html_popup_index - visible + 1;
            }
            size_t max_offset =
                (app->karma_html_count > visible) ? (app->karma_html_count - visible) : 0;
            if(app->karma_html_popup_offset > max_offset) {
                app->karma_html_popup_offset = max_offset;
            }
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
    } else if(is_short && key == InputKeyOk) {
        if(app->karma_html_popup_index < app->karma_html_count) {
            const KarmaHtmlEntry* entry = &app->karma_html_entries[app->karma_html_popup_index];
            app->karma_selected_html_id = entry->id;
            strncpy(
                app->karma_selected_html_name,
                entry->name,
                KARMA_HTML_NAME_MAX - 1);
            app->karma_selected_html_name[KARMA_HTML_NAME_MAX - 1] = '\0';

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

            if(app->screen == ScreenPortalMenu) {
                app->portal_menu_index = PORTAL_MENU_OPTION_COUNT - 1;
                simple_app_portal_sync_offset(app);
            }

            app->karma_html_popup_active = false;
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
    }
}

static void simple_app_request_karma_html_list(SimpleApp* app) {
    if(!app) return;
    simple_app_reset_karma_html_listing(app);
    app->karma_html_listing_active = true;
    bool show_status = (app->screen == ScreenKarmaMenu) || (app->screen == ScreenPortalMenu);
    if(show_status) {
        simple_app_show_status_message(app, "Listing HTML...", 0, false);
        app->karma_status_active = true;
    } else {
        app->karma_status_active = false;
    }
    simple_app_send_command(app, "list_sd", false);
    if(show_status && app->viewport) {
        view_port_update(app->viewport);
    }
}

static void simple_app_start_karma_sniffer(SimpleApp* app) {
    if(!app) return;
    if(app->karma_probe_listing_active || app->karma_html_listing_active || app->evil_twin_listing_active) {
        simple_app_send_stop_if_needed(app);
        simple_app_reset_karma_probe_listing(app);
        simple_app_reset_karma_html_listing(app);
        if(app->evil_twin_listing_active) {
            simple_app_reset_evil_twin_listing(app);
        }
    }
    if(app->karma_sniffer_running) {
        simple_app_send_stop_if_needed(app);
        app->karma_sniffer_running = false;
        app->karma_pending_probe_refresh = false;
    }
    simple_app_update_karma_duration_label(app);
    uint32_t duration_ms = app->karma_sniffer_duration_sec * 1000;
    app->karma_sniffer_stop_tick = furi_get_tick() + furi_ms_to_ticks(duration_ms);
    app->karma_sniffer_running = true;
    app->karma_pending_probe_refresh = false;

    simple_app_show_status_message(app, "Collecting probes...", 0, false);
    app->karma_status_active = true;
    simple_app_send_command(app, "start_sniffer", false);
    if(app->viewport) {
        view_port_update(app->viewport);
    }
}

static void simple_app_start_karma_attack(SimpleApp* app) {
    if(!app) return;
    if(app->karma_probe_listing_active || app->karma_html_listing_active || app->evil_twin_listing_active) {
        simple_app_show_status_message(app, "Wait for list\ncompletion", 1500, true);
        return;
    }
    if(app->karma_selected_probe_id == 0) {
        simple_app_show_status_message(app, "Select probe\nbefore starting", 1500, true);
        return;
    }
    if(app->karma_selected_html_id == 0) {
        simple_app_show_status_message(app, "Select HTML file\nbefore starting", 1500, true);
        return;
    }

    char select_command[48];
    snprintf(select_command, sizeof(select_command), "select_html %u", (unsigned)app->karma_selected_html_id);
    simple_app_send_command(app, select_command, false);
    app->last_command_sent = false;

    char start_command[48];
    snprintf(start_command, sizeof(start_command), "start_karma %u", (unsigned)app->karma_selected_probe_id);
    simple_app_send_command(app, start_command, true);
}

static void simple_app_draw_karma_menu(SimpleApp* app, Canvas* canvas) {
    if(!app || !canvas) return;

    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 4, 8, "Karma");

    canvas_set_font(canvas, FontSecondary);

    const size_t visible_count = 3;
    const size_t total_count = KARMA_MENU_OPTION_COUNT;
    size_t offset = app->karma_menu_offset;

    if(app->karma_menu_index < offset) {
        offset = app->karma_menu_index;
    } else if(app->karma_menu_index >= offset + visible_count) {
        offset = (app->karma_menu_index >= visible_count)
                     ? (app->karma_menu_index - visible_count + 1)
                     : 0;
    }

    if(total_count <= visible_count) {
        offset = 0;
    } else if(offset + visible_count > total_count) {
        offset = total_count - visible_count;
    }
    app->karma_menu_offset = offset;

    const uint8_t base_y = 18;
    uint8_t current_y = base_y;
    uint8_t list_bottom_y = base_y;

    size_t draw_count = 0;
    for(size_t idx = offset; idx < total_count && draw_count < visible_count; idx++, draw_count++) {
        bool is_selected = (app->karma_menu_index == idx);
        bool detail_block = (idx == 2 || idx == 3);

        char label[20];
        char info[48];
        info[0] = '\0';

        switch(idx) {
        case 0:
            strncpy(label, "Collect Probes", sizeof(label) - 1);
            label[sizeof(label) - 1] = '\0';
            if(app->karma_sniffer_running) {
                strncpy(info, "running", sizeof(info) - 1);
            } else if(app->karma_pending_probe_refresh) {
                strncpy(info, "updating", sizeof(info) - 1);
            } else {
                strncpy(info, "idle", sizeof(info) - 1);
            }
            break;
        case 1:
            strncpy(label, "Duration", sizeof(label) - 1);
            label[sizeof(label) - 1] = '\0';
            snprintf(info, sizeof(info), "%lus", (unsigned long)app->karma_sniffer_duration_sec);
            break;
        case 2:
            strncpy(label, "Select Probe", sizeof(label) - 1);
            label[sizeof(label) - 1] = '\0';
            if(app->karma_selected_probe_id != 0 && app->karma_selected_probe_name[0] != '\0') {
                strncpy(info, app->karma_selected_probe_name, sizeof(info) - 1);
                info[sizeof(info) - 1] = '\0';
                simple_app_truncate_text(info, 20);
            } else {
                strncpy(info, "<none>", sizeof(info) - 1);
            }
            break;
        case 3:
            strncpy(label, "Select HTML", sizeof(label) - 1);
            label[sizeof(label) - 1] = '\0';
            if(app->karma_selected_html_id != 0 && app->karma_selected_html_name[0] != '\0') {
                strncpy(info, app->karma_selected_html_name, sizeof(info) - 1);
                info[sizeof(info) - 1] = '\0';
                simple_app_truncate_text(info, 20);
            } else {
                strncpy(info, "<none>", sizeof(info) - 1);
            }
            break;
        default:
            strncpy(label, "Start Karma", sizeof(label) - 1);
            label[sizeof(label) - 1] = '\0';
            if(app->karma_selected_probe_id == 0) {
                strncpy(info, "need probe", sizeof(info) - 1);
            } else if(app->karma_selected_html_id == 0) {
                strncpy(info, "need HTML", sizeof(info) - 1);
            } else if(app->karma_sniffer_running) {
                strncpy(info, "sniffer", sizeof(info) - 1);
            } else {
                info[0] = '\0';
            }
            break;
        }
        label[sizeof(label) - 1] = '\0';
        info[sizeof(info) - 1] = '\0';

        if(is_selected) {
            canvas_draw_str(canvas, 2, current_y, ">");
        }
        canvas_draw_str(canvas, 12, current_y, label);

        if(detail_block) {
            canvas_draw_str(canvas, 14, (uint8_t)(current_y + 10), info);
        } else if(info[0] != '\0') {
            canvas_draw_str_aligned(canvas, 124, current_y, AlignRight, AlignCenter, info);
        }

        uint8_t block_height = detail_block ? 18 : 12;
        current_y = (uint8_t)(current_y + block_height);
        list_bottom_y = current_y;
    }

    uint8_t arrow_x = DISPLAY_WIDTH - 6;
    if(offset > 0) {
        int16_t top_arrow_y = (base_y > 4) ? (int16_t)(base_y - 4) : 12;
        simple_app_draw_scroll_arrow(canvas, arrow_x, top_arrow_y, true);
    }
    if(offset + visible_count < total_count) {
        int16_t raw_y = (int16_t)list_bottom_y - 8;
        if(raw_y > 60) raw_y = 60;
        if(raw_y < 16) raw_y = 16;
        simple_app_draw_scroll_arrow(canvas, arrow_x, raw_y, false);
    }
}

static void simple_app_handle_karma_menu_input(SimpleApp* app, InputKey key) {
    if(!app) return;

    if(key == InputKeyBack || key == InputKeyLeft) {
        simple_app_send_stop_if_needed(app);
        simple_app_reset_karma_probe_listing(app);
        simple_app_reset_karma_html_listing(app);
        simple_app_clear_status_message(app);
        app->karma_status_active = false;
        app->karma_probe_popup_active = false;
        app->karma_html_popup_active = false;
        app->karma_menu_offset = 0;
        simple_app_focus_attacks_menu(app);
        if(app->viewport) {
            view_port_update(app->viewport);
        }
        return;
    }

    if(key == InputKeyUp) {
        if(app->karma_menu_index > 0) {
            app->karma_menu_index--;
            if(app->karma_menu_index < app->karma_menu_offset) {
                app->karma_menu_offset = app->karma_menu_index;
            }
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
    } else if(key == InputKeyDown) {
        if(app->karma_menu_index + 1 < KARMA_MENU_OPTION_COUNT) {
            app->karma_menu_index++;
            size_t visible = 3;
            if(app->karma_menu_index >= app->karma_menu_offset + visible) {
                app->karma_menu_offset = app->karma_menu_index - visible + 1;
            }
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
    } else if(key == InputKeyOk) {
        switch(app->karma_menu_index) {
        case 0:
            simple_app_start_karma_sniffer(app);
            break;
        case 1:
            simple_app_clear_status_message(app);
            app->karma_status_active = false;
            app->screen = ScreenSetupKarma;
            if(app->viewport) {
                view_port_update(app->viewport);
            }
            break;
        case 2:
            if(app->karma_probe_listing_active || app->karma_probe_count == 0) {
                simple_app_request_karma_probe_list(app);
            } else {
                simple_app_clear_status_message(app);
                app->karma_status_active = false;
                if(app->karma_probe_popup_index >= app->karma_probe_count) {
                    app->karma_probe_popup_index = 0;
                }
                if(app->karma_probe_popup_offset >= app->karma_probe_count) {
                    app->karma_probe_popup_offset = 0;
                }
                app->karma_probe_popup_active = true;
                if(app->viewport) {
                    view_port_update(app->viewport);
                }
            }
            break;
        case 3:
            if(app->karma_html_listing_active || app->karma_html_count == 0) {
                simple_app_request_karma_html_list(app);
            } else {
                simple_app_clear_status_message(app);
                app->karma_status_active = false;
                if(app->karma_html_popup_index >= app->karma_html_count) {
                    app->karma_html_popup_index = 0;
                }
                if(app->karma_html_popup_offset >= app->karma_html_count) {
                    app->karma_html_popup_offset = 0;
                }
                app->karma_html_popup_active = true;
                if(app->viewport) {
                    view_port_update(app->viewport);
                }
            }
            break;
        default:
            simple_app_start_karma_attack(app);
            break;
        }
    }
}

static void simple_app_update_karma_sniffer(SimpleApp* app) {
    if(!app) return;

    uint32_t now = furi_get_tick();
    if(app->karma_sniffer_running && now >= app->karma_sniffer_stop_tick) {
        app->karma_sniffer_running = false;
        simple_app_send_command(app, "stop", false);
        app->last_command_sent = false;
        if(app->screen == ScreenKarmaMenu) {
            simple_app_show_status_message(app, "Sniffer stopped", 1000, true);
            app->karma_status_active = false;
        } else {
            simple_app_clear_status_message(app);
            app->karma_status_active = false;
        }
        app->karma_pending_probe_refresh = true;
        app->karma_pending_probe_tick = now + furi_ms_to_ticks(KARMA_AUTO_LIST_DELAY_MS);
        if(app->screen == ScreenKarmaMenu && app->viewport) {
            view_port_update(app->viewport);
        }
    }

    if(app->karma_pending_probe_refresh && now >= app->karma_pending_probe_tick) {
        if(app->karma_probe_listing_active) {
            app->karma_pending_probe_tick = now + furi_ms_to_ticks(KARMA_AUTO_LIST_DELAY_MS);
        } else {
            app->karma_pending_probe_refresh = false;
            simple_app_request_karma_probe_list(app);
            if(app->screen == ScreenKarmaMenu && app->viewport) {
                view_port_update(app->viewport);
            }
        }
    }
}

static void simple_app_draw_setup_karma(SimpleApp* app, Canvas* canvas) {
    if(!app || !canvas) return;

    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 6, 16, "Karma Sniffer");

    canvas_set_font(canvas, FontSecondary);
    char line[32];
    snprintf(line, sizeof(line), "Duration: %lus", (unsigned long)app->karma_sniffer_duration_sec);
    canvas_draw_str(canvas, 6, 32, line);
    canvas_draw_str(canvas, 6, 46, "Adjust with arrows");
    canvas_draw_str(canvas, 6, 58, "OK to exit");
}

static void simple_app_handle_setup_karma_input(SimpleApp* app, InputKey key) {
    if(!app) return;

    if(key == InputKeyBack || key == InputKeyOk) {
        simple_app_save_config_if_dirty(app, "Config saved", true);
        app->screen = ScreenKarmaMenu;
        if(app->viewport) {
            view_port_update(app->viewport);
        }
        return;
    }

    uint32_t before = app->karma_sniffer_duration_sec;

    if(key == InputKeyUp) {
        simple_app_modify_karma_duration(app, KARMA_SNIFFER_DURATION_STEP);
    } else if(key == InputKeyDown) {
        simple_app_modify_karma_duration(app, -(int32_t)KARMA_SNIFFER_DURATION_STEP);
    } else if(key == InputKeyRight) {
        simple_app_modify_karma_duration(app, 1);
    } else if(key == InputKeyLeft) {
        simple_app_modify_karma_duration(app, -1);
    }

    if(before != app->karma_sniffer_duration_sec && app->viewport) {
        view_port_update(app->viewport);
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
            if(app->scanner_setup_index == ScannerOptionShowVendor) {
                if(app->scanner_show_vendor && simple_app_enabled_field_count(app) <= 1) {
                    if(app->viewport) {
                        view_port_update(app->viewport);
                    }
                } else {
                    bool new_state = !app->scanner_show_vendor;
                    app->scanner_show_vendor = new_state;
                    app->vendor_scan_enabled = new_state;
                    simple_app_mark_config_dirty(app);
                    simple_app_update_result_layout(app);
                    simple_app_rebuild_visible_results(app);
                    simple_app_adjust_result_offset(app);
                    simple_app_send_vendor_command(app, new_state);
                    if(app->viewport) {
                        view_port_update(app->viewport);
                    }
                }
                return;
            }
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

static void simple_app_handle_setup_led_input(SimpleApp* app, InputKey key) {
    if(!app) return;

    if(key == InputKeyBack) {
        simple_app_save_config_if_dirty(app, "Config saved", true);
        app->screen = ScreenMenu;
        if(app->viewport) {
            view_port_update(app->viewport);
        }
        return;
    }

    if(key == InputKeyUp) {
        if(app->led_setup_index > 0) {
            app->led_setup_index = 0;
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
        return;
    }

    if(key == InputKeyDown) {
        if(app->led_setup_index < 1) {
            app->led_setup_index = 1;
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
        return;
    }

    if(app->led_setup_index == 0) {
        bool previous = app->led_enabled;
        if(key == InputKeyLeft) {
            app->led_enabled = false;
        } else if(key == InputKeyRight) {
            app->led_enabled = true;
        } else if(key == InputKeyOk) {
            app->led_enabled = !app->led_enabled;
        } else {
            return;
        }
        if(previous != app->led_enabled) {
            simple_app_update_led_label(app);
            simple_app_send_led_power_command(app);
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
        return;
    }

    if(app->led_setup_index == 1) {
        uint32_t before = app->led_level;
        if(key == InputKeyLeft) {
            if(app->led_level > 1) {
                app->led_level--;
            }
        } else if(key == InputKeyRight) {
            if(app->led_level < 100) {
                app->led_level++;
            }
        } else if(key == InputKeyOk) {
            return;
        } else {
            return;
        }
        if(before != app->led_level) {
            simple_app_update_led_label(app);
            simple_app_send_led_level_command(app);
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
    }
}

static void simple_app_handle_setup_boot_input(SimpleApp* app, InputKey key) {
    if(!app) return;

    if(key == InputKeyBack) {
        simple_app_save_config_if_dirty(app, "Config saved", true);
        app->screen = ScreenMenu;
        if(app->viewport) {
            view_port_update(app->viewport);
        }
        return;
    }

    if(key == InputKeyUp) {
        if(app->boot_setup_index > 0) {
            app->boot_setup_index = 0;
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
        return;
    }

    if(key == InputKeyDown) {
        if(app->boot_setup_index < 1) {
            app->boot_setup_index = 1;
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
        return;
    }

    bool is_long = app->boot_setup_long;
    bool* enabled_ptr = is_long ? &app->boot_long_enabled : &app->boot_short_enabled;
    uint8_t* cmd_index_ptr = is_long ? &app->boot_long_command_index : &app->boot_short_command_index;

    if(app->boot_setup_index == 0) {
        bool previous = *enabled_ptr;
        if(key == InputKeyLeft) {
            *enabled_ptr = false;
        } else if(key == InputKeyRight) {
            *enabled_ptr = true;
        } else if(key == InputKeyOk) {
            *enabled_ptr = !(*enabled_ptr);
        } else {
            return;
        }
        if(previous != *enabled_ptr) {
            simple_app_mark_config_dirty(app);
            simple_app_update_boot_labels(app);
            simple_app_send_boot_status(app, !is_long, *enabled_ptr);
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
        return;
    }

    if(app->boot_setup_index == 1) {
        uint8_t before = *cmd_index_ptr;
        if(key == InputKeyLeft) {
            if(*cmd_index_ptr == 0) {
                *cmd_index_ptr = BOOT_COMMAND_OPTION_COUNT - 1;
            } else {
                (*cmd_index_ptr)--;
            }
        } else if(key == InputKeyRight || key == InputKeyOk) {
            *cmd_index_ptr = (uint8_t)((*cmd_index_ptr + 1) % BOOT_COMMAND_OPTION_COUNT);
        } else {
            return;
        }
        if(before != *cmd_index_ptr) {
            simple_app_mark_config_dirty(app);
            simple_app_update_boot_labels(app);
            simple_app_send_boot_command(app, !is_long, *cmd_index_ptr);
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
    }
}

static void simple_app_handle_serial_input(SimpleApp* app, InputKey key) {
    if(!app) return;
    if(app->blackout_view_active && key != InputKeyBack && key != InputKeyUp && key != InputKeyDown) {
        return;
    }

    if(key == InputKeyBack) {
        simple_app_send_stop_if_needed(app);
        app->serial_targets_hint = false;
        if(app->blackout_view_active) {
            app->blackout_view_active = false;
            simple_app_focus_attacks_menu(app);
        } else {
            app->screen = ScreenMenu;
        }
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
            simple_app_reset_result_scroll(app);
            simple_app_adjust_result_offset(app);
            view_port_update(app->viewport);
        }
    } else if(key == InputKeyDown) {
        if(app->scan_result_index + 1 < app->visible_result_count) {
            app->scan_result_index++;
            simple_app_reset_result_scroll(app);
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

    if(app->sd_delete_confirm_active) {
        simple_app_handle_sd_delete_confirm_event(app, event);
        return;
    }

    if(app->sd_file_popup_active) {
        simple_app_handle_sd_file_popup_event(app, event);
        return;
    }

    if(app->sd_folder_popup_active) {
        simple_app_handle_sd_folder_popup_event(app, event);
        return;
    }

    if(app->portal_ssid_popup_active) {
        simple_app_handle_portal_ssid_popup_event(app, event);
        return;
    }

    if(app->karma_probe_popup_active) {
        simple_app_handle_karma_probe_popup_event(app, event);
        return;
    }

    if(app->karma_html_popup_active) {
        simple_app_handle_karma_html_popup_event(app, event);
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
    case ScreenSetupLed:
        simple_app_handle_setup_led_input(app, event->key);
        break;
    case ScreenSetupBoot:
        simple_app_handle_setup_boot_input(app, event->key);
        break;
    case ScreenSetupSdManager:
        simple_app_handle_setup_sd_manager_input(app, event->key);
        break;
    case ScreenSetupKarma:
        simple_app_handle_setup_karma_input(app, event->key);
        break;
    case ScreenConsole:
        simple_app_handle_console_input(app, event->key);
        break;
    case ScreenPackageMonitor:
        simple_app_handle_package_monitor_input(app, event->key);
        break;
    case ScreenChannelView:
        simple_app_handle_channel_view_input(app, event->key);
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
    case ScreenKarmaMenu:
        simple_app_handle_karma_menu_input(app, event->key);
        break;
    case ScreenPortalMenu:
        simple_app_handle_portal_menu_input(app, event->key);
        break;
    case ScreenDownloadBridge:
        if(event->key == InputKeyBack) {
            simple_app_download_bridge_stop(app);
        }
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

        // Detect pong in incoming chunk
        for(size_t i = 0; i + 3 < received; i++) {
            if(chunk[i] == 'p' && chunk[i + 1] == 'o' && chunk[i + 2] == 'n' && chunk[i + 3] == 'g') {
                simple_app_handle_pong(app);
                break;
            }
        }

        simple_app_append_serial_data(app, chunk, received);
        updated = true;
    }

    if(updated && (app->screen == ScreenSerial || app->screen == ScreenConsole)) {
        view_port_update(app->viewport);
    }
    if(app->package_monitor_dirty && app->screen == ScreenPackageMonitor && app->viewport) {
        view_port_update(app->viewport);
    }
    if(app->channel_view_dirty && app->screen == ScreenChannelView && app->viewport) {
        view_port_update(app->viewport);
    }
}

static bool simple_app_download_bridge_start(SimpleApp* app) {
    if(!app) return false;
    simple_app_send_command_quiet(app, "download");
    simple_app_show_status_message(app, "Download sent.\nStart UART bridge\nand reconnect USB.", 5000, true);
    return true;
}

static void simple_app_download_bridge_stop(SimpleApp* app) {
    (void)app;
}

static void simple_app_serial_irq(FuriHalSerialHandle* handle, FuriHalSerialRxEvent event, void* context) {
    SimpleApp* app = context;
    if(!app || !app->rx_stream || !(event & FuriHalSerialRxEventData)) return;

    do {
        uint8_t byte = furi_hal_serial_async_rx(handle);
        furi_stream_buffer_send(app->rx_stream, &byte, 1, 0);
        app->board_last_rx_tick = furi_get_tick();
    } while(furi_hal_serial_async_rx_available(handle));
}

static void simple_app_draw_download_bridge(SimpleApp* app, Canvas* canvas) {
    if(!app) return;
    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, 14, AlignCenter, AlignCenter, "Download mode");
    canvas_set_font(canvas, FontSecondary);
    char line1[32];
    char line2[32];
    snprintf(line1, sizeof(line1), "Baud: %lu", (unsigned long)app->download_baud);
    snprintf(
        line2,
        sizeof(line2),
        "TX:%lu RX:%lu",
        (unsigned long)app->download_uart_to_usb,
        (unsigned long)app->download_usb_to_uart);
    canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, 28, AlignCenter, AlignCenter, line1);
    canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, 40, AlignCenter, AlignCenter, line2);
    canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, 52, AlignCenter, AlignCenter, "Back = exit bridge");
}

int32_t Lab_C5_app(void* p) {
    UNUSED(p);

    SimpleApp* app = malloc(sizeof(SimpleApp));
    if(!app) {
        return 0;
    }
    memset(app, 0, sizeof(SimpleApp));
    app->package_monitor_channel = PACKAGE_MONITOR_DEFAULT_CHANNEL;
    app->channel_view_band = ChannelViewBand24;
    simple_app_channel_view_reset(app);
    app->scanner_show_ssid = true;
    app->scanner_show_bssid = true;
    app->scanner_show_channel = true;
    app->scanner_show_security = true;
    app->scanner_show_power = true;
    app->scanner_show_band = true;
    app->scanner_show_vendor = false;
    app->vendor_scan_enabled = false;
    app->vendor_read_pending = false;
    app->vendor_read_length = 0;
    app->vendor_read_buffer[0] = '\0';
    app->scanner_min_power = SCAN_POWER_MIN_DBM;
    app->scanner_setup_index = 0;
    app->scanner_adjusting_power = false;
    app->otg_power_initial_state = furi_hal_power_is_otg_enabled();
    app->otg_power_enabled = app->otg_power_initial_state;
    app->backlight_enabled = true;
    app->led_enabled = true;
    app->led_level = 10;
    app->led_setup_index = 0;
    app->board_ready_seen = false;
    app->board_sync_pending = true;
    app->board_ping_outstanding = false;
    app->board_last_ping_tick = 0;
    app->board_last_rx_tick = furi_get_tick();
    app->board_missing_shown = false;
    app->boot_short_enabled = false;
    app->boot_long_enabled = false;
    app->boot_short_command_index = 1; // start_sniffer_dog
    app->boot_long_command_index = 0;  // start_blackout
    app->boot_setup_index = 0;
    app->boot_setup_long = false;
    app->scanner_view_offset = 0;
    app->karma_sniffer_duration_sec = 15;
    simple_app_update_karma_duration_label(app);
    simple_app_update_result_layout(app);
    simple_app_update_backlight_label(app);
    simple_app_update_led_label(app);
    simple_app_update_boot_labels(app);
    app->sd_folder_index = 0;
    app->sd_folder_offset = 0;
    app->sd_refresh_pending = false;
    simple_app_reset_sd_listing(app);
    if(sd_folder_option_count > 0) {
        simple_app_copy_sd_folder(app, &sd_folder_options[0]);
    }
    simple_app_update_otg_label(app);
    simple_app_apply_otg_power(app);
    app->notifications = furi_record_open(RECORD_NOTIFICATION);
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

    simple_app_load_config(app);
    app->vendor_scan_enabled = app->scanner_show_vendor;
    simple_app_update_backlight_label(app);
    simple_app_update_led_label(app);
    simple_app_update_boot_labels(app);
    simple_app_apply_backlight(app);
    simple_app_update_otg_label(app);
    simple_app_apply_otg_power(app);
    if(app->viewport) {
        view_port_update(app->viewport);
    }

    if(!simple_app_status_message_is_active(app)) {
        simple_app_show_status_message(app, "Board detection", 1500, true);
    }
    simple_app_send_ping(app);

    while(!app->exit_app) {
        if(!app->download_bridge_active) {
            simple_app_process_stream(app);
            simple_app_update_karma_sniffer(app);
            simple_app_update_result_scroll(app);
            simple_app_update_sd_scroll(app);
            simple_app_ping_watchdog(app);
        }

        if(!app->download_bridge_active && app->portal_input_requested && !app->portal_input_active) {
            app->portal_input_requested = false;
            bool accepted = simple_app_portal_run_text_input(app);
            if(accepted) {
                app->portal_ssid_missing = false;
                if(app->portal_ssid[0] != '\0') {
                    simple_app_show_status_message(app, "SSID updated", 1000, true);
                    app->portal_menu_index = 1;
                } else {
                    simple_app_show_status_message(app, "SSID cleared", 1000, true);
                }
                simple_app_portal_sync_offset(app);
            }
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }

        if(app->sd_refresh_pending && !app->sd_listing_active &&
           app->screen == ScreenSetupSdManager) {
            uint32_t now = furi_get_tick();
            if(now >= app->sd_refresh_tick && sd_folder_option_count > 0 &&
               app->sd_folder_index < sd_folder_option_count) {
                simple_app_request_sd_listing(app, &sd_folder_options[app->sd_folder_index]);
            }
        }

        bool previous_help_hint = app->help_hint_visible;
        bool can_show_help_hint = (app->screen == ScreenMenu) && (app->menu_state == MenuStateSections) &&
                                  !app->hint_active && !app->evil_twin_popup_active &&
                                  !app->portal_ssid_popup_active && !app->sd_folder_popup_active &&
                                  !app->sd_file_popup_active && !app->sd_delete_confirm_active &&
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

        furi_delay_ms(app->download_bridge_active ? 1 : 20);
    }

    if(app->download_bridge_active) {
        simple_app_download_bridge_stop(app);
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
