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
#include <furi/core/memmgr.h>
#include <gui/view_dispatcher.h>
#include <gui/modules/text_input.h>
#include <furi_hal_usb.h>
#include <furi_hal_usb_cdc.h>
#include <usb_cdc.h>
#include <furi_hal_vibro.h>
#include <dialogs/dialogs.h>
#include "command_io.h"
#include "attack_rx_guard.h"
#include "gfx/help_qr_bitmap.h"
#include "module_loader.h"
#include "secure_clear.h"
#include "modules/recon/recon_module.h"
#include "modules/recon/recon_targets.h"
#include "modules/web/web_module.h"
#include "modules/rogue/rogue_module.h"
#include "modules/arp/arp_module.h"
#include "modules/wardrive/wardrive_module.h"
#include "modules/beacon/beacon_module.h"
#include "modules/mitm_pcap/mitm_pcap_module.h"
#include "modules/wardrive_upload/wardrive_upload_module.h"
#include "modules/nmap/nmap_module.h"
#include "modules/wpasec/wpasec_module.h"
#include "modules/connect/connect_module.h"

#define TAG "Lab_C5"

#ifdef FW_ORIGIN_Unleashed
#define LAB_C5_CODE_SECTION __attribute__((section(".labtext")))
#else
#define LAB_C5_CODE_SECTION
#endif

#define USB_RUNTIME_GUARD_INTERVAL_MS 50

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
    ScreenSetupScanner,
    ScreenSetupScannerTiming,
    ScreenSetupLed,
    ScreenSetupBoot,
    ScreenSetupSdManager,
    ScreenSetupOta,
    ScreenOtaStatus,
    ScreenOtaList,
    ScreenOtaInfo,
    ScreenHelpQr,
    ScreenConsole,
    ScreenGps,
    ScreenGpsLoading,
    ScreenWebMenu,
    ScreenWebLoading,
    ScreenRecon,
    ScreenReconLoading,
    ScreenAttackModule,
    ScreenAttackLoading,
    ScreenWardriveMenu,
    ScreenPackageMonitor,
    ScreenChannelView,
    ScreenConfirmBlackout,
    ScreenConfirmSnifferDos,
    ScreenConfirmOtaConnect,
    ScreenConfirmExit,
    ScreenBtLocatorList,
} AppScreen;

typedef enum {
    C5ModuleRequestNone = 0,
    C5ModuleRequestLoadGps,
    C5ModuleRequestUnloadGps,
    C5ModuleRequestLoadWeb,
    C5ModuleRequestUnloadWeb,
    C5ModuleRequestLoadRecon,
    C5ModuleRequestUnloadRecon,
    C5ModuleRequestLoadAttack,
    C5ModuleRequestUnloadAttack,
} C5ModuleRequest;

typedef enum {
    C5AttackModuleRogue,
    C5AttackModuleArp,
    C5AttackModuleArpSaved,
    C5AttackModuleMitmPcap,
    C5AttackModuleBeacon,
    C5AttackModuleWardriveLegacy,
    C5AttackModuleWardrivePromisc,
    C5AttackModuleWardriveTrace,
    C5AttackModuleWardriveUploadWigle,
    C5AttackModuleWardriveUploadWdgwars,
    C5AttackModuleNmap,
    C5AttackModuleWpasec,
    C5AttackModuleConnect,
} C5AttackModule;

static bool simple_app_attack_requires_target(C5AttackModule module) {
    return module == C5AttackModuleRogue || module == C5AttackModuleArp ||
           module == C5AttackModuleConnect ||
           module == C5AttackModuleMitmPcap;
}

static bool simple_app_attack_may_stop_prior(C5AttackModule module) {
    /* Connect can fail its RAM/load gate; never disconnect an existing STA first. */
    return module != C5AttackModuleConnect;
}

static C5AttackModule simple_app_wardrive_module_for_index(size_t index) {
    switch(index) {
    case 1: return C5AttackModuleWardrivePromisc;
    case 2: return C5AttackModuleWardriveTrace;
    case 3: return C5AttackModuleWardriveUploadWigle;
    case 4: return C5AttackModuleWardriveUploadWdgwars;
    default: return C5AttackModuleWardriveLegacy;
    }
}

typedef enum {
    MenuStateSections,
    MenuStateItems,
} MenuState;

typedef enum {
    BlackoutPhaseIdle,
    BlackoutPhaseStarting,
    BlackoutPhaseScanning,
    BlackoutPhaseSorting,
    BlackoutPhaseAttacking,
    BlackoutPhaseStopping,
    BlackoutPhaseFinished,
} BlackoutPhase;

typedef enum {
    SnifferDogPhaseIdle,
    SnifferDogPhaseStarting,
    SnifferDogPhaseHunting,
    SnifferDogPhaseStopping,
    SnifferDogPhaseError,
    SnifferDogPhaseFinished,
} SnifferDogPhase;
#define LAB_C5_VERSION_TEXT "0.41"

typedef enum {
    OtaInputNone = 0,
    OtaInputSsid,
    OtaInputPassword,
    OtaInputIp,
    OtaInputNetmask,
    OtaInputGw,
    OtaInputDns,
} OtaInputField;

typedef enum {
    OtaItemCheck = 0,
    OtaItemSsid,
    OtaItemPass,
    OtaItemMode,
    OtaItemIp,
    OtaItemNetmask,
    OtaItemGw,
    OtaItemDns,
    OtaItemChannel,
    OtaItemList,
    OtaItemInfo,
    OtaItemBoot,
} OtaSetupItem;

#define SCAN_LINE_BUFFER_SIZE 192
#define SCAN_SSID_MAX_LEN 33
#define SCAN_POWER_MIN_DBM (-110)
#define SCAN_POWER_MAX_DBM 0
#define SCAN_POWER_STEP 1
#define BACKLIGHT_ON_LEVEL 255
#define BACKLIGHT_OFF_LEVEL 0
#define GPS_UTC_OFFSET_MIN_MINUTES (-12 * 60)
#define GPS_UTC_OFFSET_MAX_MINUTES (14 * 60)

#define SERIAL_BUFFER_SIZE 1024
#define UART_STREAM_SIZE 512
#define MENU_VISIBLE_COUNT 6
#define MENU_VISIBLE_COUNT_SNIFFERS 4
#define MENU_VISIBLE_COUNT_ATTACKS 4
#define MENU_VISIBLE_COUNT_SETUP 4
#define MENU_SECTION_VISIBLE_COUNT 6
#define MENU_SECTION_BASE_Y 14
#define MENU_SECTION_SPACING 9
#define PACKAGE_MONITOR_MAX_HISTORY 96
#define MENU_TITLE_Y 12
#define MENU_ITEM_BASE_Y 24
#define MENU_ITEM_SPACING 12
#define MENU_SCROLL_TRACK_Y 14
#define SERIAL_VISIBLE_LINES 6
#define SERIAL_LINE_CHAR_LIMIT 26
#define SERIAL_TEXT_LINE_HEIGHT 10
#define DISPLAY_WIDTH 128
#define DISPLAY_HEIGHT 64
#define BT_SCAN_CONSOLE_LINES 3
#define BT_LOCATOR_MAX_DEVICES 24
#define BT_LOCATOR_VISIBLE_COUNT 6
#define BT_LOCATOR_WARMUP_MS 10000
#define BT_LOCATOR_NAME_MAX_LEN 24
#define BT_SCAN_PREVIEW_MAX 32
#define BT_SCAN_LINE_BUFFER_LEN 96
#define BT_LOCATOR_SCAN_LINE_LEN 128
#define BT_LOCATOR_SCROLL_TEXT_LEN 64
#define RESULT_SCROLL_INTERVAL_MS 200
#define RESULT_SCROLL_EDGE_PAUSE_STEPS 3
#define DEAUTH_GUARD_BLINK_MS 500
#define DEAUTH_GUARD_VIBRO_MS 400
#define DEAUTH_GUARD_BLINK_TOGGLES 6
#define DEAUTH_GUARD_IDLE_MONITOR_MS 60000
#define DEAUTH_RUNNING_BLINK_MS 500
#define CONSOLE_VISIBLE_LINES 4
#define MENU_SECTION_SCANNER 0
#define MENU_SECTION_SNIFFERS 1
#define MENU_SECTION_ATTACKS 2
#define MENU_SECTION_MONITORING 3
#define MENU_SECTION_BLUETOOTH 4
#define MENU_SECTION_SETUP 5
#define SCANNER_FILTER_VISIBLE_COUNT 3
#define LAB_C5_CONFIG_DIR_PATH "apps_assets/labC5"
#define LAB_C5_CONFIG_FILE_PATH LAB_C5_CONFIG_DIR_PATH "/config.txt"
#define FLIPPER_SD_BASE_PATH EXT_PATH(LAB_C5_CONFIG_DIR_PATH)
#define FLIPPER_SD_DEBUG_PATH FLIPPER_SD_BASE_PATH "/debug_last.txt"
#define FLIPPER_SD_DEBUG_LOG_PATH FLIPPER_SD_BASE_PATH "/debug_cli.txt"

#define BOARD_PING_INTERVAL_MS 4000
#define BOARD_PING_TIMEOUT_MS 3000
#define BOARD_PING_FAILURE_LIMIT 2

#define PACKAGE_MONITOR_CHANNELS_24GHZ 14
#define PACKAGE_MONITOR_CHANNELS_5GHZ 23
#define PACKAGE_MONITOR_TOTAL_CHANNELS (PACKAGE_MONITOR_CHANNELS_24GHZ + PACKAGE_MONITOR_CHANNELS_5GHZ)
#define PACKAGE_MONITOR_DEFAULT_CHANNEL 1
#define PACKAGE_MONITOR_COMMAND "packet_monitor"
#define PACKAGE_MONITOR_BAR_SPACING 2
#define PACKAGE_MONITOR_CHANNEL_SWITCH_COOLDOWN_MS 200

#define CHANNEL_VIEW_COMMAND "channel_view"
#define CHANNEL_VIEW_LINE_BUFFER 64

#define SCANNER_CHANNEL_TIME_MIN_MS 10
#define SCANNER_CHANNEL_TIME_MAX_MS 2000
#define SCANNER_CHANNEL_TIME_STEP_MS 10
#define SCANNER_CHANNEL_TIME_DEFAULT_MIN 100
#define SCANNER_CHANNEL_TIME_DEFAULT_MAX 300
#define OTA_PASS_MAX_LEN 64
#define OTA_IP_MAX_LEN 16
#define OTA_SETUP_VISIBLE_COUNT 4
#define OTA_STATUS_LINE_MAX 48
#define OTA_STATUS_LINES 3
#define OTA_LIST_MAX 5
#define OTA_INFO_MAX 5
#define OTA_LINE_BUFFER 160

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

#define HINT_LINE_HEIGHT 12
#define KARMA_SNIFFER_DURATION_MIN_SEC 5
#define KARMA_SNIFFER_DURATION_MAX_SEC 180
#define KARMA_AUTO_LIST_DELAY_MS 500
#define DOUBLE_BACK_EXIT_MS 700
#define SD_MANAGER_MAX_FILES 24
#define SD_MANAGER_FILE_NAME_MAX 64
#define SD_MANAGER_POPUP_VISIBLE_LINES 3
#define SD_MANAGER_FOLDER_LABEL_MAX 24
#define SD_MANAGER_PATH_MAX 160
#define SD_LIST_BUFFER_LEN 160

typedef enum {
    MenuActionCommand,
    MenuActionCommandWithTargets,
    MenuActionToggleBacklight,
    MenuActionToggleOtgPower,
    MenuActionToggleShowRam,
    MenuActionToggleDebugMark,
    MenuActionToggleRedTeam,
    MenuActionOpenScannerSetup,
    MenuActionOpenScannerTiming,
    MenuActionOpenLedSetup,
    MenuActionOpenBootSetup,
    MenuActionOpenDownload,
    MenuActionOpenSdManager,
    MenuActionOpenOta,
    MenuActionOpenHelp,

    MenuActionOpenConsole,
    MenuActionOpenGps,
    MenuActionOpenPackageMonitor,
    MenuActionOpenChannelView,
    MenuActionConfirmBlackout,
    MenuActionConfirmSnifferDos,
    MenuActionOpenEvilTwinMenu,
    MenuActionOpenKarmaMenu,
    MenuActionOpenPortalMenu,
    MenuActionOpenConnect,
    MenuActionOpenRogue,
    MenuActionOpenArp,
    MenuActionOpenArpSaved,
    MenuActionOpenMitmPcap,
    MenuActionOpenNmap,
    MenuActionOpenWpasec,
    MenuActionOpenBeacon,
    MenuActionOpenWardrive,
    MenuActionOpenBtLocator,
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
    char mac[18];
    char name[32];
    int rssi;
    bool has_name;
} BtScanPreview;

typedef struct {
    char mac[18];
    int rssi;
    bool has_rssi;
    char name[BT_LOCATOR_NAME_MAX_LEN];
} BtLocatorDevice;

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
    uint32_t section_offset;
    uint32_t item_index;
    uint32_t item_offset;
    AppScreen screen;
    FuriHalSerialHandle* serial;
    FuriMutex* serial_mutex;
    FuriStreamBuffer* rx_stream;
    volatile uint32_t rx_dropped_bytes;
    ViewPort* viewport;
    Gui* gui;
    char serial_buffer[SERIAL_BUFFER_SIZE];
    size_t serial_len;
    size_t serial_scroll;
    bool serial_follow_tail;
    bool blackout_view_active;
    bool blackout_full_console;
    bool blackout_running;
    BlackoutPhase blackout_phase;
    uint32_t blackout_networks;
    uint32_t blackout_cycle;
    uint8_t blackout_channel;
    bool blackout_has_channel;
    char blackout_note[32];
    char blackout_line_buffer[96];
    size_t blackout_line_length;
    uint32_t blackout_last_update_tick;
    bool sniffer_dog_view_active;
    bool sniffer_dog_full_console;
    bool sniffer_dog_running;
    SnifferDogPhase sniffer_dog_phase;
    uint32_t sniffer_dog_deauth_count;
    uint8_t sniffer_dog_channel;
    bool sniffer_dog_has_channel;
    int sniffer_dog_rssi;
    bool sniffer_dog_has_rssi;
    char sniffer_dog_note[32];
    char sniffer_dog_line_buffer[128];
    size_t sniffer_dog_line_length;
    uint32_t sniffer_dog_last_update_tick;
    bool deauth_view_active;
    bool deauth_full_console;
    bool deauth_running;
    uint32_t deauth_targets;
    bool deauth_overlay_allowed;
    char deauth_ssid[SCAN_SSID_MAX_LEN];
    char deauth_bssid[18];
    uint8_t deauth_channel;
    bool deauth_has_channel;
    size_t deauth_list_offset;
    size_t deauth_list_scroll_x;
    uint32_t deauth_blink_last_tick;
    char deauth_note[32];
    bool handshake_view_active;
    bool handshake_full_console;
    bool handshake_running;
    uint32_t handshake_targets;
    uint32_t handshake_captured;
    char handshake_ssid[SCAN_SSID_MAX_LEN];
    uint8_t handshake_channel;
    bool handshake_has_channel;
    int handshake_rssi;
    bool handshake_has_rssi;
    bool handshake_overlay_allowed;
    uint32_t handshake_blink_last_tick;
    bool handshake_vibro_done;
    char handshake_note[32];
    bool sae_view_active;
    bool sae_full_console;
    bool sae_running;
    bool sae_overlay_allowed;
    char sae_ssid[SCAN_SSID_MAX_LEN];
    uint8_t sae_channel;
    bool sae_has_channel;
    char sae_note[16];
    char handshake_line_buffer[160];
    size_t handshake_line_length;
    char deauth_line_buffer[128];
    size_t deauth_line_length;
    char sae_line_buffer[128];
    size_t sae_line_length;
    uint32_t deauth_last_update_tick;
    bool gps_view_active;
    bool gps_console_mode;
    bool gps_time_24h;
    int16_t gps_utc_offset_minutes;
    bool gps_dst_enabled;
    bool gps_zda_tz_enabled;
    C5ModuleRuntime gps_module;
    C5ModuleRequest gps_module_request;
    bool gps_module_loading;
    bool web_module_loading;
    bool web_view_active;
    bool web_console_mode;
    bool recon_view_active;
    bool recon_console_mode;
    bool recon_open_attacks_pending;
    bool recon_stations_selected;
    bool attack_view_active;
    bool attack_module_loading;
    bool attack_return_to_sections;
    C5AttackModule attack_module;
    uint8_t wardrive_mode_index;
    C5AttackRxGuard attack_rx_guard;
    C5ReconMode recon_mode;
    C5ReconSavedTargets recon_targets;
    C5WebMode web_mode;
    C5WebSessionPrefs web_prefs;
    bool module_redraw_pending;
    bool module_command_pending;
    char module_command[160];
    bool module_status_pending;
    char module_status[64];
    uint32_t module_status_duration_ms;
    bool module_status_fullscreen;
    bool otg_power_enabled;
    bool otg_power_initial_state;
    bool bt_scan_view_active;
    bool bt_scan_summary_seen;
    bool airtag_scan_mode;
    bool bt_scan_full_console;
    uint32_t bt_scan_last_update_tick;
    bool bt_scan_show_list;
    BtScanPreview* bt_scan_preview;
    size_t bt_scan_preview_count;
    size_t bt_scan_list_offset;
    bool bt_scan_running;
    bool bt_scan_has_data;
    int bt_scan_airtags;
    int bt_scan_smarttags;
    int bt_scan_total;
    bool bt_locator_console_mode;
    bool bt_locator_mode;
    bool bt_locator_has_rssi;
    int bt_locator_rssi;
    uint32_t bt_locator_start_tick;
    uint32_t bt_locator_last_console_tick;
    char bt_locator_mac[18];
    char bt_locator_saved_mac[18];
    bool bt_locator_preserve_mac;
    bool bt_locator_list_loading;
    bool bt_locator_list_ready;
    size_t bt_locator_count;
    size_t bt_locator_index;
    size_t bt_locator_offset;
    int32_t bt_locator_selected; // -1 none, otherwise index
    char bt_locator_current_name[BT_LOCATOR_NAME_MAX_LEN];
    char* bt_locator_scroll_text;
    size_t bt_locator_scroll_offset;
    int bt_locator_scroll_dir;
    uint8_t bt_locator_scroll_hold;
    uint32_t bt_locator_scroll_last_tick;
    char* bt_locator_scan_line;
    size_t bt_locator_scan_len;
    BtLocatorDevice* bt_locator_devices;
    char* bt_scan_line_buffer;
    size_t bt_scan_line_length;
    bool deauth_guard_view_active;
    bool deauth_guard_full_console;
    bool deauth_guard_has_detection;
    bool deauth_guard_has_rssi;
    int deauth_guard_last_channel;
    int deauth_guard_last_rssi;
    uint32_t deauth_guard_started_tick;
    uint32_t deauth_guard_last_detection_tick;
    uint32_t deauth_guard_blink_until;
    uint32_t deauth_guard_last_blink_tick;
    bool deauth_guard_blink_state;
    uint8_t deauth_guard_blink_count;
    uint32_t deauth_guard_vibro_until;
    bool deauth_guard_vibro_on;
    char deauth_guard_last_ssid[SCAN_SSID_MAX_LEN];
    char deauth_guard_line_buffer[SCAN_LINE_BUFFER_SIZE];
    size_t deauth_guard_line_length;
    bool deauth_guard_monitoring;
    uint32_t deauth_guard_detection_count;
    bool last_command_sent;
    bool confirm_blackout_yes;
    bool confirm_sniffer_dos_yes;
    bool confirm_exit_yes;
    uint32_t last_attack_index;
    bool exit_confirm_active;
    uint32_t exit_confirm_tick;
    size_t sd_folder_index;
    size_t sd_folder_offset;
    bool sd_folder_popup_active;
    SdFileEntry* sd_files;
    size_t sd_file_count;
    size_t sd_file_popup_index;
    size_t sd_file_popup_offset;
    bool sd_file_popup_active;
    bool sd_listing_active;
    bool sd_list_header_seen;
    char sd_list_buffer[SD_LIST_BUFFER_LEN];
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
    uint32_t karma_sniffer_duration_sec;
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
    uint16_t scanner_min_channel_time;
    uint16_t scanner_max_channel_time;
    size_t scanner_timing_index;
    bool scanner_timing_min_pending;
    bool scanner_timing_max_pending;
    char scanner_timing_read_buffer[32];
    size_t scanner_timing_read_length;
    size_t scanner_setup_index;
    bool scanner_adjusting_power;
    bool backlight_enabled;
    bool show_ram_overlay;
    bool debug_mark_enabled;
    bool debug_log_initialized;
    size_t heap_start_free;
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
    size_t ota_setup_index;
    size_t ota_setup_offset;
    bool ota_use_dhcp;
    bool ota_pass_show;
    bool ota_connect_confirm_yes;
    bool ota_input_requested;
    bool ota_input_active;
    OtaInputField ota_input_field;
    char ota_ssid[SCAN_SSID_MAX_LEN];
    char ota_password[OTA_PASS_MAX_LEN];
    char ota_ip[OTA_IP_MAX_LEN];
    char ota_netmask[OTA_IP_MAX_LEN];
    char ota_gw[OTA_IP_MAX_LEN];
    char ota_dns[OTA_IP_MAX_LEN];
    bool ota_status_active;
    bool ota_list_active;
    bool ota_info_active;
    bool ota_boot_target_slot1;
    char ota_channel[8];
    char ota_wifi_status[OTA_STATUS_LINE_MAX];
    char ota_ip_status[OTA_STATUS_LINE_MAX];
    char ota_response[OTA_STATUS_LINE_MAX];
    char ota_list_lines[OTA_LIST_MAX][OTA_STATUS_LINE_MAX];
    size_t ota_list_count;
    char ota_info_lines[OTA_INFO_MAX][OTA_STATUS_LINE_MAX];
    size_t ota_info_count;
    char ota_line_buffer[OTA_LINE_BUFFER];
    size_t ota_line_length;
    bool led_read_pending;
    char led_read_buffer[64];
    size_t led_read_length;
    size_t scanner_view_offset;
    NotificationApp* notifications;
    bool backlight_notification_enforced;
    bool config_dirty;
    bool red_team_mode;
    bool config_seen_led_enabled;
    bool config_seen_led_level;
    bool config_seen_gps_utc_offset;
    bool config_seen_gps_dst;
    bool config_seen_gps_zda_tz;
    char status_message[64];
    uint32_t status_message_until;
    bool status_message_fullscreen;
    bool board_ready_seen;
    bool board_sync_pending;
    bool board_ping_outstanding;
    uint32_t board_last_ping_tick;
    uint32_t board_last_rx_tick;
    bool board_missing_shown;
    bool board_bootstrap_active;
    bool board_bootstrap_reboot_sent;
    uint8_t board_ping_failures;
    uint32_t last_input_tick;
    uint32_t last_back_tick;
    uint32_t usb_guard_last_tick;
    bool package_monitor_active;
    uint8_t package_monitor_channel;
    uint16_t* package_monitor_history;
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
    uint16_t* channel_view_counts_24;
    uint16_t* channel_view_counts_5;
    uint16_t* channel_view_working_counts_24;
    uint16_t* channel_view_working_counts_5;
    char channel_view_line_buffer[CHANNEL_VIEW_LINE_BUFFER];
    size_t channel_view_line_length;
    char channel_view_status_text[32];
    uint8_t channel_view_offset_24;
    uint8_t channel_view_offset_5;
} SimpleApp;
static bool simple_app_bssid_is_empty(const uint8_t bssid[6]);
static void simple_app_format_bssid(const uint8_t bssid[6], char* out, size_t out_size);
static bool simple_app_parse_bool_value(const char* value, bool current);
static void simple_app_apply_backlight(SimpleApp* app);
static void simple_app_toggle_backlight(SimpleApp* app);
static void simple_app_update_ram_label(SimpleApp* app);
static void simple_app_update_debug_label(SimpleApp* app);
static void simple_app_toggle_show_ram(SimpleApp* app);
static void simple_app_toggle_debug_mark(SimpleApp* app);
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
static size_t simple_app_ota_item_count(const SimpleApp* app);
static void simple_app_ota_adjust_offset(SimpleApp* app);
static void simple_app_ota_request_text_input(SimpleApp* app, OtaInputField field);
static bool simple_app_ota_run_text_input(SimpleApp* app);
static void simple_app_reset_ota_status(SimpleApp* app);
static void simple_app_reset_ota_list(SimpleApp* app);
static void simple_app_reset_ota_info(SimpleApp* app);
static OtaSetupItem simple_app_ota_item_at(const SimpleApp* app, size_t index);
static void simple_app_ota_process_line(SimpleApp* app, const char* line);
static void simple_app_ota_feed(SimpleApp* app, char ch);
static void simple_app_draw_setup_ota(SimpleApp* app, Canvas* canvas);
static void simple_app_handle_setup_ota_input(SimpleApp* app, InputKey key);
static void simple_app_draw_confirm_ota_connect(SimpleApp* app, Canvas* canvas);
static void simple_app_handle_confirm_ota_connect_input(SimpleApp* app, InputKey key);
static void simple_app_draw_ota_status(SimpleApp* app, Canvas* canvas);
static void simple_app_handle_ota_status_input(SimpleApp* app, InputKey key);
static void simple_app_draw_ota_list(SimpleApp* app, Canvas* canvas);
static void simple_app_handle_ota_list_input(SimpleApp* app, InputKey key);
static void simple_app_draw_ota_info(SimpleApp* app, Canvas* canvas);
static void simple_app_handle_ota_info_input(SimpleApp* app, InputKey key);
static void simple_app_serial_irq(
    FuriHalSerialHandle* handle, FuriHalSerialRxEvent event, void* context);
static void simple_app_handle_boot_trigger(SimpleApp* app, bool is_long);
static void simple_app_on_board_online(SimpleApp* app, const char* source);
static void simple_app_clear_station_selection(SimpleApp* app);
static void simple_app_draw_sync_status(const SimpleApp* app, Canvas* canvas);
static void simple_app_draw_ram_overlay(SimpleApp* app, Canvas* canvas);
static void simple_app_send_vendor_command(SimpleApp* app, bool enable);
static void simple_app_request_vendor_status(SimpleApp* app);
static bool simple_app_handle_vendor_status_line(SimpleApp* app, const char* line);
static void simple_app_vendor_feed(SimpleApp* app, char ch);
static void simple_app_request_scanner_timing(SimpleApp* app);
static void simple_app_request_channel_time(SimpleApp* app, bool request_min);
static void simple_app_send_channel_time(SimpleApp* app, bool is_min, uint16_t value);
static bool simple_app_handle_scanner_timing_line(SimpleApp* app, const char* line);
static void simple_app_scanner_timing_feed(SimpleApp* app, char ch);
static void simple_app_modify_channel_time(SimpleApp* app, bool is_min, int32_t delta);
static void simple_app_module_unload(SimpleApp* app);
static bool simple_app_open_gps(SimpleApp* app);
static bool simple_app_open_web(SimpleApp* app);
static bool simple_app_open_recon(SimpleApp* app);
static void simple_app_request_recon(SimpleApp* app, C5ReconMode mode);
static void simple_app_handle_recon_input(SimpleApp* app, const InputEvent* event);
static void simple_app_request_web(SimpleApp* app, C5WebMode mode);
static void simple_app_handle_web_input(SimpleApp* app, const InputEvent* event);
static void simple_app_reset_blackout_status(SimpleApp* app);
static void simple_app_process_blackout_line(SimpleApp* app, const char* line);
static void simple_app_blackout_feed(SimpleApp* app, char ch);
static void simple_app_draw_blackout_overlay(SimpleApp* app, Canvas* canvas);
static void simple_app_reset_sniffer_dog_status(SimpleApp* app);
static void simple_app_process_sniffer_dog_line(SimpleApp* app, const char* line);
static void simple_app_sniffer_dog_feed(SimpleApp* app, char ch);
static void simple_app_draw_sniffer_dog_overlay(SimpleApp* app, Canvas* canvas);
static void simple_app_reset_handshake_status(SimpleApp* app);
static void simple_app_process_handshake_line(SimpleApp* app, const char* line);
static void simple_app_handshake_feed(SimpleApp* app, char ch);
static void simple_app_draw_handshake_overlay(SimpleApp* app, Canvas* canvas);
static void simple_app_reset_sae_status(SimpleApp* app);
static void simple_app_process_sae_line(SimpleApp* app, const char* line);
static void simple_app_sae_feed(SimpleApp* app, char ch);
static void simple_app_draw_sae_overlay(SimpleApp* app, Canvas* canvas);
static void simple_app_reset_deauth_status(SimpleApp* app);
static void simple_app_process_deauth_line(SimpleApp* app, const char* line);
static void simple_app_deauth_feed(SimpleApp* app, char ch);
static void simple_app_draw_deauth_overlay(SimpleApp* app, Canvas* canvas);
static void simple_app_update_otg_label(SimpleApp* app);
static void simple_app_apply_otg_power(SimpleApp* app);
static void simple_app_toggle_otg_power(SimpleApp* app);
static void simple_app_send_download(SimpleApp* app);
static bool simple_app_usb_profile_ok(void);
static void simple_app_show_usb_blocker(void);
static void simple_app_send_command(SimpleApp* app, const char* command, bool go_to_serial);
static void simple_app_handle_serial_input(SimpleApp* app, InputKey key);
static void simple_app_append_serial_data(SimpleApp* app, const uint8_t* data, size_t length);
static void simple_app_run_module_text_input(SimpleApp* app);
static void simple_app_mark_config_dirty(SimpleApp* app);
static void simple_app_package_monitor_enter(SimpleApp* app);
static void simple_app_package_monitor_start(SimpleApp* app, uint8_t channel, bool reset_history);
static void simple_app_package_monitor_stop(SimpleApp* app);
static void simple_app_package_monitor_reset(SimpleApp* app);
static void simple_app_package_monitor_process_line(SimpleApp* app, const char* line);
static void simple_app_package_monitor_feed(SimpleApp* app, char ch);
static void simple_app_draw_package_monitor(SimpleApp* app, Canvas* canvas);
static void simple_app_handle_package_monitor_input(SimpleApp* app, InputKey key);
static bool simple_app_alloc_package_monitor_buffers(SimpleApp* app);
static void simple_app_free_package_monitor_buffers(SimpleApp* app);
static bool simple_app_alloc_channel_view_buffers(SimpleApp* app);
static void simple_app_free_channel_view_buffers(SimpleApp* app);
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
static void simple_app_bt_locator_reset_list(SimpleApp* app);
static void simple_app_bt_locator_begin_scan(SimpleApp* app);
static void simple_app_bt_locator_feed(SimpleApp* app, char ch);
static void simple_app_draw_bt_locator_list(SimpleApp* app, Canvas* canvas);
static void simple_app_handle_bt_locator_input(SimpleApp* app, InputKey key);
static void simple_app_bt_locator_reset_scroll(SimpleApp* app);
static void simple_app_bt_locator_set_scroll_text(SimpleApp* app, const char* text);
static void simple_app_bt_locator_tick_scroll(SimpleApp* app, size_t char_limit);
static void simple_app_usb_runtime_guard(SimpleApp* app);
static bool simple_app_sd_ok(void);
static void simple_app_show_sd_busy(void);
static void simple_app_ensure_flipper_sd_dirs(Storage* storage);
static bool simple_app_append_log_line(const char* path, const char* line);
static void simple_app_debug_mark(SimpleApp* app, const char* tag);
static void simple_app_log_cli_command(SimpleApp* app, const char* source, const char* command);
static void simple_app_reset_debug_log(SimpleApp* app);
static void simple_app_trim(char* text);
static bool simple_app_sd_alloc_files(SimpleApp* app);
static void simple_app_sd_free_files(SimpleApp* app);
static void simple_app_channel_view_show_status(SimpleApp* app, const char* status);
static void simple_app_reset_deauth_guard(SimpleApp* app);
static void simple_app_start_deauth_guard(SimpleApp* app);
static void simple_app_process_deauth_guard_line(SimpleApp* app, const char* line);
static void simple_app_deauth_guard_feed(SimpleApp* app, char ch);
static void simple_app_update_deauth_guard(SimpleApp* app);
static void simple_app_draw_deauth_guard(SimpleApp* app, Canvas* canvas);
static int simple_app_channel_view_find_channel_index(const uint8_t* list, size_t count, uint8_t channel);
static size_t simple_app_channel_view_visible_columns(ChannelViewBand band);
static uint8_t simple_app_channel_view_max_offset(ChannelViewBand band);
static uint8_t* simple_app_channel_view_offset_ptr(SimpleApp* app, ChannelViewBand band);
static bool simple_app_channel_view_adjust_offset(SimpleApp* app, ChannelViewBand band, int delta);
static void simple_app_open_sd_manager(SimpleApp* app);
static void simple_app_copy_sd_folder(SimpleApp* app, const SdFolderOption* folder);
static void simple_app_draw_setup_sd_manager(SimpleApp* app, Canvas* canvas);
static void simple_app_handle_setup_sd_manager_input(SimpleApp* app, InputKey key);
static void simple_app_draw_help_qr(SimpleApp* app, Canvas* canvas);
static void simple_app_handle_help_qr_input(SimpleApp* app, InputKey key);
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
static void simple_app_update_deauth_blink(SimpleApp* app);
static void simple_app_update_handshake_blink(SimpleApp* app);
static void simple_app_draw_scroll_arrow(Canvas* canvas, uint8_t base_left_x, int16_t base_y, bool upwards);
static uint8_t simple_app_bt_locator_item_height(const SimpleApp* app, size_t idx);
static void simple_app_bt_locator_ensure_visible(SimpleApp* app);
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
static void simple_app_draw_setup_led(SimpleApp* app, Canvas* canvas);
static void simple_app_handle_setup_led_input(SimpleApp* app, InputKey key);
static void simple_app_save_config_if_dirty(SimpleApp* app, const char* message, bool fullscreen);
static bool simple_app_save_config(SimpleApp* app, const char* success_message, bool fullscreen);
static void simple_app_load_config(SimpleApp* app);
static void simple_app_show_status_message(SimpleApp* app, const char* message, uint32_t duration_ms, bool fullscreen);
static void simple_app_clear_status_message(SimpleApp* app);
static bool simple_app_status_message_is_active(SimpleApp* app);
static void simple_app_send_command_with_targets(SimpleApp* app, const char* base_command);
static void simple_app_handle_attack_input(SimpleApp* app, const InputEvent* event);
static size_t simple_app_menu_visible_count(const SimpleApp* app, uint32_t section_index);
static size_t simple_app_section_visible_count(void);
static void simple_app_adjust_section_offset(SimpleApp* app);
static void simple_app_prepare_exit(SimpleApp* app);
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
    bool red_team_only;
} MenuEntry;

typedef struct {
    const char* title;
    const MenuEntry* entries;
    size_t entry_count;
    uint8_t display_y;
    uint8_t display_height;
} MenuSection;

static const uint8_t image_icon_0_bits[] = {
    0xff, 0x03, 0xff, 0x03, 0xff, 0x03, 0x11, 0x03, 0xdd, 0x03,
    0x1d, 0x03, 0x71, 0x03, 0x1f, 0x03, 0xff, 0x03, 0xff, 0x03,
};

static const SdFolderOption sd_folder_options[] = {
    {"Handshakes", "lab/handshakes"},
    {"HTML portals", "lab/htmls"},
    {"Wardrives", "lab/wardrives"},
};

static const size_t sd_folder_option_count = sizeof(sd_folder_options) / sizeof(sd_folder_options[0]);

static const MenuEntry menu_entries_sniffers[] = {
    {"Start Sniffer", "start_sniffer", MenuActionCommand, false},
    {"Show Sniffer Results", "show_sniffer_results", MenuActionCommand, false},
    {"Show Probes", "show_probes", MenuActionCommand, false},
    {"Resume Sniffer", "start_sniffer_noscan", MenuActionCommand, false},
    {"Sniffer Debug", "sniffer_debug 1", MenuActionCommand, false},
};

static const MenuEntry menu_entries_attacks[] = {
    {"Connect", NULL, MenuActionOpenConnect, false},
    {"Blackout", NULL, MenuActionConfirmBlackout, true},
    {"Deauth", "start_deauth", MenuActionCommandWithTargets, true},
    {"Deauth Guard", "deauth_detector", MenuActionCommandWithTargets, false},
    {"Handshaker", "start_handshake", MenuActionCommandWithTargets, true},
    {"Evil Twin", NULL, MenuActionOpenEvilTwinMenu, true},
    {"Rogue AP", NULL, MenuActionOpenRogue, true},
    {"ARP Poisoning", NULL, MenuActionOpenArp, true},
    {"ARP Saved", NULL, MenuActionOpenArpSaved, true},
    {"MITM PCAP", NULL, MenuActionOpenMitmPcap, true},
    {"Nmap", NULL, MenuActionOpenNmap, true},
    {"Portal", NULL, MenuActionOpenPortalMenu, false},
    {"Karma", NULL, MenuActionOpenKarmaMenu, false},
    {"Sniffer", "start_sniffer", MenuActionCommand, false},
    {"SAE Overflow", "sae_overflow", MenuActionCommandWithTargets, true},
    {"Sniffer Dog", NULL, MenuActionConfirmSnifferDos, true},
    {"Beacon Spam", NULL, MenuActionOpenBeacon, true},
    {"Wardrive", NULL, MenuActionOpenWardrive, false},
};


static const MenuEntry menu_entries_monitoring[] = {
    {"Package Monitor", NULL, MenuActionOpenPackageMonitor, false},
    {"Channel View", NULL, MenuActionOpenChannelView, false},
};

static const MenuEntry menu_entries_bluetooth[] = {
    {"AirTag Scan", "scan_airtag", MenuActionCommand, false},
    {"BT Scan", "scan_bt", MenuActionCommand, false},
    {"BT Locator", NULL, MenuActionOpenBtLocator, false},
};

static char menu_label_backlight[24] = "Backlight: On";
static char menu_label_otg_power[24] = "5V Power: On";
static char menu_label_led[24] = "LED: On (10)";
static char menu_label_boot_short[40] = "Boot short: Off";
static char menu_label_boot_long[40] = "Boot long: Off";
static char menu_label_ram[24] = "Show RAM: Off";
static char menu_label_debug[24] = "Debug Log: Off";
static char menu_label_red_team[24] = "Red Team: On";

static const MenuEntry menu_entries_setup[] = {
    {menu_label_backlight, NULL, MenuActionToggleBacklight, false},
    {menu_label_boot_long, NULL, MenuActionOpenBootSetup, false},
    {menu_label_boot_short, NULL, MenuActionOpenBootSetup, false},
    {"Console", NULL, MenuActionOpenConsole, false},
    {"Download Mode", NULL, MenuActionOpenDownload, false},
    {"OTA Update", NULL, MenuActionOpenOta, false},
    {"Scanner Filters", NULL, MenuActionOpenScannerSetup, false},
    {"Scanner Timing", NULL, MenuActionOpenScannerTiming, false},
    {"GPS", NULL, MenuActionOpenGps, false},
    {"Help", NULL, MenuActionOpenHelp, false},
    {menu_label_led, NULL, MenuActionOpenLedSetup, false},
    {menu_label_otg_power, NULL, MenuActionToggleOtgPower, false},
    {menu_label_ram, NULL, MenuActionToggleShowRam, false},
    {menu_label_debug, NULL, MenuActionToggleDebugMark, false},
    {menu_label_red_team, NULL, MenuActionToggleRedTeam, false},
    {"WPA-sec Upload", NULL, MenuActionOpenWpasec, false},
    {"SD Manager", NULL, MenuActionOpenSdManager, false},
};

static const MenuSection menu_sections[] = {
    {"Scanner", NULL, 0, 10, MENU_VISIBLE_COUNT * MENU_ITEM_SPACING},
    {"Sniffers", menu_entries_sniffers, sizeof(menu_entries_sniffers) / sizeof(menu_entries_sniffers[0]), 18, MENU_VISIBLE_COUNT_SNIFFERS * MENU_ITEM_SPACING},
    {"Attacks", menu_entries_attacks, sizeof(menu_entries_attacks) / sizeof(menu_entries_attacks[0]), 26, MENU_VISIBLE_COUNT_ATTACKS * MENU_ITEM_SPACING},
    {"Monitoring", menu_entries_monitoring, sizeof(menu_entries_monitoring) / sizeof(menu_entries_monitoring[0]), 34, MENU_VISIBLE_COUNT * MENU_ITEM_SPACING},
    {"Bluetooth", menu_entries_bluetooth, sizeof(menu_entries_bluetooth) / sizeof(menu_entries_bluetooth[0]), 42, MENU_VISIBLE_COUNT * MENU_ITEM_SPACING},
    {"Setup", menu_entries_setup, sizeof(menu_entries_setup) / sizeof(menu_entries_setup[0]), 50, MENU_VISIBLE_COUNT_SETUP * MENU_ITEM_SPACING},
};

static const size_t menu_section_count = sizeof(menu_sections) / sizeof(menu_sections[0]);
static const char* const wardrive_modes[] = {
    "Legacy", "Promisc", "Promisc + Trace", "Upload WiGLE", "Upload WDGWars"};

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

static bool simple_app_menu_entry_is_visible(
    const SimpleApp* app, uint32_t section_index, size_t raw_index) {
    const MenuSection* section = &menu_sections[section_index];
    return section_index != MENU_SECTION_ATTACKS || app->red_team_mode ||
           !section->entries[raw_index].red_team_only;
}

static size_t simple_app_menu_entry_count(const SimpleApp* app, uint32_t section_index) {
    if(!app || section_index >= menu_section_count) return 0;
    const MenuSection* section = &menu_sections[section_index];
    size_t count = 0;
    for(size_t raw_index = 0; raw_index < section->entry_count; raw_index++) {
        if(simple_app_menu_entry_is_visible(app, section_index, raw_index)) count++;
    }
    return count;
}

static const MenuEntry* simple_app_menu_entry_at(
    const SimpleApp* app, uint32_t section_index, size_t visible_index) {
    if(!app || section_index >= menu_section_count) return NULL;
    const MenuSection* section = &menu_sections[section_index];
    for(size_t raw_index = 0; raw_index < section->entry_count; raw_index++) {
        if(!simple_app_menu_entry_is_visible(app, section_index, raw_index)) continue;
        if(visible_index == 0) return &section->entries[raw_index];
        visible_index--;
    }
    return NULL;
}

static size_t simple_app_attack_index_for_command(const SimpleApp* app, const char* command) {
    size_t count = simple_app_menu_entry_count(app, MENU_SECTION_ATTACKS);
    for(size_t index = 0; index < count; index++) {
        const MenuEntry* entry = simple_app_menu_entry_at(app, MENU_SECTION_ATTACKS, index);
        if(entry && entry->command && strcmp(entry->command, command) == 0) return index;
    }
    return 0;
}

static size_t simple_app_section_visible_count(void) {
    return (menu_section_count < MENU_SECTION_VISIBLE_COUNT) ? menu_section_count : MENU_SECTION_VISIBLE_COUNT;
}

static void simple_app_adjust_section_offset(SimpleApp* app) {
    if(!app) return;
    size_t visible = simple_app_section_visible_count();
    if(visible == 0) {
        app->section_offset = 0;
        return;
    }

    if(app->section_index >= menu_section_count) {
        app->section_index = (menu_section_count > 0) ? (menu_section_count - 1) : 0;
    }

    size_t max_offset = (menu_section_count > visible) ? (menu_section_count - visible) : 0;
    if(app->section_offset > max_offset) {
        app->section_offset = max_offset;
    }

    if(app->section_index < app->section_offset) {
        app->section_offset = app->section_index;
    } else if(app->section_index >= app->section_offset + visible) {
        app->section_offset = app->section_index - visible + 1;
    }
}

static void simple_app_focus_attacks_menu(SimpleApp* app) {
    if(!app) return;
    app->screen = ScreenMenu;
    app->menu_state = MenuStateItems;
    app->section_index = MENU_SECTION_ATTACKS;
    size_t entry_count = simple_app_menu_entry_count(app, MENU_SECTION_ATTACKS);
    if(entry_count == 0) {
        app->item_index = 0;
        app->item_offset = 0;
        return;
    }
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

static bool simple_app_menu_move_item(SimpleApp* app, bool down) {
    size_t entry_count = simple_app_menu_entry_count(app, app->section_index);
    if(entry_count == 0) return false;
    size_t visible_count = simple_app_menu_visible_count(app, app->section_index);
    if(visible_count == 0) visible_count = 1;
    if(down) {
        if(app->item_index + 1 < entry_count) {
            app->item_index++;
            if(app->item_index >= app->item_offset + visible_count) {
                app->item_offset = app->item_index - visible_count + 1;
            }
        } else {
            app->item_index = 0;
            app->item_offset = 0;
        }
    } else if(app->item_index > 0) {
        app->item_index--;
        if(app->item_index < app->item_offset) app->item_offset = app->item_index;
    } else {
        app->item_index = entry_count - 1;
        app->item_offset =
            (app->item_index >= visible_count) ? (app->item_index - visible_count + 1) : 0;
    }
    if(app->section_index == MENU_SECTION_ATTACKS) app->last_attack_index = app->item_index;
    return true;
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

static void simple_app_utf8_to_ascii_pl(const char* src, char* dst, size_t dst_size) {
    if(!dst || dst_size == 0) return;
    if(!src) {
        dst[0] = '\0';
        return;
    }

    size_t out = 0;
    for(size_t i = 0; src[i] != '\0' && out + 1 < dst_size;) {
        uint8_t b0 = (uint8_t)src[i];
        if(b0 < 0x80) {
            dst[out++] = (char)b0;
            i++;
            continue;
        }

        uint8_t b1 = (uint8_t)src[i + 1];
        if(b1 == 0) {
            dst[out++] = '?';
            break;
        }

        char mapped = '\0';
        if(b0 == 0xC4) {
            if(b1 == 0x84) mapped = 'A'; // Ą
            else if(b1 == 0x85) mapped = 'a'; // ą
            else if(b1 == 0x86) mapped = 'C'; // Ć
            else if(b1 == 0x87) mapped = 'c'; // ć
            else if(b1 == 0x98) mapped = 'E'; // Ę
            else if(b1 == 0x99) mapped = 'e'; // ę
        } else if(b0 == 0xC5) {
            if(b1 == 0x81) mapped = 'L'; // Ł
            else if(b1 == 0x82) mapped = 'l'; // ł
            else if(b1 == 0x83) mapped = 'N'; // Ń
            else if(b1 == 0x84) mapped = 'n'; // ń
            else if(b1 == 0x9A) mapped = 'S'; // Ś
            else if(b1 == 0x9B) mapped = 's'; // ś
            else if(b1 == 0xB9) mapped = 'Z'; // Ź
            else if(b1 == 0xBA) mapped = 'z'; // ź
            else if(b1 == 0xBB) mapped = 'Z'; // Ż
            else if(b1 == 0xBC) mapped = 'z'; // ż
        } else if(b0 == 0xC3) {
            if(b1 == 0x93) mapped = 'O'; // Ó
            else if(b1 == 0xB3) mapped = 'o'; // ó
        }

        if(mapped != '\0') {
            dst[out++] = mapped;
            i += 2;
        } else {
            dst[out++] = '?';
            i += 1;
        }
    }

    dst[out] = '\0';
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

static uint8_t simple_app_bt_locator_item_height(const SimpleApp* app, size_t idx) {
    if(!app || !app->bt_locator_devices || idx >= app->bt_locator_count) return 1;
    const char* name = app->bt_locator_devices[idx].name;
    return (name && name[0] != '\0') ? 2 : 1;
}

static void simple_app_bt_locator_ensure_visible(SimpleApp* app) {
    if(!app || !app->bt_locator_devices || app->bt_locator_count == 0) return;

    if(app->bt_locator_index >= app->bt_locator_count) {
        app->bt_locator_index = app->bt_locator_count - 1;
    }

    int16_t list_top = 8;
    int16_t list_bottom = DISPLAY_HEIGHT - 2;
    uint8_t line_height = SERIAL_TEXT_LINE_HEIGHT;
    size_t max_lines = (list_bottom - list_top) / line_height;
    if(max_lines == 0) max_lines = 1;

    if(app->bt_locator_offset >= app->bt_locator_count) {
        app->bt_locator_offset = 0;
    }

    // Check if current window already contains the selection
    size_t lines = 0;
    bool visible = false;
    for(size_t i = app->bt_locator_offset; i < app->bt_locator_count; i++) {
        size_t h = simple_app_bt_locator_item_height(app, i);
        if(lines + h > max_lines) break;
        if(i == app->bt_locator_index) {
            visible = true;
            break;
        }
        lines += h;
    }
    if(visible) return;

    // Find the earliest offset that still shows the selection within available lines
    size_t best_offset = app->bt_locator_offset;
    for(size_t candidate = 0; candidate <= app->bt_locator_index; candidate++) {
        lines = 0;
        visible = false;
        for(size_t i = candidate; i < app->bt_locator_count; i++) {
            size_t h = simple_app_bt_locator_item_height(app, i);
            if(lines + h > max_lines) break;
            lines += h;
            if(i == app->bt_locator_index) {
                visible = true;
                break;
            }
        }
        if(visible) {
            best_offset = candidate;
            break;
        }
    }
    app->bt_locator_offset = best_offset;
}

static void simple_app_bt_scan_preview_insert(SimpleApp* app, const char* mac, int rssi, const char* name) {
    if(!app || !mac || !app->bt_scan_preview) return;
    if(app->bt_scan_preview_count >= BT_SCAN_PREVIEW_MAX) return;
    BtScanPreview* slot = &app->bt_scan_preview[app->bt_scan_preview_count++];
    strncpy(slot->mac, mac, sizeof(slot->mac) - 1);
    slot->mac[sizeof(slot->mac) - 1] = '\0';
    slot->rssi = rssi;
    slot->has_name = (name && name[0] != '\0');
    if(slot->has_name) {
        strncpy(slot->name, name, sizeof(slot->name) - 1);
        slot->name[sizeof(slot->name) - 1] = '\0';
    } else {
        slot->name[0] = '\0';
    }
}

static uint8_t simple_app_bt_scan_item_height(const BtScanPreview* p) {
    if(!p) return 1;
    return (p->has_name && p->name[0] != '\0') ? 2 : 1;
}

static bool simple_app_bt_scan_can_scroll_down(const SimpleApp* app) {
    if(!app || !app->bt_scan_preview) return false;
    if(app->bt_scan_preview_count == 0) return false;
    if(app->bt_scan_list_offset >= app->bt_scan_preview_count) return false;
    const uint8_t list_top = 10;
    const uint8_t list_bottom = DISPLAY_HEIGHT - 2;
    uint8_t max_lines =
        (uint8_t)((list_bottom - list_top + SERIAL_TEXT_LINE_HEIGHT) / SERIAL_TEXT_LINE_HEIGHT);
    if(max_lines > 6) max_lines = 6;
    if(max_lines == 0) max_lines = 1;

    size_t lines_used = 0;
    for(size_t i = app->bt_scan_list_offset; i < app->bt_scan_preview_count; i++) {
        uint8_t h = simple_app_bt_scan_item_height(&app->bt_scan_preview[i]);
        if(lines_used + h > max_lines) {
            return true; // there is more content below
        }
        lines_used += h;
    }
    return false;
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




static size_t simple_app_target_count(const SimpleApp* app) {
    if(!app || app->recon_targets.failed) return 0;
    return app->recon_targets.targets ? app->recon_targets.count : 0;
}

static uint16_t simple_app_target_number(const SimpleApp* app, size_t index) {
    if(!app || app->recon_targets.failed) return 0;
    return app->recon_targets.targets && index < app->recon_targets.count ?
               app->recon_targets.targets[index].number : 0;
}

static bool simple_app_get_first_selected_ssid(SimpleApp* app, char* out, size_t out_size) {
    if(!app || !out || out_size == 0) return false;
    if(app->recon_targets.failed) return false;
    if(!app->recon_targets.targets || app->recon_targets.count == 0) return false;
    simple_app_utf8_to_ascii_pl(app->recon_targets.targets[0].ssid, out, out_size);
    simple_app_trim(out);
    return out[0] != '\0';
}


static void simple_app_update_backlight_label(SimpleApp* app) {
    if(!app) return;
    snprintf(
        menu_label_backlight,
        sizeof(menu_label_backlight),
        "Backlight: %s",
        app->backlight_enabled ? "On" : "Off");
}

static void simple_app_update_ram_label(SimpleApp* app) {
    if(!app) return;
    snprintf(
        menu_label_ram,
        sizeof(menu_label_ram),
        "Show RAM: %s",
        app->show_ram_overlay ? "On" : "Off");
}

static void simple_app_update_debug_label(SimpleApp* app) {
    if(!app) return;
    snprintf(
        menu_label_debug,
        sizeof(menu_label_debug),
        "Debug Log: %s",
        app->debug_mark_enabled ? "On" : "Off");
}

static void simple_app_update_red_team_label(SimpleApp* app) {
    if(!app) return;
    snprintf(
        menu_label_red_team,
        sizeof(menu_label_red_team),
        "Red Team: %s",
        app->red_team_mode ? "On" : "Off");
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
                simple_app_on_board_online(app, "boot");
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

static void simple_app_on_board_online(SimpleApp* app, const char* source) {
    if(!app) return;
    (void)source;

    bool was_ready = app->board_ready_seen;
    app->board_ready_seen = true;
    app->board_sync_pending = false;
    app->board_ping_outstanding = false;
    app->board_last_rx_tick = furi_get_tick();
    app->board_missing_shown = false;
    app->board_ping_failures = 0;

    /* A prior cleanup could not be transmitted while the board was missing. */
    if(!was_ready && app->recon_stations_selected) {
        simple_app_clear_station_selection(app);
    }

    if(app->board_bootstrap_active) {
        // End bootstrap discovery without forcing a reboot
        app->board_bootstrap_active = false;
        app->board_bootstrap_reboot_sent = false;
        simple_app_show_status_message(app, "Board ready", 1200, true);
        if(app->viewport) {
            view_port_update(app->viewport);
        }
        return;
    }

    if(!was_ready) {
        simple_app_show_status_message(app, "Board found", 1000, true);
        if(app->viewport) {
            view_port_update(app->viewport);
        }
    }

    simple_app_request_led_status(app);
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

static void simple_app_draw_ram_overlay(SimpleApp* app, Canvas* canvas) {
    if(!app || !canvas || !app->show_ram_overlay) return;
    size_t free_heap = memmgr_get_free_heap();
    size_t min_heap = memmgr_get_minimum_free_heap();
    unsigned long free_kb = (unsigned long)(free_heap / 1024);
    unsigned long min_kb = (unsigned long)(min_heap / 1024);
    unsigned long start_kb = (unsigned long)(app->heap_start_free / 1024);
    char line[40];
    snprintf(line, sizeof(line), "R:%luK M:%luK S:%luK", free_kb, min_kb, start_kb);
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str_aligned(
        canvas,
        DISPLAY_WIDTH - 2,
        DISPLAY_HEIGHT - 2,
        AlignRight,
        AlignBottom,
        line);
}

static void simple_app_handle_pong(SimpleApp* app) {
    simple_app_on_board_online(app, "pong");
}

static void simple_app_send_ping(SimpleApp* app) {
    if(!app || !app->serial || !app->serial_mutex) return;
    lab_c5_serial_write_line(app->serial, app->serial_mutex, "ping", sizeof("ping") - 1);
    app->board_ping_outstanding = true;
    app->board_last_ping_tick = furi_get_tick();
}

static void simple_app_ping_watchdog(SimpleApp* app) {
    if(!app) return;
    uint32_t now = furi_get_tick();

    bool status_active = simple_app_status_message_is_active(app);
    // Ping on idle menu (no modal) or whenever we are running the bootstrap discovery
    bool idle_menu = (app->screen == ScreenMenu) && (app->menu_state == MenuStateSections);
    bool attack_barrier_pending = app->attack_rx_guard.suppress &&
                                  app->attack_rx_guard.pongs_remaining > 0;
    bool allow_ping = ((idle_menu && !status_active) || app->board_bootstrap_active ||
                       attack_barrier_pending);

    if(allow_ping && !app->board_ping_outstanding &&
       (now - app->board_last_ping_tick) >= BOARD_PING_INTERVAL_MS) {
        simple_app_send_ping(app);
    }

    if(app->board_ping_outstanding &&
       (now - app->board_last_ping_tick) >= BOARD_PING_TIMEOUT_MS) {
        app->board_ping_outstanding = false;

        if(app->board_bootstrap_active) {
            const char* waiting_msg = app->board_bootstrap_reboot_sent
                                          ? "Rebooting\nfor stability\nWaiting for board..."
                                          : "Board discovery\nWaiting for board...";
            simple_app_show_status_message(app, waiting_msg, 0, true);
            if(app->viewport) {
                view_port_update(app->viewport);
            }
            return;
        }

        if(app->board_ping_failures < UINT8_MAX) {
            app->board_ping_failures++;
        }
        if(app->board_ping_failures >= BOARD_PING_FAILURE_LIMIT) {
            app->board_ready_seen = false;
            if(!app->board_missing_shown) {
                app->board_missing_shown = true;
                simple_app_show_status_message(app, "No board", 1500, true);
            }
        }
    }
}

static void simple_app_send_command_quiet(SimpleApp* app, const char* command) {
    if(!app || !command || !app->serial || !app->serial_mutex) return;

    // Block commands until board reports ready (except reboot which triggers sync)
    if(!app->board_ready_seen) {
        // Allow reboot to kick off sync
        if(strncmp(command, "reboot", 6) != 0 && strncmp(command, "ping", 4) != 0) {
            simple_app_show_status_message(app, "Waiting for board...", 1000, true);
            return;
        }
    }
    app->board_ping_outstanding = false;

    simple_app_log_cli_command(app, "UI", command);

    size_t command_length = strlen(command);
    if(app->rx_stream) {
        furi_stream_buffer_reset(app->rx_stream);
    }
    lab_c5_serial_write_line(app->serial, app->serial_mutex, command, command_length);
    char log_line[96];
    size_t log_length =
        lab_c5_format_tx_log(log_line, sizeof(log_line), command, command_length);
    if(log_length > 0) {
        simple_app_append_serial_data(app, (const uint8_t*)log_line, log_length);
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
    simple_app_mark_config_dirty(app);
    simple_app_save_config_if_dirty(app, NULL, false);

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

static uint16_t simple_app_clamp_channel_time(uint32_t value) {
    if(value < SCANNER_CHANNEL_TIME_MIN_MS) {
        value = SCANNER_CHANNEL_TIME_MIN_MS;
    } else if(value > SCANNER_CHANNEL_TIME_MAX_MS) {
        value = SCANNER_CHANNEL_TIME_MAX_MS;
    }
    return (uint16_t)value;
}

static bool simple_app_extract_first_uint(const char* line, uint32_t* value_out) {
    if(!line || !value_out) return false;
    const char* cursor = line;
    while(*cursor && !isdigit((unsigned char)*cursor)) {
        cursor++;
    }
    if(*cursor == '\0') return false;
    char* endptr = NULL;
    uint32_t parsed = (uint32_t)strtoul(cursor, &endptr, 10);
    if(endptr == cursor) return false;
    *value_out = parsed;
    return true;
}

static bool simple_app_set_channel_time(SimpleApp* app, bool is_min, uint16_t value, bool from_remote) {
    if(!app) return false;
    uint16_t clamped = simple_app_clamp_channel_time(value);
    uint16_t before_min = app->scanner_min_channel_time;
    uint16_t before_max = app->scanner_max_channel_time;

    if(is_min) {
        app->scanner_min_channel_time = clamped;
        if(app->scanner_max_channel_time < clamped) {
            app->scanner_max_channel_time = clamped;
        }
    } else {
        app->scanner_max_channel_time = clamped;
        if(app->scanner_min_channel_time > clamped) {
            app->scanner_min_channel_time = clamped;
        }
    }

    bool changed = (before_min != app->scanner_min_channel_time) ||
                   (before_max != app->scanner_max_channel_time);

    if(changed && !from_remote) {
        simple_app_mark_config_dirty(app);
    }

    if(changed && app->viewport && app->screen == ScreenSetupScannerTiming) {
        view_port_update(app->viewport);
    }

    return changed;
}

static void simple_app_request_channel_time(SimpleApp* app, bool request_min) {
    if(!app || !app->serial) return;
    if(request_min) {
        app->scanner_timing_min_pending = true;
    } else {
        app->scanner_timing_max_pending = true;
    }
    app->scanner_timing_read_length = 0;
    app->scanner_timing_read_buffer[0] = '\0';
    simple_app_send_command_quiet(app, request_min ? "channel_time read min" : "channel_time read max");
}

static void simple_app_request_scanner_timing(SimpleApp* app) {
    if(!app || !app->serial) return;
    simple_app_request_channel_time(app, true);
    simple_app_request_channel_time(app, false);
}

static void simple_app_send_channel_time(SimpleApp* app, bool is_min, uint16_t value) {
    if(!app || !app->serial) return;
    char command[48];
    snprintf(
        command,
        sizeof(command),
        "channel_time set %s %u",
        is_min ? "min" : "max",
        (unsigned)value);
    simple_app_send_command_quiet(app, command);
    simple_app_request_channel_time(app, is_min);
}

static bool simple_app_handle_scanner_timing_line(SimpleApp* app, const char* line) {
    if(!app || !line) return false;

    char lower[96];
    size_t len = simple_app_bounded_strlen(line, sizeof(lower) - 1);
    for(size_t i = 0; i < len; i++) {
        lower[i] = (char)tolower((unsigned char)line[i]);
    }
    lower[len] = '\0';

    bool mentions_min = strstr(lower, "min") != NULL;
    bool mentions_max = strstr(lower, "max") != NULL;

    uint32_t parsed = 0;
    bool has_number = simple_app_extract_first_uint(line, &parsed);

    // If no explicit min/max marker, use pending flags to decide target.
    if(!mentions_min && !mentions_max) {
        if(app->scanner_timing_min_pending && !app->scanner_timing_max_pending) {
            mentions_min = true;
        } else if(app->scanner_timing_max_pending && !app->scanner_timing_min_pending) {
            mentions_max = true;
        } else if(app->scanner_timing_min_pending) {
            mentions_min = true;
        } else if(app->scanner_timing_max_pending) {
            mentions_max = true;
        }
    }

    if(!mentions_min && !mentions_max) return false;
    if(!has_number) return false;

    bool handled = false;
    if(mentions_min) {
        handled = simple_app_set_channel_time(app, true, (uint16_t)parsed, true) || handled;
        app->scanner_timing_min_pending = false;
    }
    if(mentions_max) {
        handled = simple_app_set_channel_time(app, false, (uint16_t)parsed, true) || handled;
        app->scanner_timing_max_pending = false;
    }

    return handled;
}

static void simple_app_scanner_timing_feed(SimpleApp* app, char ch) {
    if(!app || (!app->scanner_timing_min_pending && !app->scanner_timing_max_pending)) return;
    if(ch == '\r') return;
    if(ch == '\n') {
        if(app->scanner_timing_read_length > 0) {
            app->scanner_timing_read_buffer[app->scanner_timing_read_length] = '\0';
            simple_app_handle_scanner_timing_line(app, app->scanner_timing_read_buffer);
        }
        app->scanner_timing_read_length = 0;
        return;
    }
    if(app->scanner_timing_read_length + 1 >= sizeof(app->scanner_timing_read_buffer)) {
        app->scanner_timing_read_length = 0;
        return;
    }
    app->scanner_timing_read_buffer[app->scanner_timing_read_length++] = ch;
}

static void simple_app_modify_channel_time(SimpleApp* app, bool is_min, int32_t delta) {
    if(!app || delta == 0) return;
    uint16_t target = is_min ? app->scanner_min_channel_time : app->scanner_max_channel_time;
    int32_t proposed = (int32_t)target + delta;
    if(proposed < 0) {
        proposed = 0;
    }
    uint16_t before_min = app->scanner_min_channel_time;
    uint16_t before_max = app->scanner_max_channel_time;

    if(simple_app_set_channel_time(app, is_min, (uint16_t)proposed, false)) {
        if(app->scanner_min_channel_time != before_min) {
            simple_app_send_channel_time(app, true, app->scanner_min_channel_time);
        }
        if(app->scanner_max_channel_time != before_max) {
            simple_app_send_channel_time(app, false, app->scanner_max_channel_time);
        }
    }
}

static int16_t simple_app_clamp_gps_utc_offset(int32_t minutes) {
    if(minutes < GPS_UTC_OFFSET_MIN_MINUTES) {
        return GPS_UTC_OFFSET_MIN_MINUTES;
    }
    if(minutes > GPS_UTC_OFFSET_MAX_MINUTES) {
        return GPS_UTC_OFFSET_MAX_MINUTES;
    }
    return (int16_t)minutes;
}

static void simple_app_reset_blackout_status(SimpleApp* app) {
    if(!app) return;
    app->blackout_full_console = false;
    app->blackout_running = false;
    app->blackout_phase = BlackoutPhaseIdle;
    app->blackout_networks = 0;
    app->blackout_cycle = 0;
    app->blackout_channel = 0;
    app->blackout_has_channel = false;
    app->blackout_note[0] = '\0';
    app->blackout_line_length = 0;
    app->blackout_last_update_tick = 0;
}

static void simple_app_blackout_set_phase(SimpleApp* app, BlackoutPhase phase, const char* note) {
    if(!app) return;
    app->blackout_phase = phase;
    app->blackout_running = (phase != BlackoutPhaseIdle && phase != BlackoutPhaseFinished);
    app->blackout_last_update_tick = furi_get_tick();
    if(note && note[0] != '\0') {
        strncpy(app->blackout_note, note, sizeof(app->blackout_note) - 1);
        app->blackout_note[sizeof(app->blackout_note) - 1] = '\0';
    } else if(note) {
        app->blackout_note[0] = '\0';
    }
}

static void simple_app_reset_sniffer_dog_status(SimpleApp* app) {
    if(!app) return;
    app->sniffer_dog_full_console = false;
    app->sniffer_dog_running = false;
    app->sniffer_dog_phase = SnifferDogPhaseIdle;
    app->sniffer_dog_deauth_count = 0;
    app->sniffer_dog_channel = 0;
    app->sniffer_dog_has_channel = false;
    app->sniffer_dog_rssi = 0;
    app->sniffer_dog_has_rssi = false;
    app->sniffer_dog_note[0] = '\0';
    app->sniffer_dog_line_length = 0;
    app->sniffer_dog_last_update_tick = 0;
}

static void simple_app_sniffer_dog_set_phase(SimpleApp* app, SnifferDogPhase phase, const char* note) {
    if(!app) return;
    app->sniffer_dog_phase = phase;
    app->sniffer_dog_running =
        (phase != SnifferDogPhaseIdle && phase != SnifferDogPhaseFinished && phase != SnifferDogPhaseError);
    app->sniffer_dog_last_update_tick = furi_get_tick();
    if(note && note[0] != '\0') {
        strncpy(app->sniffer_dog_note, note, sizeof(app->sniffer_dog_note) - 1);
        app->sniffer_dog_note[sizeof(app->sniffer_dog_note) - 1] = '\0';
    } else if(note) {
        app->sniffer_dog_note[0] = '\0';
    }
}

static bool simple_app_blackout_parse_channel(const char* line, uint8_t* out_channel) {
    if(!line || !out_channel) return false;
    const char* found = strstr(line, "channel");
    if(found) {
        const char* digits = found + strlen("channel");
        while(*digits && !isdigit((unsigned char)*digits)) {
            digits++;
        }
        if(isdigit((unsigned char)*digits)) {
            unsigned long value = strtoul(digits, NULL, 10);
            if(value > 0 && value <= 255) {
                *out_channel = (uint8_t)value;
                return true;
            }
        }
    }

    const char* cursor = line;
    while((found = strstr(cursor, "ch")) != NULL) {
        char before = (found == line) ? ' ' : *(found - 1);
        bool boundary = (before == ' ' || before == '[' || before == '(' || before == ':' || before == '#');
        if(!boundary) {
            cursor = found + 2;
            continue;
        }
        const char* digits = found + 2;
        while(*digits && !isdigit((unsigned char)*digits)) {
            digits++;
        }
        if(!isdigit((unsigned char)*digits)) {
            cursor = found + 2;
            continue;
        }
        unsigned long value = strtoul(digits, NULL, 10);
        if(value == 0 || value > 255) {
            cursor = found + 2;
            continue;
        }
        *out_channel = (uint8_t)value;
        return true;
    }
    return false;
}

static bool simple_app_blackout_extract_networks(const char* line, uint32_t* out_count) {
    if(!line || !out_count) return false;
    if(strstr(line, "networks") == NULL) return false;
    const char* digits = line;
    while(*digits && !isdigit((unsigned char)*digits)) {
        digits++;
    }
    if(!isdigit((unsigned char)*digits)) return false;
    unsigned long value = strtoul(digits, NULL, 10);
    *out_count = (uint32_t)value;
    return true;
}

static void simple_app_process_sniffer_dog_line(SimpleApp* app, const char* line) {
    if(!app || !line) return;

    while(*line == '>' || *line == ' ') {
        line++;
    }
    if(*line == '\0') return;

    if(strstr(line, "Starting Sniffer Dog mode") != NULL) {
        app->sniffer_dog_view_active = true;
        simple_app_sniffer_dog_set_phase(app, SnifferDogPhaseStarting, "");
        return;
    }

    if(strstr(line, "Sniffer Dog started") != NULL) {
        app->sniffer_dog_view_active = true;
        simple_app_sniffer_dog_set_phase(app, SnifferDogPhaseHunting, "");
        return;
    }

    if(strstr(line, "Sniffer Dog already active") != NULL) {
        app->sniffer_dog_view_active = true;
        simple_app_sniffer_dog_set_phase(app, SnifferDogPhaseHunting, "Already active");
        return;
    }

    if(strstr(line, "Regular sniffer is active") != NULL) {
        app->sniffer_dog_view_active = true;
        simple_app_sniffer_dog_set_phase(app, SnifferDogPhaseError, "Stop sniffer");
        return;
    }

    if(strstr(line, "Failed to create Sniffer Dog channel hopping task") != NULL) {
        app->sniffer_dog_view_active = true;
        simple_app_sniffer_dog_set_phase(app, SnifferDogPhaseError, "Task failed");
        return;
    }

    if(strstr(line, "Stopping Sniffer Dog task") != NULL ||
       strstr(line, "Sniffer Dog task forcefully stopped") != NULL ||
       strstr(line, "Sniffer Dog channel task ending") != NULL) {
        app->sniffer_dog_view_active = true;
        simple_app_sniffer_dog_set_phase(app, SnifferDogPhaseStopping, "Stopping");
        return;
    }

    if(strstr(line, "Sniffer Dog stopped") != NULL) {
        app->sniffer_dog_view_active = true;
        simple_app_sniffer_dog_set_phase(app, SnifferDogPhaseFinished, "Stopped");
        return;
    }

    unsigned long deauth_count = 0;
    if(sscanf(line, "[SnifferDog #%lu]", &deauth_count) == 1) {
        app->sniffer_dog_view_active = true;
        app->sniffer_dog_deauth_count = (uint32_t)deauth_count;
        app->sniffer_dog_running = true;
        app->sniffer_dog_last_update_tick = furi_get_tick();

        const char* ch_ptr = strstr(line, "Ch=");
        if(ch_ptr) {
            int channel = atoi(ch_ptr + 3);
            if(channel > 0 && channel <= 255) {
                app->sniffer_dog_channel = (uint8_t)channel;
                app->sniffer_dog_has_channel = true;
            }
        }

        const char* rssi_ptr = strstr(line, "RSSI=");
        if(rssi_ptr) {
            int rssi = atoi(rssi_ptr + 5);
            app->sniffer_dog_rssi = rssi;
            app->sniffer_dog_has_rssi = true;
        }
        simple_app_sniffer_dog_set_phase(app, SnifferDogPhaseHunting, "");
        return;
    }
}

static void simple_app_sniffer_dog_feed(SimpleApp* app, char ch) {
    if(!app) return;
    if(ch == '\r') return;
    if(ch == '\n') {
        if(app->sniffer_dog_line_length > 0) {
            app->sniffer_dog_line_buffer[app->sniffer_dog_line_length] = '\0';
            simple_app_process_sniffer_dog_line(app, app->sniffer_dog_line_buffer);
        }
        app->sniffer_dog_line_length = 0;
        return;
    }
    if(app->sniffer_dog_line_length + 1 >= sizeof(app->sniffer_dog_line_buffer)) {
        app->sniffer_dog_line_length = 0;
        return;
    }
    app->sniffer_dog_line_buffer[app->sniffer_dog_line_length++] = ch;
}

static void simple_app_deauth_trim(char* text) {
    if(!text) return;
    char* start = text;
    while(*start && isspace((unsigned char)*start)) start++;
    char* end = start + strlen(start);
    while(end > start && isspace((unsigned char)*(end - 1))) {
        end--;
    }
    size_t len = (size_t)(end - start);
    if(start != text) {
        memmove(text, start, len);
    }
    text[len] = '\0';
}

static void simple_app_deauth_set_note(SimpleApp* app, const char* note) {
    if(!app || !note) return;
    strncpy(app->deauth_note, note, sizeof(app->deauth_note) - 1);
    app->deauth_note[sizeof(app->deauth_note) - 1] = '\0';
    app->deauth_last_update_tick = furi_get_tick();
}

static void simple_app_reset_deauth_status(SimpleApp* app) {
    if(!app) return;
    app->deauth_full_console = false;
    app->deauth_running = false;
    app->deauth_targets = 0;
    app->deauth_overlay_allowed = false;
    app->deauth_channel = 0;
    app->deauth_has_channel = false;
    app->deauth_list_offset = 0;
    app->deauth_list_scroll_x = 0;
    app->deauth_blink_last_tick = 0;
    app->deauth_note[0] = '\0';
    app->deauth_line_length = 0;
    app->deauth_last_update_tick = 0;
    app->deauth_ssid[0] = '\0';
    app->deauth_bssid[0] = '\0';
}

static void simple_app_reset_handshake_status(SimpleApp* app) {
    if(!app) return;
    app->handshake_view_active = false;
    app->handshake_full_console = false;
    app->handshake_running = false;
    app->handshake_targets = 0;
    app->handshake_captured = 0;
    app->handshake_channel = 0;
    app->handshake_has_channel = false;
    app->handshake_rssi = 0;
    app->handshake_has_rssi = false;
    app->handshake_overlay_allowed = false;
    app->handshake_blink_last_tick = 0;
    app->handshake_vibro_done = false;
    app->handshake_note[0] = '\0';
    app->handshake_line_length = 0;
    app->handshake_ssid[0] = '\0';
}

static void simple_app_reset_sae_status(SimpleApp* app) {
    if(!app) return;
    app->sae_view_active = false;
    app->sae_full_console = false;
    app->sae_running = false;
    app->sae_overlay_allowed = false;
    app->sae_has_channel = false;
    app->sae_channel = 0;
    app->sae_note[0] = '\0';
    app->sae_line_length = 0;
    app->sae_ssid[0] = '\0';
}

static bool simple_app_deauth_extract_targets(const char* line, uint32_t* out_count) {
    if(!line || !out_count) return false;
    const char* digits = line;
    while(*digits && !isdigit((unsigned char)*digits)) {
        digits++;
    }
    if(!isdigit((unsigned char)*digits)) return false;
    unsigned long value = strtoul(digits, NULL, 10);
    *out_count = (uint32_t)value;
    return true;
}

static void simple_app_process_deauth_line(SimpleApp* app, const char* line) {
    if(!app || !line) return;
    if(!app->deauth_overlay_allowed) return;

    while(*line == '>' || *line == ' ') {
        line++;
    }
    if(*line == '\0') return;

    if(strstr(line, "Evil twin: no selected APs") != NULL) {
        app->deauth_view_active = true;
        app->deauth_running = false;
        simple_app_deauth_set_note(app, "No targets");
        return;
    }

    if(strstr(line, "Deauth attack already running") != NULL) {
        app->deauth_view_active = true;
        app->deauth_running = true;
        simple_app_deauth_set_note(app, "Already");
        return;
    }

    if(strstr(line, "Deauth attack started") != NULL) {
        app->deauth_view_active = true;
        app->deauth_running = true;
        simple_app_deauth_set_note(app, "Running");
        return;
    }

    if(strstr(line, "Starting deauth attack") != NULL) {
        app->deauth_view_active = true;
        app->deauth_running = true;
        simple_app_deauth_set_note(app, "Starting");
        return;
    }

    if(strstr(line, "Stopping deauth attack task") != NULL) {
        app->deauth_view_active = true;
        app->deauth_running = false;
        simple_app_deauth_set_note(app, "Stopping");
        return;
    }

    if(strstr(line, "Deauth attack task forcefully stopped") != NULL) {
        app->deauth_view_active = true;
        app->deauth_running = false;
        simple_app_deauth_set_note(app, "Force stop");
        return;
    }

    if(strstr(line, "Deauth attack task finished") != NULL ||
       strstr(line, "Deauth attack stopped") != NULL) {
        app->deauth_view_active = true;
        app->deauth_running = false;
        simple_app_deauth_set_note(app, "Stopped");
        return;
    }

    if(strstr(line, "Attacking") != NULL && strstr(line, "network") != NULL) {
        uint32_t targets = 0;
        if(simple_app_deauth_extract_targets(line, &targets)) {
            app->deauth_targets = targets;
        }
        app->deauth_view_active = true;
        app->deauth_last_update_tick = furi_get_tick();
        return;
    }

    if(strstr(line, "Target BSSID[") != NULL) {
        char ssid[SCAN_SSID_MAX_LEN];
        char bssid[18];
        int channel = 0;
        int matched = sscanf(
            line,
            "Target BSSID[%*u]: %32[^,], BSSID: %17[^,], Channel: %d",
            ssid,
            bssid,
            &channel);
        if(matched >= 2) {
            simple_app_deauth_trim(ssid);
            simple_app_deauth_trim(bssid);
            strncpy(app->deauth_ssid, ssid, sizeof(app->deauth_ssid) - 1);
            app->deauth_ssid[sizeof(app->deauth_ssid) - 1] = '\0';
            strncpy(app->deauth_bssid, bssid, sizeof(app->deauth_bssid) - 1);
            app->deauth_bssid[sizeof(app->deauth_bssid) - 1] = '\0';
        }
        if(matched == 3 && channel > 0 && channel <= 255) {
            app->deauth_channel = (uint8_t)channel;
            app->deauth_has_channel = true;
        }
        app->deauth_view_active = true;
        app->deauth_last_update_tick = furi_get_tick();
        return;
    }
}

static void simple_app_deauth_feed(SimpleApp* app, char ch) {
    if(!app) return;
    if(ch == '\r') return;
    if(ch == '\n') {
        if(app->deauth_line_length > 0) {
            app->deauth_line_buffer[app->deauth_line_length] = '\0';
            simple_app_process_deauth_line(app, app->deauth_line_buffer);
        }
        app->deauth_line_length = 0;
        return;
    }
    if(app->deauth_line_length + 1 >= sizeof(app->deauth_line_buffer)) {
        app->deauth_line_length = 0;
        return;
    }
    app->deauth_line_buffer[app->deauth_line_length++] = ch;
}

static bool simple_app_alloc_bt_buffers(SimpleApp* app) {
    if(!app) return false;
    if(app->bt_scan_preview && app->bt_locator_devices &&
       app->bt_locator_scan_line && app->bt_scan_line_buffer &&
       app->bt_locator_scroll_text) {
        return true;
    }
    app->bt_scan_preview = calloc(BT_SCAN_PREVIEW_MAX, sizeof(BtScanPreview));
    app->bt_locator_devices = calloc(BT_LOCATOR_MAX_DEVICES, sizeof(BtLocatorDevice));
    app->bt_locator_scan_line = calloc(BT_LOCATOR_SCAN_LINE_LEN, 1);
    app->bt_scan_line_buffer = calloc(BT_SCAN_LINE_BUFFER_LEN, 1);
    app->bt_locator_scroll_text = calloc(BT_LOCATOR_SCROLL_TEXT_LEN, 1);
    if(!app->bt_scan_preview || !app->bt_locator_devices ||
       !app->bt_locator_scan_line || !app->bt_scan_line_buffer ||
       !app->bt_locator_scroll_text) {
        if(app->bt_scan_preview) {
            free(app->bt_scan_preview);
            app->bt_scan_preview = NULL;
        }
        if(app->bt_locator_devices) {
            free(app->bt_locator_devices);
            app->bt_locator_devices = NULL;
        }
        if(app->bt_locator_scan_line) {
            free(app->bt_locator_scan_line);
            app->bt_locator_scan_line = NULL;
        }
        if(app->bt_scan_line_buffer) {
            free(app->bt_scan_line_buffer);
            app->bt_scan_line_buffer = NULL;
        }
        if(app->bt_locator_scroll_text) {
            free(app->bt_locator_scroll_text);
            app->bt_locator_scroll_text = NULL;
        }
        return false;
    }
    return true;
}

static void simple_app_free_bt_buffers(SimpleApp* app) {
    if(!app) return;
    if(app->bt_scan_preview) {
        free(app->bt_scan_preview);
        app->bt_scan_preview = NULL;
    }
    if(app->bt_locator_devices) {
        free(app->bt_locator_devices);
        app->bt_locator_devices = NULL;
    }
    if(app->bt_locator_scan_line) {
        free(app->bt_locator_scan_line);
        app->bt_locator_scan_line = NULL;
    }
    if(app->bt_scan_line_buffer) {
        free(app->bt_scan_line_buffer);
        app->bt_scan_line_buffer = NULL;
    }
    if(app->bt_locator_scroll_text) {
        free(app->bt_locator_scroll_text);
        app->bt_locator_scroll_text = NULL;
    }
}

static void simple_app_handshake_set_note(SimpleApp* app, const char* note) {
    if(!app || !note) return;
    strncpy(app->handshake_note, note, sizeof(app->handshake_note) - 1);
    app->handshake_note[sizeof(app->handshake_note) - 1] = '\0';
}

static void simple_app_handshake_buzz_once(SimpleApp* app) {
    if(!app || app->handshake_vibro_done) return;
    app->handshake_vibro_done = true;
    furi_hal_vibro_on(true);
    furi_delay_ms(40);
    furi_hal_vibro_on(false);
}

static void simple_app_handshake_parse_attacking(SimpleApp* app, const char* line) {
    if(!app || !line) return;
    char ssid[SCAN_SSID_MAX_LEN];
    int channel = 0;
    int rssi = 0;
    int matched = sscanf(
        line,
        ">>> [%*u/%*u] Attacking '%32[^']' (Ch %d, RSSI: %d dBm) <<<",
        ssid,
        &channel,
        &rssi);
    if(matched >= 2) {
        simple_app_trim(ssid);
        strncpy(app->handshake_ssid, ssid, sizeof(app->handshake_ssid) - 1);
        app->handshake_ssid[sizeof(app->handshake_ssid) - 1] = '\0';
        if(channel > 0 && channel <= 255) {
            app->handshake_channel = (uint8_t)channel;
            app->handshake_has_channel = true;
        }
        if(matched >= 3) {
            app->handshake_rssi = rssi;
            app->handshake_has_rssi = true;
        }
        app->handshake_running = true;
        if(app->handshake_has_rssi) {
            char note[32];
            snprintf(note, sizeof(note), "Attack CH%u %d", app->handshake_channel, app->handshake_rssi);
            simple_app_handshake_set_note(app, note);
        } else if(app->handshake_has_channel) {
            char note[32];
            snprintf(note, sizeof(note), "Attack CH%u", app->handshake_channel);
            simple_app_handshake_set_note(app, note);
        } else {
            simple_app_handshake_set_note(app, "Attacking");
        }
    }
}





static void simple_app_sae_set_note(SimpleApp* app, const char* note) {
    if(!app) return;
    if(note) {
        strncpy(app->sae_note, note, sizeof(app->sae_note) - 1);
        app->sae_note[sizeof(app->sae_note) - 1] = '\0';
    } else {
        app->sae_note[0] = '\0';
    }
}

static void simple_app_process_sae_line(SimpleApp* app, const char* line) {
    if(!app || !line) return;
    if(!app->sae_overlay_allowed) return;

    if(strstr(line, "WPA3 SAE Overflow Attack") != NULL ||
       strstr(line, "SAE attack started") != NULL ||
       strstr(line, "SAE overflow task started") != NULL) {
        app->sae_view_active = true;
        app->sae_running = true;
        simple_app_sae_set_note(app, "Running");
    }

    if(strstr(line, "Stopping SAE overflow task") != NULL ||
       strstr(line, "SAE overflow: Stop requested") != NULL ||
       strstr(line, "SAE overflow task finished") != NULL ||
       strstr(line, "SAE overflow task forcefully stopped") != NULL) {
        app->sae_view_active = true;
        app->sae_running = false;
        simple_app_sae_set_note(app, NULL);
    }

    const char* ssid_ptr = strstr(line, "SSID='");
    if(ssid_ptr) {
        ssid_ptr += 6;
        const char* ssid_end = strchr(ssid_ptr, '\'');
        if(ssid_end && ssid_end > ssid_ptr) {
            size_t len = (size_t)(ssid_end - ssid_ptr);
            if(len >= sizeof(app->sae_ssid)) len = sizeof(app->sae_ssid) - 1;
            memcpy(app->sae_ssid, ssid_ptr, len);
            app->sae_ssid[len] = '\0';
            app->sae_view_active = true;
        }
        const char* ch_ptr = strstr(ssid_end ? ssid_end : ssid_ptr, "Ch=");
        if(ch_ptr) {
            int channel = atoi(ch_ptr + 3);
            if(channel > 0) {
                app->sae_channel = (uint8_t)channel;
                app->sae_has_channel = true;
            }
        }
    }
}

static void simple_app_sae_feed(SimpleApp* app, char ch) {
    if(!app) return;
    if(!app->sae_overlay_allowed) {
        app->sae_line_length = 0;
        return;
    }
    if(ch == '\r') return;
    if(ch == '\n') {
        if(app->sae_line_length > 0) {
            app->sae_line_buffer[app->sae_line_length] = '\0';
            simple_app_process_sae_line(app, app->sae_line_buffer);
        }
        app->sae_line_length = 0;
        return;
    }
    if(app->sae_line_length + 1 >= sizeof(app->sae_line_buffer)) {
        app->sae_line_length = 0;
        return;
    }
    app->sae_line_buffer[app->sae_line_length++] = ch;
}

static void simple_app_process_handshake_line(SimpleApp* app, const char* line) {
    if(!app || !line) return;
    if(!app->handshake_overlay_allowed) return;

    while(*line == '>' || *line == ' ') {
        line++;
    }
    if(*line == '\0') return;

    if(strstr(line, "Starting WPA Handshake Capture") != NULL) {
        app->handshake_view_active = true;
        app->handshake_running = true;
        simple_app_handshake_set_note(app, "Starting");
        return;
    }
    if(strstr(line, "Enabling AP mode") != NULL) {
        app->handshake_view_active = true;
        app->handshake_running = true;
        simple_app_handshake_set_note(app, "AP enable");
        return;
    }
    if(strstr(line, "AP mode enabled") != NULL) {
        app->handshake_view_active = true;
        app->handshake_running = true;
        simple_app_handshake_set_note(app, "AP ready");
        return;
    }
    if(strstr(line, "Handshake attack task started") != NULL) {
        app->handshake_view_active = true;
        app->handshake_running = true;
        simple_app_handshake_set_note(app, "Running");
        return;
    }
    if(strstr(line, "Handshake attack task finished") != NULL) {
        app->handshake_view_active = true;
        app->handshake_running = false;
        simple_app_handshake_set_note(app, "Finished");
        return;
    }
    if(strstr(line, "Attack complete") != NULL ||
       strstr(line, "All selected networks captured") != NULL) {
        app->handshake_view_active = true;
        app->handshake_running = false;
        simple_app_handshake_set_note(app, "Complete");
        return;
    }
    if(strstr(line, "Attack Cycle Complete") != NULL) {
        app->handshake_view_active = true;
        simple_app_handshake_set_note(app, "Cycle done");
        return;
    }
    if(strstr(line, "Selected mode:") != NULL ||
       strstr(line, "Selected Networks Mode") != NULL) {
        app->handshake_view_active = true;
        app->handshake_running = true;
        simple_app_handshake_set_note(app, "Running");
        return;
    }
    if(strstr(line, "Attacking ") != NULL && strstr(line, "networks") != NULL) {
        app->handshake_view_active = true;
        app->handshake_running = true;
        simple_app_handshake_set_note(app, "Running");
        return;
    }
    if(strstr(line, "Saving handshake") != NULL ||
       strstr(line, "Attempting to save handshake") != NULL) {
        app->handshake_view_active = true;
        simple_app_handshake_set_note(app, "Saving");
        return;
    }
    if(strstr(line, "No handshake for") != NULL) {
        app->handshake_view_active = true;
        app->handshake_running = true;
        simple_app_handshake_set_note(app, "No handshake");
        return;
    }
    if(strstr(line, "Handshake captured for") != NULL) {
        app->handshake_view_active = true;
        app->handshake_running = true;
        simple_app_handshake_set_note(app, "Captured");
        simple_app_handshake_buzz_once(app);
        return;
    }
    if(strstr(line, "HANDSHAKE IS COMPLETE AND VALID") != NULL ||
       strstr(line, "Complete 4-way handshake saved") != NULL) {
        app->handshake_view_active = true;
        app->handshake_running = true;
        simple_app_handshake_set_note(app, "Valid");
        simple_app_handshake_buzz_once(app);
        return;
    }

    unsigned long targets = 0;
    if(sscanf(line, "Targets: %lu network(s)", &targets) == 1) {
        app->handshake_targets = (uint32_t)targets;
        app->handshake_view_active = true;
        if(app->handshake_targets == 0) {
            simple_app_handshake_set_note(app, "No targets");
        }
        return;
    }

    unsigned long captured = 0;
    if(sscanf(line, "Handshakes captured so far: %lu", &captured) == 1) {
        app->handshake_captured = (uint32_t)captured;
        app->handshake_view_active = true;
        return;
    }

    const char* captured_ptr = strstr(line, "Handshake #");
    if(captured_ptr) {
        unsigned captured_index = 0;
        if(sscanf(captured_ptr, "Handshake #%u captured!", &captured_index) == 1) {
            app->handshake_captured = captured_index;
            app->handshake_view_active = true;
            simple_app_handshake_buzz_once(app);
            return;
        }
    }

    if(strstr(line, ">>> [") != NULL && strstr(line, "Attacking '") != NULL) {
        app->handshake_view_active = true;
        simple_app_handshake_parse_attacking(app, line);
        return;
    }
}

static void simple_app_handshake_feed(SimpleApp* app, char ch) {
    if(!app) return;
    if(ch == '\r') return;
    if(ch == '\n') {
        if(app->handshake_line_length > 0) {
            app->handshake_line_buffer[app->handshake_line_length] = '\0';
            simple_app_process_handshake_line(app, app->handshake_line_buffer);
        }
        app->handshake_line_length = 0;
        return;
    }
    if(app->handshake_line_length + 1 >= sizeof(app->handshake_line_buffer)) {
        app->handshake_line_length = 0;
        return;
    }
    app->handshake_line_buffer[app->handshake_line_length++] = ch;
}

static void simple_app_process_blackout_line(SimpleApp* app, const char* line) {
    if(!app || !line) return;

    while(*line == '>' || *line == ' ') {
        line++;
    }
    if(*line == '\0') return;

    if(strstr(line, "Blackout attack task started") != NULL ||
       strstr(line, "Starting blackout attack") != NULL) {
        app->blackout_view_active = true;
        if(app->blackout_cycle == 0) app->blackout_cycle = 1;
        simple_app_blackout_set_phase(app, BlackoutPhaseStarting, "");
        return;
    }

    if(strstr(line, "Starting blackout cycle") != NULL) {
        app->blackout_view_active = true;
        if(app->blackout_cycle == 0) {
            app->blackout_cycle = 1;
        }
        simple_app_blackout_set_phase(app, BlackoutPhaseScanning, "");
        return;
    }

    if(strstr(line, "Stopping blackout attack task") != NULL) {
        app->blackout_view_active = true;
        simple_app_blackout_set_phase(app, BlackoutPhaseStopping, "Stopping");
        return;
    }

    if(strstr(line, "Blackout attack task finished") != NULL) {
        app->blackout_view_active = true;
        simple_app_blackout_set_phase(app, BlackoutPhaseFinished, "Done");
        return;
    }

    if(!app->blackout_view_active) {
        return;
    }

    if(strstr(line, "Found") != NULL && strstr(line, "networks") != NULL &&
       strstr(line, "sorting by channel") != NULL) {
        uint32_t networks = 0;
        if(simple_app_blackout_extract_networks(line, &networks)) {
            app->blackout_networks = networks;
        }
        app->blackout_view_active = true;
        simple_app_blackout_set_phase(app, BlackoutPhaseSorting, "");
        return;
    }

    if(strstr(line, "Starting deauth attack") != NULL) {
        uint32_t networks = 0;
        if(simple_app_blackout_extract_networks(line, &networks)) {
            app->blackout_networks = networks;
        }
        app->blackout_view_active = true;
        simple_app_blackout_set_phase(app, BlackoutPhaseAttacking, "");
        return;
    }

    if(strstr(line, "3-minute attack cycle completed") != NULL) {
        app->blackout_view_active = true;
        app->blackout_cycle++;
        simple_app_blackout_set_phase(app, BlackoutPhaseScanning, "");
        return;
    }

    if(strstr(line, "Scan timeout") != NULL) {
        app->blackout_view_active = true;
        simple_app_blackout_set_phase(app, BlackoutPhaseScanning, "Scan timeout");
        return;
    }

    if(strstr(line, "No scan results available") != NULL) {
        app->blackout_view_active = true;
        simple_app_blackout_set_phase(app, BlackoutPhaseScanning, "No results");
        return;
    }

    if(strstr(line, "Failed to start scan") != NULL) {
        app->blackout_view_active = true;
        simple_app_blackout_set_phase(app, BlackoutPhaseScanning, "Scan failed");
        return;
    }

    if(strstr(line, "Stop requested") != NULL || strstr(line, "Stopping blackout attack task") != NULL) {
        app->blackout_view_active = true;
        simple_app_blackout_set_phase(app, BlackoutPhaseStopping, "Stopping");
        return;
    }

    uint8_t channel = 0;
    if(simple_app_blackout_parse_channel(line, &channel)) {
        app->blackout_channel = channel;
        app->blackout_has_channel = true;
    }
}

static void simple_app_blackout_feed(SimpleApp* app, char ch) {
    if(!app) return;
    if(ch == '\r') return;
    if(ch == '\n') {
        if(app->blackout_line_length > 0) {
            app->blackout_line_buffer[app->blackout_line_length] = '\0';
            simple_app_process_blackout_line(app, app->blackout_line_buffer);
        }
        app->blackout_line_length = 0;
        return;
    }
    if(app->blackout_line_length + 1 >= sizeof(app->blackout_line_buffer)) {
        app->blackout_line_length = 0;
        return;
    }
    app->blackout_line_buffer[app->blackout_line_length++] = ch;
}








static void simple_app_clear_station_selection(SimpleApp* app) {
    if(!app || !app->recon_stations_selected) return;
    if(!app->board_ready_seen || !app->serial || !app->serial_mutex) return;
    simple_app_send_command_quiet(app, "unselect_stations");
    app->recon_stations_selected = false;
}













static void simple_app_reset_bt_scan_summary(SimpleApp* app) {
    if(!app) return;
    app->bt_scan_airtags = 0;
    app->bt_scan_smarttags = 0;
    app->bt_scan_total = 0;
    app->bt_scan_line_length = 0;
    app->bt_scan_summary_seen = false;
    app->airtag_scan_mode = false;
    app->bt_scan_full_console = false;
    app->bt_scan_last_update_tick = 0;
    app->bt_scan_running = false;
    app->bt_scan_has_data = false;
    app->bt_scan_show_list = false;
    app->bt_scan_preview_count = 0;
    app->bt_scan_list_offset = 0;
    if(app->bt_scan_preview) {
        memset(app->bt_scan_preview, 0, sizeof(BtScanPreview) * BT_SCAN_PREVIEW_MAX);
    }
    app->bt_locator_console_mode = false;
    app->bt_locator_mode = false;
    app->bt_locator_has_rssi = false;
    app->bt_locator_rssi = 0;
    app->bt_locator_start_tick = 0;
    app->bt_locator_last_console_tick = 0;
    app->bt_locator_mac[0] = '\0';
    if(app->bt_locator_preserve_mac && app->bt_locator_saved_mac[0] != '\0') {
        strncpy(app->bt_locator_mac, app->bt_locator_saved_mac, sizeof(app->bt_locator_mac) - 1);
        app->bt_locator_mac[sizeof(app->bt_locator_mac) - 1] = '\0';
    } else {
        app->bt_locator_saved_mac[0] = '\0';
        app->bt_locator_preserve_mac = false;
    }
    app->bt_locator_list_loading = false;
    app->bt_locator_list_ready = false;
    app->bt_locator_count = 0;
    app->bt_locator_index = 0;
    app->bt_locator_offset = 0;
    app->bt_locator_selected = -1;
    app->bt_locator_scan_len = 0;
    if(app->bt_locator_scan_line) {
        memset(app->bt_locator_scan_line, 0, BT_LOCATOR_SCAN_LINE_LEN);
    }
    if(app->bt_locator_devices) {
        memset(app->bt_locator_devices, 0, sizeof(BtLocatorDevice) * BT_LOCATOR_MAX_DEVICES);
    }
}

static void simple_app_process_bt_scan_line(SimpleApp* app, const char* line) {
    if(!app || !line || !app->bt_scan_view_active) return;

    int airtags = 0;
    int smarttags = 0;
    int total = 0;
    if(app->bt_locator_mode) {
        char mac[18] = {0};
        int rssi = 0;
        if(sscanf(line, " %17s RSSI: %d", mac, &rssi) == 2) {
            app->bt_locator_rssi = rssi;
            app->bt_locator_has_rssi = true;
            app->bt_scan_last_update_tick = furi_get_tick();
        } else if(sscanf(line, " %17s RSSI: N/A", mac) == 1) {
            app->bt_locator_has_rssi = false;
            app->bt_scan_last_update_tick = furi_get_tick();
        }
        return;
    }

    if(app->airtag_scan_mode) {
        if(sscanf(line, " %d , %d", &airtags, &smarttags) == 2 ||
           sscanf(line, " %d,%d", &airtags, &smarttags) == 2) {
            app->bt_scan_airtags = airtags;
            app->bt_scan_smarttags = smarttags;
            app->bt_scan_total = airtags + smarttags;
            app->bt_scan_last_update_tick = furi_get_tick();
            app->bt_scan_has_data = true;
            app->bt_scan_running = true;
        }
        return;
    }

    if(sscanf(
           line, "Summary: %d AirTags, %d SmartTags, %d total devices", &airtags, &smarttags, &total) == 3) {
        app->bt_scan_airtags = airtags;
        app->bt_scan_smarttags = smarttags;
        app->bt_scan_total = total;
        app->bt_scan_summary_seen = true;
        app->bt_scan_last_update_tick = furi_get_tick();
        app->bt_scan_has_data = true;
        app->bt_scan_running = false;
        return;
    }

    if(sscanf(line, "Found %d devices", &total) == 1) {
        app->bt_scan_total = total;
        app->bt_scan_last_update_tick = furi_get_tick();
        app->bt_scan_has_data = true;
        app->bt_scan_running = true;
    }

    // Parse individual device lines for preview: "<num>. <MAC>  RSSI: <rssi> dBm [Name: ...]"
    int idx = 0;
    char mac[18] = {0};
    int rssi = 0;
    if(sscanf(line, " %d . %17s RSSI: %d", &idx, mac, &rssi) == 3 ||
       sscanf(line, " %d. %17s RSSI: %d", &idx, mac, &rssi) == 3) {
        const char* name_ptr = strstr(line, "Name:");
        char name_buf[32] = {0};
        if(name_ptr) {
            name_ptr += strlen("Name:");
            while(*name_ptr == ' ') name_ptr++;
            strncpy(name_buf, name_ptr, sizeof(name_buf) - 1);
            name_buf[sizeof(name_buf) - 1] = '\0';
        }
        simple_app_bt_scan_preview_insert(app, mac, rssi, name_buf);
    }

    if(app->bt_locator_mode) {
        const char* name_ptr = strstr(line, "Name:");
        if(name_ptr) {
            name_ptr += strlen("Name:");
            while(*name_ptr == ' ') name_ptr++;
            char name_buf[32] = {0};
            strncpy(name_buf, name_ptr, sizeof(name_buf) - 1);
            name_buf[sizeof(name_buf) - 1] = '\0';
            size_t nb_len = strlen(name_buf);
            while(nb_len > 0 && isspace((unsigned char)name_buf[nb_len - 1])) {
                name_buf[nb_len - 1] = '\0';
                nb_len--;
            }
            if(name_buf[0] != '\0') {
                strncpy(app->bt_locator_current_name, name_buf, sizeof(app->bt_locator_current_name) - 1);
                app->bt_locator_current_name[sizeof(app->bt_locator_current_name) - 1] = '\0';
            }
        }
    }
}

static void simple_app_bt_scan_feed(SimpleApp* app, char ch) {
    if(!app || !app->bt_scan_line_buffer) return;
    if(!app->bt_scan_view_active) {
        app->bt_scan_line_length = 0;
        return;
    }
    if(app->bt_locator_mode) {
        app->bt_locator_last_console_tick = furi_get_tick();
    }
    if(ch == '\r') return;
    if(ch == '\n') {
        if(app->bt_scan_line_length > 0) {
            app->bt_scan_line_buffer[app->bt_scan_line_length] = '\0';
            simple_app_process_bt_scan_line(app, app->bt_scan_line_buffer);
        }
        app->bt_scan_line_length = 0;
        return;
    }
    if(app->bt_scan_line_length + 1 >= BT_SCAN_LINE_BUFFER_LEN) {
        app->bt_scan_line_length = 0;
        return;
    }
    app->bt_scan_line_buffer[app->bt_scan_line_length++] = ch;
}

static void simple_app_reset_deauth_guard(SimpleApp* app) {
    if(!app) return;
    bool was_blinking = app->deauth_guard_blink_until > 0;
    app->deauth_guard_view_active = false;
    app->deauth_guard_full_console = false;
    app->deauth_guard_has_detection = false;
    app->deauth_guard_has_rssi = false;
    app->deauth_guard_last_channel = -1;
    app->deauth_guard_last_rssi = 0;
    app->deauth_guard_started_tick = 0;
    app->deauth_guard_last_detection_tick = 0;
    app->deauth_guard_monitoring = false;
    app->deauth_guard_blink_until = 0;
    app->deauth_guard_last_blink_tick = 0;
    app->deauth_guard_blink_state = false;
    app->deauth_guard_blink_count = 0;
    if(app->deauth_guard_vibro_on) {
        furi_hal_vibro_on(false);
    }
    app->deauth_guard_vibro_on = false;
    app->deauth_guard_detection_count = 0;
    app->deauth_guard_line_length = 0;
    memset(app->deauth_guard_last_ssid, 0, sizeof(app->deauth_guard_last_ssid));
    memset(app->deauth_guard_line_buffer, 0, sizeof(app->deauth_guard_line_buffer));
    if(was_blinking) {
        simple_app_apply_backlight(app);
    }
}

static void simple_app_start_deauth_guard(SimpleApp* app) {
    if(!app) return;
    simple_app_reset_deauth_guard(app);
    app->deauth_guard_view_active = true;
    app->deauth_guard_started_tick = furi_get_tick();
    app->deauth_guard_last_detection_tick = app->deauth_guard_started_tick;
}

static void simple_app_process_deauth_guard_line(SimpleApp* app, const char* line) {
    if(!app || !line || !app->deauth_guard_view_active) return;
    // Ignore startup and prompt noise
    if(strncmp(line, "[MEM]", 5) == 0) return;
    if(strncmp(line, "Deauth Detector started", 24) == 0) return;
    if(strncmp(line, "Output: [DEAUTH]", 16) == 0) return;
    if(strncmp(line, "Use 'stop' to stop.", 19) == 0) return;
    if(strncmp(line, "->", 2) == 0) return;

    if(strstr(line, "[DEAUTH]") == NULL) return;
    if(strstr(line, "RSSI:") == NULL || strstr(line, "CH:") == NULL) return;

    int channel = -1;
    int rssi = 0;
    bool has_rssi = false;

    const char* ch_ptr = strstr(line, "CH:");
    if(ch_ptr) {
        channel = atoi(ch_ptr + 3);
    }

    const char* rssi_ptr = strstr(line, "RSSI:");
    if(rssi_ptr) {
        rssi = atoi(rssi_ptr + 5);
        has_rssi = true;
    }

    char ssid[SCAN_SSID_MAX_LEN];
    ssid[0] = '\0';
    const char* ap_ptr = strstr(line, "AP:");
    if(ap_ptr) {
        ap_ptr += 3;
        while(*ap_ptr == ' ' || *ap_ptr == '|') {
            ap_ptr++;
        }
        const char* end = ap_ptr;
        while(*end && *end != '(' && *end != '|' && *end != '\r' && *end != '\n') {
            end++;
        }
        size_t len = (size_t)(end - ap_ptr);
        while(len > 0 && isspace((unsigned char)ap_ptr[len - 1])) {
            len--;
        }
        if(len >= sizeof(ssid)) {
            len = sizeof(ssid) - 1;
        }
        memcpy(ssid, ap_ptr, len);
        ssid[len] = '\0';
    }
    if(ssid[0] == '\0') {
        snprintf(ssid, sizeof(ssid), "Unknown");
    }

    strncpy(app->deauth_guard_last_ssid, ssid, sizeof(app->deauth_guard_last_ssid) - 1);
    app->deauth_guard_last_ssid[sizeof(app->deauth_guard_last_ssid) - 1] = '\0';
    app->deauth_guard_last_channel = channel;
    app->deauth_guard_has_rssi = has_rssi;
    app->deauth_guard_last_rssi = rssi;
    app->deauth_guard_has_detection = true;
    app->deauth_guard_detection_count++;

    uint32_t now = furi_get_tick();
    app->deauth_guard_last_detection_tick = now;
    app->deauth_guard_blink_count = 0;
    app->deauth_guard_blink_until =
        now + furi_ms_to_ticks(DEAUTH_GUARD_BLINK_MS * DEAUTH_GUARD_BLINK_TOGGLES);
    app->deauth_guard_last_blink_tick = now;
    app->deauth_guard_blink_state = true;

    if(!app->deauth_guard_vibro_on) {
        app->deauth_guard_vibro_on = true;
        app->deauth_guard_vibro_until = now + furi_ms_to_ticks(DEAUTH_GUARD_VIBRO_MS);
        furi_hal_vibro_on(true);
    } else {
        app->deauth_guard_vibro_until = now + furi_ms_to_ticks(DEAUTH_GUARD_VIBRO_MS);
    }

    if(app->viewport) {
        view_port_update(app->viewport);
    }
}

static void simple_app_deauth_guard_feed(SimpleApp* app, char ch) {
    if(!app) return;
    if(!app->deauth_guard_view_active) {
        app->deauth_guard_line_length = 0;
        return;
    }
    if(ch == '\r') return;
    if(ch == '\n') {
        if(app->deauth_guard_line_length > 0) {
            app->deauth_guard_line_buffer[app->deauth_guard_line_length] = '\0';
            simple_app_process_deauth_guard_line(app, app->deauth_guard_line_buffer);
        }
        app->deauth_guard_line_length = 0;
        return;
    }
    if(app->deauth_guard_line_length + 1 >= sizeof(app->deauth_guard_line_buffer)) {
        app->deauth_guard_line_length = 0;
        return;
    }
    app->deauth_guard_line_buffer[app->deauth_guard_line_length++] = ch;
}

static void simple_app_update_deauth_guard(SimpleApp* app) {
    if(!app) return;
    if(!app->deauth_guard_view_active) {
        if(app->deauth_guard_blink_until > 0) {
            app->deauth_guard_blink_until = 0;
            app->deauth_guard_blink_state = false;
            simple_app_apply_backlight(app);
        }
        return;
    }

    if(!app->backlight_enabled || app->backlight_notification_enforced) {
        // Still allow LED/vibro even if backlight is enforced off/on.
        app->deauth_guard_blink_state = true;
    }

    uint32_t now = furi_get_tick();
    if(app->deauth_guard_blink_until == 0) {
        // Track idle monitoring state once per loop.
        if(!app->deauth_guard_has_detection) {
            uint32_t since_start = now - app->deauth_guard_started_tick;
            app->deauth_guard_monitoring =
                (since_start >= furi_ms_to_ticks(DEAUTH_GUARD_IDLE_MONITOR_MS));
        } else {
            app->deauth_guard_monitoring = false;
        }
        return;
    }
    if(now >= app->deauth_guard_blink_until) {
        app->deauth_guard_blink_until = 0;
        app->deauth_guard_blink_state = false;
        simple_app_apply_backlight(app);
        if(app->deauth_guard_vibro_on) {
            furi_hal_vibro_on(false);
            app->deauth_guard_vibro_on = false;
            app->deauth_guard_vibro_until = 0;
        }
        return;
    }

    uint32_t interval = furi_ms_to_ticks(DEAUTH_GUARD_BLINK_MS);
    if(interval == 0) interval = 1;
    if(now - app->deauth_guard_last_blink_tick >= interval) {
        app->deauth_guard_last_blink_tick = now;
        app->deauth_guard_blink_state = !app->deauth_guard_blink_state;
        if(app->deauth_guard_blink_count < DEAUTH_GUARD_BLINK_TOGGLES) {
            app->deauth_guard_blink_count++;
        }
        uint8_t level =
            app->deauth_guard_blink_state ? BACKLIGHT_ON_LEVEL : BACKLIGHT_OFF_LEVEL;
        furi_hal_light_set(LightBacklight, level);
    }

    if(app->deauth_guard_vibro_on && now >= app->deauth_guard_vibro_until) {
        furi_hal_vibro_on(false);
        app->deauth_guard_vibro_on = false;
        app->deauth_guard_vibro_until = 0;
    }

    // Update idle monitoring flag after blink handling to avoid extra reads.
    if(!app->deauth_guard_has_detection) {
        uint32_t since_start = now - app->deauth_guard_started_tick;
        app->deauth_guard_monitoring =
            (since_start >= furi_ms_to_ticks(DEAUTH_GUARD_IDLE_MONITOR_MS));
    } else {
        app->deauth_guard_monitoring = false;
    }
}

static void simple_app_bt_locator_reset_list(SimpleApp* app) {
    if(!app) return;
    app->bt_locator_list_loading = false;
    app->bt_locator_list_ready = false;
    app->bt_locator_console_mode = false;
    app->bt_locator_count = 0;
    app->bt_locator_index = 0;
    app->bt_locator_offset = 0;
    app->bt_locator_selected = -1;
    app->bt_locator_current_name[0] = '\0';
    if(app->bt_locator_scroll_text) {
        app->bt_locator_scroll_text[0] = '\0';
    }
    app->bt_locator_scroll_offset = 0;
    app->bt_locator_scroll_dir = 1;
    app->bt_locator_scroll_hold = RESULT_SCROLL_EDGE_PAUSE_STEPS;
    app->bt_locator_scroll_last_tick = furi_get_tick();
    app->bt_locator_start_tick = 0;
    app->bt_locator_last_console_tick = 0;
    app->bt_locator_scan_len = 0;
    if(app->bt_locator_scan_line) {
        memset(app->bt_locator_scan_line, 0, BT_LOCATOR_SCAN_LINE_LEN);
    }
    if(app->bt_locator_devices) {
        memset(app->bt_locator_devices, 0, sizeof(BtLocatorDevice) * BT_LOCATOR_MAX_DEVICES);
    }
    app->bt_locator_saved_mac[0] = '\0';
    app->bt_locator_preserve_mac = false;
}

static void simple_app_bt_locator_add(SimpleApp* app, const char* mac, int rssi, const char* name) {
    if(!app || !mac || mac[0] == '\0' || !app->bt_locator_devices) return;
    // Update if exists
    for(size_t i = 0; i < app->bt_locator_count; i++) {
        if(strncmp(app->bt_locator_devices[i].mac, mac, sizeof(app->bt_locator_devices[i].mac)) == 0) {
            app->bt_locator_devices[i].rssi = rssi;
            app->bt_locator_devices[i].has_rssi = true;
            if(name && name[0] != '\0') {
                strncpy(app->bt_locator_devices[i].name, name, sizeof(app->bt_locator_devices[i].name) - 1);
                app->bt_locator_devices[i].name[sizeof(app->bt_locator_devices[i].name) - 1] = '\0';
            }
            return;
        }
    }
    if(app->bt_locator_count >= BT_LOCATOR_MAX_DEVICES) return;
    strncpy(app->bt_locator_devices[app->bt_locator_count].mac, mac, sizeof(app->bt_locator_devices[app->bt_locator_count].mac));
    app->bt_locator_devices[app->bt_locator_count].mac[sizeof(app->bt_locator_devices[app->bt_locator_count].mac) - 1] = '\0';
    app->bt_locator_devices[app->bt_locator_count].rssi = rssi;
    app->bt_locator_devices[app->bt_locator_count].has_rssi = true;
    if(name && name[0] != '\0') {
        strncpy(app->bt_locator_devices[app->bt_locator_count].name, name, sizeof(app->bt_locator_devices[app->bt_locator_count].name) - 1);
        app->bt_locator_devices[app->bt_locator_count].name[sizeof(app->bt_locator_devices[app->bt_locator_count].name) - 1] = '\0';
    }
    app->bt_locator_count++;

    // Keep list sorted by RSSI desc (strongest first)
    for(size_t pos = app->bt_locator_count; pos > 1; pos--) {
        size_t i = pos - 1;
        size_t prev = i - 1;
        bool swap = false;
        if(app->bt_locator_devices[i].has_rssi && app->bt_locator_devices[prev].has_rssi) {
            swap = app->bt_locator_devices[i].rssi > app->bt_locator_devices[prev].rssi;
        } else if(app->bt_locator_devices[i].has_rssi && !app->bt_locator_devices[prev].has_rssi) {
            swap = true;
        }
        if(swap) {
            struct {
                char mac[18];
                int rssi;
                bool has_rssi;
                char name[BT_LOCATOR_NAME_MAX_LEN];
            } tmp = {0};
            memcpy(tmp.mac, app->bt_locator_devices[i].mac, sizeof(tmp.mac));
            tmp.rssi = app->bt_locator_devices[i].rssi;
            tmp.has_rssi = app->bt_locator_devices[i].has_rssi;
            memcpy(tmp.name, app->bt_locator_devices[i].name, sizeof(tmp.name));

            memcpy(app->bt_locator_devices[i].mac, app->bt_locator_devices[prev].mac, sizeof(tmp.mac));
            app->bt_locator_devices[i].rssi = app->bt_locator_devices[prev].rssi;
            app->bt_locator_devices[i].has_rssi = app->bt_locator_devices[prev].has_rssi;
            memcpy(app->bt_locator_devices[i].name, app->bt_locator_devices[prev].name, sizeof(tmp.name));

            memcpy(app->bt_locator_devices[prev].mac, tmp.mac, sizeof(tmp.mac));
            app->bt_locator_devices[prev].rssi = tmp.rssi;
            app->bt_locator_devices[prev].has_rssi = tmp.has_rssi;
            memcpy(app->bt_locator_devices[prev].name, tmp.name, sizeof(tmp.name));
        } else {
            break;
        }
    }
    // Restore selection mac if it matches newly inserted entry
    if(app->bt_locator_preserve_mac && app->bt_locator_mac[0] == '\0' && app->bt_locator_saved_mac[0] != '\0') {
        strncpy(app->bt_locator_mac, app->bt_locator_saved_mac, sizeof(app->bt_locator_mac) - 1);
        app->bt_locator_mac[sizeof(app->bt_locator_mac) - 1] = '\0';
    }
}

static void simple_app_bt_locator_finish(SimpleApp* app) {
    if(!app) return;
    app->bt_locator_list_loading = false;
    app->bt_locator_list_ready = true;
    app->bt_locator_console_mode = true;
    if(app->bt_locator_count == 0) {
        app->bt_locator_index = 0;
        app->bt_locator_offset = 0;
    } else if(app->bt_locator_index >= app->bt_locator_count) {
        app->bt_locator_index = app->bt_locator_count - 1;
    }
    simple_app_bt_locator_ensure_visible(app);
    if(app->viewport && app->screen == ScreenBtLocatorList) {
        view_port_update(app->viewport);
    }
}

static void simple_app_bt_locator_reset_scroll(SimpleApp* app) {
    if(!app || !app->bt_locator_scroll_text) return;
    app->bt_locator_scroll_text[0] = '\0';
    app->bt_locator_scroll_offset = 0;
    app->bt_locator_scroll_dir = 1;
    app->bt_locator_scroll_hold = RESULT_SCROLL_EDGE_PAUSE_STEPS;
    app->bt_locator_scroll_last_tick = furi_get_tick();
}

static void simple_app_bt_locator_set_scroll_text(SimpleApp* app, const char* text) {
    if(!app || !app->bt_locator_scroll_text || !text) return;
    strncpy(app->bt_locator_scroll_text, text, BT_LOCATOR_SCROLL_TEXT_LEN - 1);
    app->bt_locator_scroll_text[BT_LOCATOR_SCROLL_TEXT_LEN - 1] = '\0';
    app->bt_locator_scroll_offset = 0;
    app->bt_locator_scroll_dir = 1;
    app->bt_locator_scroll_hold = RESULT_SCROLL_EDGE_PAUSE_STEPS;
    app->bt_locator_scroll_last_tick = furi_get_tick();
}

static void simple_app_bt_locator_tick_scroll(SimpleApp* app, size_t char_limit) {
    if(!app || !app->bt_locator_scroll_text) return;
    size_t len = strlen(app->bt_locator_scroll_text);
    if(len <= char_limit || char_limit == 0) {
        app->bt_locator_scroll_offset = 0;
        return;
    }

    uint32_t interval_ticks = furi_ms_to_ticks(RESULT_SCROLL_INTERVAL_MS);
    if(interval_ticks == 0) interval_ticks = 1;
    uint32_t now = furi_get_tick();
    if((now - app->bt_locator_scroll_last_tick) < interval_ticks) {
        return;
    }
    app->bt_locator_scroll_last_tick = now;

    if(app->bt_locator_scroll_hold > 0) {
        app->bt_locator_scroll_hold--;
        return;
    }

    size_t max_offset = len - char_limit;
    bool changed = false;
    if(app->bt_locator_scroll_dir > 0) {
        if(app->bt_locator_scroll_offset < max_offset) {
            app->bt_locator_scroll_offset++;
            changed = true;
            if(app->bt_locator_scroll_offset >= max_offset) {
                app->bt_locator_scroll_dir = -1;
                app->bt_locator_scroll_hold = RESULT_SCROLL_EDGE_PAUSE_STEPS;
            }
        } else {
            app->bt_locator_scroll_dir = -1;
            app->bt_locator_scroll_hold = RESULT_SCROLL_EDGE_PAUSE_STEPS;
        }
    } else {
        if(app->bt_locator_scroll_offset > 0) {
            app->bt_locator_scroll_offset--;
            changed = true;
            if(app->bt_locator_scroll_offset == 0) {
                app->bt_locator_scroll_dir = 1;
                app->bt_locator_scroll_hold = RESULT_SCROLL_EDGE_PAUSE_STEPS;
            }
        } else {
            app->bt_locator_scroll_dir = 1;
            app->bt_locator_scroll_hold = RESULT_SCROLL_EDGE_PAUSE_STEPS;
        }
    }

    if(changed && app->viewport && app->screen == ScreenBtLocatorList) {
        view_port_update(app->viewport);
    }
}

static void simple_app_bt_locator_feed(SimpleApp* app, char ch) {
    if(!app || !app->bt_locator_list_loading || !app->bt_locator_scan_line) return;
    if(ch == '\r') return;
    if(ch == '\n') {
        if(app->bt_locator_scan_len > 0) {
            app->bt_locator_scan_line[app->bt_locator_scan_len] = '\0';
            const char* line = app->bt_locator_scan_line;
            if(strstr(line, "Summary:") != NULL) {
                simple_app_bt_locator_finish(app);
            } else {
                int idx = 0;
                char mac[18] = {0};
                int rssi = 0;
                if(sscanf(line, " %d . %17s  RSSI: %d", &idx, mac, &rssi) == 3 ||
                   sscanf(line, " %d. %17s  RSSI: %d", &idx, mac, &rssi) == 3) {
                    const char* name_ptr = strstr(line, "Name:");
                    char name_buf[32] = {0};
                    if(name_ptr) {
                        name_ptr += strlen("Name:");
                        while(*name_ptr == ' ') name_ptr++;
                        strncpy(name_buf, name_ptr, sizeof(name_buf) - 1);
                        // trim trailing spaces
                        size_t nb_len = strlen(name_buf);
                        while(nb_len > 0 && isspace((unsigned char)name_buf[nb_len - 1])) {
                            name_buf[nb_len - 1] = '\0';
                            nb_len--;
                        }
                    }
                    simple_app_bt_locator_add(app, mac, rssi, name_buf[0] ? name_buf : NULL);
                    if(app->viewport && app->screen == ScreenBtLocatorList) {
                        view_port_update(app->viewport);
                    }
                }
            }
        }
        app->bt_locator_scan_len = 0;
        return;
    }
    if(app->bt_locator_scan_len + 1 >= BT_LOCATOR_SCAN_LINE_LEN) {
        app->bt_locator_scan_len = 0;
        return;
    }
    app->bt_locator_scan_line[app->bt_locator_scan_len++] = ch;
}

static void simple_app_bt_locator_begin_scan(SimpleApp* app) {
    if(!app) return;
    if(!simple_app_alloc_bt_buffers(app)) {
        simple_app_show_status_message(app, "OOM: BT buffers", 1500, true);
        return;
    }
    simple_app_reset_bt_scan_summary(app);
    simple_app_bt_locator_reset_list(app);
    app->bt_locator_current_name[0] = '\0';
    app->bt_locator_console_mode = true;
    app->bt_locator_list_loading = true;
    app->bt_locator_list_ready = false;
    app->bt_locator_mode = false;
    simple_app_bt_locator_reset_scroll(app);
    app->screen = ScreenSerial;
    if(app->viewport) {
        view_port_update(app->viewport);
    }
    simple_app_send_command(app, "scan_bt", false);
    // send_command resets scan state; reassert locator flags so UI stays in "scanning" console mode
    app->bt_locator_console_mode = true;
    app->bt_locator_list_loading = true;
    app->bt_locator_list_ready = false;
    app->bt_locator_mode = false;
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
    if(app->otg_power_enabled && !currently_enabled) {
        furi_hal_power_enable_otg();
    } else if(!app->otg_power_enabled && currently_enabled) {
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

static void simple_app_send_download(SimpleApp* app) {
    if(!app) return;
    simple_app_send_command_quiet(app, "download");
    simple_app_show_status_message(app, "Download sent", 2000, true);
}

static bool simple_app_usb_profile_ok(void) {
    const FuriHalUsbInterface* current = furi_hal_usb_get_config();
    if(!current) return true;
    return current == &usb_cdc_single;
}

static bool simple_app_sd_ok(void) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    if(!storage) return true;
    bool ok = (storage_sd_status(storage) == FSE_OK);
    furi_record_close(RECORD_STORAGE);
    return ok;
}

static void simple_app_show_sd_busy(void) {
    DialogsApp* dialogs = furi_record_open(RECORD_DIALOGS);
    if(dialogs) {
        DialogMessage* msg = dialog_message_alloc();
        if(msg) {
            dialog_message_set_header(msg, "SD busy", 64, 8, AlignCenter, AlignTop);
            dialog_message_set_text(
                msg,
                "Close qFlipper/FileMgr\nor disable USB storage,\nthen relaunch.",
                64,
                32,
                AlignCenter,
                AlignCenter);
            dialog_message_show(dialogs, msg);
            dialog_message_free(msg);
        }
        furi_record_close(RECORD_DIALOGS);
    }
}

static void simple_app_ensure_flipper_sd_dirs(Storage* storage) {
    if(!storage) return;
    storage_simply_mkdir(storage, EXT_PATH("apps_assets"));
    storage_simply_mkdir(storage, FLIPPER_SD_BASE_PATH);
}

static bool simple_app_append_log_line(const char* path, const char* line) {
    if(!path || !line) return false;
    Storage* storage = furi_record_open(RECORD_STORAGE);
    if(!storage) return false;
    simple_app_ensure_flipper_sd_dirs(storage);

    File* file = storage_file_alloc(storage);
    if(!file) {
        furi_record_close(RECORD_STORAGE);
        return false;
    }
    bool ok = false;
    if(storage_file_open(file, path, FSAM_WRITE, FSOM_OPEN_APPEND) ||
       storage_file_open(file, path, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        size_t len = strlen(line);
        if(len > 0) {
            ok = (storage_file_write(file, line, len) == len);
        }
        if(ok && len > 0 && line[len - 1] != '\n') {
            const char nl = '\n';
            ok = (storage_file_write(file, &nl, 1) == 1);
        }
        storage_file_close(file);
    }
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
    return ok;
}

static void simple_app_debug_mark(SimpleApp* app, const char* tag) {
    if(!app || !app->debug_mark_enabled) return;
    if(!tag || tag[0] == '\0') return;
    if(!simple_app_sd_ok()) return;
    Storage* storage = furi_record_open(RECORD_STORAGE);
    if(!storage) return;
    simple_app_ensure_flipper_sd_dirs(storage);

    File* file = storage_file_alloc(storage);
    if(file) {
        char line[96];
        unsigned long tick = (unsigned long)furi_get_tick();
        int len = snprintf(line, sizeof(line), "%lu %s\n", tick, tag);
        if(len < 0) len = 0;
        if((size_t)len > sizeof(line)) len = (int)sizeof(line);
        if(storage_file_open(file, FLIPPER_SD_DEBUG_PATH, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
            if(len > 0) {
                storage_file_write(file, line, (size_t)len);
            }
            storage_file_close(file);
        }
        storage_file_free(file);
    }
    furi_record_close(RECORD_STORAGE);
}

static void simple_app_log_memory(SimpleApp* app, const char* stage) {
    if(!app || !stage) return;
    unsigned long free_bytes = (unsigned long)memmgr_get_free_heap();
    unsigned long min_bytes = (unsigned long)memmgr_get_minimum_free_heap();
    unsigned long block_bytes = (unsigned long)memmgr_heap_get_max_free_block();
    unsigned long caller_stack =
        (unsigned long)furi_thread_get_stack_space(furi_thread_get_current_id());
    unsigned long dropped = (unsigned long)app->rx_dropped_bytes;
    FURI_LOG_I(
        TAG,
        "MEM %s free:%lu min:%lu block:%lu caller_stack:%lu rx_drop:%lu",
        stage,
        free_bytes,
        min_bytes,
        block_bytes,
        caller_stack,
        dropped);
    if(app->debug_mark_enabled && app->debug_log_initialized) {
        char line[112];
        snprintf(
            line,
            sizeof(line),
            "MEM %s R:%lu M:%lu B:%lu St:%lu D:%lu",
            stage,
            free_bytes,
            min_bytes,
            block_bytes,
            caller_stack,
            dropped);
        simple_app_append_log_line(FLIPPER_SD_DEBUG_LOG_PATH, line);
        simple_app_debug_mark(app, line);
    }
}

static void simple_app_log_cli_command(SimpleApp* app, const char* source, const char* command) {
    if(!app || !app->debug_mark_enabled || !command || command[0] == '\0') return;
    if(!simple_app_sd_ok()) return;

    if(!app->debug_log_initialized) {
        simple_app_reset_debug_log(app);
        app->debug_log_initialized = true;
    }

    char cmd[96];
    size_t out = 0;
    for(size_t i = 0; command[i] != '\0' && out < sizeof(cmd) - 1; i++) {
        char c = command[i];
        if(c == '\n' || c == '\r') {
            c = ';';
        } else if(c == '\t') {
            c = ' ';
        }
        cmd[out++] = c;
    }
    cmd[out] = '\0';
    if(cmd[0] == '\0') return;

    size_t free_kb = (size_t)(memmgr_get_free_heap() / 1024);
    size_t min_kb = (size_t)(memmgr_get_minimum_free_heap() / 1024);
    size_t start_kb = (size_t)(app->heap_start_free / 1024);
    char line[160];
    unsigned long tick = (unsigned long)furi_get_tick();
    snprintf(
        line,
        sizeof(line),
        "%lu %s %s R:%luK M:%luK S:%luK",
        tick,
        source ? source : "SRC",
        cmd,
        (unsigned long)free_kb,
        (unsigned long)min_kb,
        (unsigned long)start_kb);
    simple_app_append_log_line(FLIPPER_SD_DEBUG_LOG_PATH, line);
    simple_app_debug_mark(app, line);
}

static void simple_app_reset_debug_log(SimpleApp* app) {
    if(!app || !app->debug_mark_enabled) return;
    if(!simple_app_sd_ok()) return;
    Storage* storage = furi_record_open(RECORD_STORAGE);
    if(!storage) return;
    simple_app_ensure_flipper_sd_dirs(storage);

    File* file = storage_file_alloc(storage);
    if(file) {
        if(storage_file_open(file, FLIPPER_SD_DEBUG_LOG_PATH, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
            storage_file_close(file);
        }
        if(storage_file_open(file, FLIPPER_SD_DEBUG_PATH, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
            storage_file_close(file);
        }
        storage_file_free(file);
    }
    furi_record_close(RECORD_STORAGE);

    {
        char header[128];
        size_t free_kb = (size_t)(memmgr_get_free_heap() / 1024);
        size_t min_kb = (size_t)(memmgr_get_minimum_free_heap() / 1024);
        size_t start_kb = (size_t)(app->heap_start_free / 1024);
        unsigned long tick = (unsigned long)furi_get_tick();
        snprintf(
            header,
            sizeof(header),
            "%lu START R:%luK M:%luK S:%luK",
            tick,
            (unsigned long)free_kb,
            (unsigned long)min_kb,
            (unsigned long)start_kb);
        simple_app_append_log_line(FLIPPER_SD_DEBUG_LOG_PATH, header);
        simple_app_debug_mark(app, header);
    }

    {
        char allocs[160];
        snprintf(
            allocs,
            sizeof(allocs),
            "ALLOC app=%lu rx=%u vp=1 gui=1 notif=1 mutex=1",
            (unsigned long)sizeof(SimpleApp),
            (unsigned)UART_STREAM_SIZE);
        simple_app_append_log_line(FLIPPER_SD_DEBUG_LOG_PATH, allocs);
        simple_app_debug_mark(app, allocs);
    }
}



static bool simple_app_alloc_package_monitor_buffers(SimpleApp* app) {
    if(!app) return false;
    if(app->package_monitor_history) return true;
    app->package_monitor_history = calloc(PACKAGE_MONITOR_MAX_HISTORY, sizeof(uint16_t));
    return app->package_monitor_history != NULL;
}

static void simple_app_free_package_monitor_buffers(SimpleApp* app) {
    if(!app) return;
    if(app->package_monitor_history) {
        free(app->package_monitor_history);
        app->package_monitor_history = NULL;
    }
}

static bool simple_app_alloc_channel_view_buffers(SimpleApp* app) {
    if(!app) return false;
    if(app->channel_view_counts_24 && app->channel_view_counts_5 &&
       app->channel_view_working_counts_24 && app->channel_view_working_counts_5) {
        return true;
    }

    app->channel_view_counts_24 = calloc(CHANNEL_VIEW_24GHZ_CHANNEL_COUNT, sizeof(uint16_t));
    app->channel_view_counts_5 = calloc(CHANNEL_VIEW_5GHZ_CHANNEL_COUNT, sizeof(uint16_t));
    app->channel_view_working_counts_24 =
        calloc(CHANNEL_VIEW_24GHZ_CHANNEL_COUNT, sizeof(uint16_t));
    app->channel_view_working_counts_5 =
        calloc(CHANNEL_VIEW_5GHZ_CHANNEL_COUNT, sizeof(uint16_t));

    if(!app->channel_view_counts_24 || !app->channel_view_counts_5 ||
       !app->channel_view_working_counts_24 || !app->channel_view_working_counts_5) {
        if(app->channel_view_counts_24) {
            free(app->channel_view_counts_24);
            app->channel_view_counts_24 = NULL;
        }
        if(app->channel_view_counts_5) {
            free(app->channel_view_counts_5);
            app->channel_view_counts_5 = NULL;
        }
        if(app->channel_view_working_counts_24) {
            free(app->channel_view_working_counts_24);
            app->channel_view_working_counts_24 = NULL;
        }
        if(app->channel_view_working_counts_5) {
            free(app->channel_view_working_counts_5);
            app->channel_view_working_counts_5 = NULL;
        }
        return false;
    }
    return true;
}

static void simple_app_free_channel_view_buffers(SimpleApp* app) {
    if(!app) return;
    if(app->channel_view_counts_24) {
        free(app->channel_view_counts_24);
        app->channel_view_counts_24 = NULL;
    }
    if(app->channel_view_counts_5) {
        free(app->channel_view_counts_5);
        app->channel_view_counts_5 = NULL;
    }
    if(app->channel_view_working_counts_24) {
        free(app->channel_view_working_counts_24);
        app->channel_view_working_counts_24 = NULL;
    }
    if(app->channel_view_working_counts_5) {
        free(app->channel_view_working_counts_5);
        app->channel_view_working_counts_5 = NULL;
    }
}


static bool simple_app_sd_alloc_files(SimpleApp* app) {
    if(!app) return false;
    if(app->sd_files) return true;
    app->sd_files = calloc(SD_MANAGER_MAX_FILES, sizeof(SdFileEntry));
    return app->sd_files != NULL;
}

static void simple_app_sd_free_files(SimpleApp* app) {
    if(!app) return;
    if(app->sd_files) {
        free(app->sd_files);
        app->sd_files = NULL;
    }
}


static void simple_app_show_low_memory(size_t free_heap, size_t needed) {
    DialogsApp* dialogs = furi_record_open(RECORD_DIALOGS);
    if(dialogs) {
        DialogMessage* msg = dialog_message_alloc();
        if(msg) {
            dialog_message_set_header(msg, "Low memory", 64, 2, AlignCenter, AlignTop);
            char text[96];
            snprintf(
                text,
                sizeof(text),
                "Free: %lu B\nNeed: %lu B\nClose qFlipper/USB\nand relaunch.",
                (unsigned long)free_heap,
                (unsigned long)needed);
            dialog_message_set_text(msg, text, 64, 32, AlignCenter, AlignCenter);
            dialog_message_show(dialogs, msg);
            dialog_message_free(msg);
        }
        furi_record_close(RECORD_DIALOGS);
    }
}

static void simple_app_show_usb_blocker(void) {
    DialogsApp* dialogs = furi_record_open(RECORD_DIALOGS);
    if(dialogs) {
        DialogMessage* msg = dialog_message_alloc();
        if(msg) {
            dialog_message_set_header(msg, "USB busy", 64, 8, AlignCenter, AlignTop);
            dialog_message_set_text(
                msg,
                "Switch USB to CDC/Serial\nthen relaunch.",
                64,
                32,
                AlignCenter,
                AlignCenter);
            dialog_message_show(dialogs, msg);
            dialog_message_free(msg);
        }
        furi_record_close(RECORD_DIALOGS);
    }
}

static void simple_app_usb_runtime_guard(SimpleApp* app) {
    if(!app) return;
    uint32_t now = furi_get_tick();
    if(app->usb_guard_last_tick != 0) {
        uint32_t interval = furi_ms_to_ticks(USB_RUNTIME_GUARD_INTERVAL_MS);
        if(interval == 0) interval = 1;
        if((now - app->usb_guard_last_tick) < interval) {
            return;
        }
    }
    app->usb_guard_last_tick = now;

    if(!simple_app_usb_profile_ok()) {
        simple_app_show_usb_blocker();
        app->exit_app = true;
        return;
    }

    if(!simple_app_sd_ok()) {
        simple_app_show_sd_busy();
        app->exit_app = true;
        return;
    }
}




static void simple_app_show_status_message(
    SimpleApp* app,
    const char* message,
    uint32_t duration_ms,
    bool fullscreen) {
    if(!app) return;
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

static bool __attribute__((unused)) simple_app_wait_for_sd(Storage* storage, uint32_t timeout_ms) {
    if(!storage) return false;
    uint32_t start = furi_get_tick();
    while(true) {
        if(storage_sd_status(storage) == FSE_OK) {
            return true;
        }
        if(timeout_ms > 0) {
            uint32_t elapsed = furi_get_tick() - start;
            if(elapsed >= furi_ms_to_ticks(timeout_ms)) {
                return false;
            }
        }
        furi_delay_ms(50);
    }
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
    } else if(strcmp(key, "min_channel_time") == 0) {
        app->scanner_min_channel_time = (uint16_t)strtoul(value, NULL, 10);
    } else if(strcmp(key, "max_channel_time") == 0) {
        app->scanner_max_channel_time = (uint16_t)strtoul(value, NULL, 10);
    } else if(strcmp(key, "backlight_enabled") == 0) {
        app->backlight_enabled = simple_app_parse_bool_value(value, app->backlight_enabled);
    } else if(strcmp(key, "otg_power_enabled") == 0) {
        app->otg_power_enabled = simple_app_parse_bool_value(value, app->otg_power_enabled);
    } else if(strcmp(key, "show_ram_overlay") == 0) {
        app->show_ram_overlay = simple_app_parse_bool_value(value, app->show_ram_overlay);
    } else if(strcmp(key, "debug_mark") == 0) {
        app->debug_mark_enabled = simple_app_parse_bool_value(value, app->debug_mark_enabled);
    } else if(strcmp(key, "red_team_mode") == 0) {
        app->red_team_mode = simple_app_parse_bool_value(value, app->red_team_mode);
    } else if(strcmp(key, "karma_duration") == 0) {
        app->karma_sniffer_duration_sec = (uint32_t)strtoul(value, NULL, 10);
    } else if(strcmp(key, "led_enabled") == 0) {
        app->config_seen_led_enabled = true;
        app->led_enabled = simple_app_parse_bool_value(value, app->led_enabled);
    } else if(strcmp(key, "led_level") == 0) {
        app->config_seen_led_level = true;
        long parsed = strtol(value, NULL, 10);
        if(parsed >= 0) {
            if(parsed > 255) {
                parsed = 255;
            }
            app->led_level = (uint8_t)parsed;
        }
    } else if(strcmp(key, "gps_utc_offset_min") == 0) {
        app->config_seen_gps_utc_offset = true;
        app->gps_utc_offset_minutes = simple_app_clamp_gps_utc_offset(strtol(value, NULL, 10));
    } else if(strcmp(key, "gps_dst") == 0) {
        app->config_seen_gps_dst = true;
        app->gps_dst_enabled = simple_app_parse_bool_value(value, app->gps_dst_enabled);
    } else if(strcmp(key, "gps_zda_tz") == 0) {
        app->config_seen_gps_zda_tz = true;
        app->gps_zda_tz_enabled = simple_app_parse_bool_value(value, app->gps_zda_tz_enabled);
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
    if(storage_file_open(
           file, EXT_PATH(LAB_C5_CONFIG_FILE_PATH), FSAM_READ_WRITE, FSOM_CREATE_ALWAYS)) {
        char buffer[576];
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
            "min_channel_time=%u\n"
            "max_channel_time=%u\n"
              "backlight_enabled=%d\n"
              "otg_power_enabled=%d\n"
              "show_ram_overlay=%d\n"
              "debug_mark=%d\n"
              "red_team_mode=%d\n"
              "karma_duration=%lu\n"
            "gps_utc_offset_min=%d\n"
            "gps_dst=%d\n"
            "gps_zda_tz=%d\n"
            "led_enabled=%d\n"
            "led_level=%u\n"
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
            (unsigned)app->scanner_min_channel_time,
            (unsigned)app->scanner_max_channel_time,
            app->backlight_enabled ? 1 : 0,
            app->otg_power_enabled ? 1 : 0,
              app->show_ram_overlay ? 1 : 0,
              app->debug_mark_enabled ? 1 : 0,
              app->red_team_mode ? 1 : 0,
              (unsigned long)app->karma_sniffer_duration_sec,
              (int)app->gps_utc_offset_minutes,
              app->gps_dst_enabled ? 1 : 0,
              app->gps_zda_tz_enabled ? 1 : 0,
              app->led_enabled ? 1 : 0,
              (unsigned)app->led_level,
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
    app->config_seen_led_enabled = false;
    app->config_seen_led_level = false;
    app->config_seen_gps_utc_offset = false;
    app->config_seen_gps_dst = false;
    app->config_seen_gps_zda_tz = false;
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
    if(app->scanner_min_channel_time < SCANNER_CHANNEL_TIME_MIN_MS) {
        app->scanner_min_channel_time = SCANNER_CHANNEL_TIME_MIN_MS;
    } else if(app->scanner_min_channel_time > SCANNER_CHANNEL_TIME_MAX_MS) {
        app->scanner_min_channel_time = SCANNER_CHANNEL_TIME_MAX_MS;
    }
    if(app->scanner_max_channel_time < SCANNER_CHANNEL_TIME_MIN_MS) {
        app->scanner_max_channel_time = SCANNER_CHANNEL_TIME_MIN_MS;
    } else if(app->scanner_max_channel_time > SCANNER_CHANNEL_TIME_MAX_MS) {
        app->scanner_max_channel_time = SCANNER_CHANNEL_TIME_MAX_MS;
    }
    if(app->scanner_min_channel_time > app->scanner_max_channel_time) {
        app->scanner_max_channel_time = app->scanner_min_channel_time;
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
    app->gps_utc_offset_minutes = simple_app_clamp_gps_utc_offset(app->gps_utc_offset_minutes);
    if(app->boot_short_command_index >= BOOT_COMMAND_OPTION_COUNT) {
        app->boot_short_command_index = 1;
    }
    if(app->boot_long_command_index >= BOOT_COMMAND_OPTION_COUNT) {
        app->boot_long_command_index = 0;
    }
    if(loaded) {
        bool missing_fields = !app->config_seen_led_enabled ||
                              !app->config_seen_led_level ||
                              !app->config_seen_gps_utc_offset ||
                              !app->config_seen_gps_dst ||
                              !app->config_seen_gps_zda_tz;
        if(missing_fields) {
            simple_app_save_config(app, NULL, false);
        }
    }
}

static void simple_app_save_config_if_dirty(SimpleApp* app, const char* message, bool fullscreen) {
    if(!app) return;
    if(app->config_dirty) {
        simple_app_save_config(app, message, fullscreen);
    }
}

static void simple_app_toggle_red_team(SimpleApp* app) {
    if(!app) return;
    app->red_team_mode = !app->red_team_mode;
    app->last_attack_index = 0;
    simple_app_update_red_team_label(app);
    simple_app_mark_config_dirty(app);
    simple_app_save_config_if_dirty(app, NULL, false);
    if(app->viewport) view_port_update(app->viewport);
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

static void simple_app_toggle_show_ram(SimpleApp* app) {
    if(!app) return;
    app->show_ram_overlay = !app->show_ram_overlay;
    simple_app_update_ram_label(app);
    simple_app_mark_config_dirty(app);
    if(app->viewport) {
        view_port_update(app->viewport);
    }
}

static void simple_app_toggle_debug_mark(SimpleApp* app) {
    if(!app) return;
    app->debug_mark_enabled = !app->debug_mark_enabled;
    simple_app_update_debug_label(app);
    simple_app_mark_config_dirty(app);
    if(app->viewport) {
        view_port_update(app->viewport);
    }
}




static bool simple_app_bssid_is_empty(const uint8_t bssid[6]) {
    if(!bssid) return true;
    for(size_t i = 0; i < 6; i++) {
        if(bssid[i] != 0) return false;
    }
    return true;
}


static void simple_app_format_bssid(const uint8_t bssid[6], char* out, size_t out_size) {
    if(!out || out_size == 0) return;
    if(simple_app_bssid_is_empty(bssid)) {
        snprintf(out, out_size, "%s", "--:--:--:--:--:--");
        return;
    }
    snprintf(
        out,
        out_size,
        "%02X:%02X:%02X:%02X:%02X:%02X",
        bssid[0],
        bssid[1],
        bssid[2],
        bssid[3],
        bssid[4],
        bssid[5]);
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

static void simple_app_update_deauth_blink(SimpleApp* app) {
    if(!app || !app->viewport) return;
    if(!app->deauth_view_active || app->deauth_full_console) return;
    if(!app->deauth_running || app->screen != ScreenSerial) return;

    uint32_t now = furi_get_tick();
    uint32_t interval = furi_ms_to_ticks(DEAUTH_RUNNING_BLINK_MS);
    if(interval == 0) interval = 1;
    if(app->deauth_blink_last_tick == 0) {
        app->deauth_blink_last_tick = now;
        return;
    }
    if(now - app->deauth_blink_last_tick >= interval) {
        app->deauth_blink_last_tick = now;
        view_port_update(app->viewport);
    }
}

static void simple_app_update_handshake_blink(SimpleApp* app) {
    if(!app || !app->viewport) return;
    if(!app->handshake_view_active || app->handshake_full_console) return;
    if(!app->handshake_running || app->screen != ScreenSerial) return;

    uint32_t now = furi_get_tick();
    uint32_t interval = furi_ms_to_ticks(DEAUTH_RUNNING_BLINK_MS);
    if(interval == 0) interval = 1;
    if(app->handshake_blink_last_tick == 0) {
        app->handshake_blink_last_tick = now;
        return;
    }
    if(now - app->handshake_blink_last_tick >= interval) {
        app->handshake_blink_last_tick = now;
        view_port_update(app->viewport);
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
    if(app->screen == ScreenSerial) {
        if(app->bt_scan_view_active && !app->bt_scan_full_console) {
            return BT_SCAN_CONSOLE_LINES;
        }
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
    simple_app_update_scroll(app);
}

LAB_C5_CODE_SECTION static void simple_app_append_serial_data(
    SimpleApp* app, const uint8_t* data, size_t length) {
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

    furi_mutex_release(app->serial_mutex);

    for(size_t i = 0; i < length; i++) {
        char ch = (char)data[i];
        simple_app_package_monitor_feed(app, ch);
        simple_app_channel_view_feed(app, ch);
        simple_app_sd_feed(app, ch);
        simple_app_led_feed(app, ch);
        simple_app_boot_feed(app, ch);
        simple_app_vendor_feed(app, ch);
        simple_app_scanner_timing_feed(app, ch);
        simple_app_ota_feed(app, ch);
        simple_app_deauth_guard_feed(app, ch);
        simple_app_deauth_feed(app, ch);
        simple_app_handshake_feed(app, ch);
        simple_app_sae_feed(app, ch);
        if(app->blackout_view_active) {
            simple_app_blackout_feed(app, ch);
        }
        if(app->sniffer_dog_view_active) {
            simple_app_sniffer_dog_feed(app, ch);
        }
        simple_app_bt_scan_feed(app, ch);
        simple_app_bt_locator_feed(app, ch);
    }

    if(trimmed_any && !app->serial_follow_tail) {
        size_t max_scroll = simple_app_max_scroll(app);
        if(app->serial_scroll > max_scroll) {
            app->serial_scroll = max_scroll;
        }
    }

    simple_app_update_scroll(app);
    if(app->viewport &&
       (app->screen == ScreenOtaStatus || app->screen == ScreenOtaList || app->screen == ScreenOtaInfo)) {
        view_port_update(app->viewport);
    }
}


static bool simple_app_is_start_blackout_command(const char* command) {
    if(!command) return false;
    const char* cursor = command;
    const char* needle = "start_blackout";
    size_t needle_len = strlen(needle);
    while(true) {
        const char* found = strstr(cursor, needle);
        if(!found) return false;
        char before = (found == command) ? ' ' : *(found - 1);
        char after = *(found + needle_len);
        bool before_ok = (before == ' ' || before == '\n' || before == '\t');
        bool after_ok = (after == '\0' || after == ' ' || after == '\n' || after == '\t');
        if(before_ok && after_ok) return true;
        cursor = found + needle_len;
    }
}


static bool simple_app_is_start_sniffer_dog_command(const char* command) {
    if(!command) return false;
    const char* cursor = command;
    const char* needle = "start_sniffer_dog";
    size_t needle_len = strlen(needle);
    while(true) {
        const char* found = strstr(cursor, needle);
        if(!found) return false;
        char before = (found == command) ? ' ' : *(found - 1);
        char after = *(found + needle_len);
        bool before_ok = (before == ' ' || before == '\n' || before == '\t');
        bool after_ok = (after == '\0' || after == ' ' || after == '\n' || after == '\t');
        if(before_ok && after_ok) return true;
        cursor = found + needle_len;
    }
}

static bool simple_app_is_start_deauth_command(const char* command) {
    if(!command) return false;
    const char* cursor = command;
    const char* needle = "start_deauth";
    size_t needle_len = strlen(needle);
    while(true) {
        const char* found = strstr(cursor, needle);
        if(!found) return false;
        char before = (found == command) ? ' ' : *(found - 1);
        char after = *(found + needle_len);
        bool before_ok = (before == ' ' || before == '\n' || before == '\t');
        bool after_ok = (after == '\0' || after == ' ' || after == '\n' || after == '\t');
        if(before_ok && after_ok) return true;
        cursor = found + needle_len;
    }
}

static bool simple_app_is_start_handshake_command(const char* command) {
    if(!command) return false;
    const char* cursor = command;
    const char* needle = "start_handshake";
    size_t needle_len = strlen(needle);
    while(true) {
        const char* found = strstr(cursor, needle);
        if(!found) return false;
        char before = (found == command) ? ' ' : *(found - 1);
        char after = *(found + needle_len);
        bool before_ok = (before == ' ' || before == '\n' || before == '\t');
        bool after_ok = (after == '\0' || after == ' ' || after == '\n' || after == '\t');
        if(before_ok && after_ok) return true;
        cursor = found + needle_len;
    }
}

static bool simple_app_is_start_sae_command(const char* command) {
    if(!command) return false;
    const char* cursor = command;
    const char* needle = "sae_overflow";
    size_t needle_len = strlen(needle);
    while(true) {
        const char* found = strstr(cursor, needle);
        if(!found) return false;
        char before = (found == command) ? ' ' : *(found - 1);
        char after = *(found + needle_len);
        bool before_ok = (before == ' ' || before == '\n' || before == '\t');
        bool after_ok = (after == '\0' || after == ' ' || after == '\n' || after == '\t');
        if(before_ok && after_ok) return true;
        cursor = found + needle_len;
    }
}


static void simple_app_send_command(SimpleApp* app, const char* command, bool go_to_serial) {
    if(!app || !command || command[0] == '\0' || !app->serial || !app->serial_mutex) return;

    bool is_stop_command = strcmp(command, "stop") == 0;
    bool is_start_sniffer_dog = simple_app_is_start_sniffer_dog_command(command);
    bool is_start_blackout = simple_app_is_start_blackout_command(command);
    bool is_start_deauth = simple_app_is_start_deauth_command(command);
    bool is_start_handshake = simple_app_is_start_handshake_command(command);
    bool is_start_sae = simple_app_is_start_sae_command(command);
    bool is_airtag_scan_command = strstr(command, "scan_airtag") != NULL;
    bool is_bt_scan_command = is_airtag_scan_command || strstr(command, "scan_bt") != NULL;
    bool is_deauth_guard_command = strstr(command, "deauth_detector") != NULL;
    bool is_start_gps_raw = strstr(command, "start_gps_raw") != NULL;
    if(is_start_gps_raw) {
        app->gps_view_active = true;
    } else if(is_stop_command) {
        app->gps_view_active = false;
        app->gps_console_mode = false;
    }
    if(is_bt_scan_command) {
        if(!simple_app_alloc_bt_buffers(app)) {
            simple_app_show_status_message(app, "OOM: BT buffers", 1500, true);
            return;
        }
        app->bt_scan_view_active = true;
        simple_app_reset_bt_scan_summary(app);
        app->airtag_scan_mode = is_airtag_scan_command;
        app->bt_scan_running = true;
        app->bt_scan_has_data = false;
        app->bt_scan_last_update_tick = 0;
        app->bt_scan_show_list = false;
        if(!is_airtag_scan_command) {
            const char* mac_ptr = strstr(command, "scan_bt");
            if(mac_ptr) {
                mac_ptr += strlen("scan_bt");
                while(*mac_ptr == ' ') mac_ptr++;
                if(strchr(mac_ptr, ':')) {
                    strncpy(app->bt_locator_mac, mac_ptr, sizeof(app->bt_locator_mac));
                    app->bt_locator_mac[sizeof(app->bt_locator_mac) - 1] = '\0';
                    app->bt_locator_mode = true;
                    app->bt_locator_has_rssi = false;
                    app->bt_locator_start_tick = furi_get_tick();
                    app->bt_locator_last_console_tick = app->bt_locator_start_tick;
                }
            }
        }
    } else if(app->bt_scan_view_active) {
        app->bt_scan_view_active = false;
        simple_app_reset_bt_scan_summary(app);
        simple_app_free_bt_buffers(app);
    }
    if(is_deauth_guard_command) {
        simple_app_start_deauth_guard(app);
    } else if(is_stop_command || app->deauth_guard_view_active) {
        simple_app_reset_deauth_guard(app);
    }
    if(is_start_handshake) {
        app->handshake_view_active = true;
        app->handshake_full_console = false;
        simple_app_reset_handshake_status(app);
        app->handshake_view_active = true;
        app->handshake_running = true;
        app->handshake_overlay_allowed = true;
        app->handshake_vibro_done = false;
        simple_app_handshake_set_note(app, "Starting");
    } else if(is_stop_command) {
        simple_app_reset_handshake_status(app);
    } else {
        simple_app_reset_handshake_status(app);
    }
    if(is_start_sae) {
        app->sae_view_active = true;
        app->sae_full_console = false;
        simple_app_reset_sae_status(app);
        app->sae_view_active = true;
        app->sae_running = true;
        app->sae_overlay_allowed = true;
        simple_app_sae_set_note(app, "Running");
    } else if(is_stop_command) {
        simple_app_reset_sae_status(app);
    } else {
        simple_app_reset_sae_status(app);
    }
    if(is_start_deauth) {
        app->deauth_view_active = true;
        app->deauth_full_console = false;
        simple_app_reset_deauth_status(app);
        app->deauth_view_active = true;
        simple_app_deauth_set_note(app, "Starting");
        app->deauth_list_offset = 0;
        app->deauth_list_scroll_x = 0;
        app->deauth_overlay_allowed = true;
    } else if(is_stop_command) {
        app->deauth_view_active = false;
        simple_app_reset_deauth_status(app);
    } else {
        app->deauth_view_active = false;
        simple_app_reset_deauth_status(app);
    }
    if(is_start_blackout) {
        app->blackout_view_active = true;
        app->blackout_full_console = false;
        simple_app_reset_blackout_status(app);
        if(app->blackout_cycle == 0) app->blackout_cycle = 1;
        simple_app_blackout_set_phase(app, BlackoutPhaseStarting, "");
    } else if(is_stop_command) {
        app->blackout_view_active = false;
        simple_app_reset_blackout_status(app);
    } else {
        app->blackout_view_active = false;
        simple_app_reset_blackout_status(app);
    }
    if(is_start_sniffer_dog) {
        app->sniffer_dog_view_active = true;
        app->sniffer_dog_full_console = false;
        simple_app_reset_sniffer_dog_status(app);
        simple_app_sniffer_dog_set_phase(app, SnifferDogPhaseStarting, "");
    } else if(is_stop_command) {
        app->sniffer_dog_view_active = false;
        simple_app_reset_sniffer_dog_status(app);
    } else {
        app->sniffer_dog_view_active = false;
        simple_app_reset_sniffer_dog_status(app);
    }
    simple_app_log_cli_command(app, "SYS", command);

    size_t command_length = strlen(command);
    lab_c5_serial_write_line(app->serial, app->serial_mutex, command, command_length);

    furi_stream_buffer_reset(app->rx_stream);
    simple_app_reset_serial_log(app, "COMMAND SENT");

    char log_line[96];
    size_t log_length =
        lab_c5_format_tx_log(log_line, sizeof(log_line), command, command_length);
    if(log_length > 0) {
        simple_app_append_serial_data(app, (const uint8_t*)log_line, log_length);
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
    if(app->recon_stations_selected && !app->board_ready_seen) {
        simple_app_show_status_message(app, "Waiting for board", 1200, true);
        return;
    }
    if(app->recon_targets.failed) {
        simple_app_show_status_message(app, "Targets lost\nScan again", 1800, true);
        return;
    }
    size_t target_count = simple_app_target_count(app);
    if(target_count > C5_RECON_SAFE_SELECTED_NETWORKS) {
        simple_app_show_status_message(app, "Too many targets", 1500, true);
        return;
    }
    bool requires_select_networks = simple_app_command_requires_select_networks(base_command);
    if(target_count == 0 && requires_select_networks) {
        simple_app_show_status_message(app, "Please select\nnetwork first", 1500, true);
        if(app->viewport) {
            view_port_update(app->viewport);
        }
        return;
    }

    if(requires_select_networks) {
        char select_command[256] = "select_networks";
        size_t written = strlen(select_command);
        for(size_t i = 0; i < target_count; i++) {
            uint16_t number = simple_app_target_number(app, i);
            int added = number ? snprintf(
                select_command + written, sizeof(select_command) - written,
                " %u", (unsigned)number) : -1;
            if(added < 0 || (size_t)added >= sizeof(select_command) - written) {
                simple_app_show_status_message(app, "Too many targets", 1500, true);
                return;
            }
            written += (size_t)added;
        }
        char combined_command[320];
        int combined_written = snprintf(
            combined_command, sizeof(combined_command), "%s\n%s", select_command, base_command);
        if(combined_written < 0 || (size_t)combined_written >= sizeof(combined_command)) {
            simple_app_show_status_message(app, "Too many targets", 1500, true);
            return;
        }
        simple_app_send_command(app, combined_command, true);
        return;
    }

    char command[256];
    int first = snprintf(command, sizeof(command), "%s", base_command);
    if(first < 0 || (size_t)first >= sizeof(command)) return;
    size_t written = (size_t)first;
    for(size_t i = 0; i < target_count; i++) {
        uint16_t number = simple_app_target_number(app, i);
        int added = number ? snprintf(
            command + written, sizeof(command) - written, " %u", (unsigned)number) : -1;
        if(added < 0 || (size_t)added >= sizeof(command) - written) {
            simple_app_show_status_message(app, "Too many targets", 1500, true);
            return;
        }
        written += (size_t)added;
    }

    simple_app_send_command(app, command, true);
}

static void simple_app_module_host_send_command(void* context, const char* command) {
    SimpleApp* app = context;
    if(!app || !app->gps_module.lock || !command || !command[0]) return;
    size_t length = strlen(command);
    if(length >= sizeof(app->module_command)) {
        FURI_LOG_W(TAG, "Module command too long:%lu", (unsigned long)length);
        return;
    }
    furi_mutex_acquire(app->gps_module.lock, FuriWaitForever);
    if(!app->module_command_pending) {
        memcpy(app->module_command, command, length + 1);
        app->module_command_pending = true;
    } else {
        FURI_LOG_W(TAG, "Module command queue full");
    }
    furi_mutex_release(app->gps_module.lock);
}

static bool simple_app_module_host_send_raw_lines(
    void* context,
    const char* batch,
    size_t length) {
    SimpleApp* app = context;
    if(!app || !app->serial || !app->serial_mutex || !batch || length == 0 ||
       length > C5_MODULE_RAW_TX_MAX || batch[length - 1] != '\n' ||
       memchr(batch, '\0', length) != NULL) {
        return false;
    }

    furi_mutex_acquire(app->serial_mutex, FuriWaitForever);
    furi_hal_serial_tx(app->serial, (const uint8_t*)batch, length);
    furi_hal_serial_tx_wait_complete(app->serial);
    furi_mutex_release(app->serial_mutex);
    return true;
}

static bool simple_app_module_host_request_text_input(
    void* context,
    const C5TextInputRequest* request) {
    SimpleApp* app = context;
    return app && c5_module_runtime_request_text_input(&app->gps_module, request);
}

static void simple_app_module_host_request_redraw(void* context) {
    SimpleApp* app = context;
    if(!app || !app->gps_module.lock) return;
    furi_mutex_acquire(app->gps_module.lock, FuriWaitForever);
    app->module_redraw_pending = true;
    furi_mutex_release(app->gps_module.lock);
}

static void simple_app_module_host_show_status(
    void* context, const char* message, uint32_t duration_ms, bool fullscreen) {
    SimpleApp* app = context;
    if(!app || !app->gps_module.lock) return;
    furi_mutex_acquire(app->gps_module.lock, FuriWaitForever);
    snprintf(app->module_status, sizeof(app->module_status), "%s", message ? message : "");
    app->module_status_duration_ms = duration_ms;
    app->module_status_fullscreen = fullscreen;
    app->module_status_pending = true;
    furi_mutex_release(app->gps_module.lock);
}

static void simple_app_request_module(SimpleApp* app, C5ModuleRequest request) {
    if(!app || !app->gps_module.lock) return;
    furi_mutex_acquire(app->gps_module.lock, FuriWaitForever);
    if(request == C5ModuleRequestLoadGps && app->gps_module_loading) {
        // Back followed by OK resumes the in-flight load instead of starting a second one.
        if(app->gps_module_request == C5ModuleRequestUnloadGps) {
            app->gps_module_request = C5ModuleRequestNone;
        }
    } else if(request == C5ModuleRequestLoadWeb && app->web_module_loading) {
        if(app->gps_module_request == C5ModuleRequestUnloadWeb) {
            app->gps_module_request = C5ModuleRequestNone;
        }
    } else if(request == C5ModuleRequestLoadAttack && app->attack_module_loading) {
        if(app->gps_module_request == C5ModuleRequestUnloadAttack) {
            app->gps_module_request = C5ModuleRequestNone;
        }
    } else {
        app->gps_module_request = request;
    }
    furi_mutex_release(app->gps_module.lock);
}

static int32_t simple_app_module_host_get_setting(void* context, C5Setting setting) {
    const SimpleApp* app = context;
    if(!app) return 0;
    switch(setting) {
    case GPS_TIME_24H:
        return app->gps_time_24h;
    case GPS_UTC_OFFSET_MIN:
        return app->gps_utc_offset_minutes;
    case GPS_DST:
        return app->gps_dst_enabled;
    case GPS_ZDA_TZ:
        return app->gps_zda_tz_enabled;
    case C5SettingKarmaDurationSec:
        return (int32_t)app->karma_sniffer_duration_sec;
    default:
        return 0;
    }
}

static void simple_app_module_host_set_setting(void* context, C5Setting setting, int32_t value) {
    SimpleApp* app = context;
    if(!app) return;
    switch(setting) {
    case GPS_TIME_24H:
        app->gps_time_24h = value != 0;
        break;
    case GPS_UTC_OFFSET_MIN: {
        int16_t clamped = simple_app_clamp_gps_utc_offset(value);
        if(app->gps_utc_offset_minutes != clamped) {
            app->gps_utc_offset_minutes = clamped;
            simple_app_mark_config_dirty(app);
        }
        break;
    }
    case GPS_DST:
        if(app->gps_dst_enabled != (value != 0)) {
            app->gps_dst_enabled = value != 0;
            simple_app_mark_config_dirty(app);
        }
        break;
    case GPS_ZDA_TZ:
        if(app->gps_zda_tz_enabled != (value != 0)) {
            app->gps_zda_tz_enabled = value != 0;
            simple_app_mark_config_dirty(app);
        }
        break;
    case C5SettingKarmaDurationSec:
        if(value < (int32_t)KARMA_SNIFFER_DURATION_MIN_SEC) value = KARMA_SNIFFER_DURATION_MIN_SEC;
        if(value > (int32_t)KARMA_SNIFFER_DURATION_MAX_SEC) value = KARMA_SNIFFER_DURATION_MAX_SEC;
        if(app->karma_sniffer_duration_sec != (uint32_t)value) {
            app->karma_sniffer_duration_sec = (uint32_t)value;
            simple_app_mark_config_dirty(app);
        }
        break;
    default:
        break;
    }
}

static void simple_app_module_host_save_session(void* context, const void* data, size_t size) {
    SimpleApp* app = context;
    if(app && app->recon_view_active) {
        /* The active FAL still owns data here. Clone before its leave returns. */
        if(!c5_recon_targets_replace(&app->recon_targets, data, size, malloc)) {
            FURI_LOG_W(TAG, "Rejected Recon target snapshot or out of memory");
        }
        return;
    }
    if(!app || !data || size != sizeof(C5WebSessionPrefs) || !app->web_view_active) return;
    const C5WebSessionPrefs* prefs = data;
    if(!memchr(prefs->portal_ssid, '\0', sizeof(prefs->portal_ssid)) ||
       !memchr(prefs->selected_html_name, '\0', sizeof(prefs->selected_html_name)) ||
       !memchr(prefs->evil_html_name, '\0', sizeof(prefs->evil_html_name)) ||
       !memchr(prefs->selected_probe_name, '\0', sizeof(prefs->selected_probe_name)) ||
       prefs->portal_menu_index >= 4 || prefs->evil_menu_index >= 5 ||
       prefs->karma_menu_index >= 5 ||
       (prefs->selected_html_id == 0) != (prefs->selected_html_name[0] == '\0') ||
       (prefs->evil_html_id == 0) != (prefs->evil_html_name[0] == '\0') ||
       (prefs->selected_probe_id == 0) != (prefs->selected_probe_name[0] == '\0')) {
        FURI_LOG_W(TAG, "Rejected Web session metadata");
        return;
    }
    app->web_prefs = *prefs;
}

static void simple_app_module_unload(SimpleApp* app) {
    if(!app || !c5_module_runtime_active(&app->gps_module)) return;
    bool was_web = app->web_view_active;
    bool was_recon = app->recon_view_active;
    bool was_attack = app->attack_view_active;
    c5_module_runtime_unload(&app->gps_module);
    app->gps_view_active = false;
    app->gps_console_mode = false;
    app->web_view_active = false;
    app->web_console_mode = false;
    app->recon_view_active = false;
    app->recon_console_mode = false;
    app->attack_view_active = false;
    if(was_attack) {
        c5_attack_rx_guard_end(&app->attack_rx_guard);
        /* Serial command order makes the second exact pong a safe boundary.
         * The first may belong to a menu ping sent before the attack. */
        simple_app_send_ping(app);
        simple_app_send_ping(app);
    }
    simple_app_log_memory(
        app, was_attack ? "attack_unload_post" :
             (was_recon ? "recon_unload_post" :
              (was_web ? "web_unload_post" : "module_unload_post")));
}

static void simple_app_send_stop_if_needed(SimpleApp* app) {
    if(!app) return;
    if(app->web_view_active) return; /* Web leave or terminal Back owns its stop. */
    if(app->attack_view_active) {
        if(app->screen != ScreenAttackLoading) {
            InputEvent stop_event = {.type = InputTypeShort, .key = InputKeyBack};
            simple_app_handle_attack_input(app, &stop_event);
        }
        return; /* The attack FAL owns stop and its ACK. */
    }
    if(app->recon_view_active) {
        simple_app_request_module(app, C5ModuleRequestUnloadRecon);
        return; /* Recon leave owns its stop and result cleanup. */
    }
    if(app->gps_module.lock) {
        furi_mutex_acquire(app->gps_module.lock, FuriWaitForever);
        if(app->gps_module_request == C5ModuleRequestLoadGps || app->gps_module_loading) {
            app->gps_module_request = C5ModuleRequestUnloadGps;
        }
        furi_mutex_release(app->gps_module.lock);
    }
    if(!app->last_command_sent && !c5_module_runtime_active(&app->gps_module)) return;
    simple_app_send_command(app, "stop", false);
    app->last_command_sent = false;
    app->blackout_view_active = false;
    simple_app_reset_blackout_status(app);
    app->deauth_view_active = false;
    simple_app_reset_deauth_status(app);
    simple_app_reset_handshake_status(app);
    simple_app_reset_sae_status(app);
    app->sniffer_dog_view_active = false;
    simple_app_reset_sniffer_dog_status(app);
    app->bt_scan_running = false;
    app->bt_scan_show_list = false;
    simple_app_free_bt_buffers(app);
    simple_app_free_package_monitor_buffers(app);
    simple_app_free_channel_view_buffers(app);
    app->gps_view_active = false;
    app->gps_console_mode = false;
    if(c5_module_runtime_active(&app->gps_module)) {
        simple_app_request_module(app, C5ModuleRequestUnloadGps);
    }
}

static void simple_app_request_web(SimpleApp* app, C5WebMode mode) {
    if(!app || !app->gps_module.lock || mode > C5WebModeKarma) return;
    app->web_mode = mode;
    app->last_back_tick = 0;
    app->screen = ScreenWebLoading;
    simple_app_request_module(app, C5ModuleRequestLoadWeb);
    if(app->viewport) view_port_update(app->viewport);
}

static void simple_app_request_recon(SimpleApp* app, C5ReconMode mode) {
    if(!app || !app->gps_module.lock || mode > C5ReconModeProbeResults) return;
    simple_app_clear_station_selection(app);
    app->recon_mode = mode;
    app->recon_open_attacks_pending = false;
    app->screen = ScreenReconLoading;
    simple_app_request_module(app, C5ModuleRequestLoadRecon);
    if(app->viewport) view_port_update(app->viewport);
}

static void simple_app_request_attack(SimpleApp* app, C5AttackModule module) {
    if(!app || !app->gps_module.lock || module > C5AttackModuleConnect) return;
    app->attack_module = module;
    app->attack_return_to_sections = false;
    app->last_back_tick = 0;
    app->screen = ScreenAttackLoading;
    simple_app_request_module(app, C5ModuleRequestLoadAttack);
    if(app->viewport) view_port_update(app->viewport);
}

static bool simple_app_open_attack(SimpleApp* app) {
    if(!app || !app->serial || !app->gps_module.lock) return false;
    if(!c5_attack_rx_guard_should_log(&app->attack_rx_guard)) {
        simple_app_show_status_message(app, "Finishing previous task", 1400, true);
        return false;
    }
    if(!app->board_ready_seen) {
        simple_app_show_status_message(app, "Waiting for board", 1200, true);
        return false;
    }
    if(simple_app_attack_requires_target(app->attack_module) && app->recon_targets.failed) {
        simple_app_show_status_message(app, "Targets lost\nScan again", 1800, true);
        return false;
    }
    if(simple_app_attack_requires_target(app->attack_module)) {
        if(app->recon_targets.count != 1 || !app->recon_targets.targets) {
            simple_app_show_status_message(app, "Select one network", 1800, true);
            return false;
        }
        const C5ReconTarget* target = &app->recon_targets.targets[0];
        size_t ssid_len = simple_app_bounded_strlen(target->ssid, sizeof(target->ssid));
        if(!target->number || target->number > C5_RECON_SCAN_MAX_RESULTS ||
           ssid_len == 0 || ssid_len > 32) {
            simple_app_show_status_message(app, "Invalid network", 1800, true);
            return false;
        }
        if(app->attack_module == C5AttackModuleArp && ssid_len == 32) {
            simple_app_show_status_message(app, "SSID too long for ARP", 1800, true);
            return false;
        }
        if(app->attack_module == C5AttackModuleConnect && ssid_len == 32) {
            simple_app_show_status_message(app, "SSID too long for Connect", 1800, true);
            return false;
        }
    }
    simple_app_clear_station_selection(app);
    if(app->recon_stations_selected) {
        simple_app_show_status_message(app, "Waiting for board", 1200, true);
        return false;
    }
    if(app->last_command_sent && !app->attack_view_active &&
       simple_app_attack_may_stop_prior(app->attack_module)) {
        simple_app_send_command(app, "stop", false);
        app->last_command_sent = false;
    }
    if(c5_module_runtime_active(&app->gps_module)) simple_app_module_unload(app);

    C5RogueLaunchContext rogue = {
        .version = C5_ROGUE_LAUNCH_VERSION,
        .size = sizeof(C5RogueLaunchContext),
        .ticks_per_second = furi_ms_to_ticks(1000),
    };
    C5ArpLaunchContext arp = {
        .version = C5_ARP_LAUNCH_VERSION,
        .size = sizeof(C5ArpLaunchContext),
        .saved_only = app->attack_module == C5AttackModuleArpSaved,
    };
    C5BeaconLaunchContext beacon = {
        .version = C5_BEACON_LAUNCH_VERSION,
        .size = sizeof(C5BeaconLaunchContext),
        .ticks_per_second = furi_ms_to_ticks(1000),
    };
    C5WardriveLaunchContext wardrive = {
        .version = C5_WARDRIVE_LAUNCH_VERSION,
        .size = sizeof(C5WardriveLaunchContext),
        .mode = C5WardriveModeLegacy,
        .ticks_per_second = furi_ms_to_ticks(1000),
    };
    C5MitmPcapLaunchContext mitm = {
        .version = C5_MITM_PCAP_LAUNCH_VERSION,
        .size = sizeof(C5MitmPcapLaunchContext),
        .ticks_per_second = furi_ms_to_ticks(1000),
    };
    C5WardriveUploadLaunchContext upload = {
        .version = C5_WARDRIVE_UPLOAD_LAUNCH_VERSION,
        .size = sizeof(C5WardriveUploadLaunchContext),
        .provider = C5WardriveUploadWigle,
        .ticks_per_second = furi_ms_to_ticks(1000),
        .tls_verified = false,
    };
    C5NmapLaunchContext nmap = {
        .version = C5_NMAP_LAUNCH_VERSION,
        .size = sizeof(C5NmapLaunchContext),
        .ticks_per_second = furi_ms_to_ticks(1000),
    };
    C5WpasecLaunchContext wpasec = {
        .version = C5_WPASEC_LAUNCH_VERSION,
        .size = sizeof(C5WpasecLaunchContext),
        .ticks_per_second = furi_ms_to_ticks(1000),
        .tls_verified = false,
    };
    C5ConnectLaunchContext connect = {
        .version = C5_CONNECT_LAUNCH_VERSION,
        .size = sizeof(C5ConnectLaunchContext),
        .ticks_per_second = furi_ms_to_ticks(1000),
    };
    const char* path;
    const void* params;
    size_t params_size;
    if(app->attack_module == C5AttackModuleConnect) {
        const C5ReconTarget* target = &app->recon_targets.targets[0];
        memcpy(connect.ssid, target->ssid, strlen(target->ssid) + 1);
        path = APP_ASSETS_PATH("plugins/lab_c5_connect.fal");
        params = &connect;
        params_size = sizeof(connect);
    } else if(app->attack_module == C5AttackModuleRogue) {
        const C5ReconTarget* target = &app->recon_targets.targets[0];
        rogue.selected_number = target->number;
        memcpy(rogue.ssid, target->ssid, strlen(target->ssid) + 1);
        simple_app_format_bssid(target->bssid, rogue.bssid, sizeof(rogue.bssid));
        path = APP_ASSETS_PATH("plugins/lab_c5_rogue.fal");
        params = &rogue;
        params_size = sizeof(rogue);
    } else if(app->attack_module == C5AttackModuleArp ||
              app->attack_module == C5AttackModuleArpSaved) {
        if(!arp.saved_only) {
            const C5ReconTarget* target = &app->recon_targets.targets[0];
            arp.selected_number = target->number;
            memcpy(arp.ssid, target->ssid, strlen(target->ssid) + 1);
        }
        path = APP_ASSETS_PATH("plugins/lab_c5_arp.fal");
        params = &arp;
        params_size = sizeof(arp);
    } else if(app->attack_module == C5AttackModuleBeacon) {
        path = APP_ASSETS_PATH("plugins/lab_c5_beacon.fal");
        params = &beacon;
        params_size = sizeof(beacon);
    } else if(app->attack_module == C5AttackModuleMitmPcap) {
        const C5ReconTarget* target = &app->recon_targets.targets[0];
        mitm.selected_number = target->number;
        memcpy(mitm.ssid, target->ssid, strlen(target->ssid) + 1);
        simple_app_format_bssid(target->bssid, mitm.bssid, sizeof(mitm.bssid));
        path = APP_ASSETS_PATH("plugins/lab_c5_mitm_pcap.fal");
        params = &mitm;
        params_size = sizeof(mitm);
    } else if(app->attack_module == C5AttackModuleWardriveUploadWigle ||
              app->attack_module == C5AttackModuleWardriveUploadWdgwars) {
        if(app->attack_module == C5AttackModuleWardriveUploadWdgwars)
            upload.provider = C5WardriveUploadWdgwars;
        path = APP_ASSETS_PATH("plugins/lab_c5_wardrive_upload.fal");
        params = &upload;
        params_size = sizeof(upload);
    } else if(app->attack_module == C5AttackModuleNmap) {
        path = APP_ASSETS_PATH("plugins/lab_c5_nmap.fal");
        params = &nmap;
        params_size = sizeof(nmap);
    } else if(app->attack_module == C5AttackModuleWpasec) {
        path = APP_ASSETS_PATH("plugins/lab_c5_wpasec.fal");
        params = &wpasec;
        params_size = sizeof(wpasec);
    } else {
        if(app->attack_module == C5AttackModuleWardrivePromisc) {
            wardrive.mode = C5WardriveModePromisc;
        } else if(app->attack_module == C5AttackModuleWardriveTrace) {
            wardrive.mode = C5WardriveModePromiscTrace;
        }
        path = APP_ASSETS_PATH("plugins/lab_c5_wardrive.fal");
        params = &wardrive;
        params_size = sizeof(wardrive);
    }
    simple_app_log_memory(app, "attack_load_pre");
    size_t free_heap = memmgr_get_free_heap();
    size_t max_block = memmgr_heap_get_max_free_block();
    if(free_heap < 24 * 1024 || max_block < 12 * 1024) {
        FURI_LOG_W(TAG, "Attack load skipped: free:%lu block:%lu",
                   (unsigned long)free_heap, (unsigned long)max_block);
        simple_app_show_status_message(app, "Low RAM for attack", 2000, true);
        simple_app_log_memory(app, "attack_load_skip");
        return false;
    }
    c5_attack_rx_guard_begin(&app->attack_rx_guard);
    C5ModuleLoadResult result = c5_module_runtime_load(
        &app->gps_module, path, params, params_size);
    if(result != C5ModuleLoadOk) {
        c5_attack_rx_guard_end(&app->attack_rx_guard);
        simple_app_send_ping(app);
        simple_app_send_ping(app);
        FURI_LOG_E(TAG, "Attack module load failed:%u", (unsigned)result);
        simple_app_show_status_message(app, "Attack unavailable", 1800, true);
        simple_app_log_memory(app, "attack_load_fail");
        return false;
    }
    app->attack_view_active = true;
    if(app->attack_module == C5AttackModuleConnect)
        c5_recon_targets_clear(&app->recon_targets);
    app->last_command_sent = false;
    app->screen = ScreenAttackModule;
    simple_app_log_memory(app, "attack_load_post");
    return true;
}

static bool simple_app_open_recon(SimpleApp* app) {
    if(!app || !app->serial || !app->gps_module.lock) return false;
    if(!c5_attack_rx_guard_should_log(&app->attack_rx_guard)) {
        simple_app_show_status_message(app, "Finishing previous task", 1400, true);
        return false;
    }
    if(app->recon_stations_selected && !app->board_ready_seen) {
        simple_app_show_status_message(app, "Waiting for board", 1200, true);
        return false;
    }
    if(app->last_command_sent && !app->recon_view_active) {
        simple_app_send_command(app, "stop", false);
        app->last_command_sent = false;
    }
    if(c5_module_runtime_active(&app->gps_module)) simple_app_module_unload(app);
    uint16_t selected_numbers[C5_RECON_SAFE_SELECTED_NETWORKS];
    size_t selected_count = 0;
    if(app->recon_mode == C5ReconModeScanner) {
        c5_recon_targets_clear(&app->recon_targets);
    } else if(app->recon_targets.failed) {
        simple_app_show_status_message(app, "Targets lost\nScan again", 1800, true);
        return false;
    } else {
        selected_count = app->recon_targets.count;
        if(selected_count > C5_RECON_SAFE_SELECTED_NETWORKS ||
           (selected_count && !app->recon_targets.targets)) return false;
        for(size_t i = 0; i < selected_count; i++) {
            selected_numbers[i] = app->recon_targets.targets[i].number;
        }
    }

    uint16_t fields = 0;
    if(app->scanner_show_ssid) fields |= C5ReconFieldSsid;
    if(app->scanner_show_bssid) fields |= C5ReconFieldBssid;
    if(app->scanner_show_channel) fields |= C5ReconFieldChannel;
    if(app->scanner_show_security) fields |= C5ReconFieldSecurity;
    if(app->scanner_show_power) fields |= C5ReconFieldPower;
    if(app->scanner_show_band) fields |= C5ReconFieldBand;
    if(app->scanner_show_vendor) fields |= C5ReconFieldVendor;
    C5ReconLaunchContext launch = {
        .version = C5_RECON_LAUNCH_VERSION,
        .size = sizeof(C5ReconLaunchContext),
        .mode = app->recon_mode,
        .min_power_dbm = app->scanner_min_power,
        .field_mask = fields,
        .selected_count = selected_count,
        .selected_numbers = selected_count ? selected_numbers : NULL,
    };
    simple_app_log_memory(app, "recon_load_pre");
    size_t free_heap = memmgr_get_free_heap();
    size_t max_block = memmgr_heap_get_max_free_block();
    if(free_heap < 24 * 1024 || max_block < 12 * 1024) {
        FURI_LOG_W(TAG, "Recon load skipped: free:%lu block:%lu",
                   (unsigned long)free_heap, (unsigned long)max_block);
        simple_app_show_status_message(app, "Low RAM for Recon", 2000, true);
        simple_app_log_memory(app, "recon_load_skip");
        return false;
    }
    C5ModuleLoadResult result = c5_module_runtime_load(
        &app->gps_module, APP_ASSETS_PATH("plugins/lab_c5_recon.fal"), &launch, sizeof(launch));
    if(result != C5ModuleLoadOk) {
        FURI_LOG_E(TAG, "Recon module load failed:%u", (unsigned)result);
        simple_app_show_status_message(app, "Recon unavailable", 1800, true);
        simple_app_log_memory(app, "recon_load_fail");
        return false;
    }
    app->recon_view_active = true;
    app->recon_console_mode = false;
    app->last_command_sent = false;
    app->screen = ScreenRecon;
    simple_app_reset_serial_log(app, "COMMAND SENT");
    simple_app_log_memory(app, "recon_load_post");
    return true;
}

static bool simple_app_open_web(SimpleApp* app) {
    if(!app || !app->serial || !app->gps_module.lock) return false;
    if(!c5_attack_rx_guard_should_log(&app->attack_rx_guard)) {
        simple_app_show_status_message(app, "Finishing previous task", 1400, true);
        return false;
    }
    /* A station choice is only for the immediate targeted attack. Web modes
       must not leave it armed for a later Deauth command. */
    simple_app_clear_station_selection(app);
    if(app->recon_stations_selected) {
        simple_app_show_status_message(app, "Waiting for board", 1200, true);
        return false;
    }
    if(app->recon_targets.failed) {
        simple_app_show_status_message(app, "Targets lost\nScan again", 1800, true);
        return false;
    }
    if(app->last_command_sent && !app->web_view_active) {
        simple_app_send_command(app, "stop", false);
        app->last_command_sent = false;
    }
    if(c5_module_runtime_active(&app->gps_module)) simple_app_module_unload(app);

    C5WebLaunchContext launch = {
        .version = C5_WEB_LAUNCH_VERSION,
        .size = sizeof(C5WebLaunchContext),
        .mode = app->web_mode,
        .karma_duration_sec = app->karma_sniffer_duration_sec,
        .ticks_per_second = furi_ms_to_ticks(1000),
        .probe_refresh_delay_ticks = furi_ms_to_ticks(KARMA_AUTO_LIST_DELAY_MS),
        .prefs = app->web_prefs,
    };
    size_t selected_count = simple_app_target_count(app);
    if(selected_count > C5_RECON_SAFE_SELECTED_NETWORKS) {
        simple_app_show_status_message(app, "Too many targets", 1500, true);
        return false;
    }
    if(selected_count) {
        if(!simple_app_target_number(app, 0)) {
            simple_app_show_status_message(app, "No targets selected", 1500, true);
            return false;
        }
        simple_app_get_first_selected_ssid(app, launch.first_selected_ssid,
                                            sizeof(launch.first_selected_ssid));
        size_t used = strlen("select_networks");
        memcpy(launch.select_networks, "select_networks", used + 1);
        for(size_t i = 0; i < selected_count; i++) {
            uint16_t number = simple_app_target_number(app, i);
            int added = snprintf(launch.select_networks + used,
                                 sizeof(launch.select_networks) - used, " %u",
                                 (unsigned)number);
            if(added < 0 || (size_t)added >= sizeof(launch.select_networks) - used) {
                simple_app_show_status_message(app, "Too many targets", 1500, true);
                return false;
            }
            used += (size_t)added;
        }
        launch.selected_count = selected_count;
    }

    simple_app_log_memory(app, "web_load_pre");
    size_t free_heap = memmgr_get_free_heap();
    size_t max_block = memmgr_heap_get_max_free_block();
    if(free_heap < 32 * 1024 || max_block < 20 * 1024) {
        FURI_LOG_W(TAG, "Web load skipped: free:%lu block:%lu",
                   (unsigned long)free_heap, (unsigned long)max_block);
        simple_app_show_status_message(app, "Low RAM for Web", 2000, true);
        simple_app_log_memory(app, "web_load_skip");
        return false;
    }
    C5ModuleLoadResult result = c5_module_runtime_load(
        &app->gps_module, APP_ASSETS_PATH("plugins/lab_c5_web.fal"), &launch, sizeof(launch));
    if(result != C5ModuleLoadOk) {
        FURI_LOG_E(TAG, "Web module load failed:%u", (unsigned)result);
        simple_app_show_status_message(app, "Web module unavailable", 2000, true);
        simple_app_log_memory(app, "web_load_fail");
        return false;
    }
    app->web_view_active = true;
    app->web_console_mode = false;
    app->last_command_sent = false;
    app->screen = ScreenWebMenu;
    simple_app_log_memory(app, "web_load_post");
    return true;
}

static bool simple_app_open_gps(SimpleApp* app) {
    if(!app || !app->serial || !app->gps_module.lock) return false;
    if(!c5_attack_rx_guard_should_log(&app->attack_rx_guard)) {
        simple_app_show_status_message(app, "Finishing previous task", 1400, true);
        return false;
    }
    if(app->last_command_sent) {
        simple_app_send_command(app, "stop", false);
        app->last_command_sent = false;
    }
    if(c5_module_runtime_active(&app->gps_module)) simple_app_module_unload(app);
    simple_app_log_memory(app, "gps_load_pre");
    size_t free_heap = memmgr_get_free_heap();
    size_t max_block = memmgr_heap_get_max_free_block();
    if(free_heap < 12 * 1024 || max_block < 8 * 1024) {
        FURI_LOG_W(TAG, "GPS load skipped: free:%lu block:%lu", (unsigned long)free_heap, (unsigned long)max_block);
        simple_app_show_status_message(app, "Low RAM for GPS", 2000, true);
        return false;
    }

    C5ModuleLoadResult result = c5_module_runtime_load(
        &app->gps_module, APP_ASSETS_PATH("plugins/lab_c5_gps.fal"), NULL, 0);
    if(result != C5ModuleLoadOk) {
        FURI_LOG_E(TAG, "GPS module load failed:%u", (unsigned)result);
        simple_app_show_status_message(app, "GPS module unavailable", 2000, true);
        simple_app_log_memory(app, "gps_load_fail");
        return false;
    }
    furi_mutex_acquire(app->serial_mutex, FuriWaitForever);
    furi_mutex_acquire(app->gps_module.lock, FuriWaitForever);
    bool canceled = app->gps_module_request == C5ModuleRequestUnloadGps;
    if(canceled) {
        app->gps_module_request = C5ModuleRequestNone;
        app->gps_module_loading = false;
        furi_mutex_release(app->gps_module.lock);
        furi_mutex_release(app->serial_mutex);
        simple_app_module_unload(app);
        app->screen = ScreenMenu;
        return false;
    }
    furi_stream_buffer_reset(app->rx_stream);
    static const char start_command[] = "start_gps_raw";
    static const uint8_t newline = '\n';
    furi_hal_serial_tx(app->serial, (const uint8_t*)start_command, sizeof(start_command) - 1);
    furi_hal_serial_tx(app->serial, &newline, 1);
    furi_hal_serial_tx_wait_complete(app->serial);
    app->last_command_sent = true;
    app->gps_view_active = true;
    app->gps_console_mode = false;
    app->screen = ScreenGps;
    app->gps_module_loading = false;
    furi_mutex_release(app->gps_module.lock);
    furi_mutex_release(app->serial_mutex);
    simple_app_log_cli_command(app, "SYS", "start_gps_raw");
    simple_app_reset_serial_log(app, "COMMAND SENT");
    static const char start_log[] = "TX: start_gps_raw\n";
    simple_app_append_serial_data(app, (const uint8_t*)start_log, sizeof(start_log) - 1);
    simple_app_log_memory(app, "gps_load_post");
    return true;
}

static void simple_app_process_module_requests(SimpleApp* app) {
    if(!app || !app->gps_module.lock) return;
    char command[sizeof(app->module_command)];
    char status[sizeof(app->module_status)];
    furi_mutex_acquire(app->gps_module.lock, FuriWaitForever);
    C5ModuleRequest request = app->gps_module_request;
    bool redraw = app->module_redraw_pending;
    bool send_command = app->module_command_pending;
    if(send_command) memcpy(command, app->module_command, sizeof(command));
    bool show_status = app->module_status_pending;
    if(show_status) memcpy(status, app->module_status, sizeof(status));
    uint32_t status_duration_ms = app->module_status_duration_ms;
    bool status_fullscreen = app->module_status_fullscreen;
    app->gps_module_request = C5ModuleRequestNone;
    if(request == C5ModuleRequestLoadGps) app->gps_module_loading = true;
    if(request == C5ModuleRequestLoadWeb) app->web_module_loading = true;
    if(request == C5ModuleRequestLoadAttack) app->attack_module_loading = true;
    app->module_redraw_pending = false;
    app->module_command_pending = false;
    app->module_status_pending = false;
    furi_mutex_release(app->gps_module.lock);

    if(request == C5ModuleRequestLoadGps) {
        bool opened = simple_app_open_gps(app);
        furi_mutex_acquire(app->gps_module.lock, FuriWaitForever);
        app->gps_module_loading = false;
        if(!opened && app->screen == ScreenGpsLoading) app->screen = ScreenMenu;
        furi_mutex_release(app->gps_module.lock);
        redraw = true;
    } else if(request == C5ModuleRequestLoadWeb) {
        bool opened = simple_app_open_web(app);
        furi_mutex_acquire(app->gps_module.lock, FuriWaitForever);
        app->web_module_loading = false;
        if(!opened && app->screen == ScreenWebLoading) app->screen = ScreenMenu;
        furi_mutex_release(app->gps_module.lock);
        send_command = false;
        redraw = true;
    } else if(request == C5ModuleRequestUnloadGps) {
        if(app->last_command_sent && c5_module_runtime_active(&app->gps_module)) {
            simple_app_send_command(app, "stop", false);
            app->last_command_sent = false;
        }
        simple_app_module_unload(app);
        if(app->screen == ScreenGps || app->screen == ScreenGpsLoading) app->screen = ScreenMenu;
        send_command = false;
        redraw = true;
    } else if(request == C5ModuleRequestUnloadWeb) {
        simple_app_module_unload(app);
        if(app->screen == ScreenWebMenu || app->screen == ScreenWebLoading ||
           app->screen == ScreenSerial) app->screen = ScreenMenu;
        send_command = false;
        redraw = true;
    } else if(request == C5ModuleRequestLoadRecon) {
        bool opened = simple_app_open_recon(app);
        if(!opened && app->screen == ScreenReconLoading) app->screen = ScreenMenu;
        send_command = false;
        redraw = true;
    } else if(request == C5ModuleRequestUnloadRecon) {
        simple_app_module_unload(app);
        if(app->recon_open_attacks_pending && !app->recon_targets.failed &&
           app->recon_targets.count) {
            app->last_attack_index = app->recon_mode == C5ReconModeScanner ? 0 :
                                     app->red_team_mode ? 2 :
                                     simple_app_attack_index_for_command(app, "start_sniffer");
            simple_app_focus_attacks_menu(app);
        } else {
            simple_app_clear_station_selection(app);
            if(app->recon_targets.failed) {
                simple_app_show_status_message(app, "Targets lost\nScan again", 1800, true);
            }
            app->screen = ScreenMenu;
        }
        app->recon_open_attacks_pending = false;
        send_command = false;
        redraw = true;
    } else if(request == C5ModuleRequestLoadAttack) {
        bool opened = simple_app_open_attack(app);
        furi_mutex_acquire(app->gps_module.lock, FuriWaitForever);
        app->attack_module_loading = false;
        if(!opened && app->screen == ScreenAttackLoading) app->screen = ScreenMenu;
        furi_mutex_release(app->gps_module.lock);
        send_command = false;
        redraw = true;
    } else if(request == C5ModuleRequestUnloadAttack) {
        simple_app_module_unload(app);
        if(app->attack_return_to_sections) {
            app->screen = ScreenMenu;
            app->menu_state = MenuStateSections;
            simple_app_adjust_section_offset(app);
            simple_app_clear_station_selection(app);
            app->attack_return_to_sections = false;
        } else if(app->attack_module == C5AttackModuleWpasec) {
            app->screen = ScreenMenu;
            app->menu_state = MenuStateItems;
            app->section_index = MENU_SECTION_SETUP;
        } else {
            simple_app_focus_attacks_menu(app);
        }
        send_command = false;
        redraw = true;
    }
    if(send_command) simple_app_send_command(app, command, false);
    if(show_status) {
        simple_app_show_status_message(app, status, status_duration_ms, status_fullscreen);
    }
    if(redraw && app->viewport) view_port_update(app->viewport);
}


static void simple_app_prepare_exit(SimpleApp* app) {
    if(!app) return;

    if(app->web_view_active || app->recon_view_active || app->attack_view_active) {
        simple_app_module_unload(app);
    } else {
        simple_app_send_stop_if_needed(app);
    }
    simple_app_send_command_quiet(app, "unselect_networks");
    simple_app_clear_station_selection(app);
    simple_app_send_command_quiet(app, "clear_sniffer_results");
    simple_app_send_command_quiet(app, "reboot");
    simple_app_reset_sd_listing(app);
    simple_app_reset_deauth_guard(app);
    app->deauth_view_active = false;
    simple_app_reset_deauth_status(app);
    simple_app_reset_handshake_status(app);
    simple_app_reset_sae_status(app);
    simple_app_free_bt_buffers(app);
    simple_app_free_package_monitor_buffers(app);
    simple_app_free_channel_view_buffers(app);
    simple_app_clear_status_message(app);

    app->gps_view_active = false;
    simple_app_module_unload(app);
    app->sd_folder_popup_active = false;
    app->sd_file_popup_active = false;
    app->sd_delete_confirm_active = false;

    if(app->rx_stream) {
        furi_stream_buffer_reset(app->rx_stream);
    }
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

static void simple_app_draw_confirm_ota_connect(SimpleApp* app, Canvas* canvas) {
    if(!app) return;
    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str_aligned(
        canvas, DISPLAY_WIDTH / 2, 14, AlignCenter, AlignCenter, "Connect WiFi?");
    canvas_draw_str_aligned(
        canvas, DISPLAY_WIDTH / 2, 26, AlignCenter, AlignCenter, "Required for OTA");
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, 42, AlignCenter, AlignCenter, "Confirm?");
    canvas_set_font(canvas, FontSecondary);
    const char* option_line = app->ota_connect_confirm_yes ? "No        > Yes" : "> No        Yes";
    canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, 54, AlignCenter, AlignCenter, option_line);
}

static void simple_app_draw_confirm_exit(SimpleApp* app, Canvas* canvas) {
    if(!app) return;
    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str_aligned(
        canvas, DISPLAY_WIDTH / 2, 14, AlignCenter, AlignCenter, "Exit and clean up?");
    canvas_draw_str_aligned(
        canvas, DISPLAY_WIDTH / 2, 26, AlignCenter, AlignCenter, "Current tasks will stop");
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, 42, AlignCenter, AlignCenter, "Confirm?");
    canvas_set_font(canvas, FontSecondary);
    const char* option_line = app->confirm_exit_yes ? "No        > Yes" : "> No        Yes";
    canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, 54, AlignCenter, AlignCenter, option_line);
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

static void simple_app_handle_gps_input(SimpleApp* app, const InputEvent* event) {
    if(!app || !event) return;
    if(event->key == InputKeyBack && event->type == InputTypeShort) {
        simple_app_send_stop_if_needed(app);
        app->screen = ScreenMenu;
        if(app->viewport) view_port_update(app->viewport);
        return;
    }
    C5InputResult result = c5_module_runtime_input(&app->gps_module, event);
    if(result == C5InputSwitchTerminal) {
        app->screen = ScreenSerial;
        app->gps_console_mode = true;
        app->serial_follow_tail = true;
        simple_app_update_scroll(app);
        if(app->viewport) view_port_update(app->viewport);
    }
}

static void simple_app_handle_web_input(SimpleApp* app, const InputEvent* event) {
    if(!app || !event || !app->web_view_active) return;
    if(event->type == InputTypeShort && event->key == InputKeyBack) app->last_back_tick = 0;
    C5InputResult result = c5_module_runtime_input(&app->gps_module, event);
    if(result == C5InputSwitchTerminal) {
        simple_app_reset_serial_log(app, "COMMAND SENT");
        app->screen = ScreenSerial;
        app->web_console_mode = false;
        app->serial_follow_tail = true;
        simple_app_update_scroll(app);
    } else if(result == C5InputSwitchModule) {
        app->screen = ScreenWebMenu;
        app->web_console_mode = false;
        app->serial_follow_tail = true;
        simple_app_update_scroll(app);
    } else if(result == C5InputToggleConsole) {
        app->web_console_mode = !app->web_console_mode;
        app->serial_follow_tail = true;
        simple_app_update_scroll(app);
    } else if(result == C5InputIgnored && app->screen == ScreenWebMenu &&
              event->type == InputTypeShort &&
              (event->key == InputKeyBack || event->key == InputKeyLeft)) {
        simple_app_request_module(app, C5ModuleRequestUnloadWeb);
        simple_app_focus_attacks_menu(app);
    } else if(result == C5InputIgnored && app->screen == ScreenSerial &&
              event->key != InputKeyBack &&
              (event->type == InputTypeShort || event->type == InputTypeRepeat)) {
        simple_app_handle_serial_input(app, event->key);
    }
    if(app->viewport) view_port_update(app->viewport);
}

static void simple_app_handle_recon_input(SimpleApp* app, const InputEvent* event) {
    if(!app || !event || !app->recon_view_active) return;
    C5InputResult result = c5_module_runtime_input(&app->gps_module, event);
    if(result == C5InputOpenAttacks) {
        app->recon_open_attacks_pending = true;
        if(app->recon_mode != C5ReconModeScanner) app->recon_stations_selected = true;
        simple_app_request_module(app, C5ModuleRequestUnloadRecon);
        app->screen = ScreenReconLoading;
    } else if(result == C5InputSwitchModule ||
              (result == C5InputIgnored && event->type == InputTypeShort &&
               event->key == InputKeyBack)) {
        app->recon_open_attacks_pending = false;
        simple_app_request_module(app, C5ModuleRequestUnloadRecon);
        app->screen = ScreenReconLoading;
    } else if(result == C5InputSwitchTerminal) {
        app->recon_console_mode = true;
        app->screen = ScreenSerial;
        app->serial_follow_tail = true;
        simple_app_update_scroll(app);
    } else if(result == C5InputToggleConsole) {
        app->recon_console_mode = !app->recon_console_mode;
        app->screen = app->recon_console_mode ? ScreenSerial : ScreenRecon;
        app->serial_follow_tail = true;
        simple_app_update_scroll(app);
    } else if(result == C5InputIgnored && app->screen == ScreenSerial &&
              event->key != InputKeyBack &&
              (event->type == InputTypeShort || event->type == InputTypeRepeat)) {
        simple_app_handle_serial_input(app, event->key);
    }
    if(app->viewport) view_port_update(app->viewport);
}

static void simple_app_handle_attack_input(SimpleApp* app, const InputEvent* event) {
    if(!app || !event || !app->attack_view_active) return;
    if(event->type == InputTypeShort && event->key == InputKeyBack) app->last_back_tick = 0;
    C5InputResult result = c5_module_runtime_input(&app->gps_module, event);
    if(result == C5InputSwitchModule ||
       (result == C5InputIgnored && event->type == InputTypeShort &&
        (event->key == InputKeyBack || event->key == InputKeyLeft))) {
        simple_app_request_module(app, C5ModuleRequestUnloadAttack);
        app->screen = ScreenAttackLoading;
    }
    if(app->viewport) view_port_update(app->viewport);
}

static void simple_app_handle_confirm_exit_input(SimpleApp* app, InputKey key) {
    if(!app) return;
    if(key == InputKeyBack) {
        app->confirm_exit_yes = false;
        app->screen = ScreenMenu;
        app->menu_state = MenuStateSections;
        view_port_update(app->viewport);
        return;
    }

    if(key == InputKeyLeft || key == InputKeyRight) {
        app->confirm_exit_yes = !app->confirm_exit_yes;
        view_port_update(app->viewport);
        return;
    }

    if(key == InputKeyOk) {
        if(app->confirm_exit_yes) {
            app->exit_app = true;
        } else {
            app->confirm_exit_yes = false;
            app->screen = ScreenMenu;
            app->menu_state = MenuStateSections;
            view_port_update(app->viewport);
        }
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
            simple_app_reset_blackout_status(app);
            if(app->blackout_cycle == 0) app->blackout_cycle = 1;
            simple_app_blackout_set_phase(app, BlackoutPhaseStarting, "");
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
            app->sniffer_dog_view_active = true;
            simple_app_reset_sniffer_dog_status(app);
            simple_app_sniffer_dog_set_phase(app, SnifferDogPhaseStarting, "");
            simple_app_send_command(app, "start_sniffer_dog", true);
        } else {
            simple_app_focus_attacks_menu(app);
            view_port_update(app->viewport);
        }
    }
}

static void simple_app_package_monitor_reset(SimpleApp* app) {
    if(!app) return;
    if(app->package_monitor_history) {
        memset(app->package_monitor_history, 0, sizeof(uint16_t) * PACKAGE_MONITOR_MAX_HISTORY);
    }
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

    if(!app->package_monitor_history) return;

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

    simple_app_send_stop_if_needed(app);
    if(!simple_app_alloc_package_monitor_buffers(app)) {
        simple_app_show_status_message(app, "OOM: monitor", 1500, true);
        if(app->viewport) view_port_update(app->viewport);
        return;
    }
    if(reset_history) {
        simple_app_package_monitor_reset(app);
    }

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
    if(!simple_app_alloc_package_monitor_buffers(app)) {
        simple_app_show_status_message(app, "OOM: monitor", 1500, true);
        if(app->viewport) view_port_update(app->viewport);
        return;
    }
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

    if(!app->package_monitor_history) {
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str_aligned(
            canvas, DISPLAY_WIDTH / 2, 40, AlignCenter, AlignCenter, "OOM: history");
        return;
    }

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
        simple_app_free_package_monitor_buffers(app);
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
    if(app->channel_view_counts_24) {
        memset(app->channel_view_counts_24, 0, sizeof(uint16_t) * CHANNEL_VIEW_24GHZ_CHANNEL_COUNT);
    }
    if(app->channel_view_counts_5) {
        memset(app->channel_view_counts_5, 0, sizeof(uint16_t) * CHANNEL_VIEW_5GHZ_CHANNEL_COUNT);
    }
    if(app->channel_view_working_counts_24) {
        memset(
            app->channel_view_working_counts_24,
            0,
            sizeof(uint16_t) * CHANNEL_VIEW_24GHZ_CHANNEL_COUNT);
    }
    if(app->channel_view_working_counts_5) {
        memset(
            app->channel_view_working_counts_5,
            0,
            sizeof(uint16_t) * CHANNEL_VIEW_5GHZ_CHANNEL_COUNT);
    }
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
    if(!app->channel_view_working_counts_24 || !app->channel_view_working_counts_5) return;
    memset(
        app->channel_view_working_counts_24,
        0,
        sizeof(uint16_t) * CHANNEL_VIEW_24GHZ_CHANNEL_COUNT);
    memset(
        app->channel_view_working_counts_5,
        0,
        sizeof(uint16_t) * CHANNEL_VIEW_5GHZ_CHANNEL_COUNT);
    app->channel_view_section = ChannelViewSectionNone;
    app->channel_view_dataset_active = true;
}

static void simple_app_channel_view_commit_dataset(SimpleApp* app) {
    if(!app) return;
    if(!app->channel_view_counts_24 || !app->channel_view_counts_5 ||
       !app->channel_view_working_counts_24 || !app->channel_view_working_counts_5) {
        return;
    }
    memcpy(
        app->channel_view_counts_24,
        app->channel_view_working_counts_24,
        sizeof(uint16_t) * CHANNEL_VIEW_24GHZ_CHANNEL_COUNT);
    memcpy(
        app->channel_view_counts_5,
        app->channel_view_working_counts_5,
        sizeof(uint16_t) * CHANNEL_VIEW_5GHZ_CHANNEL_COUNT);
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
    if(!simple_app_alloc_channel_view_buffers(app)) {
        simple_app_show_status_message(app, "OOM: channels", 1500, true);
        if(app->viewport) view_port_update(app->viewport);
        return;
    }
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

    if(!app->channel_view_working_counts_24 || !app->channel_view_working_counts_5) {
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

    if(!app->channel_view_counts_24 || !app->channel_view_counts_5) {
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str_aligned(
            canvas, DISPLAY_WIDTH / 2, 40, AlignCenter, AlignCenter, "OOM: channels");
        return;
    }

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
        simple_app_free_channel_view_buffers(app);
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

typedef struct {
    ViewDispatcher* dispatcher;
    bool accepted;
} SimpleAppModuleInputContext;

static void simple_app_module_text_input_result(void* context) {
    SimpleAppModuleInputContext* input = context;
    if(!input || !input->dispatcher) return;
    input->accepted = true;
    view_dispatcher_stop(input->dispatcher);
}

static bool simple_app_module_text_input_navigation(void* context) {
    SimpleAppModuleInputContext* input = context;
    if(!input || !input->dispatcher) return false;
    input->accepted = false;
    view_dispatcher_stop(input->dispatcher);
    return true;
}

static void simple_app_run_module_text_input(SimpleApp* app) {
    if(!app || !app->gui || !app->viewport) return;

    C5TextInputRequest request;
    uint32_t generation;
    if(!c5_module_runtime_take_text_input(&app->gps_module, &request, &generation)) return;

    ViewDispatcher* dispatcher = view_dispatcher_alloc();
    if(!dispatcher) {
        c5_module_runtime_complete_text_input(&app->gps_module, generation, false, NULL, 0);
        c5_secure_clear(&request, sizeof(request));
        return;
    }
    TextInput* text_input = text_input_alloc();
    if(!text_input) {
        view_dispatcher_free(dispatcher);
        c5_module_runtime_complete_text_input(&app->gps_module, generation, false, NULL, 0);
        c5_secure_clear(&request, sizeof(request));
        return;
    }

    char value[C5_TEXT_INPUT_VALUE_CAPACITY];
    memcpy(value, request.initial, sizeof(value));
    value[sizeof(value) - 1] = '\0';
    SimpleAppModuleInputContext result = {
        .dispatcher = dispatcher,
        .accepted = false,
    };
    view_dispatcher_set_event_callback_context(dispatcher, &result);
    view_dispatcher_set_navigation_event_callback(
        dispatcher, simple_app_module_text_input_navigation);
    text_input_set_header_text(text_input, request.header);
    text_input_set_result_callback(
        text_input,
        simple_app_module_text_input_result,
        &result,
        value,
        request.capacity,
        false);
    if(request.minimum_length) {
        text_input_set_minimum_length(text_input, request.minimum_length);
    }
    view_dispatcher_add_view(dispatcher, 0, text_input_get_view(text_input));
    gui_remove_view_port(app->gui, app->viewport);
    view_dispatcher_attach_to_gui(dispatcher, app->gui, ViewDispatcherTypeFullscreen);
    view_dispatcher_switch_to_view(dispatcher, 0);
    view_dispatcher_run(dispatcher);

    view_dispatcher_remove_view(dispatcher, 0);
    view_dispatcher_free(dispatcher);
    text_input_free(text_input);
    gui_add_view_port(app->gui, app->viewport, GuiLayerFullscreen);
    view_port_update(app->viewport);

    c5_module_runtime_complete_text_input(
        &app->gps_module,
        generation,
        result.accepted,
        result.accepted ? value : NULL,
        result.accepted ? simple_app_bounded_strlen(value, request.capacity) : 0);
    c5_secure_clear(value, sizeof(value));
    c5_secure_clear(&request, sizeof(request));
}

typedef struct {
    ViewDispatcher* dispatcher;
    bool accepted;
} SimpleAppOtaInputContext;

static void simple_app_ota_text_input_result(void* context) {
    SimpleAppOtaInputContext* ctx = context;
    if(!ctx || !ctx->dispatcher) return;
    ctx->accepted = true;
    view_dispatcher_stop(ctx->dispatcher);
}

static bool simple_app_ota_text_input_navigation(void* context) {
    SimpleAppOtaInputContext* ctx = context;
    if(!ctx || !ctx->dispatcher) return false;
    ctx->accepted = false;
    view_dispatcher_stop(ctx->dispatcher);
    return true;
}

static bool simple_app_ota_run_text_input(SimpleApp* app) {
    if(!app || !app->gui || !app->viewport) return false;

    char* target = NULL;
    size_t max_len = 0;
    size_t min_len = 0;
    const char* header = NULL;
    switch(app->ota_input_field) {
    case OtaInputSsid:
        target = app->ota_ssid;
        max_len = sizeof(app->ota_ssid);
        min_len = 1;
        header = "WiFi SSID";
        break;
    case OtaInputPassword:
        target = app->ota_password;
        max_len = sizeof(app->ota_password);
        header = "WiFi Password";
        break;
    case OtaInputIp:
        target = app->ota_ip;
        max_len = sizeof(app->ota_ip);
        header = "Static IP";
        break;
    case OtaInputNetmask:
        target = app->ota_netmask;
        max_len = sizeof(app->ota_netmask);
        header = "Netmask";
        break;
    case OtaInputGw:
        target = app->ota_gw;
        max_len = sizeof(app->ota_gw);
        header = "Gateway";
        break;
    case OtaInputDns:
        target = app->ota_dns;
        max_len = sizeof(app->ota_dns);
        header = "DNS";
        break;
    default:
        return false;
    }

    if(!target || max_len < 2 || !header) return false;

    bool viewport_detached = false;
    char buffer[OTA_PASS_MAX_LEN];
    if(max_len > sizeof(buffer)) {
        max_len = sizeof(buffer);
    }
    strncpy(buffer, target, max_len - 1);
    buffer[max_len - 1] = '\0';

    ViewDispatcher* dispatcher = view_dispatcher_alloc();
    if(!dispatcher) return false;

    TextInput* text_input = text_input_alloc();
    if(!text_input) {
        view_dispatcher_free(dispatcher);
        return false;
    }

    SimpleAppOtaInputContext ctx = {
        .dispatcher = dispatcher,
        .accepted = false,
    };

    view_dispatcher_set_event_callback_context(dispatcher, &ctx);
    view_dispatcher_set_navigation_event_callback(dispatcher, simple_app_ota_text_input_navigation);

    text_input_set_header_text(text_input, header);
    text_input_set_result_callback(
        text_input,
        simple_app_ota_text_input_result,
        &ctx,
        buffer,
        max_len,
        false);
    if(min_len > 0) {
        text_input_set_minimum_length(text_input, min_len);
    }

    view_dispatcher_add_view(dispatcher, 0, text_input_get_view(text_input));

    gui_remove_view_port(app->gui, app->viewport);
    viewport_detached = true;
    app->ota_input_active = true;

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
    app->ota_input_active = false;

    if(ctx.accepted) {
        strncpy(target, buffer, max_len - 1);
        target[max_len - 1] = '\0';
        simple_app_trim(target);
    }

    return ctx.accepted;
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

    if(simple_app_status_message_is_active(app) && !app->status_message_fullscreen) {
        canvas_draw_str(canvas, 2, 52, app->status_message);
    }
    if(show_setup_branding) {
        char version_text[24];
        snprintf(version_text, sizeof(version_text), "v.%s", LAB_C5_VERSION_TEXT);
        canvas_draw_str_aligned(canvas, DISPLAY_WIDTH - 15, 11, AlignRight, AlignBottom, version_text);
    }

    if(app->menu_state == MenuStateSections) {
        size_t visible_sections = simple_app_section_visible_count();
        if(visible_sections == 0) visible_sections = 1;
        simple_app_adjust_section_offset(app);

        canvas_set_font(canvas, FontPrimary);
        for(size_t i = 0; i < visible_sections; i++) {
            size_t idx = app->section_offset + i;
            if(idx >= menu_section_count) break;
            uint8_t y = MENU_SECTION_BASE_Y + (uint8_t)(i * MENU_SECTION_SPACING);
            const char* title = (idx == MENU_SECTION_ATTACKS && !app->red_team_mode)
                                    ? "Tests"
                                    : menu_sections[idx].title;
            if(app->section_index == idx) {
                canvas_draw_str(canvas, 0, y, ">");
                canvas_draw_str(canvas, 12, y, title);
            } else {
                canvas_draw_str(canvas, 6, y, title);
            }
        }

        if(menu_section_count > visible_sections) {
            bool show_up = (app->section_offset > 0);
            bool show_down = (app->section_offset + visible_sections < menu_section_count);
            if(show_up || show_down) {
                uint8_t arrow_x = DISPLAY_WIDTH - 6;
                int16_t content_top = MENU_SECTION_BASE_Y;
                int16_t content_bottom =
                    MENU_SECTION_BASE_Y + (int16_t)((visible_sections - 1) * MENU_SECTION_SPACING);
                simple_app_draw_scroll_hints_clamped(
                    canvas, arrow_x, content_top, content_bottom, show_up, show_down, 12, 44);
            }
        }
        return;
    }

    if(app->section_index >= menu_section_count) {
        app->section_index = 0;
    }

    const MenuSection* section = &menu_sections[app->section_index];
    size_t entry_count = simple_app_menu_entry_count(app, app->section_index);

    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(
        canvas,
        3,
        MENU_TITLE_Y,
        (app->section_index == MENU_SECTION_ATTACKS && !app->red_team_mode) ? "Tests" : section->title);

    canvas_set_font(canvas, FontSecondary);

    size_t visible_count = simple_app_menu_visible_count(app, app->section_index);
    if(visible_count == 0) {
        visible_count = 1;
    }

    if(entry_count == 0) {
        const char* hint = "No options";
        if(app->section_index == MENU_SECTION_SCANNER) {
            hint = "OK: Scan networks";
        }
        canvas_draw_str(canvas, 3, MENU_ITEM_BASE_Y + (MENU_ITEM_SPACING / 2), hint);
        return;
    }

    if(app->item_index >= entry_count) {
        app->item_index = entry_count - 1;
    }

    size_t max_offset = 0;
    if(entry_count > visible_count) {
        max_offset = entry_count - visible_count;
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
        if(idx >= entry_count) break;
        const MenuEntry* entry = simple_app_menu_entry_at(app, app->section_index, idx);
        if(!entry) break;
        uint8_t y = MENU_ITEM_BASE_Y + i * MENU_ITEM_SPACING;

        if(idx == app->item_index) {
            canvas_draw_str(canvas, 2, y, ">");
            canvas_draw_str(canvas, 12, y, entry->label);
        } else {
            canvas_draw_str(canvas, 8, y, entry->label);
        }
    }

    if(entry_count > visible_count) {
        bool show_up = (app->item_offset > 0);
        bool show_down = (app->item_offset + visible_count < entry_count);
        if(show_up || show_down) {
            uint8_t arrow_x = DISPLAY_WIDTH - 6;
            uint8_t max_rows =
                (entry_count < visible_count) ? entry_count : visible_count;
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

static void simple_app_draw_deauth_guard(SimpleApp* app, Canvas* canvas) {
    if(!app || !canvas) return;

    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, 14, AlignCenter, AlignCenter, "Deauth Guard");

    canvas_set_font(canvas, FontSecondary);
    if(!app->deauth_guard_has_detection) {
        if(app->deauth_guard_monitoring) {
            canvas_draw_str_aligned(
                canvas, DISPLAY_WIDTH / 2, 32, AlignCenter, AlignCenter, "Monitoring...");
            canvas_draw_str_aligned(
                canvas, DISPLAY_WIDTH / 2, 48, AlignCenter, AlignCenter, "No deauths detected");
        } else {
            canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, 32, AlignCenter, AlignCenter, "Warm up...");
            canvas_draw_str_aligned(
                canvas, DISPLAY_WIDTH / 2, 48, AlignCenter, AlignCenter, "Listening for deauths");
        }
        return;
    }

    canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, 30, AlignCenter, AlignCenter, "Attack ongoing!");
    char status_line[48];
    if(app->deauth_guard_last_channel > 0) {
        if(app->deauth_guard_has_rssi) {
            snprintf(
                status_line,
                sizeof(status_line),
                "CH %d | RSSI %d",
                app->deauth_guard_last_channel,
                app->deauth_guard_last_rssi);
        } else {
            snprintf(status_line, sizeof(status_line), "CH %d", app->deauth_guard_last_channel);
        }
    } else {
        snprintf(status_line, sizeof(status_line), "Channel: ?");
    }
    canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, 44, AlignCenter, AlignCenter, status_line);

    char ssid_line[SCAN_SSID_MAX_LEN + 8];
    snprintf(
        ssid_line,
        sizeof(ssid_line),
        "%s",
        (app->deauth_guard_last_ssid[0] != '\0') ? app->deauth_guard_last_ssid : "Unknown SSID");
    canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, 58, AlignCenter, AlignCenter, ssid_line);
}

static void simple_app_draw_deauth_overlay(SimpleApp* app, Canvas* canvas) {
    if(!app || !canvas) return;

    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str(canvas, 2, 12, "Deauth");
    if(app->deauth_running) {
        bool blink_on = ((furi_get_tick() / furi_ms_to_ticks(500)) % 2) == 0;
        if(blink_on) {
            canvas_draw_str_aligned(
                canvas, DISPLAY_WIDTH / 2, 12, AlignCenter, AlignBottom, "Running");
        }
    }

    size_t saved_target_count = simple_app_target_count(app);
    uint32_t target_count = saved_target_count ? (uint32_t)saved_target_count : app->deauth_targets;
    char header_right[24];
    if(target_count > 0) {
        snprintf(header_right, sizeof(header_right), "Targets:%lu", (unsigned long)target_count);
    } else {
        snprintf(header_right, sizeof(header_right), "Targets:--");
    }
    canvas_draw_str_aligned(
        canvas, DISPLAY_WIDTH - 2, 12, AlignRight, AlignBottom, header_right);

    if(saved_target_count == 0 || !app->recon_targets.targets) {
        canvas_draw_str_aligned(
            canvas, DISPLAY_WIDTH / 2, 36, AlignCenter, AlignCenter, "No target list");
        return;
    }

    size_t visible = 4;
    size_t max_offset = saved_target_count > visible ? saved_target_count - visible : 0;
    size_t offset = app->deauth_list_offset;
    if(offset > max_offset) offset = max_offset;

    canvas_set_font(canvas, FontSecondary);
    for(size_t i = 0; i < visible; i++) {
        size_t idx = offset + i;
        if(idx >= saved_target_count) break;
        const C5ReconTarget* result = &app->recon_targets.targets[idx];
        uint16_t number = result->number;
        char line[32];
        if(result) {
            char ssid_ascii[SCAN_SSID_MAX_LEN];
            simple_app_utf8_to_ascii_pl(result->ssid, ssid_ascii, sizeof(ssid_ascii));
            simple_app_trim(ssid_ascii);
            if(ssid_ascii[0] == '\0') {
                strncpy(ssid_ascii, "Hidden", sizeof(ssid_ascii) - 1);
                ssid_ascii[sizeof(ssid_ascii) - 1] = '\0';
            }

            char channel_short[4];
            if(result->channel > 0) {
                snprintf(channel_short, sizeof(channel_short), "%u", (unsigned)result->channel);
            } else {
                strncpy(channel_short, "--", sizeof(channel_short) - 1);
                channel_short[sizeof(channel_short) - 1] = '\0';
            }

            char bssid_text[18];
            simple_app_format_bssid(result->bssid, bssid_text, sizeof(bssid_text));

            char idx_buf[6];
            unsigned idx_value = (unsigned)(idx + 1);
            if(idx_value > 9999U) idx_value = 9999U;
            snprintf(idx_buf, sizeof(idx_buf), "%2u", idx_value);

            char full_line[96];
            size_t pos = 0;
            size_t chunk = strlen(idx_buf);
            if(chunk > sizeof(full_line) - pos - 1) chunk = sizeof(full_line) - pos - 1;
            memcpy(full_line + pos, idx_buf, chunk);
            pos += chunk;
            if(pos < sizeof(full_line) - 1) {
                full_line[pos++] = ' ';
            }
            if(pos < sizeof(full_line) - 1) {
                full_line[pos++] = 'C';
            }
            if(pos < sizeof(full_line) - 1) {
                full_line[pos++] = 'H';
            }
            chunk = strlen(channel_short);
            if(chunk > sizeof(full_line) - pos - 1) chunk = sizeof(full_line) - pos - 1;
            memcpy(full_line + pos, channel_short, chunk);
            pos += chunk;
            if(pos < sizeof(full_line) - 1) {
                full_line[pos++] = ' ';
            }
            chunk = strlen(ssid_ascii);
            if(chunk > sizeof(full_line) - pos - 1) chunk = sizeof(full_line) - pos - 1;
            memcpy(full_line + pos, ssid_ascii, chunk);
            pos += chunk;
            if(pos < sizeof(full_line) - 1) {
                full_line[pos++] = ' ';
            }
            chunk = strlen(bssid_text);
            if(chunk > sizeof(full_line) - pos - 1) chunk = sizeof(full_line) - pos - 1;
            memcpy(full_line + pos, bssid_text, chunk);
            pos += chunk;
            full_line[pos] = '\0';

            char default_line[64];
            size_t dpos = 0;
            chunk = strlen(idx_buf);
            if(chunk > sizeof(default_line) - dpos - 1) chunk = sizeof(default_line) - dpos - 1;
            memcpy(default_line + dpos, idx_buf, chunk);
            dpos += chunk;
            if(dpos < sizeof(default_line) - 1) {
                default_line[dpos++] = ' ';
            }
            if(dpos < sizeof(default_line) - 1) {
                default_line[dpos++] = 'C';
            }
            if(dpos < sizeof(default_line) - 1) {
                default_line[dpos++] = 'H';
            }
            chunk = strlen(channel_short);
            if(chunk > sizeof(default_line) - dpos - 1) chunk = sizeof(default_line) - dpos - 1;
            memcpy(default_line + dpos, channel_short, chunk);
            dpos += chunk;
            if(dpos < sizeof(default_line) - 1) {
                default_line[dpos++] = ' ';
            }

            char bssid_tail[6];
            size_t bssid_len = strlen(bssid_text);
            const char* tail_ptr =
                (bssid_len > 5) ? (bssid_text + bssid_len - 5) : bssid_text;
            strncpy(bssid_tail, tail_ptr, sizeof(bssid_tail) - 1);
            bssid_tail[sizeof(bssid_tail) - 1] = '\0';

            size_t prefix_len = dpos;
            size_t tail_len = strlen(bssid_tail);
            size_t max_ssid = 0;
            if(SERIAL_LINE_CHAR_LIMIT > prefix_len) {
                max_ssid = SERIAL_LINE_CHAR_LIMIT - prefix_len;
                if(tail_len > 0 && max_ssid > (tail_len + 1)) {
                    max_ssid -= (tail_len + 1);
                } else if(tail_len > 0 && max_ssid <= (tail_len + 1)) {
                    max_ssid = 0;
                }
            }
            chunk = strlen(ssid_ascii);
            if(chunk > max_ssid) chunk = max_ssid;
            if(chunk > 0 && dpos < sizeof(default_line) - 1) {
                if(chunk > sizeof(default_line) - dpos - 1) chunk = sizeof(default_line) - dpos - 1;
                memcpy(default_line + dpos, ssid_ascii, chunk);
                dpos += chunk;
            }
            if(tail_len > 0 && dpos < sizeof(default_line) - 1) {
                default_line[dpos++] = ' ';
                chunk = tail_len;
                if(chunk > sizeof(default_line) - dpos - 1) chunk = sizeof(default_line) - dpos - 1;
                memcpy(default_line + dpos, bssid_tail, chunk);
                dpos += chunk;
            }
            default_line[dpos] = '\0';

            size_t len = strlen(full_line);
            size_t offset_x = app->deauth_list_scroll_x;
            if(offset_x == 0) {
                len = strlen(default_line);
                size_t copy_len = len;
                if(copy_len > SERIAL_LINE_CHAR_LIMIT) copy_len = SERIAL_LINE_CHAR_LIMIT;
                memcpy(line, default_line, copy_len);
                line[copy_len] = '\0';
            } else {
                if(len <= SERIAL_LINE_CHAR_LIMIT) {
                    offset_x = 0;
                } else if(offset_x > len - SERIAL_LINE_CHAR_LIMIT) {
                    offset_x = len - SERIAL_LINE_CHAR_LIMIT;
                }
                size_t copy_len = len - offset_x;
                if(copy_len > SERIAL_LINE_CHAR_LIMIT) copy_len = SERIAL_LINE_CHAR_LIMIT;
                memcpy(line, full_line + offset_x, copy_len);
                line[copy_len] = '\0';
            }
        } else {
            snprintf(line, sizeof(line), "ID %u (no data)", (unsigned)number);
        }

        uint8_t y = (uint8_t)(26 + (i * SERIAL_TEXT_LINE_HEIGHT));
        canvas_draw_str(canvas, 2, y, line);
    }
}

static void simple_app_draw_handshake_overlay(SimpleApp* app, Canvas* canvas) {
    if(!app || !canvas) return;

    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str(canvas, 2, 12, "Handshaker  ");

    char targets_line[32];
    snprintf(
        targets_line,
        sizeof(targets_line),
        "Targets:%lu",
        (unsigned long)app->handshake_targets);
    canvas_draw_str_aligned(
        canvas, DISPLAY_WIDTH - 2, 12, AlignRight, AlignBottom, targets_line);

    canvas_set_font(canvas, FontPrimary);
    char count_line[32];
    snprintf(
        count_line,
        sizeof(count_line),
        "Captured: %lu",
        (unsigned long)app->handshake_captured);
    canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, 28, AlignCenter, AlignCenter, count_line);

    canvas_set_font(canvas, FontSecondary);
    char ssid_line[32];
    if(app->handshake_ssid[0] != '\0') {
        snprintf(
            ssid_line,
            sizeof(ssid_line),
            "SSID: %.*s",
            (int)(sizeof(ssid_line) - 7),
            app->handshake_ssid);
        simple_app_truncate_text(ssid_line, SERIAL_LINE_CHAR_LIMIT);
        canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, 42, AlignCenter, AlignCenter, ssid_line);
    } else {
        ssid_line[0] = '\0';
    }

    char stage_line[32];
    if(app->handshake_note[0] != '\0') {
        snprintf(
            stage_line,
            sizeof(stage_line),
            "Stage: %.*s",
            (int)(sizeof(stage_line) - 8),
            app->handshake_note);
    } else {
        snprintf(stage_line, sizeof(stage_line), "Stage: --");
    }
    simple_app_truncate_text(stage_line, SERIAL_LINE_CHAR_LIMIT);
    canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, 54, AlignCenter, AlignCenter, stage_line);
}

static void simple_app_draw_sae_overlay(SimpleApp* app, Canvas* canvas) {
    if(!app || !canvas) return;

    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str(canvas, 2, 12, "SAE Overflow");

    canvas_set_font(canvas, FontPrimary);
    char stage_line[24];
    if(app->sae_running) {
        snprintf(stage_line, sizeof(stage_line), "Stage: Running");
    } else {
        snprintf(stage_line, sizeof(stage_line), "Stage: --");
    }
    canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, 28, AlignCenter, AlignCenter, stage_line);

    canvas_set_font(canvas, FontSecondary);
    if(app->sae_ssid[0] != '\0') {
        char ssid_line[32];
        snprintf(
            ssid_line,
            sizeof(ssid_line),
            "SSID: %.*s",
            (int)(sizeof(ssid_line) - 7),
            app->sae_ssid);
        simple_app_truncate_text(ssid_line, SERIAL_LINE_CHAR_LIMIT);
        canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, 42, AlignCenter, AlignCenter, ssid_line);
    }

    if(app->sae_has_channel) {
        char ch_line[16];
        snprintf(ch_line, sizeof(ch_line), "CH: %u", (unsigned)app->sae_channel);
        canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, 54, AlignCenter, AlignCenter, ch_line);
    }
}

static void simple_app_draw_blackout_overlay(SimpleApp* app, Canvas* canvas) {
    if(!app || !canvas) return;

    const char* status = "Idle";
    switch(app->blackout_phase) {
    case BlackoutPhaseStarting:
        status = "Starting";
        break;
    case BlackoutPhaseScanning:
        status = "Scanning";
        break;
    case BlackoutPhaseSorting:
        status = "Sorting";
        break;
    case BlackoutPhaseAttacking:
        status = "Attacking";
        break;
    case BlackoutPhaseStopping:
        status = "Stopping";
        break;
    case BlackoutPhaseFinished:
        status = "Done";
        break;
    case BlackoutPhaseIdle:
    default:
        status = "Idle";
        break;
    }

    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str(canvas, 2, 12, "Blackout");
    canvas_draw_str_aligned(canvas, DISPLAY_WIDTH - 2, 12, AlignRight, AlignBottom, status);

    canvas_set_font(canvas, FontPrimary);
    char targets_line[32];
    if(app->blackout_networks > 0) {
        snprintf(targets_line, sizeof(targets_line), "Targets: %lu", (unsigned long)app->blackout_networks);
    } else {
        snprintf(targets_line, sizeof(targets_line), "Targets: --");
    }
    canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, 28, AlignCenter, AlignCenter, targets_line);

    canvas_set_font(canvas, FontSecondary);
    char mid_line[32];
    if(app->blackout_note[0] != '\0') {
        const int note_limit = 20;
        snprintf(mid_line, sizeof(mid_line), "Note: %.*s", note_limit, app->blackout_note);
    } else if(app->blackout_cycle > 0) {
        snprintf(mid_line, sizeof(mid_line), "Cycle: %lu", (unsigned long)app->blackout_cycle);
    } else {
        snprintf(mid_line, sizeof(mid_line), "Cycle: --");
    }
    simple_app_truncate_text(mid_line, SERIAL_LINE_CHAR_LIMIT);
    canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, 42, AlignCenter, AlignCenter, mid_line);

    char channel_line[32];
    if(app->blackout_has_channel && app->blackout_channel > 0) {
        snprintf(channel_line, sizeof(channel_line), "Channel: %u", app->blackout_channel);
    } else {
        snprintf(channel_line, sizeof(channel_line), "Channel: --");
    }
    canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, 54, AlignCenter, AlignCenter, channel_line);
}

static void simple_app_draw_sniffer_dog_overlay(SimpleApp* app, Canvas* canvas) {
    if(!app || !canvas) return;

    const char* status = "Idle";
    switch(app->sniffer_dog_phase) {
    case SnifferDogPhaseStarting:
        status = "Starting";
        break;
    case SnifferDogPhaseHunting:
        status = "Hunting";
        break;
    case SnifferDogPhaseStopping:
        status = "Stopping";
        break;
    case SnifferDogPhaseError:
        status = "Error";
        break;
    case SnifferDogPhaseFinished:
        status = "Done";
        break;
    case SnifferDogPhaseIdle:
    default:
        status = "Idle";
        break;
    }

    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str(canvas, 2, 12, "Sniffer Dog");
    canvas_draw_str_aligned(canvas, DISPLAY_WIDTH - 2, 12, AlignRight, AlignBottom, status);

    canvas_set_font(canvas, FontPrimary);
    char deauth_line[32];
    if(app->sniffer_dog_deauth_count > 0) {
        snprintf(deauth_line, sizeof(deauth_line), "Deauth: %lu", (unsigned long)app->sniffer_dog_deauth_count);
    } else {
        snprintf(deauth_line, sizeof(deauth_line), "Deauth: --");
    }
    canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, 28, AlignCenter, AlignCenter, deauth_line);

    canvas_set_font(canvas, FontSecondary);
    char mid_line[32];
    if(app->sniffer_dog_note[0] != '\0') {
        const int note_limit = 20;
        snprintf(mid_line, sizeof(mid_line), "Note: %.*s", note_limit, app->sniffer_dog_note);
    } else if(app->sniffer_dog_has_channel) {
        if(app->sniffer_dog_has_rssi) {
            snprintf(
                mid_line,
                sizeof(mid_line),
                "CH %u | RSSI %d",
                app->sniffer_dog_channel,
                app->sniffer_dog_rssi);
        } else {
            snprintf(mid_line, sizeof(mid_line), "CH %u", app->sniffer_dog_channel);
        }
    } else {
        snprintf(mid_line, sizeof(mid_line), "Channel: --");
    }
    simple_app_truncate_text(mid_line, SERIAL_LINE_CHAR_LIMIT);
    canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, 42, AlignCenter, AlignCenter, mid_line);

    char phase_line[32];
    if(app->sniffer_dog_running) {
        snprintf(phase_line, sizeof(phase_line), "Ongoing");
    } else if(app->sniffer_dog_phase == SnifferDogPhaseFinished) {
        snprintf(phase_line, sizeof(phase_line), "Stopped");
    } else {
        snprintf(phase_line, sizeof(phase_line), "--");
    }
    canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, 54, AlignCenter, AlignCenter, phase_line);
}




static void simple_app_draw_bt_scan_overlay(SimpleApp* app, Canvas* canvas) {
    if(!app || !canvas) return;

    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontSecondary);

    char status_line[48];
    if(app->bt_scan_running) {
        snprintf(status_line, sizeof(status_line), "Scanning...");
    } else if(app->bt_scan_has_data) {
        snprintf(status_line, sizeof(status_line), "Done");
    } else {
        snprintf(status_line, sizeof(status_line), "Waiting...");
    }

    canvas_draw_str(canvas, 2, 12, "BT Scan");
    canvas_draw_str_aligned(canvas, DISPLAY_WIDTH - 2, 12, AlignRight, AlignBottom, status_line);

    canvas_set_font(canvas, FontPrimary);
    char total_line[24];
    snprintf(total_line, sizeof(total_line), "Total: %d", app->bt_scan_total);
    canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, 28, AlignCenter, AlignCenter, total_line);

    canvas_set_font(canvas, FontSecondary);
    int other = app->bt_scan_total - app->bt_scan_airtags - app->bt_scan_smarttags;
    if(other < 0) other = 0;
    char line1[32];
    char line2[32];
    snprintf(line1, sizeof(line1), "AirTags:%d Smart:%d", app->bt_scan_airtags, app->bt_scan_smarttags);
    snprintf(line2, sizeof(line2), "Others:%d", other);
    canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, 42, AlignCenter, AlignCenter, line1);
    canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, 54, AlignCenter, AlignCenter, line2);

    if(!app->bt_scan_running && app->bt_scan_has_data && app->bt_scan_total > 0) {
        canvas_draw_str_aligned(canvas, DISPLAY_WIDTH - 4, DISPLAY_HEIGHT - 2, AlignRight, AlignBottom, "->");
    }
}


static void simple_app_draw_bt_scan_list(SimpleApp* app, Canvas* canvas) {
    if(!app || !canvas) return;
    canvas_set_color(canvas, ColorBlack);
    if(!app->bt_scan_preview) {
        canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, 36, AlignCenter, AlignCenter, "BT buffers OOM");
        return;
    }

    if(app->bt_scan_preview_count == 0) {
        canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, 36, AlignCenter, AlignCenter, "No parsed devices yet");
        return;
    }

    canvas_set_font(canvas, FontSecondary);
    const size_t char_limit = 21;
    const uint8_t list_top = 10;
    const uint8_t list_bottom = DISPLAY_HEIGHT - 2;
    uint8_t y = list_top;
    uint8_t max_lines =
        (uint8_t)((list_bottom - list_top + SERIAL_TEXT_LINE_HEIGHT) / SERIAL_TEXT_LINE_HEIGHT);
    if(max_lines > 6) max_lines = 6;
    if(max_lines == 0) max_lines = 1;

    if(app->bt_scan_list_offset >= app->bt_scan_preview_count) {
        app->bt_scan_list_offset = (app->bt_scan_preview_count > 0) ? (app->bt_scan_preview_count - 1) : 0;
    }

    size_t lines_used = 0;
    size_t last_drawn = (size_t)-1;
    bool drew_any = false;
    for(size_t i = app->bt_scan_list_offset; i < app->bt_scan_preview_count; i++) {
        BtScanPreview* p = &app->bt_scan_preview[i];
        uint8_t item_h = simple_app_bt_scan_item_height(p);
        if(lines_used + item_h > max_lines) break;

        char line[64];
        snprintf(line, sizeof(line), "%s %d", p->mac, p->rssi);

        const char* to_draw = line;
        char scroll_buf[64];
        size_t len = strlen(line);
        if(len > char_limit && app->bt_locator_scroll_text) {
            if(strncmp(app->bt_locator_scroll_text, line, BT_LOCATOR_SCROLL_TEXT_LEN) != 0) {
                simple_app_bt_locator_set_scroll_text(app, line);
            }
            simple_app_bt_locator_tick_scroll(app, char_limit);
            size_t offset = app->bt_locator_scroll_offset;
            if(offset >= len) offset = 0;
            size_t copy_len = (len - offset > char_limit) ? char_limit : (len - offset);
            memcpy(scroll_buf, line + offset, copy_len);
            scroll_buf[copy_len] = '\0';
            to_draw = scroll_buf;
        } else {
            simple_app_bt_locator_reset_scroll(app);
        }
        canvas_draw_str(canvas, 4, y, to_draw);
        y += SERIAL_TEXT_LINE_HEIGHT;
        lines_used++;
        drew_any = true;

        if(p->has_name && p->name[0] != '\0' && lines_used < max_lines) {
            char name_buf[48];
            strncpy(name_buf, p->name, sizeof(name_buf) - 1);
            name_buf[sizeof(name_buf) - 1] = '\0';
            simple_app_truncate_text(name_buf, char_limit);
            canvas_draw_str(canvas, 12, y, name_buf);
            y += SERIAL_TEXT_LINE_HEIGHT;
            lines_used++;
        }
        last_drawn = i;
    }

    if(app->bt_scan_preview_count > 0 && drew_any) {
        bool show_up = app->bt_scan_list_offset > 0;
        bool show_down = (last_drawn + 1) < app->bt_scan_preview_count;
        if(show_up || show_down) {
            uint8_t arrow_x = DISPLAY_WIDTH - 6;
            int16_t content_top = list_top;
            int16_t content_bottom = y - 2;
            simple_app_draw_scroll_hints(canvas, arrow_x, content_top, content_bottom, show_up, show_down);
        }
    }
}

static void simple_app_draw_airtag_overlay(SimpleApp* app, Canvas* canvas) {
    if(!app || !canvas) return;

    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontSecondary);

    char status_line[48];
    if(app->bt_scan_running) {
        snprintf(status_line, sizeof(status_line), "Scanning...");
    } else if(app->bt_scan_has_data) {
        snprintf(status_line, sizeof(status_line), "Done");
    } else {
        snprintf(status_line, sizeof(status_line), "Waiting...");
    }

    canvas_draw_str(canvas, 2, 12, "AirTag Scan");
    canvas_draw_str_aligned(canvas, DISPLAY_WIDTH - 2, 12, AlignRight, AlignBottom, status_line);

    canvas_set_font(canvas, FontPrimary);
    char total_line[24];
    snprintf(total_line, sizeof(total_line), "Total: %d", app->bt_scan_total);
    canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, 28, AlignCenter, AlignCenter, total_line);

    canvas_set_font(canvas, FontSecondary);
    int other = app->bt_scan_total - app->bt_scan_airtags - app->bt_scan_smarttags;
    if(other < 0) other = 0;
    char line1[32];
    char line2[32];
    snprintf(line1, sizeof(line1), "AirTags: %d", app->bt_scan_airtags);
    snprintf(line2, sizeof(line2), "Smart:%d Other:%d", app->bt_scan_smarttags, other);
    canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, 42, AlignCenter, AlignCenter, line1);
    canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, 54, AlignCenter, AlignCenter, line2);

    if(!app->bt_scan_running && app->bt_scan_has_data && app->bt_scan_total > 0) {
        canvas_draw_str_aligned(canvas, DISPLAY_WIDTH - 4, DISPLAY_HEIGHT - 2, AlignRight, AlignBottom, "->");
    }
}

static void simple_app_draw_bt_locator(SimpleApp* app, Canvas* canvas) {
    if(!app || !canvas) return;
    if(!app->bt_locator_devices) {
        canvas_set_color(canvas, ColorBlack);
        canvas_set_font(canvas, FontPrimary);
        canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, 32, AlignCenter, AlignCenter, "BT buffers OOM");
        return;
    }

    canvas_set_color(canvas, ColorBlack);
    uint32_t now_ticks = furi_get_tick();
    uint32_t ticks_per_second = furi_ms_to_ticks(1000);
    if(ticks_per_second == 0) ticks_per_second = 1;
    uint32_t warmup_ticks = furi_ms_to_ticks(BT_LOCATOR_WARMUP_MS);
    if(warmup_ticks == 0) warmup_ticks = 1;
    uint32_t warmup_elapsed =
        (app->bt_locator_start_tick > 0) ? (now_ticks - app->bt_locator_start_tick) : 0;
    uint32_t console_elapsed =
        (app->bt_locator_last_console_tick > 0) ? (now_ticks - app->bt_locator_last_console_tick) : warmup_elapsed;
    bool warmup_active = !app->bt_locator_has_rssi &&
                         ((app->bt_locator_start_tick > 0 && warmup_elapsed < warmup_ticks) ||
                          (app->bt_locator_last_console_tick > 0 && console_elapsed < warmup_ticks));

    const char* mac = NULL;
    if(app->bt_locator_mac[0] != '\0') {
        mac = app->bt_locator_mac;
    } else if(app->bt_locator_saved_mac[0] != '\0') {
        mac = app->bt_locator_saved_mac;
    } else if(app->bt_locator_selected >= 0 && app->bt_locator_selected < (int32_t)app->bt_locator_count) {
        mac = app->bt_locator_devices[app->bt_locator_selected].mac;
    }
    if(!mac || mac[0] == '\0' || mac[0] == '>' || (mac[0] == 'U' && mac[1] == 's')) {
        mac = (app->bt_locator_saved_mac[0] != '\0') ? app->bt_locator_saved_mac : "No MAC";
    }
    canvas_set_font(canvas, FontSecondary);
    const uint8_t mac_y = 12;
    const uint8_t name_y = 22;
    const uint8_t rssi_y = 36;
    const uint8_t quality_y = 50;
    const uint8_t status_y = 62;

    canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, mac_y, AlignCenter, AlignCenter, mac);

    canvas_set_font(canvas, FontPrimary);
    char rssi_line[32];
    if(app->bt_locator_has_rssi) {
        snprintf(rssi_line, sizeof(rssi_line), "RSSI: %d dBm", app->bt_locator_rssi);
    } else {
        snprintf(rssi_line, sizeof(rssi_line), "RSSI: N/A");
    }
    canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, rssi_y, AlignCenter, AlignCenter, rssi_line);

    canvas_set_font(canvas, FontSecondary);
    const char* quality = warmup_active ? "Warm up" : "No signal";
    if(app->bt_locator_has_rssi) {
        if(app->bt_locator_rssi >= -60) {
            quality = "Great";
        } else if(app->bt_locator_rssi >= -75) {
            quality = "Good";
        } else if(app->bt_locator_rssi >= -90) {
            quality = "Poor";
        } else {
            quality = "Very weak";
        }
    }
    canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, quality_y, AlignCenter, AlignCenter, quality);

    // Use free space to show the device name (if known)
    const char* name_ptr = NULL;
    if(app->bt_locator_current_name[0] != '\0') {
        name_ptr = app->bt_locator_current_name;
    } else if(app->bt_locator_selected >= 0 && (size_t)app->bt_locator_selected < app->bt_locator_count) {
        const char* n = app->bt_locator_devices[app->bt_locator_selected].name;
        if(n && n[0] != '\0') name_ptr = n;
    } else {
        for(size_t i = 0; i < app->bt_locator_count; i++) {
            if(strncmp(app->bt_locator_devices[i].mac, mac, sizeof(app->bt_locator_devices[i].mac)) == 0) {
                if(app->bt_locator_devices[i].name[0] != '\0') {
                    name_ptr = app->bt_locator_devices[i].name;
                }
                break;
            }
        }
    }
    if(name_ptr) {
        char name_line[40];
        strncpy(name_line, name_ptr, sizeof(name_line) - 1);
        name_line[sizeof(name_line) - 1] = '\0';
        simple_app_truncate_text(name_line, 19);
        canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, name_y, AlignCenter, AlignCenter, name_line);
    }

    char status_line[48];
    if(app->bt_scan_running) {
        snprintf(status_line, sizeof(status_line), "Scanning...");
    } else if(app->bt_locator_list_ready) {
        snprintf(status_line, sizeof(status_line), "Done");
    } else if(app->bt_scan_last_update_tick > 0) {
        uint32_t elapsed = (now_ticks - app->bt_scan_last_update_tick) / ticks_per_second;
        snprintf(status_line, sizeof(status_line), "Updated: %lus ago", (unsigned long)elapsed);
    } else if(warmup_active) {
        uint32_t basis = warmup_elapsed;
        if(app->bt_locator_last_console_tick > 0) {
            uint32_t console_elapsed_local = (app->bt_locator_last_console_tick <= now_ticks)
                                                 ? (now_ticks - app->bt_locator_last_console_tick)
                                                 : 0;
            if(console_elapsed_local < basis || app->bt_locator_start_tick == 0) {
                basis = console_elapsed_local;
            }
        }
        uint32_t remaining_ticks = (basis < warmup_ticks) ? (warmup_ticks - basis) : 0;
        uint32_t remaining_seconds = (remaining_ticks + ticks_per_second - 1) / ticks_per_second;
        snprintf(status_line, sizeof(status_line), "Warm up... %lus", (unsigned long)remaining_seconds);
    } else {
        snprintf(status_line, sizeof(status_line), "No data");
    }
    canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, status_y, AlignCenter, AlignBottom, status_line);

    if(app->bt_locator_list_ready) {
        canvas_set_font(canvas, FontPrimary);
        canvas_draw_str_aligned(
            canvas, DISPLAY_WIDTH - 4, DISPLAY_HEIGHT - 2, AlignRight, AlignBottom, "->");
    }
}

static void simple_app_draw_bt_locator_list(SimpleApp* app, Canvas* canvas) {
    if(!app || !canvas) return;
    if(!app->bt_locator_devices) {
        canvas_set_color(canvas, ColorBlack);
        canvas_set_font(canvas, FontPrimary);
        canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, 32, AlignCenter, AlignCenter, "BT buffers OOM");
        return;
    }

    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontPrimary);

    uint8_t list_top = 10;
    uint8_t list_bottom = DISPLAY_HEIGHT - 2;

    if(app->bt_locator_list_loading) {
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, (list_top + list_bottom) / 2 - 6, AlignCenter, AlignCenter, "Scanning...");
        char count_line[32];
        snprintf(count_line, sizeof(count_line), "Found: %u", (unsigned)app->bt_locator_count);
        canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, (list_top + list_bottom) / 2 + 6, AlignCenter, AlignCenter, count_line);
        return;
    }

    if(app->bt_locator_count == 0) {
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str_aligned(canvas, DISPLAY_WIDTH / 2, (list_top + list_bottom) / 2 - 6, AlignCenter, AlignCenter, "No devices");
        return;
    }

    canvas_set_font(canvas, FontSecondary);
    size_t max_lines =
        (size_t)((list_bottom - list_top + SERIAL_TEXT_LINE_HEIGHT) / SERIAL_TEXT_LINE_HEIGHT);
    if(max_lines > 6) max_lines = 6;
    if(max_lines == 0) max_lines = 1;
    const size_t char_limit = 21;
    uint8_t y = list_top;
    size_t lines_used = 0;
    for(size_t i = app->bt_locator_offset; i < app->bt_locator_count && lines_used < max_lines; i++) {
        const bool selected = (i == app->bt_locator_index);
        const bool picked = ((int32_t)i == app->bt_locator_selected);
        const char* mac = app->bt_locator_devices[i].mac;
        int rssi = app->bt_locator_devices[i].rssi;
        bool has_rssi = app->bt_locator_devices[i].has_rssi;
        const char* name = app->bt_locator_devices[i].name;
        char line[48];
        if(has_rssi) {
            snprintf(line, sizeof(line), "%s %d", mac, rssi);
        } else {
            snprintf(line, sizeof(line), "%s ?", mac);
        }
        const char* to_draw = line;
        char scroll_buf[48];
        size_t len = strlen(line);
        if(selected && len > char_limit && app->bt_locator_scroll_text) {
            if(strncmp(app->bt_locator_scroll_text, line, BT_LOCATOR_SCROLL_TEXT_LEN) != 0) {
                simple_app_bt_locator_set_scroll_text(app, line);
            }
            simple_app_bt_locator_tick_scroll(app, char_limit);
            size_t offset = app->bt_locator_scroll_offset;
            if(offset >= len) offset = 0;
            size_t copy_len = (len - offset > char_limit) ? char_limit : (len - offset);
            memcpy(scroll_buf, line + offset, copy_len);
            scroll_buf[copy_len] = '\0';
            to_draw = scroll_buf;
        } else {
            simple_app_bt_locator_reset_scroll(app);
            simple_app_truncate_text(line, char_limit);
            to_draw = line;
        }
        if(selected) {
            canvas_draw_str(canvas, 2, y, ">");
        }
        if(picked) {
            canvas_draw_str(canvas, 10, y, "*");
        }
        canvas_draw_str(canvas, picked ? 18 : 12, y, to_draw);
        y += SERIAL_TEXT_LINE_HEIGHT;
        lines_used++;

        if(name && name[0] != '\0' && lines_used < max_lines) {
            char name_buf[48];
            strncpy(name_buf, name, sizeof(name_buf) - 1);
            name_buf[sizeof(name_buf) - 1] = '\0';
            simple_app_truncate_text(name_buf, char_limit);
            canvas_draw_str(canvas, picked ? 18 : 12, y, name_buf);
            y += SERIAL_TEXT_LINE_HEIGHT;
            lines_used++;
        }
    }

    // Hint action only when a target is selected
    if(app->bt_locator_selected >= 0 &&
       app->bt_locator_selected < (int32_t)app->bt_locator_count) {
        canvas_set_font(canvas, FontPrimary);
        canvas_draw_str_aligned(canvas, DISPLAY_WIDTH - 2, DISPLAY_HEIGHT - 2, AlignRight, AlignBottom, "->");
    }
}

static void __attribute__((unused)) simple_app_draw_bt_scan_serial(SimpleApp* app, Canvas* canvas) {
    if(!app || !canvas) return;
    canvas_set_color(canvas, ColorBlack);
    const int16_t console_top = 8;
    const int16_t line_height = SERIAL_TEXT_LINE_HEIGHT;
    if(app->bt_locator_mode) {
        simple_app_draw_bt_locator(app, canvas);
        return;
    }
    if(app->bt_locator_console_mode) {
        canvas_set_font(canvas, FontSecondary);
        char display_lines[BT_SCAN_CONSOLE_LINES][64];
        size_t lines_filled =
            simple_app_render_display_lines(app, app->serial_scroll, display_lines, BT_SCAN_CONSOLE_LINES);

        int16_t y = console_top;
        if(lines_filled == 0) {
            canvas_draw_str(canvas, 2, y, "Scanning...");
            y += SERIAL_TEXT_LINE_HEIGHT;
        } else {
            for(size_t i = 0; i < lines_filled; i++) {
                canvas_draw_str(canvas, 2, y, display_lines[i][0] ? display_lines[i] : " ");
                y += SERIAL_TEXT_LINE_HEIGHT;
            }
        }

        size_t total_lines = simple_app_total_display_lines(app);
        if(total_lines > BT_SCAN_CONSOLE_LINES) {
            size_t max_scroll = simple_app_max_scroll(app);
            bool show_up = (app->serial_scroll > 0);
            bool show_down = (app->serial_scroll < max_scroll);
            if(show_up || show_down) {
                uint8_t arrow_x = DISPLAY_WIDTH - 6;
                int16_t content_top = console_top;
                int16_t visible_rows = (BT_SCAN_CONSOLE_LINES > 0) ? (BT_SCAN_CONSOLE_LINES - 1) : 0;
                int16_t content_bottom = console_top + (int16_t)(visible_rows * line_height);
                simple_app_draw_scroll_hints(canvas, arrow_x, content_top, content_bottom, show_up, show_down);
            }
        }

        if(app->bt_locator_list_ready) {
            canvas_set_font(canvas, FontPrimary);
            canvas_draw_str_aligned(canvas,
                                    DISPLAY_WIDTH - 2,
                                    DISPLAY_HEIGHT - 2,
                                    AlignRight,
                                    AlignBottom,
                                    "->");
        }
        return;
    }
    canvas_set_font(canvas, FontSecondary);
    char display_lines[BT_SCAN_CONSOLE_LINES][64];
    size_t lines_filled = simple_app_render_display_lines(
        app, app->serial_scroll, display_lines, BT_SCAN_CONSOLE_LINES);

    int16_t y = console_top;
    if(lines_filled == 0) {
        canvas_draw_str(canvas, 2, y, "No UART data");
    } else {
        for(size_t i = 0; i < lines_filled; i++) {
            canvas_draw_str(canvas, 2, y, display_lines[i][0] ? display_lines[i] : " ");
            y += SERIAL_TEXT_LINE_HEIGHT;
        }
    }

    size_t total_lines = simple_app_total_display_lines(app);
    if(total_lines > BT_SCAN_CONSOLE_LINES) {
        size_t max_scroll = simple_app_max_scroll(app);
        bool show_up = (app->serial_scroll > 0);
        bool show_down = (app->serial_scroll < max_scroll);
        if(show_up || show_down) {
            uint8_t arrow_x = DISPLAY_WIDTH - 6;
            int16_t visible_rows =
                (BT_SCAN_CONSOLE_LINES > 0) ? (BT_SCAN_CONSOLE_LINES - 1) : 0;
            int16_t content_bottom = console_top + (int16_t)(visible_rows * line_height);
            /* Custom arrow placement: top hugs screen edge, bottom lifted off divider */
            if(show_up) {
                int16_t up_base = 2; // apex ends at y=0
                if(up_base < 0) up_base = 0;
                simple_app_draw_scroll_arrow(canvas, arrow_x, up_base, true);
            }
            if(show_down) {
                int16_t down_base = content_bottom - 2; // raise 4px higher than before
                if(down_base > 63) down_base = 63;
                simple_app_draw_scroll_arrow(canvas, arrow_x, down_base, false);
            }
        }
    }

    size_t used_lines = (lines_filled > 0) ? lines_filled : 1;
    if(used_lines > BT_SCAN_CONSOLE_LINES) used_lines = BT_SCAN_CONSOLE_LINES;
    int16_t divider_y = (int16_t)(console_top + (int16_t)(used_lines * line_height) - 2);
    if(divider_y < console_top) divider_y = console_top;
    if(divider_y > DISPLAY_HEIGHT - 6) {
        divider_y = DISPLAY_HEIGHT - 6;
    }
    canvas_draw_line(canvas, 0, divider_y, DISPLAY_WIDTH - 1, divider_y);

    char line1[32];
    char line2[32];
    char total_line[32];
    if(app->bt_locator_mode) {
        // Locator view is drawn separately
        return;
    }
    snprintf(line1, sizeof(line1), "AirTags: %d", app->bt_scan_airtags);
    snprintf(line2, sizeof(line2), "SmartTags: %d", app->bt_scan_smarttags);
    snprintf(total_line, sizeof(total_line), "Total: %d", app->bt_scan_total);

    canvas_set_font(canvas, FontPrimary);
    int16_t bottom_y = DISPLAY_HEIGHT - 2;
    int16_t top_y = bottom_y - SERIAL_TEXT_LINE_HEIGHT;
    if(top_y <= divider_y + 2) {
        top_y = divider_y + 2;
        bottom_y = top_y + SERIAL_TEXT_LINE_HEIGHT;
        if(bottom_y > DISPLAY_HEIGHT - 2) {
            bottom_y = DISPLAY_HEIGHT - 2;
            top_y = bottom_y - SERIAL_TEXT_LINE_HEIGHT;
        }
    }
    canvas_draw_str_aligned(canvas, 2, top_y, AlignLeft, AlignBottom, line1);
    canvas_draw_str_aligned(canvas, 2, bottom_y, AlignLeft, AlignBottom, line2);

    // Place total in bottom-right corner to avoid overlapping the counts
    canvas_draw_str_aligned(
        canvas, DISPLAY_WIDTH - 2, DISPLAY_HEIGHT - 2, AlignRight, AlignBottom, total_line);
}

static void simple_app_draw_serial(SimpleApp* app, Canvas* canvas) {
    if(app && app->deauth_guard_view_active && !app->deauth_guard_full_console) {
        simple_app_draw_deauth_guard(app, canvas);
        return;
    }

    if(app && app->handshake_view_active && !app->handshake_full_console) {
        simple_app_draw_handshake_overlay(app, canvas);
        return;
    }

    if(app && app->sae_view_active && !app->sae_full_console) {
        simple_app_draw_sae_overlay(app, canvas);
        return;
    }

    if(app && app->deauth_view_active && !app->deauth_full_console) {
        simple_app_draw_deauth_overlay(app, canvas);
        return;
    }

    if(app && app->blackout_view_active && !app->blackout_full_console) {
        simple_app_draw_blackout_overlay(app, canvas);
        return;
    }

    if(app && app->sniffer_dog_view_active && !app->sniffer_dog_full_console) {
        simple_app_draw_sniffer_dog_overlay(app, canvas);
        return;
    }

    if(app && app->bt_scan_view_active && !app->bt_scan_full_console) {
        if(app->airtag_scan_mode) {
            if(app->bt_scan_show_list) {
                simple_app_draw_bt_scan_list(app, canvas);
            } else {
                simple_app_draw_airtag_overlay(app, canvas);
            }
            return;
        }
        if(app->bt_locator_mode) {
            simple_app_draw_bt_locator(app, canvas);
            return;
        }
        if(app->bt_scan_show_list) {
            simple_app_draw_bt_scan_list(app, canvas);
        } else {
            simple_app_draw_bt_scan_overlay(app, canvas);
        }
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

static size_t simple_app_ota_item_count(const SimpleApp* app) {
    if(!app) return 0;
    return app->ota_use_dhcp ? 8 : 12;
}

static OtaSetupItem simple_app_ota_item_at(const SimpleApp* app, size_t index) {
    if(!app) return OtaItemCheck;
    if(app->ota_use_dhcp) {
        switch(index) {
        case 0: return OtaItemCheck;
        case 1: return OtaItemSsid;
        case 2: return OtaItemPass;
        case 3: return OtaItemMode;
        case 4: return OtaItemChannel;
        case 5: return OtaItemList;
        case 6: return OtaItemInfo;
        case 7: return OtaItemBoot;
        default: return OtaItemBoot;
        }
    }
    switch(index) {
    case 0: return OtaItemCheck;
    case 1: return OtaItemSsid;
    case 2: return OtaItemPass;
    case 3: return OtaItemMode;
    case 4: return OtaItemIp;
    case 5: return OtaItemNetmask;
    case 6: return OtaItemGw;
    case 7: return OtaItemDns;
    case 8: return OtaItemChannel;
    case 9: return OtaItemList;
    case 10: return OtaItemInfo;
    case 11: return OtaItemBoot;
    default: return OtaItemBoot;
    }
}

static void simple_app_ota_adjust_offset(SimpleApp* app) {
    if(!app) return;
    size_t count = simple_app_ota_item_count(app);
    if(count == 0) {
        app->ota_setup_index = 0;
        app->ota_setup_offset = 0;
        return;
    }
    if(app->ota_setup_index >= count) {
        app->ota_setup_index = count - 1;
    }
    size_t visible = OTA_SETUP_VISIBLE_COUNT;
    if(visible > count) visible = count;
    size_t max_offset = (count > visible) ? (count - visible) : 0;
    if(app->ota_setup_offset > max_offset) {
        app->ota_setup_offset = max_offset;
    }
    if(app->ota_setup_index < app->ota_setup_offset) {
        app->ota_setup_offset = app->ota_setup_index;
    } else if(app->ota_setup_index >= app->ota_setup_offset + visible) {
        app->ota_setup_offset = app->ota_setup_index - visible + 1;
    }
}

static void simple_app_ota_request_text_input(SimpleApp* app, OtaInputField field) {
    if(!app || app->ota_input_active) return;
    app->ota_input_field = field;
    app->ota_input_requested = true;
}

static void simple_app_reset_ota_status(SimpleApp* app) {
    if(!app) return;
    app->ota_status_active = true;
    app->ota_wifi_status[0] = '\0';
    app->ota_ip_status[0] = '\0';
    app->ota_response[0] = '\0';
}

static void simple_app_reset_ota_list(SimpleApp* app) {
    if(!app) return;
    app->ota_list_active = true;
    app->ota_list_count = 0;
    for(size_t i = 0; i < OTA_LIST_MAX; i++) {
        app->ota_list_lines[i][0] = '\0';
    }
}

static void simple_app_reset_ota_info(SimpleApp* app) {
    if(!app) return;
    app->ota_info_active = true;
    app->ota_info_count = 0;
    for(size_t i = 0; i < OTA_INFO_MAX; i++) {
        app->ota_info_lines[i][0] = '\0';
    }
}

static void simple_app_ota_store_line(char* dest, size_t dest_len, const char* line) {
    if(!dest || dest_len == 0) return;
    if(!line) {
        dest[0] = '\0';
        return;
    }
    strncpy(dest, line, dest_len - 1);
    dest[dest_len - 1] = '\0';
    simple_app_truncate_text(dest, OTA_STATUS_LINE_MAX - 1);
}

static bool simple_app_ota_extract_quoted(const char* line, char* out, size_t out_len) {
    if(!line || !out || out_len == 0) return false;
    const char* first = strchr(line, '\'');
    if(!first) return false;
    const char* second = strchr(first + 1, '\'');
    if(!second || second <= first + 1) return false;
    size_t len = (size_t)(second - first - 1);
    if(len >= out_len) len = out_len - 1;
    memcpy(out, first + 1, len);
    out[len] = '\0';
    return true;
}

static void simple_app_ota_process_line(SimpleApp* app, const char* line) {
    if(!app || !line || line[0] == '\0') return;
    if(line[0] == '>') {
        line++;
        while(*line == ' ' || *line == '\t') line++;
        if(*line == '\0') return;
    }

    if(strncmp(line, "OTA[", 4) == 0 && app->ota_list_active) {
        if(app->ota_list_count < OTA_LIST_MAX) {
            simple_app_ota_store_line(
                app->ota_list_lines[app->ota_list_count],
                sizeof(app->ota_list_lines[app->ota_list_count]),
                line);
            app->ota_list_count++;
        }
        return;
    }

    if((strncmp(line, "OTA boot:", 9) == 0 ||
        strncmp(line, "OTA running:", 12) == 0 ||
        strncmp(line, "OTA next:", 9) == 0 ||
        strncmp(line, "APP[", 4) == 0) &&
       app->ota_info_active) {
        if(app->ota_info_count < OTA_INFO_MAX) {
            simple_app_ota_store_line(
                app->ota_info_lines[app->ota_info_count],
                sizeof(app->ota_info_lines[app->ota_info_count]),
                line);
            app->ota_info_count++;
        }
        return;
    }

    if(strncmp(line, "OTA channel:", 12) == 0) {
        const char* channel = line + 12;
        while(*channel == ' ' || *channel == '\t') channel++;
        strncpy(app->ota_channel, channel, sizeof(app->ota_channel) - 1);
        app->ota_channel[sizeof(app->ota_channel) - 1] = '\0';
        simple_app_trim(app->ota_channel);
        simple_app_ota_store_line(app->ota_response, sizeof(app->ota_response), line);
        return;
    }

    if(strncmp(line, "DHCP IP:", 8) == 0 || strncmp(line, "Static IP:", 10) == 0) {
        simple_app_ota_store_line(app->ota_ip_status, sizeof(app->ota_ip_status), line);
        return;
    }

    if(strncmp(line, "Connecting to AP", 16) == 0 || strncmp(line, "Initializing WiFi", 17) == 0) {
        simple_app_ota_store_line(app->ota_wifi_status, sizeof(app->ota_wifi_status), line);
        return;
    }

    if(strncmp(line, "Wi-Fi:", 6) == 0 || strncmp(line, "SUCCESS: Connected", 18) == 0) {
        char ssid[SCAN_SSID_MAX_LEN] = {0};
        if(simple_app_ota_extract_quoted(line, ssid, sizeof(ssid))) {
            char status[OTA_STATUS_LINE_MAX];
            snprintf(status, sizeof(status), "WiFi: %s", ssid);
            simple_app_ota_store_line(app->ota_wifi_status, sizeof(app->ota_wifi_status), status);
        } else {
            simple_app_ota_store_line(app->ota_wifi_status, sizeof(app->ota_wifi_status), "WiFi: connected");
        }
        return;
    }

    if(strncmp(line, "FAILED:", 7) == 0 || strncmp(line, "TIMEOUT:", 8) == 0) {
        simple_app_ota_store_line(app->ota_wifi_status, sizeof(app->ota_wifi_status), line);
        return;
    }

    if(strncmp(line, "OTA:", 4) == 0 ||
       strncmp(line, "Usage:", 6) == 0 ||
       strncmp(line, "Command returned", 16) == 0) {
        simple_app_ota_store_line(app->ota_response, sizeof(app->ota_response), line);
        return;
    }
}

static void simple_app_ota_feed(SimpleApp* app, char ch) {
    if(!app) return;
    if(ch == '\r') return;
    if(ch == '\n') {
        if(app->ota_line_length > 0) {
            app->ota_line_buffer[app->ota_line_length] = '\0';
            simple_app_ota_process_line(app, app->ota_line_buffer);
        }
        app->ota_line_length = 0;
        return;
    }
    if(app->ota_line_length + 1 >= sizeof(app->ota_line_buffer)) {
        app->ota_line_length = 0;
        return;
    }
    app->ota_line_buffer[app->ota_line_length++] = ch;
}

static void simple_app_ota_build_line(SimpleApp* app, size_t index, char* out, size_t out_len) {
    if(!app || !out || out_len == 0) return;

    const char* value = "";
    switch(simple_app_ota_item_at(app, index)) {
    case OtaItemCheck:
        snprintf(out, out_len, "Check OTA");
        break;
    case OtaItemSsid:
        value = (app->ota_ssid[0] != '\0') ? app->ota_ssid : "<empty>";
        snprintf(out, out_len, "SSID: %s", value);
        break;
    case OtaItemPass: {
        const char* pass_value = "<empty>";
        if(app->ota_password[0] != '\0') {
            pass_value = app->ota_pass_show ? app->ota_password : "******";
        }
        int max_len = app->ota_pass_show ? 12 : 6;
        snprintf(
            out,
            out_len,
            "Pass:%.*s %s",
            max_len,
            pass_value,
            app->ota_pass_show ? "H" : "S");
        break;
    }
    case OtaItemMode:
        snprintf(out, out_len, "Mode: %s", app->ota_use_dhcp ? "DHCP" : "Manual");
        break;
    case OtaItemIp:
        value = (app->ota_ip[0] != '\0') ? app->ota_ip : "<empty>";
        snprintf(out, out_len, "IP: %s", value);
        break;
    case OtaItemNetmask:
        value = (app->ota_netmask[0] != '\0') ? app->ota_netmask : "<empty>";
        snprintf(out, out_len, "Netmask: %s", value);
        break;
    case OtaItemGw:
        value = (app->ota_gw[0] != '\0') ? app->ota_gw : "<empty>";
        snprintf(out, out_len, "GW: %s", value);
        break;
    case OtaItemDns:
        value = (app->ota_dns[0] != '\0') ? app->ota_dns : "<empty>";
        snprintf(out, out_len, "DNS: %s", value);
        break;
    case OtaItemChannel:
        value = (app->ota_channel[0] != '\0') ? app->ota_channel : "main";
        snprintf(out, out_len, "Channel: %s", value);
        break;
    case OtaItemList:
        snprintf(out, out_len, "List updates");
        break;
    case OtaItemInfo:
        snprintf(out, out_len, "Show info");
        break;
    case OtaItemBoot:
        snprintf(out, out_len, "Boot: %s", app->ota_boot_target_slot1 ? "ota_1" : "ota_0");
        break;
    default:
        out[0] = '\0';
        break;
    }

    simple_app_truncate_text(out, SERIAL_LINE_CHAR_LIMIT);
}

static void simple_app_draw_setup_ota(SimpleApp* app, Canvas* canvas) {
    if(!app || !canvas) return;

    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 16, 14, "OTA Update");

    simple_app_ota_adjust_offset(app);
    size_t count = simple_app_ota_item_count(app);
    size_t visible = OTA_SETUP_VISIBLE_COUNT;
    if(visible > count) visible = count;

    canvas_set_font(canvas, FontSecondary);
    uint8_t y = 24;
    char line[64];
    for(size_t i = 0; i < visible; i++) {
        size_t item_index = app->ota_setup_offset + i;
        simple_app_ota_build_line(app, item_index, line, sizeof(line));
        if(item_index == app->ota_setup_index) {
            canvas_draw_str(canvas, 2, y, ">");
        }
        canvas_draw_str(canvas, 12, y, line);
        y += 12;
    }

    (void)canvas;
}

static void simple_app_draw_ota_status(SimpleApp* app, Canvas* canvas) {
    if(!app || !canvas) return;
    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 18, 12, "OTA Status");

    canvas_set_font(canvas, FontSecondary);
    const char* wifi_line = (app->ota_wifi_status[0] != '\0') ? app->ota_wifi_status : "WiFi: --";
    const char* ip_line = (app->ota_ip_status[0] != '\0') ? app->ota_ip_status : "IP: --";
    const char* ota_line = (app->ota_response[0] != '\0') ? app->ota_response : "OTA: --";
    canvas_draw_str(canvas, 4, 26, wifi_line);
    canvas_draw_str(canvas, 4, 38, ip_line);
    canvas_draw_str(canvas, 4, 50, ota_line);
    canvas_draw_str(canvas, 2, 62, "Back to OTA");
}

static void simple_app_draw_ota_list(SimpleApp* app, Canvas* canvas) {
    if(!app || !canvas) return;
    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 28, 12, "OTA List");

    canvas_set_font(canvas, FontSecondary);
    if(app->ota_list_count == 0) {
        canvas_draw_str(canvas, 4, 32, "No data");
    } else {
        uint8_t y = 26;
        for(size_t i = 0; i < app->ota_list_count && i < OTA_LIST_MAX; i++) {
            canvas_draw_str(canvas, 4, y, app->ota_list_lines[i]);
            y += 12;
        }
    }
    canvas_draw_str(canvas, 2, 62, "Back to OTA");
}

static void simple_app_draw_ota_info(SimpleApp* app, Canvas* canvas) {
    if(!app || !canvas) return;
    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 30, 12, "OTA Info");

    canvas_set_font(canvas, FontSecondary);
    if(app->ota_info_count == 0) {
        canvas_draw_str(canvas, 4, 32, "No data");
    } else {
        uint8_t y = 24;
        const uint8_t max_y = 54;
        for(size_t i = 0; i < app->ota_info_count && i < OTA_INFO_MAX; i++) {
            const char* text = app->ota_info_lines[i];
            while(*text != '\0' && y <= max_y) {
                char line[32];
                size_t taken = 0;
                size_t last_space = 0;
                while(text[taken] != '\0' && taken < 26) {
                    if(text[taken] == ' ') {
                        last_space = taken;
                    }
                    taken++;
                }
                if(text[taken] != '\0' && last_space > 0) {
                    taken = last_space;
                }
                if(taken == 0) break;
                strncpy(line, text, taken);
                line[taken] = '\0';
                simple_app_trim(line);
                canvas_draw_str(canvas, 4, y, line);
                y += 10;
                text += taken;
                while(*text == ' ') text++;
            }
            if(y > max_y) break;
        }
    }
    canvas_draw_str(canvas, 2, 62, "Back to OTA");
}

static void simple_app_reset_sd_listing(SimpleApp* app) {
    if(!app) return;
    simple_app_sd_free_files(app);
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
    if(!simple_app_sd_alloc_files(app)) {
        simple_app_show_status_message(app, "OOM: SD list", 2000, true);
        return;
    }
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

    if(strncmp(text, app->sd_scroll_text, SD_MANAGER_FILE_NAME_MAX) != 0 ||
       app->sd_scroll_char_limit != char_limit) {
        strncpy(app->sd_scroll_text, text, SD_MANAGER_FILE_NAME_MAX - 1);
        app->sd_scroll_text[SD_MANAGER_FILE_NAME_MAX - 1] = '\0';
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
    if(!app->sd_files) return;

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
    if(!app->sd_files) return;

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
    if(!app->sd_files) return;
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

static void simple_app_draw_setup_scanner_timing(SimpleApp* app, Canvas* canvas) {
    if(!app || !canvas) return;

    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 6, 14, "Scanner Timing");

    canvas_set_font(canvas, FontSecondary);
    uint8_t y = 32;
    char line[48];

    snprintf(
        line,
        sizeof(line),
        "Min Channel Scan: %ums",
        (unsigned)app->scanner_min_channel_time);
    simple_app_truncate_text(line, 26);
    if(app->scanner_timing_index == 0) {
        canvas_draw_str(canvas, 2, y, ">");
    }
    canvas_draw_str(canvas, 12, y, line);

    y += 14;
    snprintf(
        line,
        sizeof(line),
        "Max Channel Scan: %ums",
        (unsigned)app->scanner_max_channel_time);
    simple_app_truncate_text(line, 26);
    if(app->scanner_timing_index == 1) {
        canvas_draw_str(canvas, 2, y, ">");
    }
    canvas_draw_str(canvas, 12, y, line);

    canvas_draw_str(canvas, 2, 62, "Left/Right adjust, Back exit");
}

static void simple_app_draw_wardrive_menu(SimpleApp* app, Canvas* canvas) {
    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 2, 11, "Wardrive mode");
    canvas_set_font(canvas, FontSecondary);
    size_t offset = app->wardrive_mode_index > 3 ? app->wardrive_mode_index - 3 : 0;
    for(size_t row = 0; row < 4 && offset + row <
         sizeof(wardrive_modes) / sizeof(wardrive_modes[0]); row++) {
        size_t index = offset + row;
        uint8_t y = (uint8_t)(23 + row * 10);
        if(index == app->wardrive_mode_index) canvas_draw_str(canvas, 2, y, ">");
        canvas_draw_str(canvas, 13, y, wardrive_modes[index]);
    }
    canvas_draw_str(canvas, 2, 63, "OK select  Back menu");
}

LAB_C5_CODE_SECTION static void simple_app_draw(Canvas* canvas, void* context) {
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
        if(app->web_view_active && !app->web_console_mode &&
           app->web_mode != C5WebModeKarma) {
            if(!c5_module_runtime_draw(&app->gps_module, canvas)) {
                simple_app_draw_serial(app, canvas);
            }
        } else {
            simple_app_draw_serial(app, canvas);
        }
        break;
    case ScreenSetupScanner:
        simple_app_draw_setup_scanner(app, canvas);
        break;
    case ScreenSetupScannerTiming:
        simple_app_draw_setup_scanner_timing(app, canvas);
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
    case ScreenSetupOta:
        simple_app_draw_setup_ota(app, canvas);
        break;
    case ScreenOtaStatus:
        simple_app_draw_ota_status(app, canvas);
        break;
    case ScreenOtaList:
        simple_app_draw_ota_list(app, canvas);
        break;
    case ScreenOtaInfo:
        simple_app_draw_ota_info(app, canvas);
        break;
    case ScreenHelpQr:
        simple_app_draw_help_qr(app, canvas);
        break;
    case ScreenConsole:
        simple_app_draw_console(app, canvas);
        break;
    case ScreenGps:
        if(!c5_module_runtime_draw(&app->gps_module, canvas)) {
            canvas_set_font(canvas, FontSecondary);
            canvas_draw_str(canvas, 2, 12, "GPS module unavailable");
        }
        break;
    case ScreenGpsLoading:
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str_aligned(canvas, 64, 32, AlignCenter, AlignCenter, "Loading GPS...");
        break;
    case ScreenWebMenu:
        if(!c5_module_runtime_draw(&app->gps_module, canvas)) {
            canvas_set_font(canvas, FontSecondary);
            canvas_draw_str(canvas, 2, 12, "Web module unavailable");
        }
        break;
    case ScreenWebLoading:
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str_aligned(canvas, 64, 32, AlignCenter, AlignCenter, "Loading Web...");
        break;
    case ScreenRecon:
        if(!c5_module_runtime_draw(&app->gps_module, canvas)) {
            canvas_set_font(canvas, FontSecondary);
            canvas_draw_str(canvas, 2, 12, "Recon unavailable");
        }
        break;
    case ScreenReconLoading:
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str_aligned(canvas, 64, 32, AlignCenter, AlignCenter,
                                app->recon_view_active ? "Closing Recon..." : "Loading Recon...");
        break;
    case ScreenAttackModule:
        if(!c5_module_runtime_draw(&app->gps_module, canvas)) {
            canvas_set_font(canvas, FontSecondary);
            canvas_draw_str(canvas, 2, 12, "Attack unavailable");
        }
        break;
    case ScreenAttackLoading:
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str_aligned(canvas, 64, 32, AlignCenter, AlignCenter,
                                app->attack_view_active ? "Closing..." : "Loading...");
        break;
    case ScreenWardriveMenu:
        simple_app_draw_wardrive_menu(app, canvas);
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
    case ScreenConfirmOtaConnect:
        simple_app_draw_confirm_ota_connect(app, canvas);
        break;
    case ScreenConfirmExit:
        simple_app_draw_confirm_exit(app, canvas);
        break;
    case ScreenBtLocatorList:
        simple_app_draw_bt_locator_list(app, canvas);
        break;
    default:
        break;
    }

    if(app->sd_delete_confirm_active) {
        simple_app_draw_sd_delete_confirm(app, canvas);
    } else if(app->sd_file_popup_active) {
        simple_app_draw_sd_file_popup(app, canvas);
    } else if(app->sd_folder_popup_active) {
        simple_app_draw_sd_folder_popup(app, canvas);
    }

    simple_app_draw_ram_overlay(app, canvas);
}

static void simple_app_handle_menu_input(SimpleApp* app, InputKey key) {
    if(key == InputKeyOk && !c5_attack_rx_guard_should_log(&app->attack_rx_guard)) {
        simple_app_show_status_message(app, "Finishing previous task", 1400, true);
        return;
    }
    if(key == InputKeyUp) {
        if(app->menu_state == MenuStateSections) {
            size_t section_count = menu_section_count;
            if(section_count == 0) return;
            if(app->section_index > 0) {
                app->section_index--;
            } else {
                app->section_index = section_count - 1;
            }
            simple_app_adjust_section_offset(app);
            app->exit_confirm_active = false;
            view_port_update(app->viewport);
        } else {
            if(!simple_app_menu_move_item(app, false)) return;
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
            simple_app_adjust_section_offset(app);
            app->exit_confirm_active = false;
            view_port_update(app->viewport);
        } else {
            if(!simple_app_menu_move_item(app, true)) return;
            view_port_update(app->viewport);
        }
    } else if(key == InputKeyOk) {
        if(app->menu_state == MenuStateSections) {
            if(app->section_index == MENU_SECTION_SCANNER) {
                simple_app_request_recon(app, C5ReconModeScanner);
                return;
            }
            app->exit_confirm_active = false;
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
            size_t entry_count = simple_app_menu_entry_count(app, app->section_index);
            if(entry_count > visible_count) {
                size_t max_offset = entry_count - visible_count;
                if(app->item_offset > max_offset) {
                    app->item_offset = max_offset;
                }
            }
            if(app->section_index == MENU_SECTION_SETUP) {
                simple_app_request_led_status(app);
                simple_app_request_boot_status(app);
                simple_app_request_vendor_status(app);
                simple_app_request_scanner_timing(app);
            }
            view_port_update(app->viewport);
            return;
        }

        size_t entry_count = simple_app_menu_entry_count(app, app->section_index);
        if(entry_count == 0) return;
        if(app->item_index >= entry_count) {
            app->item_index = entry_count - 1;
        }
        if(app->section_index == MENU_SECTION_ATTACKS) {
            app->last_attack_index = app->item_index;
        }

        const MenuEntry* entry = simple_app_menu_entry_at(app, app->section_index, app->item_index);
        if(!entry) return;
        if(entry->action == MenuActionCommandWithTargets) {
            simple_app_send_command_with_targets(app, entry->command);
        } else if(entry->action == MenuActionCommand) {
            if(entry->command && entry->command[0] != '\0') {
                if(strcmp(entry->command, "start_sniffer") == 0) {
                    simple_app_request_recon(app, C5ReconModeSnifferStart);
                    return;
                } else if(strcmp(entry->command, "start_sniffer_noscan") == 0) {
                    simple_app_request_recon(app, C5ReconModeSnifferResume);
                    return;
                } else if(strcmp(entry->command, "show_sniffer_results") == 0) {
                    simple_app_request_recon(app, C5ReconModeSnifferResults);
                    return;
                } else if(strcmp(entry->command, "show_probes") == 0) {
                    simple_app_request_recon(app, C5ReconModeProbeResults);
                    return;
                } else {
                    simple_app_send_command(app, entry->command, true);
                }
            }
        } else if(entry->action == MenuActionOpenKarmaMenu) {
            simple_app_request_web(app, C5WebModeKarma);
        } else if(entry->action == MenuActionOpenEvilTwinMenu) {
            simple_app_request_web(app, C5WebModeEvilTwin);
        } else if(entry->action == MenuActionOpenPortalMenu) {
            simple_app_request_web(app, C5WebModePortal);
        } else if(entry->action == MenuActionOpenConnect) {
            simple_app_request_attack(app, C5AttackModuleConnect);
        } else if(entry->action == MenuActionOpenRogue) {
            simple_app_request_attack(app, C5AttackModuleRogue);
        } else if(entry->action == MenuActionOpenArp) {
            simple_app_request_attack(app, C5AttackModuleArp);
        } else if(entry->action == MenuActionOpenArpSaved) {
            simple_app_request_attack(app, C5AttackModuleArpSaved);
        } else if(entry->action == MenuActionOpenMitmPcap) {
            simple_app_request_attack(app, C5AttackModuleMitmPcap);
        } else if(entry->action == MenuActionOpenNmap) {
            simple_app_request_attack(app, C5AttackModuleNmap);
        } else if(entry->action == MenuActionOpenWpasec) {
            simple_app_request_attack(app, C5AttackModuleWpasec);
        } else if(entry->action == MenuActionOpenBeacon) {
            simple_app_request_attack(app, C5AttackModuleBeacon);
        } else if(entry->action == MenuActionOpenWardrive) {
            app->wardrive_mode_index = 0;
            app->screen = ScreenWardriveMenu;
            if(app->viewport) view_port_update(app->viewport);
        } else if(entry->action == MenuActionToggleBacklight) {
            simple_app_toggle_backlight(app);
        } else if(entry->action == MenuActionToggleOtgPower) {
            simple_app_toggle_otg_power(app);
        } else if(entry->action == MenuActionToggleShowRam) {
            simple_app_toggle_show_ram(app);
        } else if(entry->action == MenuActionToggleDebugMark) {
            simple_app_toggle_debug_mark(app);
        } else if(entry->action == MenuActionToggleRedTeam) {
            simple_app_toggle_red_team(app);
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
        } else if(entry->action == MenuActionOpenOta) {
            app->screen = ScreenSetupOta;
            app->ota_setup_index = 0;
            simple_app_ota_adjust_offset(app);
            simple_app_send_command(app, "ota_channel", false);
        } else if(entry->action == MenuActionOpenHelp) {
            app->screen = ScreenHelpQr;
        } else if(entry->action == MenuActionOpenDownload) {
            simple_app_send_download(app);
        } else if(entry->action == MenuActionOpenScannerTiming) {
            app->screen = ScreenSetupScannerTiming;
            app->scanner_timing_index = 0;
            simple_app_request_scanner_timing(app);
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
        } else if(entry->action == MenuActionOpenGps) {
            app->screen = ScreenGpsLoading;
            simple_app_request_module(app, C5ModuleRequestLoadGps);
            if(app->viewport) view_port_update(app->viewport);
            return;
        } else if(entry->action == MenuActionOpenBtLocator) {
            simple_app_bt_locator_begin_scan(app);
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
            if(app->section_index == MENU_SECTION_ATTACKS) {
                simple_app_send_command_quiet(app, "unselect_networks");
                simple_app_clear_station_selection(app);
            }
            app->menu_state = MenuStateSections;
            simple_app_adjust_section_offset(app);
            view_port_update(app->viewport);
        } else {
            // Brief haptic to highlight exit confirmation
            furi_hal_vibro_on(true);
            furi_delay_ms(40);
            furi_hal_vibro_on(false);
            app->confirm_exit_yes = false;
            app->screen = ScreenConfirmExit;
            view_port_update(app->viewport);
        }
    }
}

static void simple_app_draw_help_qr(SimpleApp* app, Canvas* canvas) {
    if(!app || !canvas) return;

    const uint8_t qr_x = 0;
    const uint8_t qr_y = 0;
    const uint8_t qr_w = 64;
    const uint8_t qr_h = 64;
    const int size = LAB_C5_HELP_QR_SIZE;
    const int scale = 2;
    const int offset_x = qr_x + (qr_w - size * scale) / 2;
    const int offset_y = qr_y + (qr_h - size * scale) / 2;

    canvas_set_color(canvas, ColorWhite);
    canvas_draw_box(canvas, qr_x, qr_y, qr_w, qr_h);
    canvas_set_color(canvas, ColorBlack);

    for(int y = 0; y < size; y++) {
        for(int x = 0; x < size; x++) {
            if(lab_c5_help_qr_get_module(x, y)) {
                canvas_draw_box(canvas, offset_x + x * scale, offset_y + y * scale, scale, scale);
            }
        }
    }

    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str(canvas, 68, 20, "Scan to");
    canvas_draw_str(canvas, 68, 32, "open wiki");
    canvas_draw_str(canvas, 68, 62, "Back");
}

static void simple_app_handle_help_qr_input(SimpleApp* app, InputKey key) {
    if(!app) return;
    if(key == InputKeyBack || key == InputKeyLeft || key == InputKeyOk) {
        app->screen = ScreenMenu;
        if(app->viewport) {
            view_port_update(app->viewport);
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
                    view_port_update(app->viewport);
                }
            }
        }
    }
}

static void simple_app_handle_setup_scanner_timing_input(SimpleApp* app, InputKey key) {
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
        if(app->scanner_timing_index > 0) {
            app->scanner_timing_index = 0;
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
        return;
    }

    if(key == InputKeyDown) {
        if(app->scanner_timing_index < 1) {
            app->scanner_timing_index = 1;
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
        return;
    }

    if(key == InputKeyLeft) {
        simple_app_modify_channel_time(app, app->scanner_timing_index == 0, -SCANNER_CHANNEL_TIME_STEP_MS);
    } else if(key == InputKeyRight) {
        simple_app_modify_channel_time(app, app->scanner_timing_index == 0, SCANNER_CHANNEL_TIME_STEP_MS);
    } else if(key == InputKeyOk) {
        simple_app_request_channel_time(app, app->scanner_timing_index == 0);
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
            simple_app_mark_config_dirty(app);
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
            simple_app_mark_config_dirty(app);
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

static bool simple_app_append_escaped(char* out, size_t out_len, size_t* offset, const char* src) {
    if(!out || !offset || out_len == 0) return false;
    size_t pos = *offset;
    if(pos >= out_len) return false;
    if(!src) src = "";
    for(size_t i = 0; src[i] != '\0'; i++) {
        char ch = src[i];
        if(ch == '\\' || ch == '"') {
            if(pos + 2 >= out_len) return false;
            out[pos++] = '\\';
        }
        if(pos + 1 >= out_len) return false;
        out[pos++] = ch;
    }
    out[pos] = '\0';
    *offset = pos;
    return true;
}

static bool simple_app_ota_send_wifi_connect(SimpleApp* app) {
    if(!app) return false;

    simple_app_reset_ota_status(app);
    simple_app_ota_store_line(app->ota_wifi_status, sizeof(app->ota_wifi_status), "WiFi: connecting");

    if(app->ota_ssid[0] == '\0') {
        simple_app_show_status_message(app, "SSID required", 1200, true);
        return false;
    }

    if(!app->ota_use_dhcp) {
        if(app->ota_ip[0] == '\0' || app->ota_netmask[0] == '\0' || app->ota_gw[0] == '\0') {
            simple_app_show_status_message(app, "IP/Netmask/GW required", 1500, true);
            return false;
        }
    }

    char command[256];
    size_t pos = 0;
    int written = snprintf(command, sizeof(command), "wifi_connect \"");
    if(written <= 0 || (size_t)written >= sizeof(command)) {
        simple_app_show_status_message(app, "OTA: command too long", 1500, true);
        return false;
    }
    pos = (size_t)written;
    if(!simple_app_append_escaped(command, sizeof(command), &pos, app->ota_ssid)) {
        simple_app_show_status_message(app, "OTA: SSID too long", 1500, true);
        return false;
    }
    written = snprintf(command + pos, sizeof(command) - pos, "\" \"");
    if(written <= 0 || (size_t)written >= sizeof(command) - pos) {
        simple_app_show_status_message(app, "OTA: command too long", 1500, true);
        return false;
    }
    pos += (size_t)written;
    if(!simple_app_append_escaped(command, sizeof(command), &pos, app->ota_password)) {
        simple_app_show_status_message(app, "OTA: password too long", 1500, true);
        return false;
    }
    written = snprintf(command + pos, sizeof(command) - pos, "\" ota");
    if(written <= 0 || (size_t)written >= sizeof(command) - pos) {
        simple_app_show_status_message(app, "OTA: command too long", 1500, true);
        return false;
    }
    pos += (size_t)written;

    if(!app->ota_use_dhcp) {
        if(app->ota_dns[0] != '\0') {
            written = snprintf(
                command + pos,
                sizeof(command) - pos,
                " %s %s %s %s",
                app->ota_ip,
                app->ota_netmask,
                app->ota_gw,
                app->ota_dns);
        } else {
            written = snprintf(
                command + pos,
                sizeof(command) - pos,
                " %s %s %s",
                app->ota_ip,
                app->ota_netmask,
                app->ota_gw);
        }
        if(written <= 0 || (size_t)written >= sizeof(command) - pos) {
            simple_app_show_status_message(app, "OTA: command too long", 1500, true);
            return false;
        }
    }

    app->screen = ScreenOtaStatus;
    simple_app_send_command(app, command, false);
    return true;
}

static void simple_app_handle_setup_ota_input(SimpleApp* app, InputKey key) {
    if(!app) return;

    if(key == InputKeyBack) {
        app->screen = ScreenMenu;
        if(app->viewport) {
            view_port_update(app->viewport);
        }
        return;
    }

    size_t count = simple_app_ota_item_count(app);
    if(count == 0) return;

    if(key == InputKeyUp) {
        if(app->ota_setup_index > 0) {
            app->ota_setup_index--;
            simple_app_ota_adjust_offset(app);
            if(app->viewport) view_port_update(app->viewport);
        }
        return;
    }

    if(key == InputKeyDown) {
        if(app->ota_setup_index + 1 < count) {
            app->ota_setup_index++;
            simple_app_ota_adjust_offset(app);
            if(app->viewport) view_port_update(app->viewport);
        }
        return;
    }

    OtaSetupItem item = simple_app_ota_item_at(app, app->ota_setup_index);

    if(item == OtaItemCheck) {
        if(key == InputKeyOk) {
            app->ota_connect_confirm_yes = false;
            app->screen = ScreenConfirmOtaConnect;
            if(app->viewport) view_port_update(app->viewport);
        }
        return;
    }

    if(item == OtaItemSsid) {
        if(key == InputKeyOk) {
            simple_app_ota_request_text_input(app, OtaInputSsid);
        }
        return;
    }

    if(item == OtaItemPass) {
        if(key == InputKeyLeft || key == InputKeyRight) {
            app->ota_pass_show = !app->ota_pass_show;
            if(app->viewport) view_port_update(app->viewport);
            return;
        }
        if(key == InputKeyOk) {
            simple_app_ota_request_text_input(app, OtaInputPassword);
        }
        return;
    }

    if(item == OtaItemMode) {
        if(key == InputKeyLeft || key == InputKeyRight || key == InputKeyOk) {
            app->ota_use_dhcp = !app->ota_use_dhcp;
            simple_app_ota_adjust_offset(app);
            if(app->viewport) view_port_update(app->viewport);
        }
        return;
    }

    if(item == OtaItemChannel) {
        if(key == InputKeyLeft || key == InputKeyRight) {
            if(strcasecmp(app->ota_channel, "dev") == 0) {
                snprintf(app->ota_channel, sizeof(app->ota_channel), "main");
            } else {
                snprintf(app->ota_channel, sizeof(app->ota_channel), "dev");
            }
            if(app->viewport) view_port_update(app->viewport);
            return;
        }
        if(key == InputKeyOk) {
            char cmd[32];
            snprintf(cmd, sizeof(cmd), "ota_channel %s", app->ota_channel);
            simple_app_reset_ota_status(app);
            app->screen = ScreenOtaStatus;
            simple_app_send_command(app, cmd, false);
            if(app->viewport) view_port_update(app->viewport);
        }
        return;
    }

    if(item == OtaItemList) {
        if(key == InputKeyOk) {
            simple_app_reset_ota_list(app);
            app->screen = ScreenOtaList;
            simple_app_send_command(app, "ota_list", false);
            if(app->viewport) view_port_update(app->viewport);
        }
        return;
    }

    if(item == OtaItemInfo) {
        if(key == InputKeyOk) {
            simple_app_reset_ota_info(app);
            app->screen = ScreenOtaInfo;
            simple_app_send_command(app, "ota_info", false);
            if(app->viewport) view_port_update(app->viewport);
        }
        return;
    }

    if(item == OtaItemBoot) {
        if(key == InputKeyLeft || key == InputKeyRight) {
            app->ota_boot_target_slot1 = !app->ota_boot_target_slot1;
            if(app->viewport) view_port_update(app->viewport);
            return;
        }
        if(key == InputKeyOk) {
            const char* target = app->ota_boot_target_slot1 ? "ota_1" : "ota_0";
            char cmd[32];
            snprintf(cmd, sizeof(cmd), "ota_boot %s", target);
            simple_app_reset_ota_status(app);
            app->screen = ScreenOtaStatus;
            simple_app_send_command(app, cmd, false);
            if(app->viewport) view_port_update(app->viewport);
        }
        return;
    }

    if(key != InputKeyOk) return;

    switch(item) {
    case OtaItemIp:
        simple_app_ota_request_text_input(app, OtaInputIp);
        break;
    case OtaItemNetmask:
        simple_app_ota_request_text_input(app, OtaInputNetmask);
        break;
    case OtaItemGw:
        simple_app_ota_request_text_input(app, OtaInputGw);
        break;
    case OtaItemDns:
        simple_app_ota_request_text_input(app, OtaInputDns);
        break;
    default:
        break;
    }
}

static void simple_app_handle_confirm_ota_connect_input(SimpleApp* app, InputKey key) {
    if(!app) return;

    if(key == InputKeyBack) {
        app->screen = ScreenSetupOta;
        if(app->viewport) view_port_update(app->viewport);
        return;
    }

    if(key == InputKeyLeft || key == InputKeyRight) {
        app->ota_connect_confirm_yes = !app->ota_connect_confirm_yes;
        if(app->viewport) view_port_update(app->viewport);
        return;
    }

    if(key == InputKeyOk) {
        if(app->ota_connect_confirm_yes) {
            if(!simple_app_ota_send_wifi_connect(app)) {
                app->screen = ScreenSetupOta;
            }
        } else {
            simple_app_reset_ota_status(app);
            app->screen = ScreenOtaStatus;
            simple_app_send_command(app, "ota_check", false);
        }
        if(app->viewport) view_port_update(app->viewport);
    }
}

static void simple_app_handle_ota_status_input(SimpleApp* app, InputKey key) {
    if(!app) return;
    if(key == InputKeyBack) {
        app->screen = ScreenSetupOta;
        if(app->viewport) view_port_update(app->viewport);
    }
}

static void simple_app_handle_ota_list_input(SimpleApp* app, InputKey key) {
    if(!app) return;
    if(key == InputKeyBack) {
        app->screen = ScreenSetupOta;
        if(app->viewport) view_port_update(app->viewport);
    }
}

static void simple_app_handle_ota_info_input(SimpleApp* app, InputKey key) {
    if(!app) return;
    if(key == InputKeyBack) {
        app->screen = ScreenSetupOta;
        if(app->viewport) view_port_update(app->viewport);
    }
}

static void simple_app_handle_serial_input(SimpleApp* app, InputKey key) {
    if(!app) return;
    if(app->gps_console_mode && key == InputKeyBack) {
        app->screen = ScreenGps;
        app->gps_console_mode = false;
        if(app->viewport) {
            view_port_update(app->viewport);
        }
        return;
    }
    if(app->blackout_view_active && !app->blackout_full_console && key != InputKeyBack &&
       key != InputKeyUp && key != InputKeyDown) {
        return;
    }
    if(app->sniffer_dog_view_active && !app->sniffer_dog_full_console && key != InputKeyBack &&
       key != InputKeyUp && key != InputKeyDown) {
        return;
    }
    if(app->deauth_view_active && !app->deauth_full_console && key != InputKeyBack &&
       key != InputKeyUp && key != InputKeyDown && key != InputKeyLeft &&
       key != InputKeyRight && key != InputKeyOk) {
        return;
    }
    if(app->handshake_view_active && !app->handshake_full_console && key != InputKeyBack &&
       key != InputKeyOk) {
        return;
    }
    if(app->sae_view_active && !app->sae_full_console && key != InputKeyBack &&
       key != InputKeyOk) {
        return;
    }
    if(app->deauth_guard_view_active && !app->deauth_guard_full_console) {
        // In Deauth Guard compact mode ignore navigation; only Back stops and exits.
        if(key == InputKeyBack) {
            simple_app_send_stop_if_needed(app);
            app->screen = ScreenMenu;
            app->serial_follow_tail = true;
            simple_app_update_scroll(app);
            view_port_update(app->viewport);
        }
        return;
    }

    if(app->deauth_view_active && !app->deauth_full_console &&
       (key == InputKeyUp || key == InputKeyDown || key == InputKeyLeft || key == InputKeyRight)) {
        size_t selected_count = simple_app_target_count(app);
        if(selected_count > 0) {
            size_t visible = 4;
            size_t max_offset =
                selected_count > visible ? selected_count - visible : 0;
            if(key == InputKeyUp) {
                if(app->deauth_list_offset > 0) {
                    app->deauth_list_offset--;
                }
            } else if(key == InputKeyDown) {
                if(app->deauth_list_offset < max_offset) {
                    app->deauth_list_offset++;
                }
            } else if(key == InputKeyLeft) {
                if(app->deauth_list_scroll_x >= 4) {
                    app->deauth_list_scroll_x -= 4;
                } else {
                    app->deauth_list_scroll_x = 0;
                }
            } else if(key == InputKeyRight) {
                app->deauth_list_scroll_x += 4;
            }
            if(app->viewport) {
                view_port_update(app->viewport);
            }
        }
        return;
    }

    if(key == InputKeyBack) {
        simple_app_send_stop_if_needed(app);
        simple_app_clear_station_selection(app);
        if(app->blackout_view_active) {
            app->blackout_view_active = false;
            simple_app_reset_blackout_status(app);
            simple_app_focus_attacks_menu(app);
        } else if(app->handshake_view_active) {
            simple_app_reset_handshake_status(app);
            simple_app_focus_attacks_menu(app);
        } else if(app->sae_view_active) {
            simple_app_reset_sae_status(app);
            simple_app_focus_attacks_menu(app);
        } else if(app->deauth_view_active) {
            app->deauth_view_active = false;
            simple_app_reset_deauth_status(app);
            simple_app_focus_attacks_menu(app);
        } else if(app->sniffer_dog_view_active) {
            app->sniffer_dog_view_active = false;
            simple_app_reset_sniffer_dog_status(app);
            simple_app_focus_attacks_menu(app);
        } else {
            app->screen = ScreenMenu;
        }
        app->serial_follow_tail = true;
        simple_app_update_scroll(app);
        view_port_update(app->viewport);
    } else if(key == InputKeyUp) {
        if(app->bt_scan_view_active && app->bt_scan_show_list && !app->bt_scan_full_console) {
            if(app->bt_scan_list_offset > 0) {
                app->bt_scan_list_offset--;
                if(app->viewport) view_port_update(app->viewport);
            }
        } else if(app->serial_scroll > 0) {
            app->serial_scroll--;
            app->serial_follow_tail = false;
            view_port_update(app->viewport);
        }
    } else if(key == InputKeyDown) {
        if(app->bt_scan_view_active && app->bt_scan_show_list && !app->bt_scan_full_console) {
            if(simple_app_bt_scan_can_scroll_down(app)) {
                app->bt_scan_list_offset++;
                if(app->viewport) view_port_update(app->viewport);
            }
        } else {
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
        if(app->bt_locator_console_mode && app->bt_locator_list_ready) {
            app->bt_locator_console_mode = false;
            app->screen = ScreenBtLocatorList;
            view_port_update(app->viewport);
            return;
        }

        if(app->bt_scan_view_active && !app->bt_scan_full_console &&
           app->bt_scan_has_data && !app->bt_scan_running) {
            if(!app->bt_scan_show_list) {
                app->bt_scan_show_list = true;
                app->bt_scan_list_offset = 0;
                if(app->viewport) view_port_update(app->viewport);
                return;
            }
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


static void simple_app_handle_bt_locator_input(SimpleApp* app, InputKey key) {
    if(!app || !app->bt_locator_devices) return;
    if(key == InputKeyBack || key == InputKeyLeft) {
        simple_app_send_stop_if_needed(app);
        app->screen = ScreenMenu;
        view_port_update(app->viewport);
        return;
    }

    if(app->bt_locator_list_loading || app->bt_locator_count == 0) {
        return;
    }

    if(key == InputKeyUp) {
        if(app->bt_locator_index > 0) {
            app->bt_locator_index--;
            simple_app_bt_locator_ensure_visible(app);
            simple_app_bt_locator_reset_scroll(app);
            if(app->viewport) view_port_update(app->viewport);
        }
    } else if(key == InputKeyDown) {
        if(app->bt_locator_index + 1 < app->bt_locator_count) {
            app->bt_locator_index++;
            simple_app_bt_locator_ensure_visible(app);
            simple_app_bt_locator_reset_scroll(app);
            if(app->viewport) view_port_update(app->viewport);
        }
    } else if(key == InputKeyRight) {
    if(app->bt_locator_selected < 0) {
        return; // require explicit selection
    }
    size_t target_idx = (size_t)app->bt_locator_selected;
    if(target_idx >= app->bt_locator_count) return;
    const char* mac = app->bt_locator_devices[target_idx].mac;
    if(mac[0] != '\0' && strchr(mac, ':')) {
        // capture name for overlay
        const char* selected_name = app->bt_locator_devices[target_idx].name;
        if(selected_name && selected_name[0] != '\0') {
            strncpy(app->bt_locator_current_name, selected_name, sizeof(app->bt_locator_current_name) - 1);
            app->bt_locator_current_name[sizeof(app->bt_locator_current_name) - 1] = '\0';
        } else {
            app->bt_locator_current_name[0] = '\0';
        }
        char command[64];
        snprintf(command, sizeof(command), "scan_bt %s", mac);
        app->bt_locator_console_mode = false;
        app->bt_locator_mode = true;
        app->bt_locator_has_rssi = false;
            app->bt_locator_start_tick = furi_get_tick();
            app->bt_locator_last_console_tick = app->bt_locator_start_tick;
            strncpy(app->bt_locator_mac, mac, sizeof(app->bt_locator_mac) - 1);
            app->bt_locator_mac[sizeof(app->bt_locator_mac) - 1] = '\0';
            strncpy(app->bt_locator_saved_mac, mac, sizeof(app->bt_locator_saved_mac) - 1);
            app->bt_locator_saved_mac[sizeof(app->bt_locator_saved_mac) - 1] = '\0';
            app->bt_locator_preserve_mac = true;
            simple_app_send_command(app, command, true);
        }
    } else if(key == InputKeyOk) {
        if((int32_t)app->bt_locator_index == app->bt_locator_selected) {
            app->bt_locator_selected = -1;
        } else {
            app->bt_locator_selected = (int32_t)app->bt_locator_index;
            const char* mac_pick = app->bt_locator_devices[app->bt_locator_index].mac;
            if(mac_pick && mac_pick[0] != '\0') {
                strncpy(app->bt_locator_saved_mac, mac_pick, sizeof(app->bt_locator_saved_mac) - 1);
                app->bt_locator_saved_mac[sizeof(app->bt_locator_saved_mac) - 1] = '\0';
                strncpy(app->bt_locator_mac, mac_pick, sizeof(app->bt_locator_mac) - 1);
                app->bt_locator_mac[sizeof(app->bt_locator_mac) - 1] = '\0';
                app->bt_locator_preserve_mac = true;
                const char* selected_name = app->bt_locator_devices[app->bt_locator_index].name;
                if(selected_name && selected_name[0] != '\0') {
                    strncpy(app->bt_locator_current_name, selected_name, sizeof(app->bt_locator_current_name) - 1);
                    app->bt_locator_current_name[sizeof(app->bt_locator_current_name) - 1] = '\0';
                } else {
                    app->bt_locator_current_name[0] = '\0';
                }
                app->bt_locator_start_tick = furi_get_tick();
                app->bt_locator_last_console_tick = app->bt_locator_start_tick;
            }
        }
        simple_app_bt_locator_reset_scroll(app);
        if(app->viewport) view_port_update(app->viewport);
    }
}

static bool simple_app_is_direction_key(InputKey key) {
    return (key == InputKeyUp || key == InputKeyDown || key == InputKeyLeft || key == InputKeyRight);
}

LAB_C5_CODE_SECTION static void simple_app_input(InputEvent* event, void* context) {
    SimpleApp* app = context;
    if(!app || !event) return;

    // Global long Back: stop and return to main menu regardless of current state.
    if(event->type == InputTypeLong && event->key == InputKeyBack) {
        if(app->attack_view_active) {
            app->attack_return_to_sections = true;
            InputEvent stop_event = {.type = InputTypeShort, .key = InputKeyBack};
            simple_app_handle_attack_input(app, &stop_event);
            return;
        }
        if(app->screen == ScreenAttackLoading) {
            app->attack_return_to_sections = true;
            simple_app_request_module(app, C5ModuleRequestUnloadAttack);
            if(app->viewport) view_port_update(app->viewport);
            return;
        }
        if(app->recon_view_active || app->screen == ScreenReconLoading) {
            app->recon_open_attacks_pending = false;
            simple_app_request_module(app, C5ModuleRequestUnloadRecon);
            app->screen = ScreenReconLoading;
            if(app->viewport) view_port_update(app->viewport);
            return;
        }
        simple_app_send_stop_if_needed(app);
        if(app->web_view_active) simple_app_request_module(app, C5ModuleRequestUnloadWeb);
        if(!app->web_view_active && !app->recon_view_active)
            simple_app_clear_station_selection(app);
        app->bt_scan_view_active = false;
        app->bt_locator_mode = false;
        app->blackout_view_active = false;
        simple_app_reset_blackout_status(app);
        app->deauth_view_active = false;
        simple_app_reset_deauth_status(app);
        simple_app_reset_handshake_status(app);
        simple_app_reset_sae_status(app);
        app->sniffer_dog_view_active = false;
        simple_app_reset_sniffer_dog_status(app);
        app->deauth_guard_view_active = false;
        app->screen = ScreenMenu;
        app->menu_state = MenuStateSections;
        simple_app_adjust_section_offset(app);
        app->serial_follow_tail = true;
        app->last_back_tick = 0;
        if(app->viewport) {
            view_port_update(app->viewport);
        }
        return;
    }

    uint32_t now = furi_get_tick();

    // Global double short Back: show exit confirmation (after stopping tasks).
    if(!app->web_view_active && event->type == InputTypeShort &&
       !app->recon_view_active && !app->attack_view_active &&
       app->screen != ScreenAttackLoading &&
       event->key == InputKeyBack) {
        uint32_t last = app->last_back_tick;
        app->last_back_tick = now;
        if(last != 0 && (now - last) <= furi_ms_to_ticks(DOUBLE_BACK_EXIT_MS)) {
            simple_app_send_stop_if_needed(app);
            if(app->web_view_active) simple_app_request_module(app, C5ModuleRequestUnloadWeb);
            if(!app->web_view_active) simple_app_clear_station_selection(app);
            app->confirm_exit_yes = false;
            app->exit_confirm_active = true;
            app->exit_confirm_tick = now;
            app->screen = ScreenConfirmExit;
            app->menu_state = MenuStateSections;
            app->last_back_tick = 0;
            app->last_input_tick = now;
            if(app->viewport) {
                view_port_update(app->viewport);
            }
            return;
        }
    }

    app->last_input_tick = now;

    bool web_back = app->web_view_active && event->type == InputTypeShort &&
                    event->key == InputKeyBack &&
                    (app->screen == ScreenWebMenu || app->screen == ScreenSerial);
    bool recon_back = app->recon_view_active && event->type == InputTypeShort &&
                      event->key == InputKeyBack &&
                      (app->screen == ScreenRecon || app->screen == ScreenSerial);
    bool attack_back = app->attack_view_active && event->type == InputTypeShort &&
                       event->key == InputKeyBack && app->screen == ScreenAttackModule;
    if(web_back || recon_back || attack_back) {
        if(simple_app_status_message_is_active(app) && app->status_message_fullscreen) {
            simple_app_clear_status_message(app);
        }
        if(web_back) simple_app_handle_web_input(app, event);
        else if(recon_back) simple_app_handle_recon_input(app, event);
        else simple_app_handle_attack_input(app, event);
        return;
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

    if(app->web_view_active &&
       (app->screen == ScreenWebMenu || app->screen == ScreenSerial)) {
        simple_app_handle_web_input(app, event);
        return;
    }

    if(app->recon_view_active &&
       (app->screen == ScreenRecon || app->screen == ScreenSerial)) {
        simple_app_handle_recon_input(app, event);
        return;
    }

    if(app->attack_view_active && app->screen == ScreenAttackModule) {
        simple_app_handle_attack_input(app, event);
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

    if((event->type == InputTypeLong || event->type == InputTypeShort) &&
       event->key == InputKeyOk && app->handshake_view_active && app->screen == ScreenSerial) {
        app->handshake_full_console = !app->handshake_full_console;
        app->serial_follow_tail = true;
        if(app->viewport) {
            view_port_update(app->viewport);
        }
        return;
    }

    if((event->type == InputTypeLong || event->type == InputTypeShort) &&
       event->key == InputKeyOk && app->sae_view_active && app->screen == ScreenSerial) {
        app->sae_full_console = !app->sae_full_console;
        app->serial_follow_tail = true;
        if(app->viewport) {
            view_port_update(app->viewport);
        }
        return;
    }

    if((event->type == InputTypeLong || event->type == InputTypeShort) &&
       event->key == InputKeyOk && app->deauth_view_active && app->screen == ScreenSerial) {
        app->deauth_full_console = !app->deauth_full_console;
        app->serial_follow_tail = true;
        if(app->viewport) {
            view_port_update(app->viewport);
        }
        return;
    }

    if((event->type == InputTypeLong || event->type == InputTypeShort) &&
       event->key == InputKeyOk && app->deauth_guard_view_active) {
        app->deauth_guard_full_console = !app->deauth_guard_full_console;
        app->serial_follow_tail = true;
        if(app->viewport) {
            view_port_update(app->viewport);
        }
        return;
    }

    if(event->type == InputTypeLong && event->key == InputKeyOk) {
        if(app->screen == ScreenGps) {
            simple_app_handle_gps_input(app, event);
            return;
        }
        if(app->screen == ScreenSerial && app->gps_console_mode) {
            app->screen = ScreenGps;
            app->gps_console_mode = false;
            if(app->viewport) {
                view_port_update(app->viewport);
            }
            return;
        }
        if(app->blackout_view_active && app->screen == ScreenSerial) {
            app->blackout_full_console = !app->blackout_full_console;
            app->serial_follow_tail = true;
            if(app->viewport) {
                view_port_update(app->viewport);
            }
            return;
        }
        if(app->sniffer_dog_view_active && app->screen == ScreenSerial) {
            app->sniffer_dog_full_console = !app->sniffer_dog_full_console;
            app->serial_follow_tail = true;
            if(app->viewport) {
                view_port_update(app->viewport);
            }
            return;
        }
        if(app->bt_scan_view_active) {
            app->bt_scan_full_console = !app->bt_scan_full_console;
            if(app->bt_scan_full_console) {
                app->bt_scan_show_list = false;
            }
            app->serial_follow_tail = true;
            if(app->viewport) {
                view_port_update(app->viewport);
            }
            return;
        }
        // Debug helper: when in BT locator monitor, long OK shows raw console
        if(app->bt_locator_mode && app->screen == ScreenSerial) {
            app->bt_scan_full_console = !app->bt_scan_full_console;
            if(app->bt_scan_full_console) {
                app->bt_scan_show_list = false;
            }
            app->serial_follow_tail = true;
            if(app->viewport) {
                view_port_update(app->viewport);
            }
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

    if(event->key != InputKeyBack && app->exit_confirm_active) {
        app->exit_confirm_active = false;
    }

    switch(app->screen) {
    case ScreenMenu:
        simple_app_handle_menu_input(app, event->key);
        break;
    case ScreenSerial:
        simple_app_handle_serial_input(app, event->key);
        break;
    case ScreenSetupScanner:
        simple_app_handle_setup_scanner_input(app, event->key);
        break;
    case ScreenSetupScannerTiming:
        simple_app_handle_setup_scanner_timing_input(app, event->key);
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
    case ScreenSetupOta:
        simple_app_handle_setup_ota_input(app, event->key);
        break;
    case ScreenOtaStatus:
        simple_app_handle_ota_status_input(app, event->key);
        break;
    case ScreenOtaList:
        simple_app_handle_ota_list_input(app, event->key);
        break;
    case ScreenOtaInfo:
        simple_app_handle_ota_info_input(app, event->key);
        break;
    case ScreenHelpQr:
        simple_app_handle_help_qr_input(app, event->key);
        break;
    case ScreenConsole:
        simple_app_handle_console_input(app, event->key);
        break;
    case ScreenGps:
        simple_app_handle_gps_input(app, event);
        break;
    case ScreenGpsLoading:
        if(event->key == InputKeyBack) {
            simple_app_request_module(app, C5ModuleRequestUnloadGps);
            app->screen = ScreenMenu;
            if(app->viewport) view_port_update(app->viewport);
        }
        break;
    case ScreenWebLoading:
        if(event->key == InputKeyBack) {
            simple_app_request_module(app, C5ModuleRequestUnloadWeb);
            app->screen = ScreenMenu;
            if(app->viewport) view_port_update(app->viewport);
        }
        break;
    case ScreenReconLoading:
        if(event->key == InputKeyBack) {
            app->recon_open_attacks_pending = false;
            simple_app_request_module(app, C5ModuleRequestUnloadRecon);
            if(app->viewport) view_port_update(app->viewport);
        }
        break;
    case ScreenRecon:
        break;
    case ScreenAttackLoading:
        if(event->key == InputKeyBack) {
            simple_app_request_module(app, C5ModuleRequestUnloadAttack);
            if(app->viewport) view_port_update(app->viewport);
        }
        break;
    case ScreenAttackModule:
        break;
    case ScreenWardriveMenu:
        if(event->key == InputKeyBack) {
            app->screen = ScreenMenu;
        } else if(event->key == InputKeyUp) {
            if(app->wardrive_mode_index > 0) app->wardrive_mode_index--;
        } else if(event->key == InputKeyDown) {
            if((size_t)app->wardrive_mode_index + 1 <
               sizeof(wardrive_modes) / sizeof(wardrive_modes[0])) app->wardrive_mode_index++;
        } else if(event->key == InputKeyOk) {
            simple_app_request_attack(
                app, simple_app_wardrive_module_for_index(app->wardrive_mode_index));
        }
        if(app->viewport) view_port_update(app->viewport);
        break;
    case ScreenPackageMonitor:
        simple_app_handle_package_monitor_input(app, event->key);
        break;
    case ScreenChannelView:
        simple_app_handle_channel_view_input(app, event->key);
        break;
    case ScreenConfirmExit:
        simple_app_handle_confirm_exit_input(app, event->key);
        break;
    case ScreenConfirmBlackout:
        simple_app_handle_confirm_blackout_input(app, event->key);
        break;
    case ScreenConfirmSnifferDos:
        simple_app_handle_confirm_sniffer_dos_input(app, event->key);
        break;
    case ScreenConfirmOtaConnect:
        simple_app_handle_confirm_ota_connect_input(app, event->key);
        break;
    case ScreenBtLocatorList:
        simple_app_handle_bt_locator_input(app, event->key);
        break;
    default:
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

        /* Saved Evil Twin replies contain credentials. The attack FAL consumes
         * them, while the resident host serial log must not retain them. */
        bool log_rx = c5_attack_rx_guard_should_log(&app->attack_rx_guard) &&
                      !app->attack_view_active && !app->attack_module_loading &&
                      app->screen != ScreenAttackLoading;
        if(log_rx) {
            simple_app_append_serial_data(app, chunk, received);
        }
        c5_module_runtime_feed(&app->gps_module, chunk, received);
        c5_attack_rx_guard_feed(&app->attack_rx_guard, chunk, received);
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

static void simple_app_serial_irq(FuriHalSerialHandle* handle, FuriHalSerialRxEvent event, void* context) {
    SimpleApp* app = context;
    if(!app || !app->rx_stream || !(event & FuriHalSerialRxEventData)) return;

    do {
        uint8_t byte = furi_hal_serial_async_rx(handle);
        if(furi_stream_buffer_send(app->rx_stream, &byte, 1, 0) != 1) {
            app->rx_dropped_bytes++;
        }
        app->board_last_rx_tick = furi_get_tick();
    } while(furi_hal_serial_async_rx_available(handle));
}

int32_t Lab_C5_app(void* p) {
    UNUSED(p);

    if(!simple_app_usb_profile_ok()) {
        simple_app_show_usb_blocker();
        return 0;
    }

    // If SD is busy (e.g., mounted via qFlipper), exit immediately
    Storage* early_storage = furi_record_open(RECORD_STORAGE);
    if(early_storage) {
        if(storage_sd_status(early_storage) != FSE_OK) {
            furi_record_close(RECORD_STORAGE);
            return 0;
        }
        furi_record_close(RECORD_STORAGE);
    }

    const size_t free_heap = memmgr_get_free_heap();
    const size_t needed_heap = sizeof(SimpleApp) + 4096;
    if(free_heap < needed_heap) {
        simple_app_show_low_memory(free_heap, needed_heap);
        return 0;
    }

    SimpleApp* app = malloc(sizeof(SimpleApp));
    if(!app) {
        simple_app_show_low_memory(free_heap, needed_heap);
        return 0;
    }
    memset(app, 0, sizeof(SimpleApp));
    app->heap_start_free = memmgr_get_free_heap();
    simple_app_log_memory(app, "app_alloc");
    app->deauth_guard_last_channel = -1;
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
    app->scanner_min_channel_time = SCANNER_CHANNEL_TIME_DEFAULT_MIN;
    app->scanner_max_channel_time = SCANNER_CHANNEL_TIME_DEFAULT_MAX;
    app->scanner_timing_index = 0;
    app->scanner_timing_min_pending = false;
    app->scanner_timing_max_pending = false;
    app->scanner_timing_read_length = 0;
    app->scanner_timing_read_buffer[0] = '\0';
    app->scanner_setup_index = 0;
    app->scanner_adjusting_power = false;
    app->otg_power_initial_state = furi_hal_power_is_otg_enabled();
    app->otg_power_enabled = app->otg_power_initial_state;
    app->backlight_enabled = true;
    app->gps_time_24h = true;
    app->gps_utc_offset_minutes = 0;
    app->gps_dst_enabled = false;
    app->gps_zda_tz_enabled = false;
    app->show_ram_overlay = false;
    app->debug_mark_enabled = false;
    app->red_team_mode = true;
    app->debug_log_initialized = false;
    app->led_enabled = true;
    app->led_level = 10;
    app->led_setup_index = 0;
    app->board_ready_seen = false;
    app->board_sync_pending = true;
    app->board_ping_outstanding = false;
    app->board_last_ping_tick = 0;
    app->board_last_rx_tick = furi_get_tick();
    app->board_missing_shown = false;
    app->board_bootstrap_active = true;
    app->board_bootstrap_reboot_sent = false;
    app->board_ping_failures = 0;
    app->exit_confirm_active = false;
    app->exit_confirm_tick = 0;
    app->boot_short_enabled = false;
    app->boot_long_enabled = false;
    app->boot_short_command_index = 1; // start_sniffer_dog
    app->boot_long_command_index = 0;  // start_blackout
    app->boot_setup_index = 0;
    app->boot_setup_long = false;
    app->ota_setup_index = 0;
    app->ota_setup_offset = 0;
    app->ota_use_dhcp = true;
    app->ota_pass_show = false;
    app->ota_connect_confirm_yes = false;
    app->ota_input_requested = false;
    app->ota_input_active = false;
    app->ota_input_field = OtaInputNone;
    app->ota_ssid[0] = '\0';
    app->ota_password[0] = '\0';
    app->ota_ip[0] = '\0';
    app->ota_netmask[0] = '\0';
    app->ota_gw[0] = '\0';
    app->ota_dns[0] = '\0';
    app->ota_status_active = false;
    app->ota_list_active = false;
    app->ota_info_active = false;
    app->ota_boot_target_slot1 = false;
    snprintf(app->ota_channel, sizeof(app->ota_channel), "main");
    app->ota_wifi_status[0] = '\0';
    app->ota_ip_status[0] = '\0';
    app->ota_response[0] = '\0';
    app->ota_list_count = 0;
    app->ota_info_count = 0;
    app->ota_line_length = 0;
    app->scanner_view_offset = 0;
    app->karma_sniffer_duration_sec = 15;
    simple_app_update_backlight_label(app);
    simple_app_update_ram_label(app);
    simple_app_update_debug_label(app);
    simple_app_update_red_team_label(app);
    simple_app_update_led_label(app);
    simple_app_update_boot_labels(app);
    app->sd_folder_index = 0;
    app->sd_folder_offset = 0;
    app->sd_refresh_pending = false;
    simple_app_reset_sd_listing(app);
    if(sd_folder_option_count > 0) {
        simple_app_copy_sd_folder(app, &sd_folder_options[0]);
    }
    app->notifications = furi_record_open(RECORD_NOTIFICATION);
    app->menu_state = MenuStateSections;
    app->screen = ScreenMenu;
    app->serial_follow_tail = true;
    simple_app_reset_blackout_status(app);
    simple_app_reset_deauth_status(app);
    simple_app_reset_handshake_status(app);
    simple_app_reset_sae_status(app);
    simple_app_reset_sniffer_dog_status(app);
    app->last_input_tick = furi_get_tick();

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
    simple_app_log_memory(app, "rx_alloc");

    const C5HostApiV3 module_host = {
        .version = C5_MODULE_API_VERSION,
        .size = sizeof(C5HostApiV3),
        .ctx = app,
        .send_command = simple_app_module_host_send_command,
        .send_raw_lines = simple_app_module_host_send_raw_lines,
        .request_text_input = simple_app_module_host_request_text_input,
        .request_redraw = simple_app_module_host_request_redraw,
        .show_status = simple_app_module_host_show_status,
        .get_setting = simple_app_module_host_get_setting,
        .set_setting = simple_app_module_host_set_setting,
        .save_session = simple_app_module_host_save_session,
    };
    if(!c5_module_runtime_init(&app->gps_module, &module_host)) {
        furi_stream_buffer_free(app->rx_stream);
        furi_mutex_free(app->serial_mutex);
        furi_hal_serial_deinit(app->serial);
        furi_hal_serial_control_release(app->serial);
        if(app->notifications) furi_record_close(RECORD_NOTIFICATION);
        free(app);
        simple_app_show_low_memory(memmgr_get_free_heap(), sizeof(SimpleApp) + 4096);
        return 0;
    }

    furi_stream_buffer_reset(app->rx_stream);
    simple_app_reset_serial_log(app, "READY");

    {
        char line[96];
        snprintf(
            line,
            sizeof(line),
            "Heap start free:%lu min:%lu SimpleApp:%lu\n",
            (unsigned long)memmgr_get_free_heap(),
            (unsigned long)memmgr_get_minimum_free_heap(),
            (unsigned long)sizeof(SimpleApp));
        simple_app_append_serial_data(app, (const uint8_t*)line, strlen(line));
    }

    furi_hal_serial_async_rx_start(app->serial, simple_app_serial_irq, app, false);

    app->gui = furi_record_open(RECORD_GUI);
    app->viewport = view_port_alloc();
    view_port_draw_callback_set(app->viewport, simple_app_draw, app);
    view_port_input_callback_set(app->viewport, simple_app_input, app);
    gui_add_view_port(app->gui, app->viewport, GuiLayerFullscreen);
    simple_app_log_memory(app, "viewport");

    simple_app_load_config(app);
    app->vendor_scan_enabled = app->scanner_show_vendor;
    app->debug_log_initialized = false;
    if(app->debug_mark_enabled) {
        simple_app_reset_debug_log(app);
        app->debug_log_initialized = true;
    }
    simple_app_update_backlight_label(app);
    simple_app_update_ram_label(app);
    simple_app_update_debug_label(app);
    simple_app_update_led_label(app);
    simple_app_update_boot_labels(app);
    simple_app_apply_backlight(app);
    // Respect config value (loaded by simple_app_load_config) and apply it to HW
    simple_app_apply_otg_power(app);
    simple_app_log_memory(app, "ready");
    if(app->viewport) {
        view_port_update(app->viewport);
    }

    if(!simple_app_status_message_is_active(app)) {
        simple_app_show_status_message(app, "Board discovery\nSending ping...", 0, true);
    }
    simple_app_send_ping(app);
    if(app->viewport) {
        view_port_update(app->viewport);
    }

        while(!app->exit_app) {
            simple_app_process_module_requests(app);
            simple_app_run_module_text_input(app);
            simple_app_process_stream(app);
            simple_app_process_module_requests(app);
            simple_app_update_sd_scroll(app);
            simple_app_update_deauth_guard(app);
            simple_app_update_deauth_blink(app);
            simple_app_update_handshake_blink(app);
            c5_module_runtime_tick(&app->gps_module, furi_get_tick());
            simple_app_ping_watchdog(app);
            simple_app_usb_runtime_guard(app);

        if(app->ota_input_requested && !app->ota_input_active) {
            app->ota_input_requested = false;
            bool accepted = simple_app_ota_run_text_input(app);
            if(accepted) {
                simple_app_show_status_message(app, "OTA field updated", 1000, true);
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

        if(app->exit_confirm_active) {
            uint32_t now = furi_get_tick();
            if(now - app->exit_confirm_tick >= furi_ms_to_ticks(2000)) {
                app->exit_confirm_active = false;
            }
        }

        furi_delay_ms(20);
    }

    simple_app_log_memory(app, "exit_pre");
    simple_app_prepare_exit(app);
    simple_app_log_memory(app, "exit_post");

    simple_app_save_config_if_dirty(app, NULL, false);

    gui_remove_view_port(app->gui, app->viewport);
    view_port_free(app->viewport);
    c5_module_runtime_deinit(&app->gps_module);
    FURI_LOG_I(
        TAG,
        "Heap after viewport free:%lu min:%lu",
        (unsigned long)memmgr_get_free_heap(),
        (unsigned long)memmgr_get_minimum_free_heap());
    furi_record_close(RECORD_GUI);

    furi_hal_serial_async_rx_stop(app->serial);
    furi_stream_buffer_free(app->rx_stream);
    FURI_LOG_I(
        TAG,
        "Heap after stream free:%lu min:%lu",
        (unsigned long)memmgr_get_free_heap(),
        (unsigned long)memmgr_get_minimum_free_heap());
    furi_hal_serial_deinit(app->serial);
    furi_hal_serial_control_release(app->serial);
    furi_mutex_free(app->serial_mutex);
    FURI_LOG_I(
        TAG,
        "Heap after mutex free:%lu min:%lu",
        (unsigned long)memmgr_get_free_heap(),
        (unsigned long)memmgr_get_minimum_free_heap());
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
    // Do not restore OTG state on exit: 5V setting is user-configurable and persisted via config.
    furi_hal_light_set(LightBacklight, BACKLIGHT_ON_LEVEL);
    c5_recon_targets_clear(&app->recon_targets);
    free(app);

    return 0;
}
