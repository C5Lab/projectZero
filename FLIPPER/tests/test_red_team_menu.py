"""Execute FLIPPER's menu and config code in a small host C harness.

The app itself needs Flipper firmware. This harness extracts the production
menu and config functions and replaces only the firmware storage/UI boundary.
"""

from pathlib import Path
import os
import re
import subprocess
import unittest


SOURCE = (Path(__file__).resolve().parents[1] / "Lab_C5.c").read_text(encoding="utf-8")


def block(pattern: str) -> str:
    match = re.search(pattern, SOURCE, re.MULTILINE | re.DOTALL)
    if match is None:
        raise AssertionError(f"Missing production block: {pattern}")
    start = match.start()
    opening = SOURCE.find("{", match.start(), match.end())
    if opening < 0:
        raise AssertionError(f"No opening brace: {pattern}")
    depth = 1
    end = opening + 1
    while depth and end < len(SOURCE):
        depth += (SOURCE[end] == "{") - (SOURCE[end] == "}")
        end += 1
    if depth:
        raise AssertionError(f"Unclosed production block: {pattern}")
    if match.end() > end:
        end = match.end()
    if SOURCE[end] == ";":
        end += 1
    return SOURCE[start:end]


def function(name: str) -> str:
    return block(rf"^static\s+[^;{{\n]+\s+{re.escape(name)}\([^;{{]*\)\s*\{{")


def harness() -> str:
    menu_definitions = SOURCE[
        SOURCE.index("static const MenuEntry menu_entries_sniffers[]") :
        SOURCE.index("static const size_t menu_section_count")
    ]
    config_paths = "\n".join(
        line for line in SOURCE.splitlines()
        if line.startswith("#define LAB_C5_CONFIG_")
    )
    menu_macros = "\n".join(
        line for line in SOURCE.splitlines()
        if line.startswith("#define MENU_")
    )
    option_count = re.search(r"^#define BOOT_COMMAND_OPTION_COUNT .+$", SOURCE, re.MULTILINE)
    if option_count is None:
        raise AssertionError("Missing boot option count")
    option_list = block(r"^static const char\* boot_command_options\[BOOT_COMMAND_OPTION_COUNT\] = \{")
    enum_actions = block(r"^typedef enum \{[^}]*MenuActionCommand[^}]*\} MenuAction;")
    entry_type = block(r"^typedef struct \{[^}]*\} MenuEntry;")
    section_type = block(r"^typedef struct \{[^}]*\} MenuSection;")
    names = (
        "simple_app_menu_visible_count",
        "simple_app_menu_entry_is_visible",
        "simple_app_menu_entry_count",
        "simple_app_menu_entry_at",
        "simple_app_menu_move_item",
        "simple_app_attack_index_for_command",
        "simple_app_focus_attacks_menu",
        "simple_app_clamp_gps_utc_offset",
        "simple_app_mark_config_dirty",
        "simple_app_parse_bool_value",
        "simple_app_trim",
        "simple_app_parse_config_line",
        "simple_app_save_config",
        "simple_app_load_config",
        "simple_app_save_config_if_dirty",
        "simple_app_update_red_team_label",
        "simple_app_toggle_red_team",
    )
    functions = "\n\n".join(function(name) for name in names)
    return f"""
#include <assert.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define UNUSED(x) ((void)(x))
#define TAG "HostTest"
#define FURI_LOG_E(...) ((void)0)
#define EXT_PATH(x) x
#define RECORD_STORAGE 1
#define FSAM_READ 1
#define FSAM_READ_WRITE 2
#define FSOM_OPEN_EXISTING 1
#define FSOM_CREATE_ALWAYS 2
#define SCAN_POWER_MIN_DBM (-110)
#define SCAN_POWER_MAX_DBM 0
#define SCANNER_CHANNEL_TIME_MIN_MS 10
#define SCANNER_CHANNEL_TIME_MAX_MS 2000
#define KARMA_SNIFFER_DURATION_MIN_SEC 5
#define KARMA_SNIFFER_DURATION_MAX_SEC 180
#define GPS_UTC_OFFSET_MIN_MINUTES (-12 * 60)
#define GPS_UTC_OFFSET_MAX_MINUTES (14 * 60)
{menu_macros}
{config_paths}
{option_count.group()}
{enum_actions}
{entry_type}
{section_type}

typedef struct {{
    bool red_team_mode;
    bool config_dirty;
    bool config_seen_led_enabled, config_seen_led_level;
    bool config_seen_gps_utc_offset, config_seen_gps_dst, config_seen_gps_zda_tz;
    bool scanner_show_ssid, scanner_show_bssid, scanner_show_channel;
    bool scanner_show_security, scanner_show_power, scanner_show_band, scanner_show_vendor;
    int16_t scanner_min_power;
    uint16_t scanner_min_channel_time, scanner_max_channel_time;
    bool backlight_enabled, otg_power_enabled, show_ram_overlay, debug_mark_enabled;
    uint32_t karma_sniffer_duration_sec;
    int16_t gps_utc_offset_minutes;
    bool gps_dst_enabled, gps_zda_tz_enabled;
    bool led_enabled;
    uint8_t led_level;
    bool boot_short_enabled, boot_long_enabled;
    uint8_t boot_short_command_index, boot_long_command_index;
    int screen, menu_state;
    uint32_t section_index, item_index, item_offset, last_attack_index;
    void* viewport;
}} SimpleApp;
#define ScreenMenu 1
#define MenuStateItems 1

typedef struct {{ int unused; }} Storage;
typedef struct {{ size_t position; }} File;
static Storage test_storage;
static char config_bytes[2048];
static size_t config_length;
static bool config_exists;
static int redraw_count;
static Storage* furi_record_open(int id) {{ UNUSED(id); return &test_storage; }}
static void furi_record_close(int id) {{ UNUSED(id); }}
static void storage_simply_mkdir(Storage* storage, const char* path) {{ UNUSED(storage); UNUSED(path); }}
static File* storage_file_alloc(Storage* storage) {{ UNUSED(storage); return calloc(1, sizeof(File)); }}
static bool storage_file_open(File* file, const char* path, int access, int mode) {{
    UNUSED(path); UNUSED(access); file->position = 0;
    if(mode == FSOM_OPEN_EXISTING) return config_exists;
    config_exists = true;
    config_length = 0;
    config_bytes[0] = '\\0';
    return true;
}}
static size_t storage_file_write(File* file, const void* data, size_t length) {{
    UNUSED(file);
    assert(length < sizeof(config_bytes));
    memcpy(config_bytes, data, length);
    config_length = length;
    config_bytes[length] = '\\0';
    return length;
}}
static size_t storage_file_read(File* file, void* data, size_t length) {{
    if(file->position >= config_length) return 0;
    if(length > config_length - file->position) length = config_length - file->position;
    memcpy(data, config_bytes + file->position, length);
    file->position += length;
    return length;
}}
static void storage_file_close(File* file) {{ UNUSED(file); }}
static void storage_file_free(File* file) {{ free(file); }}
static void simple_app_show_status_message(SimpleApp* app, const char* message,
    uint32_t duration_ms, bool fullscreen) {{
    UNUSED(app); UNUSED(message); UNUSED(duration_ms); UNUSED(fullscreen);
}}
static void view_port_update(void* viewport) {{ UNUSED(viewport); redraw_count++; }}

{option_list}
{menu_definitions}
static const size_t menu_section_count = sizeof(menu_sections) / sizeof(menu_sections[0]);

static size_t simple_app_menu_entry_count(const SimpleApp* app, uint32_t section_index);
static const MenuEntry* simple_app_menu_entry_at(const SimpleApp* app,
    uint32_t section_index, size_t visible_index);
static void simple_app_mark_config_dirty(SimpleApp* app);
static bool simple_app_save_config(SimpleApp* app, const char* message, bool fullscreen);
static void simple_app_save_config_if_dirty(SimpleApp* app, const char* message, bool fullscreen);

{functions}

static void set_config(const char* value) {{
    config_length = strlen(value);
    assert(config_length < sizeof(config_bytes));
    memcpy(config_bytes, value, config_length + 1);
    config_exists = true;
}}

int main(void) {{
    SimpleApp app = {{0}};
    app.red_team_mode = true;
    const char* full[] = {{
        "Connect", "Blackout", "Deauth", "Deauth Guard", "Handshaker", "Evil Twin",
        "Rogue AP", "ARP Poisoning", "ARP Saved", "MITM PCAP", "Nmap", "Portal", "Karma",
        "Sniffer", "SAE Overflow", "Sniffer Dog", "Beacon Spam", "Wardrive"
    }};
    assert(simple_app_menu_entry_count(&app, MENU_SECTION_ATTACKS) == 18);
    for(size_t i = 0; i < 18; i++)
        assert(strcmp(simple_app_menu_entry_at(&app, MENU_SECTION_ATTACKS, i)->label, full[i]) == 0);
    assert(simple_app_menu_entry_at(&app, MENU_SECTION_ATTACKS, 0)->action == MenuActionOpenConnect);
    assert(simple_app_menu_entry_at(&app, MENU_SECTION_ATTACKS, 0)->command == NULL);
    assert(simple_app_menu_entry_at(&app, MENU_SECTION_ATTACKS, 9)->action == MenuActionOpenMitmPcap);
    assert(simple_app_menu_entry_at(&app, MENU_SECTION_ATTACKS, 10)->action == MenuActionOpenNmap);
    assert(simple_app_menu_entry_at(&app, MENU_SECTION_ATTACKS, 16)->action == MenuActionOpenBeacon);
    assert(simple_app_menu_entry_at(&app, MENU_SECTION_ATTACKS, 17)->action == MenuActionOpenWardrive);
    assert(simple_app_attack_index_for_command(&app, "start_sniffer") == 13);
    app.section_index = MENU_SECTION_ATTACKS;
    app.item_index = 17;
    app.item_offset = 14;
    simple_app_menu_move_item(&app, true);
    assert(app.item_index == 0 && app.item_offset == 0);
    simple_app_menu_move_item(&app, false);
    assert(app.item_index == 17 && app.item_offset == 14);

    app.red_team_mode = false;
    const char* basic[] = {{"Connect", "Deauth Guard", "Portal", "Karma", "Sniffer", "Wardrive"}};
    assert(simple_app_menu_entry_count(&app, MENU_SECTION_ATTACKS) == 6);
    for(size_t i = 0; i < 6; i++)
        assert(strcmp(simple_app_menu_entry_at(&app, MENU_SECTION_ATTACKS, i)->label, basic[i]) == 0);
    assert(simple_app_menu_entry_at(&app, MENU_SECTION_ATTACKS, 6) == NULL);
    assert(simple_app_attack_index_for_command(&app, "start_sniffer") == 4);
    const MenuEntry* wpasec = NULL;
    for(size_t i = 0; i < simple_app_menu_entry_count(&app, MENU_SECTION_SETUP); i++) {{
        const MenuEntry* entry = simple_app_menu_entry_at(&app, MENU_SECTION_SETUP, i);
        if(strcmp(entry->label, "WPA-sec Upload") == 0) wpasec = entry;
    }}
    assert(wpasec != NULL && wpasec->action == MenuActionOpenWpasec);
    assert(wpasec->command == NULL);

    app.section_index = MENU_SECTION_ATTACKS;
    app.item_index = 5;
    app.item_offset = 2;
    simple_app_menu_move_item(&app, true);
    assert(app.item_index == 0 && app.item_offset == 0 && app.last_attack_index == 0);
    simple_app_menu_move_item(&app, false);
    assert(app.item_index == 5 && app.item_offset == 2 && app.last_attack_index == 5);
    app.last_attack_index = 10;
    simple_app_focus_attacks_menu(&app);
    assert(app.item_index == 5 && app.item_offset == 2);
    assert(strcmp(simple_app_menu_entry_at(&app, MENU_SECTION_ATTACKS, app.item_index)->label, "Wardrive") == 0);

    app = (SimpleApp){{0}};
    app.red_team_mode = true;
    app.scanner_min_power = -110;
    app.scanner_min_channel_time = 2000;
    app.scanner_max_channel_time = 2000;
    app.karma_sniffer_duration_sec = 180;
    app.gps_utc_offset_minutes = 840;
    app.led_level = 100;
    app.boot_short_command_index = 1;
    app.boot_long_command_index = 1;
    assert(simple_app_save_config(&app, NULL, false));
    assert(strstr(config_bytes, "red_team_mode=1\\n") != NULL);
    assert(strstr(config_bytes, "boot_long=start_sniffer_dog\\n") != NULL);

    set_config("led_enabled=1\\nled_level=10\\ngps_utc_offset_min=0\\n"
        "gps_dst=0\\ngps_zda_tz=0\\n");
    app = (SimpleApp){{0}};
    app.red_team_mode = true;
    simple_app_load_config(&app);
    assert(app.red_team_mode); /* legacy file without the key retains the default */
    app.viewport = &app;
    app.last_attack_index = 10;
    redraw_count = 0;
    simple_app_toggle_red_team(&app);
    assert(!app.red_team_mode && app.last_attack_index == 0);
    assert(!app.config_dirty && redraw_count > 0);
    assert(strstr(config_bytes, "red_team_mode=0\\n") != NULL);
    SimpleApp reloaded = {{0}};
    reloaded.red_team_mode = true;
    simple_app_load_config(&reloaded);
    assert(!reloaded.red_team_mode);
    simple_app_toggle_red_team(&reloaded);
    assert(strstr(config_bytes, "red_team_mode=1\\n") != NULL);
    return 0;
}}
"""


class RedTeamHostBehavior(unittest.TestCase):
    def test_menu_navigation_and_config_round_trip(self) -> None:
        executable = f"/tmp/lab_c5_red_team_test_{os.getpid()}"
        compile_result = subprocess.run(
            ["wsl.exe", "--", "gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-x", "c", "-", "-o", executable],
            input=harness(), text=True, capture_output=True, check=False,
        )
        self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
        try:
            run_result = subprocess.run(
                ["wsl.exe", "--", executable], text=True, capture_output=True, check=False,
            )
            self.assertEqual(run_result.returncode, 0, run_result.stderr)
        finally:
            subprocess.run(["wsl.exe", "--", "rm", "-f", executable], check=False)


if __name__ == "__main__":
    unittest.main()
