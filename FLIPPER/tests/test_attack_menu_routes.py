"""Execute production menu dispatch and FAL routing in a small host harness.

The test extracts the two C decision blocks from Lab_C5.c. It catches a
visible menu item that silently chooses no module or the wrong embedded FAL.
"""

from pathlib import Path
import os
import re
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "Lab_C5.c").read_text(encoding="utf-8")


def production_enum(name: str) -> str:
    match = re.search(rf"typedef enum \{{[^}}]*\}} {re.escape(name)};", SOURCE, re.DOTALL)
    if not match:
        raise AssertionError(f"Missing production enum: {name}")
    return match.group()


def production_menu_route() -> str:
    function_start = SOURCE.index("static void simple_app_handle_menu_input(SimpleApp* app, InputKey key) {")
    start = SOURCE.index("} else if(entry->action == MenuActionOpenConnect)", function_start)
    end = SOURCE.index("} else if(entry->action == MenuActionOpenBeacon)", start)
    return SOURCE[start:end].replace("} else if(", "if(", 1) + "}\n"


def production_fal_route() -> str:
    function_start = SOURCE.index("static bool simple_app_open_attack(SimpleApp* app) {")
    start = SOURCE.index("    C5RogueLaunchContext rogue = {", function_start)
    end = SOURCE.index('    simple_app_log_memory(app, "attack_load_pre");', start)
    return SOURCE[start:end]


def harness() -> str:
    return f"""
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "modules/recon/recon_scan.h"
#include "modules/rogue/rogue_module.h"
#include "modules/arp/arp_module.h"
#include "modules/beacon/beacon_module.h"
#include "modules/wardrive/wardrive_module.h"
#include "modules/mitm_pcap/mitm_pcap_module.h"
#include "modules/wardrive_upload/wardrive_upload_module.h"
#include "modules/nmap/nmap_module.h"
#include "modules/wpasec/wpasec_module.h"
#include "modules/connect/connect_module.h"

#define APP_ASSETS_PATH(path) path
#define furi_ms_to_ticks(milliseconds) (milliseconds)
#define simple_app_format_bssid(...) ((void)0)

{production_enum("C5AttackModule")}
{production_enum("MenuAction")}

typedef struct {{
    C5AttackModule attack_module;
    struct {{ C5ReconTarget* targets; }} recon_targets;
    unsigned requests;
}} SimpleApp;
typedef struct {{ MenuAction action; }} MenuEntry;

static void simple_app_request_attack(SimpleApp* app, C5AttackModule module) {{
    app->attack_module = module;
    app->requests++;
}}

static void choose_menu_action(SimpleApp* app, const MenuEntry* entry) {{
    {production_menu_route()}
}}

static void check_fal_route(SimpleApp* app, const char* expected_path) {{
    {production_fal_route()}
    assert(strcmp(path, expected_path) == 0);
    if(app->attack_module == C5AttackModuleConnect) {{
        assert(params_size == sizeof(C5ConnectLaunchContext));
        const C5ConnectLaunchContext* launch = params;
        assert(launch->version == C5_CONNECT_LAUNCH_VERSION);
        assert(launch->size == sizeof(*launch));
        assert(strcmp(launch->ssid, "Test AP") == 0);
    }} else if(app->attack_module == C5AttackModuleNmap) {{
        assert(params_size == sizeof(C5NmapLaunchContext));
        const C5NmapLaunchContext* launch = params;
        assert(launch->version == C5_NMAP_LAUNCH_VERSION);
        assert(launch->size == sizeof(*launch));
        assert(launch->ticks_per_second > 0);
    }} else if(app->attack_module == C5AttackModuleWpasec) {{
        assert(params_size == sizeof(C5WpasecLaunchContext));
        const C5WpasecLaunchContext* launch = params;
        assert(launch->version == C5_WPASEC_LAUNCH_VERSION);
        assert(launch->size == sizeof(*launch));
        assert(!launch->tls_verified);
    }} else if(app->attack_module == C5AttackModuleWardriveUploadWigle ||
              app->attack_module == C5AttackModuleWardriveUploadWdgwars) {{
        assert(params_size == sizeof(C5WardriveUploadLaunchContext));
        const C5WardriveUploadLaunchContext* launch = params;
        assert(!launch->tls_verified);
    }}
}}

int main(void) {{
    SimpleApp app = {{0}};
    C5ReconTarget target = {{0}};
    strcpy(target.ssid, "Test AP");
    app.recon_targets.targets = &target;
    MenuEntry connect = {{.action = MenuActionOpenConnect}};
    choose_menu_action(&app, &connect);
    assert(app.requests == 1 && app.attack_module == C5AttackModuleConnect);
    check_fal_route(&app, "plugins/lab_c5_connect.fal");

    app = (SimpleApp){{0}};
    MenuEntry nmap = {{.action = MenuActionOpenNmap}};
    choose_menu_action(&app, &nmap);
    assert(app.requests == 1 && app.attack_module == C5AttackModuleNmap);
    check_fal_route(&app, "plugins/lab_c5_nmap.fal");

    app = (SimpleApp){{0}};
    MenuEntry wpasec = {{.action = MenuActionOpenWpasec}};
    choose_menu_action(&app, &wpasec);
    assert(app.requests == 1 && app.attack_module == C5AttackModuleWpasec);
    check_fal_route(&app, "plugins/lab_c5_wpasec.fal");

    app.attack_module = C5AttackModuleWardriveUploadWigle;
    check_fal_route(&app, "plugins/lab_c5_wardrive_upload.fal");
    app.attack_module = C5AttackModuleWardriveUploadWdgwars;
    check_fal_route(&app, "plugins/lab_c5_wardrive_upload.fal");
    return 0;
}}
"""


class AttackMenuRoutes(unittest.TestCase):
    def test_menu_actions_choose_embedded_plugins_with_safe_launch_context(self) -> None:
        self.assertIsNotNone(
            re.search(r'\{"Connect",\s*NULL,\s*MenuActionOpenConnect,\s*false\}', SOURCE),
            "Connect menu action missing",
        )
        self.assertRegex(SOURCE, r'\{"Nmap",\s*NULL,\s*MenuActionOpenNmap,\s*true\}')
        self.assertRegex(
            SOURCE,
            r'\{"WPA-sec Upload",\s*NULL,\s*MenuActionOpenWpasec,\s*false\}',
        )
        executable = f"/tmp/c5_attack_menu_routes_{os.getpid()}"
        built = subprocess.run(
            ["wsl.exe", "--", "cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
             "-I.", "-x", "c", "-", "-o", executable],
            cwd=ROOT, input=harness(), text=True, capture_output=True, check=False,
        )
        self.assertEqual(built.returncode, 0, built.stderr)
        try:
            ran = subprocess.run(
                ["wsl.exe", "--", executable], cwd=ROOT,
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(ran.returncode, 0, ran.stderr)
        finally:
            subprocess.run(["wsl.exe", "--", "rm", "-f", executable], cwd=ROOT, check=False)


if __name__ == "__main__":
    unittest.main()
