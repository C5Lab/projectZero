#include "led_cli_activity.h"

#include <assert.h>
#include <stdio.h>

typedef struct {
    const char *command;
    const char *subcommand;
    led_status_activity_t expected;
} cli_case_t;

static const cli_case_t cases[] = {
    {"scan_networks", NULL, LED_STATUS_SCAN},
    {"wifi_analyzer", "scan", LED_STATUS_SCAN},
    {"scan_bt", NULL, LED_STATUS_SCAN},
    {"scan_airtag", NULL, LED_STATUS_SCAN},
    {"start_zig_recon", NULL, LED_STATUS_SCAN},
    {"start_nmap", NULL, LED_STATUS_SCAN},
    {"test_radio_channel", "36", LED_STATUS_SCAN},
    {"test_radio_channels", NULL, LED_STATUS_SCAN},
    {"inspect_network", "0", LED_STATUS_SCAN},
    {"wifi_connect", "ssid", LED_STATUS_SCAN},

    {"start_sniffer", NULL, LED_STATUS_MONITOR},
    {"start_sniffer_noscan", NULL, LED_STATUS_MONITOR},
    {"packet_monitor", "6", LED_STATUS_MONITOR},
    {"start_ap_locator", NULL, LED_STATUS_MONITOR},
    {"channel_view", NULL, LED_STATUS_MONITOR},
    {"deauth_detector", NULL, LED_STATUS_MONITOR},
    {"deauth_detector_v2", NULL, LED_STATUS_MONITOR},
    {"start_antisurveillance", NULL, LED_STATUS_MONITOR},

    {"start_handshake", NULL, LED_STATUS_CAPTURE},
    {"start_pcap", "radio", LED_STATUS_CAPTURE},
    {"capture_gateway", "start", LED_STATUS_CAPTURE},
    {"start_wardrive", NULL, LED_STATUS_CAPTURE},
    {"start_wardrive_promisc", NULL, LED_STATUS_CAPTURE},
    {"start_wardrive_promisc_trace", NULL, LED_STATUS_CAPTURE},
    {"start_gps_raw", NULL, LED_STATUS_CAPTURE},

    {"start_deauth", NULL, LED_STATUS_TRANSMIT},
    {"start_deauth_station", NULL, LED_STATUS_TRANSMIT},
    {"start_sniffer_dog", NULL, LED_STATUS_TRANSMIT},
    {"sae_overflow", NULL, LED_STATUS_TRANSMIT},
    {"start_blackout", NULL, LED_STATUS_TRANSMIT},
    {"start_beacon_spam", NULL, LED_STATUS_TRANSMIT},
    {"start_beacon_spam_ssids", NULL, LED_STATUS_TRANSMIT},
    {"start_blespam", NULL, LED_STATUS_TRANSMIT},
    {"start_jammer24", NULL, LED_STATUS_TRANSMIT},
    {"arp_ban", "AA:BB:CC:DD:EE:FF", LED_STATUS_TRANSMIT},

    {"start_evil_twin", NULL, LED_STATUS_PORTAL},
    {"start_portal", NULL, LED_STATUS_PORTAL},
    {"start_admin_portal", NULL, LED_STATUS_PORTAL},
    {"start_darksword", NULL, LED_STATUS_PORTAL},
    {"start_rogueap", NULL, LED_STATUS_PORTAL},
    {"start_rogue_gitm", NULL, LED_STATUS_PORTAL},
    {"start_karma", NULL, LED_STATUS_PORTAL},

    {"wps", "verify", LED_STATUS_WPS},
    {"wps", "pixie", LED_STATUS_WPS},
    {"jwps", "campaign", LED_STATUS_WPS},

    {"sd_benchmark", NULL, LED_STATUS_TRANSFER},
    {"send_file", "capture.pcap", LED_STATUS_TRANSFER},
    {"save_handshake", NULL, LED_STATUS_TRANSFER},
    {"wardrive_cleanup", "all", LED_STATUS_TRANSFER},
    {"wardrive_fix", "capture.log", LED_STATUS_TRANSFER},
    {"wardrive_fix_kml", "trace.inprogress.kml", LED_STATUS_TRANSFER},
    {"artifact_inventory", "list", LED_STATUS_TRANSFER},
    {"artifact_inventory", "inspect", LED_STATUS_TRANSFER},
    {"wpasec_upload", NULL, LED_STATUS_TRANSFER},
    {"wigle_upload", NULL, LED_STATUS_TRANSFER},
    {"wdgwars_upload", NULL, LED_STATUS_TRANSFER},
    {"crack_worker", "start", LED_STATUS_TRANSFER},

    {NULL, NULL, LED_STATUS_IDLE},
    {"", NULL, LED_STATUS_IDLE},
    {"led", "set", LED_STATUS_IDLE},
    {"stop", NULL, LED_STATUS_IDLE},
    {"show_scan_results", NULL, LED_STATUS_IDLE},
    {"wifi_analyzer", NULL, LED_STATUS_IDLE},
    {"wifi_analyzer", "caps", LED_STATUS_IDLE},
    {"wifi_analyzer", "status", LED_STATUS_IDLE},
    {"wifi_analyzer", "stop", LED_STATUS_IDLE},
    {"wifi_analyzer", "clear", LED_STATUS_IDLE},
    {"capture_gateway", NULL, LED_STATUS_IDLE},
    {"capture_gateway", "status", LED_STATUS_IDLE},
    {"capture_gateway", "stop", LED_STATUS_IDLE},
    {"wps", NULL, LED_STATUS_IDLE},
    {"wps", "status", LED_STATUS_IDLE},
    {"wps", "stop", LED_STATUS_IDLE},
    {"jwps", NULL, LED_STATUS_IDLE},
    {"jwps", "plan", LED_STATUS_IDLE},
    {"crack_worker", NULL, LED_STATUS_IDLE},
    {"crack_worker", "capabilities", LED_STATUS_IDLE},
    {"crack_worker", "status", LED_STATUS_IDLE},
    {"crack_worker", "cancel", LED_STATUS_IDLE},
    {"crack_worker", "receive", LED_STATUS_IDLE},
    {"wardrive_cleanup", NULL, LED_STATUS_IDLE},
    {"wardrive_fix", NULL, LED_STATUS_IDLE},
    {"wardrive_fix_kml", NULL, LED_STATUS_IDLE},
    {"artifact_inventory", NULL, LED_STATUS_IDLE},
    {"artifact_inventory", "capabilities", LED_STATUS_IDLE},
    {"artifact_inventory", "cancel", LED_STATUS_IDLE},
    {"arp_ban", NULL, LED_STATUS_IDLE},
    {"download", NULL, LED_STATUS_IDLE},
    {"ota_check", NULL, LED_STATUS_IDLE},
    {"start_deauth_extra", NULL, LED_STATUS_IDLE},
    {"unknown_command", "start", LED_STATUS_IDLE},
};

int main(void)
{
    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        led_status_activity_t actual = led_cli_activity(cases[i].command, cases[i].subcommand);
        if (actual != cases[i].expected) {
            fprintf(stderr, "case %u: %s %s: got %d, want %d\n", i,
                    cases[i].command ? cases[i].command : "<null>",
                    cases[i].subcommand ? cases[i].subcommand : "<null>",
                    (int)actual, (int)cases[i].expected);
        }
        assert(actual == cases[i].expected);
    }
    puts("LED_CLI_ACTIVITY_PASS");
    return 0;
}
