#include "led_cli_activity.h"

#include <stddef.h>
#include <string.h>

typedef struct {
    const char *command;
    led_status_activity_t activity;
} led_cli_action_t;

/* Only exact registered CLI action names belong here; status/config/read commands stay idle. */
static const led_cli_action_t actions[] = {
    {"scan_networks", LED_STATUS_SCAN},
    {"scan_bt", LED_STATUS_SCAN},
    {"scan_airtag", LED_STATUS_SCAN},
    {"start_zig_recon", LED_STATUS_SCAN},
    {"start_nmap", LED_STATUS_SCAN},
    {"test_radio_channel", LED_STATUS_SCAN},
    {"test_radio_channels", LED_STATUS_SCAN},
    {"inspect_network", LED_STATUS_SCAN},
    {"wifi_connect", LED_STATUS_SCAN},

    {"start_sniffer", LED_STATUS_MONITOR},
    {"start_sniffer_noscan", LED_STATUS_MONITOR},
    {"packet_monitor", LED_STATUS_MONITOR},
    {"start_ap_locator", LED_STATUS_MONITOR},
    {"channel_view", LED_STATUS_MONITOR},
    {"deauth_detector", LED_STATUS_MONITOR},
    {"start_antisurveillance", LED_STATUS_MONITOR},

    {"start_handshake", LED_STATUS_CAPTURE},
    {"start_pcap", LED_STATUS_CAPTURE},
    {"start_wardrive", LED_STATUS_CAPTURE},
    {"start_wardrive_promisc", LED_STATUS_CAPTURE},
    {"start_wardrive_promisc_trace", LED_STATUS_CAPTURE},
    {"start_gps_raw", LED_STATUS_CAPTURE},

    {"start_deauth", LED_STATUS_TRANSMIT},
    {"start_deauth_station", LED_STATUS_TRANSMIT},
    {"start_sniffer_dog", LED_STATUS_TRANSMIT},
    {"sae_overflow", LED_STATUS_TRANSMIT},
    {"start_blackout", LED_STATUS_TRANSMIT},
    {"start_beacon_spam", LED_STATUS_TRANSMIT},
    {"start_beacon_spam_ssids", LED_STATUS_TRANSMIT},
    {"start_blespam", LED_STATUS_TRANSMIT},
    {"start_jammer24", LED_STATUS_TRANSMIT},

    {"start_evil_twin", LED_STATUS_PORTAL},
    {"start_portal", LED_STATUS_PORTAL},
    {"start_admin_portal", LED_STATUS_PORTAL},
    {"start_darksword", LED_STATUS_PORTAL},
    {"start_rogueap", LED_STATUS_PORTAL},
    {"start_rogue_gitm", LED_STATUS_PORTAL},
    {"start_karma", LED_STATUS_PORTAL},

    {"sd_benchmark", LED_STATUS_TRANSFER},
    {"send_file", LED_STATUS_TRANSFER},
    {"save_handshake", LED_STATUS_TRANSFER},
    {"wpasec_upload", LED_STATUS_TRANSFER},
    {"wigle_upload", LED_STATUS_TRANSFER},
    {"wdgwars_upload", LED_STATUS_TRANSFER},
};

led_status_activity_t led_cli_activity(const char *command, const char *subcommand)
{
    if (command == NULL || command[0] == '\0') {
        return LED_STATUS_IDLE;
    }
    if (strcmp(command, "wifi_analyzer") == 0) {
        return subcommand != NULL && strcmp(subcommand, "scan") == 0
                   ? LED_STATUS_SCAN : LED_STATUS_IDLE;
    }
    if (strcmp(command, "capture_gateway") == 0) {
        return subcommand != NULL && strcmp(subcommand, "start") == 0
                   ? LED_STATUS_CAPTURE : LED_STATUS_IDLE;
    }
    if (strcmp(command, "wps") == 0) {
        return subcommand != NULL &&
                       (strcmp(subcommand, "verify") == 0 || strcmp(subcommand, "pixie") == 0)
                   ? LED_STATUS_WPS : LED_STATUS_IDLE;
    }
    if (strcmp(command, "jwps") == 0) {
        return subcommand != NULL && strcmp(subcommand, "campaign") == 0
                   ? LED_STATUS_WPS : LED_STATUS_IDLE;
    }
    if (strcmp(command, "crack_worker") == 0) {
        return subcommand != NULL && strcmp(subcommand, "start") == 0
                   ? LED_STATUS_TRANSFER : LED_STATUS_IDLE;
    }
    if (strcmp(command, "wardrive_cleanup") == 0 ||
        strcmp(command, "wardrive_fix") == 0 ||
        strcmp(command, "wardrive_fix_kml") == 0) {
        return subcommand != NULL && subcommand[0] != '\0'
                   ? LED_STATUS_TRANSFER : LED_STATUS_IDLE;
    }
    if (strcmp(command, "artifact_inventory") == 0) {
        return subcommand != NULL &&
                       (strcmp(subcommand, "list") == 0 || strcmp(subcommand, "inspect") == 0)
                   ? LED_STATUS_TRANSFER : LED_STATUS_IDLE;
    }
    if (strcmp(command, "arp_ban") == 0) {
        return subcommand != NULL && subcommand[0] != '\0'
                   ? LED_STATUS_TRANSMIT : LED_STATUS_IDLE;
    }
    for (size_t i = 0; i < sizeof(actions) / sizeof(actions[0]); ++i) {
        if (strcmp(command, actions[i].command) == 0) {
            return actions[i].activity;
        }
    }
    return LED_STATUS_IDLE;
}
