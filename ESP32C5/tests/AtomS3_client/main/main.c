#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <time.h>
#include <arpa/inet.h>

#include "argtable3/argtable3.h"
#include "esp_console.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "nvs_flash.h"


static const char *TAG = "JanOSmini";
static const char *APP_VERSION = "1.0";
static esp_netif_t *s_netif = NULL;
static bool s_sta_connected = false;
static bool s_hold_enabled = false;

static void wifi_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        s_sta_connected = false;
        ESP_LOGI(TAG, "STA disconnected");
        if (s_hold_enabled) {
            ESP_LOGI(TAG, "Auto-reconnect enabled, reconnecting...");
            esp_wifi_connect();
        }
        return;
    }
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_CONNECTED) {
        s_sta_connected = true;
        ESP_LOGI(TAG, "STA connected");
        return;
    }
    if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        ESP_LOGI(TAG, "Got IP: " IPSTR, IP2STR(&event->ip_info.ip));
        return;
    }
}

static void wifi_init_sta(void) {
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    s_netif = esp_netif_create_default_wifi_sta();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
}

static int cmd_sta_connect(int argc, char **argv) {
    struct {
        struct arg_str *ssid;
        struct arg_str *pass;
        struct arg_end *end;
    } args;
    args.ssid = arg_str1(NULL, NULL, "<ssid>", "SSID");
    args.pass = arg_str1(NULL, NULL, "<pass>", "Password");
    args.end = arg_end(2);

    int nerrors = arg_parse(argc, argv, (void **)&args);
    if (nerrors != 0) {
        arg_print_errors(stderr, args.end, argv[0]);
        ESP_LOGI(TAG, "Usage: sta_connect <ssid> <pass>");
        arg_freetable((void **)&args, sizeof(args) / sizeof(args.ssid));
        return 1;
    }

    wifi_config_t wifi_config = {0};
    snprintf((char *)wifi_config.sta.ssid, sizeof(wifi_config.sta.ssid), "%s", args.ssid->sval[0]);
    snprintf((char *)wifi_config.sta.password, sizeof(wifi_config.sta.password), "%s", args.pass->sval[0]);
    wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    wifi_config.sta.pmf_cfg.capable = true;
    wifi_config.sta.pmf_cfg.required = false;

    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_connect());
    ESP_LOGI(TAG, "CONNECTING");

    arg_freetable((void **)&args, sizeof(args) / sizeof(args.ssid));
    return 0;
}

static int cmd_sta_disconnect(int argc, char **argv) {
    (void)argc;
    (void)argv;
    ESP_ERROR_CHECK(esp_wifi_disconnect());
    ESP_LOGI(TAG, "DISCONNECTED");
    return 0;
}

static int cmd_sta_status(int argc, char **argv) {
    (void)argc;
    (void)argv;
    esp_netif_ip_info_t ip = {0};
    if (s_netif) {
        esp_netif_get_ip_info(s_netif, &ip);
    }

    wifi_ap_record_t ap_info;
    memset(&ap_info, 0, sizeof(ap_info));
    bool has_ap = (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK);

    ESP_LOGI(TAG, "connected=%d ip=" IPSTR " rssi=%d bssid=%02x:%02x:%02x:%02x:%02x:%02x",
             s_sta_connected ? 1 : 0,
             IP2STR(&ip.ip),
             has_ap ? ap_info.rssi : 0,
             ap_info.bssid[0], ap_info.bssid[1], ap_info.bssid[2],
             ap_info.bssid[3], ap_info.bssid[4], ap_info.bssid[5]);
    return 0;
}

static int cmd_sta_hold(int argc, char **argv) {
    struct {
        struct arg_str *mode;
        struct arg_end *end;
    } args;
    args.mode = arg_str1(NULL, NULL, "<on|off>", "Enable auto-reconnect");
    args.end = arg_end(1);

    int nerrors = arg_parse(argc, argv, (void **)&args);
    if (nerrors != 0) {
        arg_print_errors(stderr, args.end, argv[0]);
        ESP_LOGI(TAG, "Usage: sta_hold <on|off>");
        arg_freetable((void **)&args, sizeof(args) / sizeof(args.mode));
        return 1;
    }

    if (strcasecmp(args.mode->sval[0], "on") == 0) {
        s_hold_enabled = true;
        ESP_LOGI(TAG, "HOLD=ON");
    } else if (strcasecmp(args.mode->sval[0], "off") == 0) {
        s_hold_enabled = false;
        ESP_LOGI(TAG, "HOLD=OFF");
    } else {
        ESP_LOGI(TAG, "Usage: sta_hold <on|off>");
    }

    arg_freetable((void **)&args, sizeof(args) / sizeof(args.mode));
    return 0;
}

static int cmd_udp_flood(int argc, char **argv) {
    struct {
        struct arg_str *ip;
        struct arg_int *port;
        struct arg_int *pps;
        struct arg_int *seconds;
        struct arg_end *end;
    } args;
    args.ip = arg_str1(NULL, NULL, "<ip>", "Target IP");
    args.port = arg_int1(NULL, NULL, "<port>", "Target port");
    args.pps = arg_int0(NULL, NULL, "<pps>", "Packets per second (default 50)");
    args.seconds = arg_int0(NULL, NULL, "<seconds>", "Duration (default 5)");
    args.end = arg_end(2);

    int nerrors = arg_parse(argc, argv, (void **)&args);
    if (nerrors != 0) {
        arg_print_errors(stderr, args.end, argv[0]);
        ESP_LOGI(TAG, "Usage: udp_flood <ip> <port> [pps] [seconds]");
        arg_freetable((void **)&args, sizeof(args) / sizeof(args.ip));
        return 1;
    }

    const char *ip_str = args.ip->sval[0];
    int port = args.port->ival[0];
    int pps = (args.pps->count > 0) ? args.pps->ival[0] : 50;
    int seconds = (args.seconds->count > 0) ? args.seconds->ival[0] : 5;
    if (pps <= 0) {
        pps = 1;
    }
    if (seconds <= 0) {
        seconds = 1;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        ESP_LOGI(TAG, "socket failed: %d", errno);
        arg_freetable((void **)&args, sizeof(args) / sizeof(args.ip));
        return 1;
    }

    struct sockaddr_in dest = {0};
    dest.sin_family = AF_INET;
    dest.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip_str, &dest.sin_addr) != 1) {
        ESP_LOGI(TAG, "Invalid IP: %s", ip_str);
        close(sock);
        arg_freetable((void **)&args, sizeof(args) / sizeof(args.ip));
        return 1;
    }

    const char payload[] = "janosmini_ping";
    int total = pps * seconds;
    int delay_ms = 1000 / pps;
    if (delay_ms <= 0) {
        delay_ms = 1;
    }

    for (int i = 0; i < total; i++) {
        sendto(sock, payload, sizeof(payload), 0, (struct sockaddr *)&dest, sizeof(dest));
        vTaskDelay(pdMS_TO_TICKS(delay_ms));
    }

    close(sock);
    ESP_LOGI(TAG, "UDP flood done: %d packets to %s:%d", total, ip_str, port);
    arg_freetable((void **)&args, sizeof(args) / sizeof(args.ip));
    return 0;
}

static int cmd_wait_disconnect(int argc, char **argv) {
    struct {
        struct arg_int *timeout;
        struct arg_end *end;
    } args;
    args.timeout = arg_int0(NULL, NULL, "<seconds>", "Timeout in seconds (default 20)");
    args.end = arg_end(1);

    int nerrors = arg_parse(argc, argv, (void **)&args);
    if (nerrors != 0) {
        arg_print_errors(stderr, args.end, argv[0]);
        ESP_LOGI(TAG, "Usage: wait_disconnect [seconds]");
        arg_freetable((void **)&args, sizeof(args) / sizeof(args.timeout));
        return 1;
    }

    int timeout_s = (args.timeout->count > 0) ? args.timeout->ival[0] : 20;
    if (timeout_s <= 0) {
        timeout_s = 1;
    }

    int waited_ms = 0;
    const int step_ms = 200;
    while (waited_ms < timeout_s * 1000) {
        if (!s_sta_connected) {
            ESP_LOGI(TAG, "DISCONNECTED");
            arg_freetable((void **)&args, sizeof(args) / sizeof(args.timeout));
            return 0;
        }
        vTaskDelay(pdMS_TO_TICKS(step_ms));
        waited_ms += step_ms;
    }

    ESP_LOGI(TAG, "TIMEOUT waiting for disconnect");
    arg_freetable((void **)&args, sizeof(args) / sizeof(args.timeout));
    return 2;
}

static int cmd_reboot(int argc, char **argv) {
    (void)argc;
    (void)argv;
    ESP_LOGI(TAG, "Rebooting...");
    esp_restart();
    return 0;
}

static void register_console(void) {
    esp_console_register_help_command();

    esp_console_cmd_t cmd = {
        .command = "sta_connect",
        .help = "Connect STA to AP: sta_connect <ssid> <pass>",
        .func = &cmd_sta_connect,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&cmd));

    cmd = (esp_console_cmd_t){
        .command = "sta_disconnect",
        .help = "Disconnect STA",
        .func = &cmd_sta_disconnect,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&cmd));

    cmd = (esp_console_cmd_t){
        .command = "sta_status",
        .help = "Show STA status",
        .func = &cmd_sta_status,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&cmd));

    cmd = (esp_console_cmd_t){
        .command = "sta_hold",
        .help = "Auto-reconnect control: sta_hold <on|off>",
        .func = &cmd_sta_hold,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&cmd));

    cmd = (esp_console_cmd_t){
        .command = "udp_flood",
        .help = "Generate UDP traffic: udp_flood <ip> <port> [pps] [seconds]",
        .func = &cmd_udp_flood,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&cmd));

    cmd = (esp_console_cmd_t){
        .command = "wait_disconnect",
        .help = "Wait until STA disconnects: wait_disconnect [seconds]",
        .func = &cmd_wait_disconnect,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&cmd));

    cmd = (esp_console_cmd_t){
        .command = "reboot",
        .help = "Reboot the device",
        .func = &cmd_reboot,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&cmd));
}

void app_main(void) {
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_LOGI(TAG, "JanOSmini v%s starting", APP_VERSION);

    wifi_init_sta();
    register_console();

    esp_console_repl_t *repl = NULL;
    esp_console_repl_config_t repl_config = ESP_CONSOLE_REPL_CONFIG_DEFAULT();
    repl_config.prompt = "JanOSmini> ";

#if CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG
    esp_console_dev_usb_serial_jtag_config_t dev_config = ESP_CONSOLE_DEV_USB_SERIAL_JTAG_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_console_new_repl_usb_serial_jtag(&dev_config, &repl_config, &repl));
#else
    esp_console_dev_uart_config_t dev_config = ESP_CONSOLE_DEV_UART_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_console_new_repl_uart(&dev_config, &repl_config, &repl));
#endif
    ESP_ERROR_CHECK(esp_console_start_repl(repl));
}
