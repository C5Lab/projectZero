#pragma once

#include <furi.h>
#include <gui/gui.h>
#include <gui/view_dispatcher.h>
#include <gui/view.h>
#include <gui/scene_manager.h>
#include <gui/view_stack.h>
#include <gui/modules/submenu.h>
#include <gui/modules/popup.h>
#include <gui/modules/text_input.h>
#include <gui/canvas.h>
#include <furi_hal_serial.h>
#include <furi_hal_serial_control.h>
#include <furi/core/stream_buffer.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct WiFiApp WiFiApp;

// WiFi network info from scan
typedef struct {
    char ssid[33];
    char bssid[18];
    int8_t rssi;
    int channel;
    char auth[32];
} WiFiNetwork;

#define MAX_SCAN_RESULTS 64

// Screen context structure
typedef struct {
    WiFiApp* app;
    View* view;
} ScreenContext;

struct WiFiApp {
    Gui* gui;
    ViewDispatcher* view_dispatcher;
    ViewStack* view_stack;
    
    // UART communication
    FuriHalSerialHandle* serial;
    FuriThread* uart_thread;
    FuriStreamBuffer* uart_rx_buffer;
    FuriString* uart_line_buffer;
    volatile bool uart_running;
    volatile uint32_t last_uart_activity;
    volatile bool board_connected;
    
    // WiFi scanning state
    WiFiNetwork* scan_results;
    uint32_t scan_result_count;
    uint32_t scan_result_capacity;
    volatile bool scanning_in_progress;
    volatile bool scan_failed;
    uint32_t scan_bytes_received;
    uint32_t scan_start_time;
    FuriString* last_scan_line;
    
    // Network selection
    uint32_t selected_networks[50];
    uint32_t selected_count;
    
    // Legacy network list (for backwards compatibility)
    char** networks;
    uint32_t network_count;
    
    // Attack state
    FuriString* attack_status;
    FuriString* attack_log;
    FuriString* current_ssid;
    FuriString* current_password;
    bool attack_in_progress;
    
    // Sniffer state
    uint32_t sniffer_packet_count;
    
    // Evil Twin state
    FuriString* evil_twin_password;
    uint32_t evil_twin_html_selection;
    char** html_files;
    uint32_t html_file_count;
};

// App entry point
int32_t wifi_attacks_app(void* p);
