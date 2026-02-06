#include "uart_comm.h"
#include <furi_hal.h>
#include <furi_hal_serial_control.h>
#include <string.h>
#include <stdlib.h>
#include <furi.h>

#define TAG "UART"
#define UART_BUFFER_SIZE 4096
#define UART_LINE_TIMEOUT_MS 5000  // 5 seconds per line - overall scan has its own timeout

static void uart_serial_irq(FuriHalSerialHandle* handle, FuriHalSerialRxEvent event, void* context) {
    WiFiApp* app = (WiFiApp*)context;
    if(!app || !app->uart_rx_buffer || !(event & FuriHalSerialRxEventData)) return;

    do {
        uint8_t byte = furi_hal_serial_async_rx(handle);
        furi_stream_buffer_send(app->uart_rx_buffer, &byte, 1, 0);
        app->last_uart_activity = furi_get_tick();
    } while(furi_hal_serial_async_rx_available(handle));
}

//=============================================================================
// CSV Parsing for network scan results
//=============================================================================

static bool csv_next_quoted_field(const char** p, char* out, size_t out_size) {
    if(!p || !*p || !out || out_size == 0) return false;

    const char* s = *p;
    while(*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
    if(*s != '"') return false;
    s++; // skip opening quote

    size_t i = 0;
    while(*s && *s != '"') {
        if(i + 1 < out_size) {
            out[i++] = *s;
        }
        s++;
    }
    if(*s != '"') return false;
    out[i] = '\0';
    s++; // skip closing quote

    if(*s == ',') s++; // skip comma if present

    *p = s;
    return true;
}

static bool parse_network_csv(const char* line, WiFiNetwork* net) {
    if(!line || !net) return false;

    // Format: "index","ssid","vendor","AA:BB:CC:DD:EE:FF","channel","auth","rssi","band"
    char index_str[8] = {0};
    char ssid[33] = {0};
    char vendor[33] = {0};
    char bssid[18] = {0};
    char channel_str[8] = {0};
    char auth[32] = {0};
    char rssi_str[8] = {0};
    char band[8] = {0};

    const char* p = line;
    bool ok = true;
    ok &= csv_next_quoted_field(&p, index_str, sizeof(index_str));
    ok &= csv_next_quoted_field(&p, ssid, sizeof(ssid));
    ok &= csv_next_quoted_field(&p, vendor, sizeof(vendor));
    ok &= csv_next_quoted_field(&p, bssid, sizeof(bssid));
    ok &= csv_next_quoted_field(&p, channel_str, sizeof(channel_str));
    ok &= csv_next_quoted_field(&p, auth, sizeof(auth));
    ok &= csv_next_quoted_field(&p, rssi_str, sizeof(rssi_str));
    ok &= csv_next_quoted_field(&p, band, sizeof(band));

    if(!ok) return false;

    int channel = 0;
    int rssi = 0;
    if(channel_str[0] != '\0') channel = atoi(channel_str);
    if(rssi_str[0] != '\0') rssi = atoi(rssi_str);

    strncpy(net->ssid, ssid, sizeof(net->ssid) - 1);
    net->ssid[sizeof(net->ssid) - 1] = '\0';
    strncpy(net->bssid, bssid, sizeof(net->bssid) - 1);
    net->bssid[sizeof(net->bssid) - 1] = '\0';
    strncpy(net->auth, auth, sizeof(net->auth) - 1);
    net->auth[sizeof(net->auth) - 1] = '\0';
    net->channel = channel;
    net->rssi = (int8_t)rssi;

    return true;
}

//=============================================================================
// UART Worker Thread - handles scanning in background
//=============================================================================

static bool uart_read_line_internal(WiFiApp* app, FuriString* line) {
    if(!app || !line) return false;
    
    furi_string_reset(line);
    uint32_t timeout = furi_get_tick() + UART_LINE_TIMEOUT_MS;
    bool has_content = false;
    
    while(furi_get_tick() < timeout) {
        uint8_t byte;
        size_t received = furi_stream_buffer_receive(app->uart_rx_buffer, &byte, 1, 10);
        
        if(received == 1) {
            if(byte == '\n' || byte == '\r') {
                if(has_content) {
                    return true;
                }
                continue;
            } else if(byte >= 32 && byte < 127) {
                furi_string_push_back(line, (char)byte);
                has_content = true;
                timeout = furi_get_tick() + UART_LINE_TIMEOUT_MS;
            }
        }
    }
    return false;
}

#define SCAN_TIMEOUT_MS 60000  // 60 seconds max for entire scan

static int32_t uart_worker(void* context) {
    WiFiApp* app = (WiFiApp*)context;
    if(!app) return -1;
    
    while(app->uart_running) {
        // If scanning, try to read results
        if(app->scanning_in_progress) {
            // Check for overall scan timeout
            if((furi_get_tick() - app->scan_start_time) > SCAN_TIMEOUT_MS) {
                // Timeout - mark as failed if no results
                if(app->scan_result_count == 0) {
                    app->scan_failed = true;
                }
                app->scanning_in_progress = false;
                continue;
            }
            
            FuriString* line = furi_string_alloc();
            
            if(uart_read_line_internal(app, line)) {
                const char* line_str = furi_string_get_cstr(line);
                size_t line_len = furi_string_size(line);
                
                // Count bytes received
                app->scan_bytes_received += line_len + 1;
                
                // Save first network line for debugging
                if(line_str[0] == '"' && furi_string_size(app->last_scan_line) == 0) {
                    furi_string_set(app->last_scan_line, line_str);
                }
                
                // Check for end of results marker
                if(strstr(line_str, "Scan results printed")) {
                    app->scanning_in_progress = false;
                } else if(strstr(line_str, "No networks found") ||
                          strstr(line_str, "Scan still in progress")) {
                    app->scanning_in_progress = false;
                } else if(line_str[0] == '"') {
                    // Parse network CSV line
                    if(app->scan_results && app->scan_result_count < app->scan_result_capacity) {
                        if(parse_network_csv(line_str, &app->scan_results[app->scan_result_count])) {
                            app->scan_result_count++;
                        }
                    }
                }
            }
            
            furi_string_free(line);
        } else {
            furi_delay_ms(100);
        }
    }
    return 0;
}

//=============================================================================
// UART Init / Deinit
//=============================================================================

void uart_comm_init(WiFiApp* app) {
    if(!app) return;
    
    app->serial = furi_hal_serial_control_acquire(FuriHalSerialIdUsart);
    if(!app->serial) return;
    
    furi_hal_serial_init(app->serial, 115200);
    
    app->uart_rx_buffer = furi_stream_buffer_alloc(UART_BUFFER_SIZE, 1);
    app->uart_line_buffer = furi_string_alloc();
    app->uart_running = true;
    app->last_uart_activity = furi_get_tick();
    
    furi_stream_buffer_reset(app->uart_rx_buffer);
    furi_hal_serial_async_rx_start(app->serial, uart_serial_irq, app, false);
    
    // Start UART worker thread for scanning
    app->uart_thread = furi_thread_alloc();
    furi_thread_set_name(app->uart_thread, "WiFiUART");
    furi_thread_set_stack_size(app->uart_thread, 2048);
    furi_thread_set_callback(app->uart_thread, uart_worker);
    furi_thread_set_context(app->uart_thread, app);
    furi_thread_start(app->uart_thread);
}

void uart_comm_deinit(WiFiApp* app) {
    if(!app) return;
    
    app->uart_running = false;
    
    if(app->uart_thread) {
        furi_thread_join(app->uart_thread);
        furi_thread_free(app->uart_thread);
        app->uart_thread = NULL;
    }
    
    if(app->serial) {
        furi_hal_serial_deinit(app->serial);
        furi_hal_serial_control_release(app->serial);
        app->serial = NULL;
    }
    
    if(app->uart_rx_buffer) {
        furi_stream_buffer_free(app->uart_rx_buffer);
        app->uart_rx_buffer = NULL;
    }
    if(app->uart_line_buffer) {
        furi_string_free(app->uart_line_buffer);
        app->uart_line_buffer = NULL;
    }
}

void uart_send_command(WiFiApp* app, const char* command) {
    if(!app || !app->serial) {
        FURI_LOG_E(TAG, "uart_send_command: app or serial is NULL");
        return;
    }
    FURI_LOG_I(TAG, "TX: %s", command);
    furi_hal_serial_tx(app->serial, (const uint8_t*)command, strlen(command));
    furi_hal_serial_tx(app->serial, (const uint8_t*)"\n", 1);
    furi_hal_serial_tx_wait_complete(app->serial);
}

const char* uart_read_line(WiFiApp* app, uint32_t timeout_ms) {
    uint32_t start = furi_get_tick();
    furi_string_reset(app->uart_line_buffer);
    
    while((furi_get_tick() - start) < timeout_ms) {
        uint8_t data = 0;
        if(furi_stream_buffer_receive(app->uart_rx_buffer, &data, 1, 10) == 1) {
            if(data == '\n') {
                if(furi_string_size(app->uart_line_buffer) > 0 && 
                   furi_string_get_char(app->uart_line_buffer, furi_string_size(app->uart_line_buffer) - 1) == '\r') {
                    furi_string_left(app->uart_line_buffer, furi_string_size(app->uart_line_buffer) - 1);
                }
                return furi_string_get_cstr(app->uart_line_buffer);
            } else if(data != '\r') {
                furi_string_push_back(app->uart_line_buffer, data);
            }
        }
    }
    
    return NULL;
}

void uart_clear_buffer(WiFiApp* app) {
    uint8_t data = 0;
    while(furi_stream_buffer_receive(app->uart_rx_buffer, &data, 1, 1) == 1) {
        // Clear
    }
    furi_string_reset(app->uart_line_buffer);
}

//=============================================================================
// Scanning helpers
//=============================================================================

void uart_start_scan(WiFiApp* app) {
    if(!app) return;
    
    // Clear previous results
    if(app->scan_results) {
        free(app->scan_results);
        app->scan_results = NULL;
    }
    app->scan_result_count = 0;
    app->scan_bytes_received = 0;
    app->scan_failed = false;
    if(app->last_scan_line) {
        furi_string_reset(app->last_scan_line);
    }
    
    // Allocate space for scan results
    app->scan_result_capacity = MAX_SCAN_RESULTS;
    app->scan_results = (WiFiNetwork*)malloc(sizeof(WiFiNetwork) * MAX_SCAN_RESULTS);
    
    // CRITICAL: Clear UART buffer before sending command
    uart_clear_buffer(app);
    furi_delay_ms(50);  // Small delay to ensure buffer is flushed
    
    // Set scanning flag and record start time
    app->scan_start_time = furi_get_tick();
    app->scanning_in_progress = true;
    uart_send_command(app, "scan_networks");
}
