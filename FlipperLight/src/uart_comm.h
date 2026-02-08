#pragma once

#include "app.h"

// UART communication functions
void uart_comm_init(WiFiApp* app);
void uart_comm_deinit(WiFiApp* app);
void uart_send_command(WiFiApp* app, const char* command);
const char* uart_read_line(WiFiApp* app, uint32_t timeout_ms);
void uart_clear_buffer(WiFiApp* app);
bool uart_check_board_connection(WiFiApp* app);
bool uart_check_sd_card(WiFiApp* app);

// CSV parsing
bool csv_next_quoted_field(const char** p, char* out, size_t out_size);

// Scanning
void uart_start_scan(WiFiApp* app);
