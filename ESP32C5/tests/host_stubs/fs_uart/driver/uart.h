#ifndef FS_TEST_UART_H
#define FS_TEST_UART_H
#include <stddef.h>
#include "esp_err.h"
#define UART_NUM_0 0
int uart_read_bytes(int uart, void *buffer, size_t length, unsigned ticks);
int uart_write_bytes(int uart, const void *buffer, size_t length);
esp_err_t uart_flush_input(int uart);
esp_err_t uart_wait_tx_done(int uart, unsigned ticks);
#endif
