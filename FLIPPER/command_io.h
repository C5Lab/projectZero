#pragma once

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

static void lab_c5_serial_write_line(
    FuriHalSerialHandle* serial,
    FuriMutex* mutex,
    const char* command,
    size_t command_length) {
    if(!serial || !mutex || !command) return;

    furi_mutex_acquire(mutex, FuriWaitForever);
    furi_hal_serial_tx(serial, (const uint8_t*)command, command_length);
    static const uint8_t line_end = '\n';
    furi_hal_serial_tx(serial, &line_end, 1);
    furi_hal_serial_tx_wait_complete(serial);
    furi_mutex_release(mutex);
}

static size_t lab_c5_format_tx_log(
    char* output,
    size_t output_capacity,
    const char* command,
    size_t command_length) {
    if(!output || !command || output_capacity < 9) return 0;

    const size_t prefix_length = sizeof("TX: ") - 1;
    const size_t max_full_length = output_capacity - prefix_length - 2;
    const bool truncated = command_length > max_full_length;
    const size_t preview_length =
        truncated ? output_capacity - prefix_length - sizeof("...\n") : command_length;

    memcpy(output, "TX: ", prefix_length);
    memcpy(output + prefix_length, command, preview_length);
    size_t used = prefix_length + preview_length;
    if(truncated) {
        memcpy(output + used, "...", 3);
        used += 3;
    }
    output[used++] = '\n';
    output[used] = '\0';
    return used;
}
