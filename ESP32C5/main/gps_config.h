#ifndef GPS_CONFIG_H
#define GPS_CONFIG_H

#include <stdbool.h>
#include <stdint.h>

#define GPS_BAUD_ATGM336H 9600
#define GPS_BAUD_M5STACK  115200

typedef enum {
    GPS_MODULE_ATGM336H = 0,
    GPS_MODULE_M5STACK_GPS_V11 = 1,
    GPS_MODULE_EXTERNAL = 2,
    GPS_MODULE_EXTERNAL_CAP = 3,
    GPS_MODULE_RF_CAP = 4,
    /* Backward compatibility aliases for previously exposed names. */
    GPS_MODULE_USB_TAB = GPS_MODULE_EXTERNAL,
    GPS_MODULE_CAP = GPS_MODULE_EXTERNAL_CAP,
} gps_module_t;

bool gps_module_parse(const char *name, gps_module_t *module);
bool gps_module_is_valid_persisted(uint8_t value);
const char *gps_get_module_name(gps_module_t module);
int gps_get_baud_for_module(gps_module_t module);
int gps_get_uart_tx_pin(gps_module_t module);
int gps_get_uart_rx_pin(gps_module_t module);
bool gps_module_uses_external_feed(gps_module_t module);
bool gps_module_uses_external_cap_feed(gps_module_t module);
const char *gps_external_position_command_name(gps_module_t module);

#endif
