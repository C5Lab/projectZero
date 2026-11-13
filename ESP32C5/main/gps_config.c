#include "gps_config.h"

#include <stddef.h>
#include <strings.h>

bool gps_module_parse(const char *name, gps_module_t *module)
{
    if (name == NULL || module == NULL) {
        return false;
    }

    gps_module_t selected;
    if (strcasecmp(name, "m5") == 0 ||
        strcasecmp(name, "m5stack") == 0 ||
        strcasecmp(name, "m5stackgps1.1") == 0 ||
        strcasecmp(name, "m5stackgpsv11") == 0) {
        selected = GPS_MODULE_M5STACK_GPS_V11;
    } else if (strcasecmp(name, "atgm") == 0 ||
               strcasecmp(name, "atgm336h") == 0) {
        selected = GPS_MODULE_ATGM336H;
    } else if (strcasecmp(name, "external") == 0 ||
               strcasecmp(name, "ext") == 0 ||
               strcasecmp(name, "usb") == 0 ||
               strcasecmp(name, "tab") == 0 ||
               strcasecmp(name, "tab5") == 0) {
        selected = GPS_MODULE_EXTERNAL;
    } else if (strcasecmp(name, "cap") == 0 ||
               strcasecmp(name, "external_cap") == 0 ||
               strcasecmp(name, "lora_cap") == 0 ||
               strcasecmp(name, "adv_cap") == 0) {
        selected = GPS_MODULE_EXTERNAL_CAP;
    } else if (strcasecmp(name, "rf_cap") == 0) {
        selected = GPS_MODULE_RF_CAP;
    } else {
        return false;
    }

    *module = selected;
    return true;
}

bool gps_module_is_valid_persisted(uint8_t value)
{
    return value <= GPS_MODULE_RF_CAP;
}

const char *gps_get_module_name(gps_module_t module)
{
    switch (module) {
        case GPS_MODULE_M5STACK_GPS_V11:
            return "M5StackGPS1.1";
        case GPS_MODULE_EXTERNAL:
            return "External";
        case GPS_MODULE_EXTERNAL_CAP:
            return "ExternalCap";
        case GPS_MODULE_RF_CAP:
            return "RFCap";
        case GPS_MODULE_ATGM336H:
        default:
            return "ATGM336H";
    }
}

int gps_get_baud_for_module(gps_module_t module)
{
    switch (module) {
        case GPS_MODULE_M5STACK_GPS_V11:
        case GPS_MODULE_RF_CAP:
            return GPS_BAUD_M5STACK;
        case GPS_MODULE_EXTERNAL:
        case GPS_MODULE_EXTERNAL_CAP:
        case GPS_MODULE_ATGM336H:
        default:
            return GPS_BAUD_ATGM336H;
    }
}

int gps_get_uart_rx_pin(gps_module_t module)
{
    /* Cap pin 1 is GPS_TX; on Monster RF it is routed through the GDO0 net. */
    return module == GPS_MODULE_RF_CAP ? 4 : 14;
}

int gps_get_uart_tx_pin(gps_module_t module)
{
    /* Cap pin 2 is GPS_RX; on Monster RF it uses the CC1101_RF_SW0 net. */
    return module == GPS_MODULE_RF_CAP ? 5 : 13;
}

bool gps_module_uses_external_feed(gps_module_t module)
{
    return module == GPS_MODULE_EXTERNAL || module == GPS_MODULE_EXTERNAL_CAP;
}

bool gps_module_uses_external_cap_feed(gps_module_t module)
{
    return module == GPS_MODULE_EXTERNAL_CAP;
}

const char *gps_external_position_command_name(gps_module_t module)
{
    return gps_module_uses_external_cap_feed(module)
        ? "set_gps_position_cap"
        : "set_gps_position";
}
