#include "gps_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); exit(1); } } while (0)

typedef struct {
    const char *alias;
    gps_module_t expected;
} alias_case_t;

typedef struct {
    gps_module_t module;
    const char *name;
    int baud;
    int tx_pin;
    int rx_pin;
    bool external_feed;
    bool external_cap_feed;
    const char *position_command;
} module_contract_t;

static void test_persisted_enum_values_remain_backward_compatible(void)
{
    CHECK(GPS_MODULE_ATGM336H == 0);
    CHECK(GPS_MODULE_M5STACK_GPS_V11 == 1);
    CHECK(GPS_MODULE_EXTERNAL == 2);
    CHECK(GPS_MODULE_EXTERNAL_CAP == 3);
    CHECK(GPS_MODULE_RF_CAP == 4);
    CHECK(GPS_MODULE_USB_TAB == GPS_MODULE_EXTERNAL);
    CHECK(GPS_MODULE_CAP == GPS_MODULE_EXTERNAL_CAP);

    for (uint8_t value = GPS_MODULE_ATGM336H; value <= GPS_MODULE_RF_CAP; value++) {
        CHECK(gps_module_is_valid_persisted(value));
    }
    CHECK(!gps_module_is_valid_persisted((uint8_t)(GPS_MODULE_RF_CAP + 1)));
    CHECK(!gps_module_is_valid_persisted(UINT8_MAX));
}

static void test_all_command_aliases_keep_their_selection(void)
{
    static const alias_case_t cases[] = {
        {"atgm", GPS_MODULE_ATGM336H},
        {"ATGM336H", GPS_MODULE_ATGM336H},
        {"m5", GPS_MODULE_M5STACK_GPS_V11},
        {"M5STACK", GPS_MODULE_M5STACK_GPS_V11},
        {"m5stackgps1.1", GPS_MODULE_M5STACK_GPS_V11},
        {"m5stackgpsv11", GPS_MODULE_M5STACK_GPS_V11},
        {"external", GPS_MODULE_EXTERNAL},
        {"ext", GPS_MODULE_EXTERNAL},
        {"usb", GPS_MODULE_EXTERNAL},
        {"tab", GPS_MODULE_EXTERNAL},
        {"tab5", GPS_MODULE_EXTERNAL},
        {"cap", GPS_MODULE_EXTERNAL_CAP},
        {"external_cap", GPS_MODULE_EXTERNAL_CAP},
        {"lora_cap", GPS_MODULE_EXTERNAL_CAP},
        {"adv_cap", GPS_MODULE_EXTERNAL_CAP},
        {"RF_CAP", GPS_MODULE_RF_CAP},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        gps_module_t module = GPS_MODULE_ATGM336H;
        CHECK(gps_module_parse(cases[i].alias, &module));
        CHECK(module == cases[i].expected);
    }
}

static void test_every_module_keeps_its_transport_contract(void)
{
    static const module_contract_t contracts[] = {
        {GPS_MODULE_ATGM336H, "ATGM336H", 9600, 13, 14, false, false, "set_gps_position"},
        {GPS_MODULE_M5STACK_GPS_V11, "M5StackGPS1.1", 115200, 13, 14, false, false, "set_gps_position"},
        {GPS_MODULE_EXTERNAL, "External", 9600, 13, 14, true, false, "set_gps_position"},
        {GPS_MODULE_EXTERNAL_CAP, "ExternalCap", 9600, 13, 14, true, true, "set_gps_position_cap"},
        {GPS_MODULE_RF_CAP, "RFCap", 115200, 5, 4, false, false, "set_gps_position"},
    };

    for (size_t i = 0; i < sizeof(contracts) / sizeof(contracts[0]); i++) {
        const module_contract_t *contract = &contracts[i];
        CHECK(strcmp(gps_get_module_name(contract->module), contract->name) == 0);
        CHECK(gps_get_baud_for_module(contract->module) == contract->baud);
        CHECK(gps_get_uart_tx_pin(contract->module) == contract->tx_pin);
        CHECK(gps_get_uart_rx_pin(contract->module) == contract->rx_pin);
        CHECK(gps_module_uses_external_feed(contract->module) == contract->external_feed);
        CHECK(gps_module_uses_external_cap_feed(contract->module) == contract->external_cap_feed);
        CHECK(strcmp(gps_external_position_command_name(contract->module),
                     contract->position_command) == 0);
    }
}

static void test_invalid_name_does_not_change_selection(void)
{
    gps_module_t module = GPS_MODULE_M5STACK_GPS_V11;
    CHECK(!gps_module_parse("not-a-gps", &module));
    CHECK(module == GPS_MODULE_M5STACK_GPS_V11);
    CHECK(!gps_module_parse(NULL, &module));
    CHECK(module == GPS_MODULE_M5STACK_GPS_V11);
    CHECK(!gps_module_parse("m5", NULL));
}

int main(void)
{
    test_persisted_enum_values_remain_backward_compatible();
    test_all_command_aliases_keep_their_selection();
    test_every_module_keeps_its_transport_contract();
    test_invalid_name_does_not_change_selection();
    puts("PASS: GPS config");
    return 0;
}
