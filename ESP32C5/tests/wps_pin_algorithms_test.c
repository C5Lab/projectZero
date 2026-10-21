#include "wps_pin_algorithms.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>

typedef struct {
    wps_pin_algo_t algorithm;
    const char *expected;
} vector_t;

int main(void)
{
    const uint8_t bssid[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    const vector_t vectors[] = {
        {WPS_PIN_ALGO_ZHAO, "33598291"},
        {WPS_PIN_ALGO_COMPUTEPIN_28, "69142611"},
        {WPS_PIN_ALGO_COMPUTEPIN_32, "37851736"},
        {WPS_PIN_ALGO_DLINK, "67456000"},
        {WPS_PIN_ALGO_DLINK1, "56271874"},
        {WPS_PIN_ALGO_ASUS, "10403853"},
        {WPS_PIN_ALGO_AIROCON, "71593579"},
        {WPS_PIN_ALGO_TRENDNET, "05168859"},
        {WPS_PIN_ALGO_INVNIC, "34173862"},
    };
    for (size_t index = 0; index < sizeof(vectors) / sizeof(vectors[0]); index++) {
        uint32_t pin = 0;
        char formatted[9];
        assert(wps_pin_generate(vectors[index].algorithm, bssid, &pin));
        assert(pin <= 99999999U);
        assert(wps_pin_format(pin, formatted));
        assert(strcmp(formatted, vectors[index].expected) == 0);
        assert((pin % 10U) == jwps_pin_checksum(pin / 10U));
    }

    const uint8_t zero[6] = {0};
    const uint8_t ones[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    uint32_t pin = 0;
    assert(wps_pin_generate(WPS_PIN_ALGO_ZHAO, zero, &pin));
    assert(pin == 0U);
    assert(wps_pin_generate(WPS_PIN_ALGO_ZHAO, ones, &pin));
    assert(!wps_pin_generate((wps_pin_algo_t)99, bssid, &pin));
    assert(!wps_pin_generate(WPS_PIN_ALGO_ZHAO, NULL, &pin));
    assert(!wps_pin_generate(WPS_PIN_ALGO_ZHAO, bssid, NULL));
    assert(!wps_pin_format(100000000U, (char[9]){0}));
    assert(!wps_pin_format(0U, NULL));
    char leading[9];
    assert(wps_pin_format(0U, leading));
    assert(strcmp(leading, "00000000") == 0);
    return 0;
}
