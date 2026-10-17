#include "pixie_time.h"

#include <assert.h>
#include <stddef.h>

int main(void)
{
    pixie_rtl_window_t window;
    assert(pixie_rtl_window_from_epoch(1700000000U, &window) == PIXIE_TIME_OK);
    assert(window.start == 1700086400U && window.end == 1699913600U);
    assert(pixie_rtl_window_from_epoch(0U, &window) == PIXIE_TIME_ABSENT);
    assert(pixie_rtl_window_from_epoch(1577836799U, &window) == PIXIE_TIME_IMPLAUSIBLE);
    assert(pixie_rtl_window_from_epoch(4102444801U, &window) == PIXIE_TIME_IMPLAUSIBLE);
    assert(pixie_rtl_window_from_epoch(1700000000U, NULL) == PIXIE_TIME_INVALID_ARGUMENT);
    return 0;
}
