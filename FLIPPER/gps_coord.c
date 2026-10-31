#include "gps_coord.h"

#include <stdint.h>
#include <stdio.h>

bool gps_coord_format(const char* raw, const char* hemi, char* out, size_t out_len) {
    if(!raw || !hemi || !out || !out_len || !raw[0] || !hemi[0]) return false;

    char h = hemi[0];
    if(h >= 'a' && h <= 'z') h -= 'a' - 'A';
    if(h != 'N' && h != 'S' && h != 'E' && h != 'W') return false;

    uint32_t whole = 0;
    unsigned whole_digits = 0;
    const char* p = raw;
    while(*p >= '0' && *p <= '9') {
        if(++whole_digits > 5) return false;
        whole = whole * 10 + (uint32_t)(*p++ - '0');
    }
    if(whole_digits < 3) return false;

    uint32_t fraction = 0;
    unsigned fraction_digits = 0;
    if(*p == '.') {
        p++;
        while(*p >= '0' && *p <= '9') {
            if(fraction_digits < 7) {
                fraction = fraction * 10 + (uint32_t)(*p - '0');
                fraction_digits++;
            }
            p++;
        }
        if(fraction_digits == 0) return false;
    }
    if(*p != '\0') return false;
    while(fraction_digits++ < 7) fraction *= 10;

    uint32_t degrees = whole / 100;
    uint32_t minutes = whole % 100;
    uint32_t max_degrees = (h == 'N' || h == 'S') ? 90 : 180;
    if(minutes >= 60 || degrees > max_degrees ||
       (degrees == max_degrees && (minutes != 0 || fraction != 0))) {
        return false;
    }

    // NMEA minutes are scaled by 10^7. One unit of 10^-5 degree is 6000 of these units.
    uint32_t five_decimals = (minutes * 10000000u + fraction + 3000u) / 6000u;
    if(five_decimals == 100000u) {
        degrees++;
        five_decimals = 0;
    }
    snprintf(
        out,
        out_len,
        "%s%u.%05u",
        (h == 'S' || h == 'W') ? "-" : "",
        (unsigned)degrees,
        (unsigned)five_decimals);
    return true;
}
