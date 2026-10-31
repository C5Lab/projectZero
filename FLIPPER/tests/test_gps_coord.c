#ifdef LAB_C5_HOST_TEST

#include "../gps_coord.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

static void check_coord(const char* raw, const char* hemi, const char* expected) {
    char actual[24] = {0};
    if(!gps_coord_format(raw, hemi, actual, sizeof(actual)) || strcmp(actual, expected) != 0) {
        fprintf(stderr, "%s %s: expected %s, got %s\n", raw, hemi, expected, actual);
        failures++;
    }
}

static void check_old_result(const char* raw, const char* hemi) {
    char actual[24] = {0};
    char reference[24] = {0};
    double value = strtod(raw, NULL);
    int degrees = (int)(value / 100.0);
    double decimal = (double)degrees + (value - ((double)degrees * 100.0)) / 60.0;
    if(hemi[0] == 'S' || hemi[0] == 'W') decimal = -decimal;
    snprintf(reference, sizeof(reference), "%.5f", decimal);

    // At an exact half-step, the old binary-double result depends on representation.
    // Those inputs are covered by explicit mathematical-rounding cases below.
    unsigned whole, fraction;
    if(sscanf(raw, "%u.%u", &whole, &fraction) == 2) {
        size_t fractional_digits = strlen(strchr(raw, '.') + 1);
        if(fractional_digits == 4 && (((whole % 100) * 10000 + fraction) % 6) == 3) {
            return;
        }
    }
    if(!gps_coord_format(raw, hemi, actual, sizeof(actual)) || strcmp(actual, reference) != 0) {
        fprintf(stderr, "%s %s: reference %s, got %s\n", raw, hemi, reference, actual);
        failures++;
    }
}

int main(void) {
    check_coord("4807.038", "N", "48.11730");
    check_coord("01131.000", "E", "11.51667");
    check_coord("3723.2475", "N", "37.38746");
    check_coord("12202.3245", "W", "-122.03874");
    check_coord("0000.0000", "S", "-0.00000");
    check_coord("0000.1017", "N", "0.00170");
    check_coord("0033.5085", "S", "-0.55848");
    check_coord("1259.9999", "N", "13.00000");
    check_coord("9000.0000", "N", "90.00000");
    check_coord("18000.0000", "E", "180.00000");

    for(unsigned degrees = 0; degrees < 90; degrees += 7) {
        for(unsigned minutes = 0; minutes < 60; minutes += 11) {
            for(unsigned fraction = 0; fraction < 10000; fraction += 1017) {
                char raw[24];
                snprintf(raw, sizeof(raw), "%02u%02u.%04u", degrees, minutes, fraction);
                check_old_result(raw, "N");
                check_old_result(raw, "S");
            }
        }
    }
    for(unsigned degrees = 0; degrees < 180; degrees += 17) {
        char raw[24];
        snprintf(raw, sizeof(raw), "%03u22.12345", degrees);
        check_old_result(raw, "E");
        check_old_result(raw, "W");
    }

    char out[8] = {'X'};
    if(gps_coord_format("", "N", out, sizeof(out))) failures++;
    if(gps_coord_format("1234.5", "", out, sizeof(out))) failures++;
    if(gps_coord_format("1260.0", "N", out, sizeof(out))) failures++;
    if(gps_coord_format("9100.0", "N", out, sizeof(out))) failures++;
    if(gps_coord_format("18100.0", "E", out, sizeof(out))) failures++;
    if(gps_coord_format("12xx.0", "N", out, sizeof(out))) failures++;
    if(gps_coord_format(NULL, "N", out, sizeof(out))) failures++;
    if(gps_coord_format("1200.0", "N", NULL, sizeof(out))) failures++;
    if(gps_coord_format("1200.0", "N", out, 0)) failures++;

    if(failures) {
        fprintf(stderr, "%d GPS coordinate failures\n", failures);
        return 1;
    }
    puts("GPS coordinate tests passed");
    return 0;
}

#endif
