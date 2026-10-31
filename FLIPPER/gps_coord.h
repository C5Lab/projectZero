#ifndef LAB_C5_GPS_COORD_H
#define LAB_C5_GPS_COORD_H

#include <stdbool.h>
#include <stddef.h>

bool gps_coord_format(const char* raw, const char* hemi, char* out, size_t out_len);

#endif
