#include "../../module_api.h"
#include "../../gps_coord.h"

#include <flipper_application/flipper_application.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GPS_OFFSET_MINUTES_MIN (-12 * 60)
#define GPS_OFFSET_MINUTES_MAX (14 * 60)

typedef enum {
    GpsAntennaUnknown = 0,
    GpsAntennaOk,
    GpsAntennaOpen,
} GpsAntennaStatus;

typedef struct {
    bool has_fix;
    bool has_coords;
    bool has_time;
    bool has_date;
    int satellites;
    GpsAntennaStatus antenna_status;
    char lat[16];
    char lon[16];
    char time[16];
    char date[16];
} C5GpsState;

static int32_t gps_setting(const C5HostApiV3* host, C5Setting setting) {
    return host->get_setting(host->ctx, setting);
}

static void gps_set_setting(const C5HostApiV3* host, C5Setting setting, int32_t value) {
    host->set_setting(host->ctx, setting, value);
}

static int32_t gps_clamp_offset(int32_t minutes) {
    if(minutes < GPS_OFFSET_MINUTES_MIN) return GPS_OFFSET_MINUTES_MIN;
    if(minutes > GPS_OFFSET_MINUTES_MAX) return GPS_OFFSET_MINUTES_MAX;
    return minutes;
}

static bool gps_format_nmea_time(const char* raw, char* out, size_t out_len) {
    if(!raw || !out || out_len < 9 || strlen(raw) < 6) return false;
    for(size_t i = 0; i < 6; i++) {
        if(!isdigit((unsigned char)raw[i])) return false;
    }
    snprintf(out, out_len, "%c%c:%c%c:%c%c", raw[0], raw[1], raw[2], raw[3], raw[4], raw[5]);
    return true;
}

static bool gps_format_nmea_date(const char* raw, char* out, size_t out_len) {
    if(!raw || !out || out_len < 9 || strlen(raw) < 6) return false;
    for(size_t i = 0; i < 6; i++) {
        if(!isdigit((unsigned char)raw[i])) return false;
    }
    snprintf(out, out_len, "%c%c/%c%c/%c%c", raw[0], raw[1], raw[2], raw[3], raw[4], raw[5]);
    return true;
}

static bool gps_parse_decimal(const char* raw, long* value) {
    if(!raw || !raw[0] || !value) return false;
    char* end = NULL;
    long parsed = strtol(raw, &end, 10);
    if(end == raw || *end != '\0') return false;
    *value = parsed;
    return true;
}

static bool gps_contains_ignore_case(const char* text, const char* needle) {
    if(!text || !needle || !needle[0]) return false;
    size_t needle_len = strlen(needle);
    for(const char* cursor = text; *cursor; cursor++) {
        size_t i = 0;
        while(i < needle_len && cursor[i] &&
              tolower((unsigned char)cursor[i]) == tolower((unsigned char)needle[i])) {
            i++;
        }
        if(i == needle_len) return true;
    }
    return false;
}

static void gps_clear_coords(C5GpsState* gps) {
    gps->has_coords = false;
    gps->lat[0] = '\0';
    gps->lon[0] = '\0';
}

static void gps_update_coords(
    C5GpsState* gps,
    const char* lat,
    const char* lat_hemi,
    const char* lon,
    const char* lon_hemi) {
    bool lat_ok = gps_coord_format(lat, lat_hemi, gps->lat, sizeof(gps->lat));
    bool lon_ok = gps_coord_format(lon, lon_hemi, gps->lon, sizeof(gps->lon));
    gps->has_coords = lat_ok && lon_ok;
    if(!gps->has_coords) gps_clear_coords(gps);
}

static void gps_update_time(C5GpsState* gps, const char* raw) {
    if(gps_format_nmea_time(raw, gps->time, sizeof(gps->time))) gps->has_time = true;
}

static void gps_update_rmc_date(C5GpsState* gps, const char* raw) {
    if(gps_format_nmea_date(raw, gps->date, sizeof(gps->date))) gps->has_date = true;
}

static void gps_update_zda_date(C5GpsState* gps, char* const* tokens) {
    long day, month, year;
    if(!gps_parse_decimal(tokens[2], &day) || !gps_parse_decimal(tokens[3], &month) ||
       !gps_parse_decimal(tokens[4], &year) || day < 1 || day > 31 || month < 1 || month > 12 ||
       year < 0 || year > 9999) {
        return;
    }
    snprintf(gps->date, sizeof(gps->date), "%02ld/%02ld/%02ld", day, month, year % 100);
    gps->has_date = true;
}

static void gps_update_zda_offset(
    const C5HostApiV3* host,
    char* const* tokens,
    size_t token_count) {
    if(!gps_setting(host, GPS_ZDA_TZ) || token_count <= 5) return;
    long hours, minutes = 0;
    if(!gps_parse_decimal(tokens[5], &hours)) return;
    if(token_count > 6 && tokens[6][0] && !gps_parse_decimal(tokens[6], &minutes)) return;
    if(hours < -12 || hours > 14 || minutes < -59 || minutes > 59) return;
    if(minutes < 0) minutes = -minutes;
    int32_t offset = (int32_t)hours * 60 + (hours < 0 ? -(int32_t)minutes : (int32_t)minutes);
    offset = gps_clamp_offset(offset);
    if(offset != gps_setting(host, GPS_UTC_OFFSET_MIN)) {
        gps_set_setting(host, GPS_UTC_OFFSET_MIN, offset);
    }
}

static void* gps_enter(const C5HostApiV3* host, const void* params, size_t params_size) {
    if(params || params_size) return NULL;
    if(!host || host->version != C5_MODULE_API_VERSION || host->size < sizeof(C5HostApiV3) ||
       !host->send_command || !host->request_redraw || !host->get_setting || !host->set_setting) {
        return NULL;
    }
    C5GpsState* gps = malloc(sizeof(C5GpsState));
    if(!gps) return NULL;
    memset(gps, 0, sizeof(C5GpsState));
    gps->satellites = -1;
    return gps;
}

static void gps_leave(void* state, const C5HostApiV3* host) {
    (void)host;
    free(state);
}

static void gps_on_line(void* state, const C5HostApiV3* host, const char* line) {
    C5GpsState* gps = state;
    if(!gps || !host || !line || strncmp(line, "[GPS RAW]", 9) != 0) return;
    const char* nmea = line + 9;
    while(*nmea == ' ') nmea++;
    if(*nmea != '$') return;

    char buffer[128];
    size_t length = strlen(nmea);
    if(length >= sizeof(buffer)) return;
    memcpy(buffer, nmea, length + 1);
    char* checksum = strchr(buffer, '*');
    if(checksum) *checksum = '\0';

    char* tokens[16] = {buffer};
    size_t token_count = 1;
    for(char* cursor = buffer; *cursor && token_count < 16; cursor++) {
        if(*cursor == ',') {
            *cursor = '\0';
            tokens[token_count++] = cursor + 1;
        }
    }

    if(strcmp(tokens[0], "$GNGGA") == 0 || strcmp(tokens[0], "$GPGGA") == 0) {
        if(token_count > 6 && tokens[6][0]) {
            long quality;
            if(gps_parse_decimal(tokens[6], &quality)) {
                gps->has_fix = quality > 0;
                if(!gps->has_fix) gps_clear_coords(gps);
            }
        }
        if(token_count > 7) {
            long satellites;
            gps->satellites = gps_parse_decimal(tokens[7], &satellites) && satellites >= 0 &&
                                      satellites <= 999 ?
                                  (int)satellites :
                                  -1;
        }
        if(token_count > 1 && tokens[1][0]) gps_update_time(gps, tokens[1]);
        if(token_count > 5 && gps->has_fix && tokens[2][0] && tokens[3][0] && tokens[4][0] &&
           tokens[5][0]) {
            gps_update_coords(gps, tokens[2], tokens[3], tokens[4], tokens[5]);
        }
    } else if(strcmp(tokens[0], "$GNRMC") == 0 || strcmp(tokens[0], "$GPRMC") == 0) {
        if(token_count > 2 && tokens[2][0]) {
            gps->has_fix = tokens[2][0] == 'A';
            if(!gps->has_fix) gps_clear_coords(gps);
        }
        if(token_count > 1 && tokens[1][0]) gps_update_time(gps, tokens[1]);
        if(token_count > 9 && tokens[9][0]) gps_update_rmc_date(gps, tokens[9]);
        if(token_count > 6 && gps->has_fix && tokens[3][0] && tokens[4][0] && tokens[5][0] &&
           tokens[6][0]) {
            gps_update_coords(gps, tokens[3], tokens[4], tokens[5], tokens[6]);
        }
    } else if(strcmp(tokens[0], "$GNZDA") == 0 || strcmp(tokens[0], "$GPZDA") == 0) {
        if(token_count > 1 && tokens[1][0]) gps_update_time(gps, tokens[1]);
        if(token_count > 4) gps_update_zda_date(gps, tokens);
        gps_update_zda_offset(host, tokens, token_count);
    } else if(strcmp(tokens[0], "$GPGSV") == 0 || strcmp(tokens[0], "$GNGSV") == 0) {
        if(token_count > 3) {
            long satellites;
            if(gps_parse_decimal(tokens[3], &satellites) && satellites >= 0 && satellites <= 999) {
                gps->satellites = (int)satellites;
            }
        }
    } else if(strcmp(tokens[0], "$GPTXT") == 0 || strcmp(tokens[0], "$GNTXT") == 0) {
        if(token_count > 4) {
            if(gps_contains_ignore_case(tokens[4], "ANTENNA OPEN")) {
                gps->antenna_status = GpsAntennaOpen;
            } else if(gps_contains_ignore_case(tokens[4], "ANTENNA OK")) {
                gps->antenna_status = GpsAntennaOk;
            }
        }
    } else {
        return;
    }
    host->request_redraw(host->ctx);
}

static C5InputResult gps_on_input(
    void* state,
    const C5HostApiV3* host,
    const InputEvent* event) {
    if(!state || !host || !event || event->key == InputKeyBack) return C5InputIgnored;
    if(event->key == InputKeyOk && event->type == InputTypeLong) {
        return C5InputSwitchTerminal;
    }
    if(event->key == InputKeyOk && event->type == InputTypeShort) {
        gps_set_setting(host, GPS_TIME_24H, !gps_setting(host, GPS_TIME_24H));
    } else if(event->type == InputTypeShort || event->type == InputTypeRepeat ||
              event->type == InputTypeLong) {
        if(event->key == InputKeyUp || event->key == InputKeyDown) {
            gps_set_setting(host, GPS_DST, !gps_setting(host, GPS_DST));
        } else if(event->key == InputKeyLeft || event->key == InputKeyRight) {
            int32_t old_offset = gps_setting(host, GPS_UTC_OFFSET_MIN);
            int32_t delta = event->key == InputKeyRight ? 60 : -60;
            int32_t new_offset = gps_clamp_offset(old_offset + delta);
            if(new_offset != old_offset) gps_set_setting(host, GPS_UTC_OFFSET_MIN, new_offset);
        } else {
            return C5InputIgnored;
        }
    } else {
        return C5InputIgnored;
    }
    host->request_redraw(host->ctx);
    return C5InputConsumed;
}

static bool gps_format_local_time(
    const C5GpsState* gps,
    const C5HostApiV3* host,
    char* out,
    size_t out_len) {
    if(!gps->has_time || !out || out_len == 0) return false;
    int hh, mm, ss;
    if(sscanf(gps->time, "%2d:%2d:%2d", &hh, &mm, &ss) != 3) return false;
    int32_t offset_minutes = gps_clamp_offset(gps_setting(host, GPS_UTC_OFFSET_MIN));
    if(gps_setting(host, GPS_DST)) offset_minutes += 60;
    int32_t total_seconds = hh * 3600 + mm * 60 + ss + offset_minutes * 60;
    total_seconds %= 24 * 3600;
    if(total_seconds < 0) total_seconds += 24 * 3600;
    hh = total_seconds / 3600;
    mm = (total_seconds % 3600) / 60;
    ss = total_seconds % 60;
    if(gps_setting(host, GPS_TIME_24H)) {
        snprintf(out, out_len, "%02d:%02d:%02d", hh, mm, ss);
    } else {
        const char* suffix = hh >= 12 ? "PM" : "AM";
        int hh12 = hh % 12;
        if(hh12 == 0) hh12 = 12;
        snprintf(out, out_len, "%02d:%02d:%02d %s", hh12, mm, ss, suffix);
    }
    return true;
}

static void gps_format_offset(const C5HostApiV3* host, char* out, size_t out_len) {
    int32_t minutes = gps_clamp_offset(gps_setting(host, GPS_UTC_OFFSET_MIN));
    bool dst = gps_setting(host, GPS_DST) != 0;
    if(dst) minutes += 60;
    char sign = '+';
    if(minutes < 0) {
        sign = '-';
        minutes = -minutes;
    }
    int hh = minutes / 60;
    int mm = minutes % 60;
    if(mm == 0) {
        snprintf(out, out_len, "UTC%c%d%s", sign, hh, dst ? " DST" : "");
    } else {
        snprintf(out, out_len, "UTC%c%d:%02d%s", sign, hh, mm, dst ? " DST" : "");
    }
}

static void gps_draw(void* state, const C5HostApiV3* host, Canvas* canvas) {
    const C5GpsState* gps = state;
    if(!gps || !host || !canvas) return;
    char line[48];
    char time_text[20];
    char offset_text[20];

    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 4, 12, "GPS");
    canvas_set_font(canvas, FontSecondary);

    if(!gps->has_coords) {
        canvas_draw_str_aligned(canvas, 64, 32, AlignCenter, AlignCenter, "Waiting for GPS fix");
        if(gps->has_time) {
            if(gps_format_local_time(gps, host, time_text, sizeof(time_text))) {
                gps_format_offset(host, offset_text, sizeof(offset_text));
                snprintf(line, sizeof(line), "Time: %s %s", time_text, offset_text);
            } else {
                snprintf(line, sizeof(line), "Time: --");
            }
            canvas_draw_str_aligned(canvas, 64, 44, AlignCenter, AlignCenter, line);
        }
        if(gps->antenna_status == GpsAntennaOpen) {
            canvas_draw_str_aligned(canvas, 64, 56, AlignCenter, AlignCenter, "Antena not detected");
        } else if(gps->satellites >= 0) {
            snprintf(line, sizeof(line), "Sats: %d", gps->satellites);
            canvas_draw_str_aligned(canvas, 64, 56, AlignCenter, AlignCenter, line);
        }
        return;
    }

    snprintf(line, sizeof(line), "Lat: %s", gps->lat);
    canvas_draw_str(canvas, 2, 24, line);
    snprintf(line, sizeof(line), "Lon: %s", gps->lon);
    canvas_draw_str(canvas, 2, 34, line);
    if(gps_format_local_time(gps, host, time_text, sizeof(time_text))) {
        gps_format_offset(host, offset_text, sizeof(offset_text));
        snprintf(line, sizeof(line), "Time: %s %s", time_text, offset_text);
    } else {
        snprintf(line, sizeof(line), "Time: --");
    }
    canvas_draw_str(canvas, 2, 44, line);
    if(gps->antenna_status == GpsAntennaOpen) {
        snprintf(line, sizeof(line), "Antena not detected");
    } else if(gps->satellites >= 0) {
        snprintf(line, sizeof(line), "Sats: %d", gps->satellites);
    } else {
        snprintf(line, sizeof(line), "Sats: --");
    }
    canvas_draw_str(canvas, 2, 54, line);
}

static void gps_tick(void* state, const C5HostApiV3* host, uint32_t now_ticks) {
    (void)state;
    (void)host;
    (void)now_ticks;
}

static const C5ModuleV3 c5_gps_module = {
    .version = C5_MODULE_API_VERSION,
    .size = sizeof(C5ModuleV3),
    .enter = gps_enter,
    .leave = gps_leave,
    .on_line = gps_on_line,
    .on_input = gps_on_input,
    .draw = gps_draw,
    .tick = gps_tick,
};

static const FlipperAppPluginDescriptor c5_gps_descriptor = {
    .appid = C5_MODULE_APP_ID,
    .ep_api_version = C5_MODULE_API_VERSION,
    .entry_point = &c5_gps_module,
};

const FlipperAppPluginDescriptor* lab_c5_gps_plugin_ep(void) {
    return &c5_gps_descriptor;
}
