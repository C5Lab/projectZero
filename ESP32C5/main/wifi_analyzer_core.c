#include "wifi_analyzer_core.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    char bytes[WFA_LINE_CAPACITY];
    size_t used;
    bool valid;
} wfa_line_t;

static void fail(const char **reason, const char *message)
{
    if (reason != NULL) {
        *reason = message;
    }
}

wfa_band_t wfa_channel_band(unsigned channel)
{
    if (channel >= 1U && channel <= 14U) {
        return WFA_BAND_24;
    }
    if ((channel >= 36U && channel <= 64U && (channel - 36U) % 4U == 0U) ||
        (channel >= 100U && channel <= 144U && (channel - 100U) % 4U == 0U) ||
        (channel >= 149U && channel <= 177U && (channel - 149U) % 4U == 0U)) {
        return WFA_BAND_5;
    }
    return WFA_BAND_NONE;
}

unsigned wfa_primary_frequency(unsigned channel)
{
    if (channel == 14U) {
        return 2484U;
    }
    if (channel >= 1U && channel <= 13U) {
        return 2407U + 5U * channel;
    }
    if (wfa_channel_band(channel) == WFA_BAND_5) {
        return 5000U + 5U * channel;
    }
    return 0U;
}

const char *wfa_band_name(wfa_band_t band)
{
    switch (band) {
    case WFA_BAND_24: return "2.4";
    case WFA_BAND_5: return "5";
    case WFA_BAND_BOTH: return "both";
    default: return NULL;
    }
}

const char *wfa_profile_name(wfa_profile_t profile)
{
    switch (profile) {
    case WFA_QUICK: return "quick";
    case WFA_DETAILED: return "detailed";
    case WFA_PASSIVE: return "passive";
    default: return NULL;
    }
}

static bool decimal(const char *first, const char *end, unsigned maximum, unsigned *value)
{
    unsigned result = 0U;
    const char *p;
    if (first == NULL || end == NULL || first == end) {
        return false;
    }
    for (p = first; p != end; ++p) {
        unsigned digit;
        if (*p < '0' || *p > '9') {
            return false;
        }
        digit = (unsigned)(*p - '0');
        if (digit > maximum || result > maximum / 10U ||
            (result == maximum / 10U && digit > maximum % 10U)) {
            return false;
        }
        result = 10U * result + digit;
    }
    *value = result;
    return true;
}

static bool parse_channels(const char *list, wfa_options_t *out)
{
    const char *first;
    const char *p;
    unsigned channel;
    unsigned i;
    if (list == NULL || *list == '\0') {
        return false;
    }
    first = list;
    for (p = list; ; ++p) {
        if (*p != ',' && *p != '\0') {
            continue;
        }
        if (!decimal(first, p, 177U, &channel) ||
            wfa_channel_band(channel) == WFA_BAND_NONE ||
            out->channel_count == WFA_MAX_CHANNELS) {
            return false;
        }
        for (i = 0U; i < out->channel_count; ++i) {
            if (out->channels[i] == channel) {
                return false;
            }
        }
        out->channels[out->channel_count++] = (uint8_t)channel;
        if (*p == '\0') {
            return true;
        }
        first = p + 1;
    }
}

bool wfa_parse_scan_args(int argc, char **argv, wfa_options_t *out, const char **reason)
{
    bool band_seen = false;
    bool channels_seen = false;
    bool profile_seen = false;
    bool limit_seen = false;
    int i;
    unsigned number;
    unsigned channel;
    if (reason != NULL) {
        *reason = NULL;
    }
    if (out == NULL || argv == NULL || argc < 2 || argv[0] == NULL || argv[1] == NULL ||
        strcmp(argv[0], "wifi_analyzer") != 0 || strcmp(argv[1], "scan") != 0) {
        fail(reason, "expected wifi_analyzer scan");
        return false;
    }
    memset(out, 0, sizeof(*out));
    out->band = WFA_BAND_BOTH;
    out->profile = WFA_QUICK;
    out->limit = WFA_DEFAULT_LIMIT;
    for (i = 2; i < argc; i += 2) {
        const char *key = argv[i];
        const char *value;
        if (key == NULL || i + 1 >= argc || argv[i + 1] == NULL) {
            fail(reason, "missing option value");
            return false;
        }
        value = argv[i + 1];
        if (strcmp(key, "--band") == 0) {
            if (band_seen) {
                fail(reason, "duplicate band option");
                return false;
            }
            band_seen = true;
            if (strcmp(value, "2.4") == 0) out->band = WFA_BAND_24;
            else if (strcmp(value, "5") == 0) out->band = WFA_BAND_5;
            else if (strcmp(value, "both") == 0) out->band = WFA_BAND_BOTH;
            else {
                fail(reason, "invalid band");
                return false;
            }
        } else if (strcmp(key, "--channels") == 0) {
            if (channels_seen) {
                fail(reason, "duplicate channels option");
                return false;
            }
            channels_seen = true;
            out->explicit_channels = true;
            if (!parse_channels(value, out)) {
                fail(reason, "invalid channel list");
                return false;
            }
        } else if (strcmp(key, "--profile") == 0) {
            if (profile_seen) {
                fail(reason, "duplicate profile option");
                return false;
            }
            profile_seen = true;
            if (strcmp(value, "quick") == 0) out->profile = WFA_QUICK;
            else if (strcmp(value, "detailed") == 0) out->profile = WFA_DETAILED;
            else if (strcmp(value, "passive") == 0) out->profile = WFA_PASSIVE;
            else {
                fail(reason, "invalid profile");
                return false;
            }
        } else if (strcmp(key, "--limit") == 0) {
            if (limit_seen) {
                fail(reason, "duplicate limit option");
                return false;
            }
            limit_seen = true;
            if (!decimal(value, value + strlen(value), WFA_MAX_APS, &number) || number == 0U) {
                fail(reason, "invalid limit");
                return false;
            }
            out->limit = (uint16_t)number;
        } else {
            fail(reason, "unknown option");
            return false;
        }
    }
    if (out->explicit_channels) {
        unsigned j;
        for (j = 0U; j < out->channel_count; ++j) {
            wfa_band_t band = wfa_channel_band(out->channels[j]);
            if (out->band != WFA_BAND_BOTH && band != out->band) {
                fail(reason, "channel outside selected band");
                return false;
            }
        }
    } else {
        for (channel = 1U; channel <= 177U; ++channel) {
            wfa_band_t band = wfa_channel_band(channel);
            if (band != WFA_BAND_NONE && (out->band == WFA_BAND_BOTH || band == out->band)) {
                out->channels[out->channel_count++] = (uint8_t)channel;
            }
        }
    }
    return true;
}

uint32_t wfa_scan_deadline_ms(const wfa_options_t *options)
{
    uint32_t dwell;
    if (options == NULL) {
        return 0U;
    }
    dwell = options->profile == WFA_QUICK ? 300U : 600U;
    return (uint32_t)options->channel_count * (dwell + 150U) + 5000U;
}

static void unknown_geometry(wfa_ap_t *ap)
{
    ap->width = WFA_WIDTH_UNKNOWN;
    ap->secondary = WFA_SECOND_UNKNOWN;
    ap->center1_mhz = 0U;
    ap->center2_mhz = 0U;
}

static bool primary_in_80_segment(unsigned primary, unsigned center)
{
    unsigned separation;
    if (center < 5000U || center > 5900U) {
        return false;
    }
    separation = primary > center ? primary - center : center - primary;
    return separation == 10U || separation == 30U;
}

void wfa_normalize_geometry(wfa_ap_t *ap)
{
    unsigned primary_frequency;
    unsigned center1;
    unsigned center2;
    unsigned offset;
    unsigned span;
    unsigned low;
    unsigned slot;
    int partner;
    wfa_band_t band;
    if (ap == NULL) {
        return;
    }
    band = wfa_channel_band(ap->primary);
    primary_frequency = wfa_primary_frequency(ap->primary);
    center1 = ap->center1_mhz;
    center2 = ap->center2_mhz;
    if (band == WFA_BAND_5 && ap->width == WFA_WIDTH_80P80 &&
        !primary_in_80_segment(primary_frequency, center1) &&
        primary_in_80_segment(primary_frequency, center2)) {
        unsigned swap = center1;
        center1 = center2;
        center2 = swap;
        ap->center1_mhz = (uint16_t)center1;
        ap->center2_mhz = (uint16_t)center2;
    }
    if (band == WFA_BAND_NONE || ap->band != band || primary_frequency == 0U ||
        center1 < (band == WFA_BAND_24 ? 2400U : 5000U) ||
        center1 > (band == WFA_BAND_24 ? 2500U : 5900U)) {
        unknown_geometry(ap);
        return;
    }
    if (ap->width == WFA_WIDTH_20) {
        if (center1 != primary_frequency || ap->secondary != WFA_SECOND_NONE || center2 != 0U) {
            unknown_geometry(ap);
        }
        return;
    }
    if (ap->secondary != WFA_SECOND_ABOVE && ap->secondary != WFA_SECOND_BELOW) {
        unknown_geometry(ap);
        return;
    }
    partner = (int)ap->primary + (ap->secondary == WFA_SECOND_ABOVE ? 4 : -4);
    if (ap->primary == 14U || partner <= 0 || partner == 14 ||
        wfa_channel_band((unsigned)partner) != band) {
        unknown_geometry(ap);
        return;
    }
    if (ap->width == WFA_WIDTH_40) {
        int expected = (int)primary_frequency +
                       (ap->secondary == WFA_SECOND_ABOVE ? 10 : -10);
        if ((int)center1 != expected || center2 != 0U) {
            unknown_geometry(ap);
        }
        return;
    }
    if (band != WFA_BAND_5 || (ap->width != WFA_WIDTH_80 &&
        ap->width != WFA_WIDTH_160 && ap->width != WFA_WIDTH_80P80)) {
        unknown_geometry(ap);
        return;
    }
    /* Full 160 MHz centers for the supported 5 GHz channel plan. An SDK
     * primary-80 center (e.g. 5290 for primary 64) also passes the offset test
     * below, but would shift the plotted footprint by 40 MHz. Without a
     * verified full-channel center, keep the AP and mark geometry unknown. */
    if (ap->width == WFA_WIDTH_160 &&
        center1 != 5250U && center1 != 5570U && center1 != 5815U) {
        unknown_geometry(ap);
        return;
    }
    span = ap->width == WFA_WIDTH_160 ? 80U : 40U;
    offset = primary_frequency > center1 ? primary_frequency - center1 : center1 - primary_frequency;
    if (offset == 0U || offset > span - 10U || offset % 20U != 10U || center1 < span) {
        unknown_geometry(ap);
        return;
    }
    low = center1 - span;
    if (primary_frequency < low + 10U || (primary_frequency - low - 10U) % 20U != 0U) {
        unknown_geometry(ap);
        return;
    }
    slot = (primary_frequency - low - 10U) / 20U;
    if (slot >= span / 10U ||
        (slot % 2U == 0U && ap->secondary != WFA_SECOND_ABOVE) ||
        (slot % 2U == 1U && ap->secondary != WFA_SECOND_BELOW)) {
        unknown_geometry(ap);
        return;
    }
    if (ap->width == WFA_WIDTH_80P80) {
        unsigned separation = center1 > center2 ? center1 - center2 : center2 - center1;
        if (center2 < 5000U || center2 > 5900U || separation <= 80U) {
            unknown_geometry(ap);
        }
    } else if (center2 != 0U) {
        unknown_geometry(ap);
    }
}

static void append(wfa_line_t *line, const char *format, ...)
{
    va_list args;
    int n;
    size_t remaining;
    if (!line->valid) {
        return;
    }
    remaining = sizeof(line->bytes) - line->used;
    va_start(args, format);
    n = vsnprintf(line->bytes + line->used, remaining, format, args);
    va_end(args);
    if (n < 0 || (size_t)n >= remaining) {
        line->valid = false;
    } else {
        line->used += (size_t)n;
    }
}

static void append_json_string(wfa_line_t *line, const char *value, size_t length)
{
    size_t i;
    append(line, "\"");
    for (i = 0U; i < length; ++i) {
        unsigned char c = (unsigned char)value[i];
        if (c == '"' || c == '\\') {
            append(line, "\\%c", (int)c);
        } else if (c < 0x20U) {
            append(line, "\\u%04x", (unsigned)c);
        } else {
            append(line, "%c", (int)c);
        }
    }
    append(line, "\"");
}

static bool ascii_string_length(const char *value, size_t maximum, size_t *length)
{
    size_t i;
    if (value == NULL) {
        return false;
    }
    for (i = 0U; i <= maximum; ++i) {
        unsigned char c = (unsigned char)value[i];
        if (c == 0U) {
            *length = i;
            return i != 0U;
        }
        if (c > 0x7eU) {
            return false;
        }
    }
    return false;
}

static bool valid_boot(const char *boot)
{
    unsigned i;
    if (boot == NULL) {
        return false;
    }
    for (i = 0U; i < 16U; ++i) {
        char c = boot[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            return false;
        }
    }
    return boot[16] == '\0';
}

static bool valid_base(const char *boot, uint32_t scan)
{
    return valid_boot(boot) && scan != 0U;
}

static int publish(wfa_line_t *line, char *out, size_t size)
{
    if (!line->valid || line->used > WFA_MAX_LINE_BYTES ||
        line->used + 2U > size || out == NULL) {
        return -1;
    }
    line->bytes[line->used++] = '\n';
    line->bytes[line->used] = '\0';
    memcpy(out, line->bytes, line->used + 1U);
    return (int)line->used;
}

int wfa_format_begin(char *out, size_t size, const char *boot, uint32_t scan,
                     const wfa_options_t *options, uint64_t started_ms)
{
    wfa_line_t line = {{0}, 0U, true};
    unsigned i;
    const char *band;
    const char *profile;
    if (!valid_base(boot, scan) || options == NULL ||
        started_ms > INT64_MAX || options->limit == 0U || options->limit > WFA_MAX_APS ||
        options->channel_count == 0U || options->channel_count > WFA_MAX_CHANNELS) {
        return -1;
    }
    band = wfa_band_name(options->band);
    profile = wfa_profile_name(options->profile);
    if (band == NULL || profile == NULL) {
        return -1;
    }
    for (i = 0U; i < options->channel_count; ++i) {
        unsigned j;
        wfa_band_t channel_band = wfa_channel_band(options->channels[i]);
        if (channel_band == WFA_BAND_NONE ||
            (options->band != WFA_BAND_BOTH && channel_band != options->band)) {
            return -1;
        }
        for (j = 0U; j < i; ++j) {
            if (options->channels[j] == options->channels[i]) {
                return -1;
            }
        }
    }
    append(&line, "[WFA1] {\"v\":1,\"type\":\"begin\",\"boot\":\"%s\",\"scan\":%lu,\"limit\":%u,\"band\":\"%s\",\"channels\":[",
           boot, (unsigned long)scan, (unsigned)options->limit, band);
    for (i = 0U; i < options->channel_count; ++i) {
        append(&line, "%s%u", i == 0U ? "" : ",", (unsigned)options->channels[i]);
    }
    append(&line, "],\"profile\":\"%s\",\"started_ms\":%llu}",
           profile, (unsigned long long)started_ms);
    return publish(&line, out, size);
}

int wfa_format_ap(char *out, size_t size, const char *boot, uint32_t scan,
                  uint16_t seq, const wfa_ap_t *ap)
{
    static const char *const phy_names[7] = {"11a", "11b", "11g", "11n", "11ac", "11ax", "lr"};
    static const unsigned phy_bits[7] = {WFA_PHY_A, WFA_PHY_B, WFA_PHY_G, WFA_PHY_N,
                                          WFA_PHY_AC, WFA_PHY_AX, WFA_PHY_LR};
    wfa_line_t line = {{0}, 0U, true};
    wfa_ap_t normalized;
    const char *band;
    const char *auth;
    const char *width = NULL;
    const char *secondary = NULL;
    size_t auth_length;
    unsigned i;
    bool first = true;
    if (!valid_base(boot, scan) || ap == NULL || seq >= WFA_MAX_APS || ap->ssid_len > 32U ||
        ap->rssi < -127 || ap->rssi > 20 ||
        (ap->band != WFA_BAND_24 && ap->band != WFA_BAND_5) ||
        wfa_channel_band(ap->primary) != ap->band ||
        (ap->phy_mask & ~(unsigned)(WFA_PHY_A | WFA_PHY_B | WFA_PHY_G |
                                    WFA_PHY_N | WFA_PHY_AC | WFA_PHY_AX | WFA_PHY_LR)) != 0U) {
        return -1;
    }
    band = wfa_band_name(ap->band);
    auth = ap->auth;
    if (!ascii_string_length(auth, 32U, &auth_length)) {
        auth = "UNKNOWN";
        auth_length = 7U;
    }
    normalized = *ap;
    wfa_normalize_geometry(&normalized);
    switch (normalized.width) {
    case WFA_WIDTH_20: width = "20"; break;
    case WFA_WIDTH_40: width = "40"; break;
    case WFA_WIDTH_80: width = "80"; break;
    case WFA_WIDTH_160: width = "160"; break;
    case WFA_WIDTH_80P80: width = "80+80"; break;
    default: break;
    }
    if (normalized.secondary == WFA_SECOND_NONE) secondary = "none";
    else if (normalized.secondary == WFA_SECOND_ABOVE) secondary = "above";
    else if (normalized.secondary == WFA_SECOND_BELOW) secondary = "below";
    append(&line, "[WFA1] {\"v\":1,\"type\":\"ap\",\"boot\":\"%s\",\"scan\":%lu,\"seq\":%u,\"bssid\":\"%02x:%02x:%02x:%02x:%02x:%02x\",\"ssid_hex\":\"",
           boot, (unsigned long)scan, (unsigned)seq,
           (unsigned)ap->bssid[0], (unsigned)ap->bssid[1], (unsigned)ap->bssid[2],
           (unsigned)ap->bssid[3], (unsigned)ap->bssid[4], (unsigned)ap->bssid[5]);
    for (i = 0U; i < ap->ssid_len; ++i) {
        append(&line, "%02x", (unsigned)ap->ssid[i]);
    }
    append(&line, "\",\"band\":\"%s\",\"primary\":%u,\"rssi\":%d,\"auth\":",
           band, (unsigned)ap->primary, (int)ap->rssi);
    append_json_string(&line, auth, auth_length);
    append(&line, ",\"phy\":[");
    for (i = 0U; i < 7U; ++i) {
        if (((unsigned)ap->phy_mask & phy_bits[i]) != 0U) {
            append(&line, "%s\"%s\"", first ? "" : ",", phy_names[i]);
            first = false;
        }
    }
    append(&line, "],\"bandwidth\":");
    if (width != NULL) append(&line, "\"%s\"", width);
    else append(&line, "null");
    append(&line, ",\"secondary\":");
    if (secondary != NULL) append(&line, "\"%s\"", secondary);
    else append(&line, "null");
    append(&line, ",\"center1_mhz\":");
    if (width != NULL) append(&line, "%u", (unsigned)normalized.center1_mhz);
    else append(&line, "null");
    append(&line, ",\"center2_mhz\":");
    if (width != NULL && normalized.width == WFA_WIDTH_80P80)
        append(&line, "%u", (unsigned)normalized.center2_mhz);
    else append(&line, "null");
    append(&line, "}");
    return publish(&line, out, size);
}

int wfa_format_end(char *out, size_t size, const char *boot, uint32_t scan,
                   const char *status, int32_t found, uint16_t returned,
                   uint64_t duration_ms, const char *code)
{
    wfa_line_t line = {{0}, 0U, true};
    bool success;
    size_t code_length = 0U;
    if (!valid_base(boot, scan) || status == NULL || returned > WFA_MAX_APS ||
        duration_ms > INT64_MAX) {
        return -1;
    }
    success = strcmp(status, "ok") == 0;
    if (success) {
        if (found < 0 || found > 65535 || returned > (uint32_t)found ||
            (found > 0 && returned == 0U) || code != NULL) {
            return -1;
        }
    } else if (strcmp(status, "error") != 0 && strcmp(status, "cancelled") != 0 &&
               strcmp(status, "timeout") != 0) {
        return -1;
    } else if (!ascii_string_length(code, 64U, &code_length)) {
        return -1;
    }
    append(&line, "[WFA1] {\"v\":1,\"type\":\"end\",\"boot\":\"%s\",\"scan\":%lu,\"status\":\"%s\",\"found\":",
           boot, (unsigned long)scan, status);
    if (success) append(&line, "%ld", (long)found);
    else append(&line, "null");
    append(&line, ",\"returned\":%u,\"truncated\":%s,\"duration_ms\":%llu",
           (unsigned)returned, success && found > (int32_t)returned ? "true" : "false",
           (unsigned long long)duration_ms);
    if (!success) {
        append(&line, ",\"code\":");
        append_json_string(&line, code, code_length);
    }
    append(&line, "}");
    return publish(&line, out, size);
}
