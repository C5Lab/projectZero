#ifndef WIFI_ANALYZER_CORE_H
#define WIFI_ANALYZER_CORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define WFA_DEFAULT_LIMIT 64U
#define WFA_MAX_APS 128U
#define WFA_MAX_CHANNELS 42U
#define WFA_MAX_LINE_BYTES 1024U
#define WFA_LINE_CAPACITY (WFA_MAX_LINE_BYTES + 2U)

typedef enum { WFA_BAND_NONE = 0, WFA_BAND_24 = 1, WFA_BAND_5 = 2, WFA_BAND_BOTH = 3 } wfa_band_t;
typedef enum { WFA_QUICK, WFA_DETAILED, WFA_PASSIVE } wfa_profile_t;
typedef enum { WFA_WIDTH_UNKNOWN = 0, WFA_WIDTH_20 = 20, WFA_WIDTH_40 = 40,
               WFA_WIDTH_80 = 80, WFA_WIDTH_160 = 160, WFA_WIDTH_80P80 = 8080 } wfa_width_t;
enum { WFA_SECOND_UNKNOWN = -1, WFA_SECOND_NONE = 0, WFA_SECOND_ABOVE = 1, WFA_SECOND_BELOW = 2 };
enum { WFA_PHY_A = 1U << 0, WFA_PHY_B = 1U << 1, WFA_PHY_G = 1U << 2,
       WFA_PHY_N = 1U << 3, WFA_PHY_AC = 1U << 4, WFA_PHY_AX = 1U << 5, WFA_PHY_LR = 1U << 6 };

typedef struct {
    wfa_band_t band;
    wfa_profile_t profile;
    uint16_t limit;
    uint8_t channels[WFA_MAX_CHANNELS];
    uint8_t channel_count;
    bool explicit_channels;
} wfa_options_t;

typedef struct {
    uint8_t bssid[6];
    uint8_t ssid[32];
    uint8_t ssid_len;
    uint8_t primary;
    int8_t rssi;
    wfa_band_t band;
    const char *auth;
    uint8_t phy_mask;
    wfa_width_t width;
    int8_t secondary;
    uint16_t center1_mhz;
    uint16_t center2_mhz;
} wfa_ap_t;

/* No allocations or ESP-IDF dependencies. Full argv includes command + "scan". */
bool wfa_parse_scan_args(int argc, char **argv, wfa_options_t *out, const char **reason);
wfa_band_t wfa_channel_band(unsigned channel);
unsigned wfa_primary_frequency(unsigned channel);
const char *wfa_band_name(wfa_band_t band);
const char *wfa_profile_name(wfa_profile_t profile);
uint32_t wfa_scan_deadline_ms(const wfa_options_t *options);
/* Invalid or incomplete geometry is deliberately converted to all-unknown. */
void wfa_normalize_geometry(wfa_ap_t *ap);
/* Returns complete line bytes including LF, or -1 without publishing on overflow. */
int wfa_format_begin(char *out, size_t size, const char *boot, uint32_t scan,
                     const wfa_options_t *options, uint64_t started_ms);
int wfa_format_ap(char *out, size_t size, const char *boot, uint32_t scan,
                  uint16_t seq, const wfa_ap_t *ap);
int wfa_format_end(char *out, size_t size, const char *boot, uint32_t scan,
                   const char *status, int32_t found, uint16_t returned,
                   uint64_t duration_ms, const char *code);

#endif
