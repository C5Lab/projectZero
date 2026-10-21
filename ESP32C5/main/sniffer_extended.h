#ifndef JANOS_SNIFFER_EXTENDED_H
#define JANOS_SNIFFER_EXTENDED_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SX_SELECTORS 8
#define SX_TEXT_BYTES 64
#define SX_AP_SUFFIX_BYTES 2304
#define SX_CLIENT_SUFFIX_BYTES 96
/* Conservative full UART record bounds, including possible CRLF, excluding NUL. */
#define SX_AP_LINE_MAX_BYTES 2432
#define SX_CLIENT_LINE_MAX_BYTES 192

typedef enum { SX_UNKNOWN, SX_ABSENT, SX_VALID, SX_INVALID } sx_status_t;
typedef enum { SX_NONE, SX_BEACON, SX_PROBE_RESP, SX_ASSOC_REQ, SX_REASSOC_REQ } sx_source_t;
typedef struct {
    uint8_t bytes[SX_TEXT_BYTES];
    uint8_t len;
    bool present, truncated;
} sx_text_t;
typedef struct {
    sx_status_t status;
    uint8_t group[4], management[4];
    bool group_present, management_present;
    uint8_t pairwise[SX_SELECTORS][4], akm[SX_SELECTORS][4];
    uint8_t pairwise_count, akm_count;
    bool pairwise_known, akm_known, truncated;
    bool pmf_capable, pmf_required;
} sx_security_t;
typedef struct {
    sx_status_t status;
    int state, config_methods, setup_locked, selected_registrar;
    sx_text_t manufacturer, model_name, model_number, device_name;
    bool truncated, present;
} sx_wps_t;
typedef struct {
    int8_t hidden; /* -1 unknown; beacon evidence only */
    uint8_t resolved_ssid[32], resolved_len;
    sx_source_t ssid_source, profile_source;
    sx_status_t frame_status;
    int8_t privacy; /* capability bit, independent of RSN/WPA */
    sx_security_t rsn, wpa;
    sx_wps_t wps;
} sx_ap_t;
typedef struct {
    uint8_t bssid[6];
    sx_source_t source;
    bool complete, ssid_present;
    uint8_t ssid[32], ssid_len;
    int8_t hidden, privacy;
    sx_security_t rsn, wpa;
    sx_wps_t wps;
} sx_observation_t;

void sx_init(sx_ap_t *ap);
/* Input is a single MPDU WITHOUT FCS. Returns false for unrelated/ambiguous headers. */
bool sx_parse(const uint8_t *frame, size_t len, sx_observation_t *observation);
void sx_apply(sx_ap_t *ap, const sx_observation_t *observation);
/* Number of bytes excluding NUL; zero on insufficient capacity (no partial suffix). */
size_t sx_format_ap(char *out, size_t capacity, const sx_ap_t *ap,
                    const uint8_t bssid[6], int rssi, bool rssi_known,
                    uint32_t last_seen, bool seen, uint32_t now);
size_t sx_format_client(char *out, size_t capacity, int rssi, bool rssi_known,
                        uint32_t last_seen, uint32_t now);
#endif
