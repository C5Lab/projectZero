#ifndef CSA_DETECTOR_CORE_H
#define CSA_DETECTOR_CORE_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CSA_SSID_SIZE 33
#define CSA_LINE_SIZE 201
#define CSA_FRAME_LIMIT 4096
#define CSA_RATE_SLOTS 16

typedef enum { CSA_VIA_BEACON, CSA_VIA_PROBE, CSA_VIA_ACTION } csa_via_t;
typedef struct {
    uint8_t bssid[6], transmitter[6];
    uint8_t rx_channel, target_channel, count, mode, operating_class;
    int8_t rssi;
    csa_via_t via;
    bool has_class;
    char ssid[CSA_SSID_SIZE];
} csa_event_t;

typedef struct {
    bool used;
    csa_event_t event;
    uint32_t last_ms;
} csa_rate_slot_t;
typedef struct {
    csa_rate_slot_t slots[CSA_RATE_SLOTS];
    uint32_t capacity_dropped;
} csa_rate_limit_t;

/* sig_len includes FCS; require a positive, complete C5 payload dump. */
bool csa_capture_length(size_t sig_len, size_t dump_len, unsigned rx_state, size_t *length);
bool csa_parse(const uint8_t *frame, size_t length, uint8_t rx_channel, int8_t rssi, csa_event_t *event);
void csa_safe_ssid(char out[CSA_SSID_SIZE], const uint8_t *ssid, size_t length);
size_t csa_format_line(const csa_event_t *event, char *line, size_t capacity);
bool csa_rate_allow(csa_rate_limit_t *state, const csa_event_t *event, uint32_t now_ms);
#endif
