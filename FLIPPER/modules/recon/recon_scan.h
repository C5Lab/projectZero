#ifndef LAB_C5_RECON_SCAN_H
#define LAB_C5_RECON_SCAN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define C5_RECON_SCAN_MAX_RESULTS 64u
#define C5_RECON_SCAN_LINE_CAPACITY 192u
#define C5_RECON_SCAN_SSID_CAPACITY 33u
#define C5_RECON_SCAN_SECURITY_CAPACITY 16u
#define C5_RECON_SCAN_VENDOR_CACHE_SIZE 16u

typedef enum {
    C5ReconBand24 = 0,
    C5ReconBand5 = 1,
    C5ReconBandUnknown = 0xff,
} C5ReconBand;

typedef enum {
    C5ReconScanEventNone = 0,
    C5ReconScanEventRow = 1u << 0,
    C5ReconScanEventDone = 1u << 1,
    C5ReconScanEventNoResults = 1u << 2,
    C5ReconScanEventStillRunning = 1u << 3,
    C5ReconScanEventNoMemory = 1u << 4,
    C5ReconScanEventError = 1u << 5,
} C5ReconScanEvent;

typedef struct {
    uint16_t number;
    char ssid[C5_RECON_SCAN_SSID_CAPACITY];
    uint8_t bssid[6];
    uint8_t channel;
    char security[C5_RECON_SCAN_SECURITY_CAPACITY];
    int16_t power_dbm;
    uint8_t band;
    bool power_valid;
    bool selected;
} C5ReconScanResult;

/* Only the fields needed by attack commands, the Deauth overlay and Web. */
typedef struct {
    uint16_t number;
    char ssid[C5_RECON_SCAN_SSID_CAPACITY];
    uint8_t bssid[6];
    uint8_t channel;
} C5ReconTarget;

typedef struct {
    uint8_t oui[3];
    char name[24];
    uint32_t last_tick;
    bool valid;
} C5ReconVendorEntry;

/* Model state belongs to the active Recon FAL. Treat members as read-only from
 * the UI; use the functions below to mutate it. No pointer refers to SimpleApp.
 */
typedef struct {
    C5ReconScanResult* results;
    uint16_t* selected_numbers;
    uint16_t* visible_indices;
    size_t capacity;
    size_t count;
    size_t visible_count;
    size_t selected_count;
    size_t visible_index;
    size_t visible_offset;
    int16_t min_power_dbm;
    bool loading;
    char line[C5_RECON_SCAN_LINE_CAPACITY];
    size_t line_length;
    bool discard_line;
    uint16_t band_24_count;
    uint16_t band_5_count;
    uint16_t open_count;
    uint16_t hidden_count;
    bool best_rssi_valid;
    int16_t best_rssi;
    char best_ssid[C5_RECON_SCAN_SSID_CAPACITY];
    uint32_t last_update_tick;
    C5ReconVendorEntry vendors[C5_RECON_SCAN_VENDOR_CACHE_SIZE];
} C5ReconScan;

void c5_recon_scan_init(C5ReconScan* scan, int16_t min_power_dbm);
void c5_recon_scan_deinit(C5ReconScan* scan);
/* Starts a fresh scan with 64 slots. A later Found/Retrieved banner can shrink
 * the capacity before the first row. Returns false and leaves no buffers on OOM.
 */
bool c5_recon_scan_begin(C5ReconScan* scan);
/* Feed actual UART RX bytes, not local TX log text. Accepts JanOS's eight-field
 * scan rows, including its extra CSV quote layer around SSID/vendor. Events
 * are ORed across complete lines. Overlong lines are discarded through LF.
 */
uint32_t c5_recon_scan_feed(C5ReconScan* scan, const uint8_t* bytes, size_t length, uint32_t now_tick);
void c5_recon_scan_set_min_power(C5ReconScan* scan, int16_t min_power_dbm);
const C5ReconScanResult* c5_recon_scan_visible(const C5ReconScan* scan, size_t visible_index);
const C5ReconScanResult* c5_recon_scan_find_number(const C5ReconScan* scan, uint16_t number);
bool c5_recon_scan_toggle_visible(C5ReconScan* scan, size_t visible_index);
const char* c5_recon_scan_vendor(const C5ReconScan* scan, const uint8_t bssid[6]);
/* Writes caller-owned target copies in selection order; no pointer into the
 * scan model escapes. The caller may pass those copies to save_session only if
 * the host copies them synchronously before the active FAL is unloaded.
 * On insufficient capacity, output is unchanged and out_count still reports
 * the required count. A stale selected number has empty details.
 */
bool c5_recon_scan_export_targets(
    const C5ReconScan* scan,
    C5ReconTarget* output,
    size_t capacity,
    size_t* out_count);

#endif
