#ifndef LAB_C5_RECON_SNIFFER_CLIENTS_H
#define LAB_C5_RECON_SNIFFER_CLIENTS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The identity snapshot is opt-in and has its own bounded storage. Exceeding
 * either cap rejects the entire snapshot, so it can never authorize TX. */
#define C5_RECON_CLIENTS_MAX_APS 32u
#define C5_RECON_CLIENTS_MAX_STATIONS 64u
#define C5_RECON_CLIENTS_LINE_CAPACITY 256u

typedef enum {
    C5ReconClientsEmpty,
    C5ReconClientsLoading,
    C5ReconClientsReady,
    C5ReconClientsStarting,
    C5ReconClientsActive,
    C5ReconClientsError,
    C5ReconClientsUnsupported,
    C5ReconClientsReloadRequired,
} C5ReconClientsPhase;

typedef enum {
    C5ReconClientsNoTickEvent,
    C5ReconClientsListTimeout,
    C5ReconClientsStartTimeout,
} C5ReconClientsTick;

typedef struct {
    char bssid[18];
    char ssid[33];
    uint8_t channel;
} C5ReconIdentityAp;

typedef struct {
    char station[18];
    uint8_t ap_index;
} C5ReconIdentityClient;

typedef struct {
    C5ReconIdentityAp* aps;
    C5ReconIdentityClient* clients;
    size_t ap_count;
    size_t client_count;
    size_t expected_aps;
    size_t expected_clients;
    C5ReconClientsPhase phase;
    uint32_t started_tick;
    uint32_t last_record_tick;
    uint32_t start_sent_tick;
    bool begun;
    char pending_bssid[18];
    char pending_station[18];
    char error[48];
    char line[C5_RECON_CLIENTS_LINE_CAPACITY];
    size_t line_length;
} C5ReconClients;

void c5_recon_clients_init(C5ReconClients* state);
void c5_recon_clients_free(C5ReconClients* state);
void c5_recon_clients_begin(C5ReconClients* state, uint32_t now_ticks);
void c5_recon_clients_feed(
    C5ReconClients* state, const uint8_t* bytes, size_t length, uint32_t now_ticks);
C5ReconClientsTick c5_recon_clients_tick(C5ReconClients* state, uint32_t now_ticks);
/* On failure, out stays unchanged. No newline is included on success. */
bool c5_recon_clients_command(
    const C5ReconClients* state, size_t client_index, char* out, size_t capacity);
void c5_recon_clients_start_sent(C5ReconClients* state, size_t client_index, uint32_t now_ticks);
void c5_recon_clients_stop_requested(C5ReconClients* state, bool tx_ok);

#endif
