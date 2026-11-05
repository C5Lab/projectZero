#ifndef CLIENT_ISOLATION_RUNTIME_H
#define CLIENT_ISOLATION_RUNTIME_H

#include "client_isolation_core.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CLIENT_ISOLATION_DEFAULT_PORT 48731U
#define CLIENT_ISOLATION_DEFAULT_COUNT 3U
#define CLIENT_ISOLATION_MAX_COUNT 10U
#define CLIENT_ISOLATION_MAX_RX_PER_PROBE 32U
#define CLIENT_ISOLATION_PROBE_TIMEOUT_MS 1000U
#define CLIENT_ISOLATION_TOTAL_TIMEOUT_MS 15000U

typedef enum {
    ISO_AUDIT_PEER_REACHABLE = 0,
    ISO_AUDIT_INCONCLUSIVE_NO_REPLY,
    ISO_AUDIT_LOCAL_ERROR,
    ISO_AUDIT_CANCELLED,
} client_isolation_conclusion_t;

typedef enum {
    CLIENT_ISOLATION_RECEIVE_ERROR = -1,
    CLIENT_ISOLATION_RECEIVE_TIMEOUT = 0,
    CLIENT_ISOLATION_RECEIVE_DATAGRAM = 1,
} client_isolation_receive_t;

typedef enum {
    CLIENT_ISOLATION_TELEMETRY_INVALID_REPLY = 1,
    CLIENT_ISOLATION_TELEMETRY_UNRELATED_DATAGRAM = 2,
} client_isolation_telemetry_t;

typedef struct {
    uint32_t local_ipv4;
    uint32_t peer_ipv4;
    uint16_t peer_port;
    uint8_t probe_count;
    uint8_t token[JISO_TOKEN_BYTES];
} client_isolation_config_t;

typedef struct {
    uint32_t sequence;
    uint32_t datagrams_received;
    uint32_t authenticated_replies;
    uint32_t invalid_replies;
    uint32_t unrelated_datagrams;
    uint32_t rtt_ms;
    bool sent;
    bool timed_out;
    bool rtt_known;
} client_isolation_probe_result_t;

typedef struct {
    client_isolation_conclusion_t conclusion;
    uint64_t run_id;
    uint32_t probes_sent;
    uint32_t datagrams_received;
    uint32_t authenticated_replies;
    uint32_t invalid_replies;
    uint32_t unrelated_datagrams;
    uint32_t local_errors;
    uint32_t probe_timeouts;
    uint32_t duration_ms;
    uint8_t probe_result_count;
    client_isolation_probe_result_t probes[CLIENT_ISOLATION_MAX_COUNT];
    bool cancelled;
    bool clock_anomaly;
    bool total_deadline_reached;
} client_isolation_result_t;

typedef struct {
    bool (*socket_open)(void *context, int *socket_handle);
    bool (*socket_bind)(void *context, int socket_handle, uint32_t local_ipv4);
    bool (*random_fill)(void *context, uint8_t *bytes, size_t length);
    bool (*send_datagram)(void *context,
                          int socket_handle,
                          uint32_t peer_ipv4,
                          uint16_t peer_port,
                          const uint8_t *packet,
                          size_t length);
    client_isolation_receive_t (*receive_datagram)(
        void *context,
        int socket_handle,
        uint32_t timeout_ms,
        uint8_t *packet,
        size_t capacity,
        size_t *length,
        uint32_t *source_ipv4,
        uint16_t *source_port);
    bool (*socket_close)(void *context, int socket_handle);
    uint64_t (*monotonic_ms)(void *context);
    bool (*cancelled)(void *context);
    void (*telemetry)(void *context,
                      client_isolation_telemetry_t event,
                      uint32_t sequence);
    const jiso_crypto_t *crypto;
    void *context;
} client_isolation_ops_t;

client_isolation_conclusion_t client_isolation_run(
    const client_isolation_config_t *config,
    const client_isolation_ops_t *ops,
    client_isolation_result_t *result);

#ifdef __cplusplus
}
#endif

#endif
