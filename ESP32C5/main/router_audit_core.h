#ifndef ROUTER_AUDIT_CORE_H
#define ROUTER_AUDIT_CORE_H

#include "router_fingerprint.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ROUTER_HTTP_HEADER_MAX 4096U
#define ROUTER_UPNP_XML_MAX 8192U
#define ROUTER_NETWORK_TIMEOUT_MS 2000U
#define ROUTER_SSDP_RESPONSE_MAX 4U
#define ROUTER_IO_OPERATION_MAX 64U
#define ROUTER_LOCATION_PATH_MAX 256U
#define ROUTER_AUDIT_SCRATCH_MIN \
    (ROUTER_HTTP_HEADER_MAX + ROUTER_UPNP_XML_MAX + 2U)

#define ROUTER_IO_TIMEOUT INT64_C(-1)
#define ROUTER_IO_ERROR INT64_C(-2)

typedef enum {
    ROUTER_AUDIT_PASSIVE = 0,
    ROUTER_AUDIT_STANDARD_OWNED
} router_audit_mode_t;

typedef enum {
    ROUTER_AUDIT_RESULT_OK = 0,
    ROUTER_AUDIT_RESULT_PARTIAL,
    ROUTER_AUDIT_RESULT_PRECONDITION,
    ROUTER_AUDIT_RESULT_CANCELLED,
    ROUTER_AUDIT_RESULT_INVALID
} router_audit_result_t;

typedef enum {
    ROUTER_SOCKET_UDP = 0,
    ROUTER_SOCKET_TCP
} router_socket_kind_t;

enum {
    ROUTER_AUDIT_ERROR_SSDP_IO = 1U << 0,
    ROUTER_AUDIT_ERROR_SSDP_SOURCE = 1U << 1,
    ROUTER_AUDIT_ERROR_SSDP_PARSE = 1U << 2,
    ROUTER_AUDIT_ERROR_LOCATION = 1U << 3,
    ROUTER_AUDIT_ERROR_HTTP = 1U << 4,
    ROUTER_AUDIT_ERROR_XML = 1U << 5,
    ROUTER_AUDIT_ERROR_CAPACITY = 1U << 6,
    ROUTER_AUDIT_ERROR_CLOCK = 1U << 7,
    ROUTER_AUDIT_ERROR_EVIDENCE = 1U << 8
};

/* IPv4 fields are numeric network order: 192.0.2.1 is 0xC0000201. */
typedef struct {
    bool sta_connected;
    uint32_t local_ipv4;
    uint32_t netmask_ipv4;
    uint32_t gateway_ipv4;
    bool bssid_known;
    uint8_t bssid[6];
    bool gateway_mac_known;
    uint8_t gateway_mac[6];
    char dhcp_vendor[ROUTER_EVIDENCE_TEXT_MAX + 1U];
    char dhcp_model[ROUTER_EVIDENCE_TEXT_MAX + 1U];
} router_network_context_t;

typedef struct {
    router_evidence_t items[ROUTER_EVIDENCE_MAX];
    size_t count;
    uint32_t error_mask;
    uint32_t gateway_ipv4;
    bool bssid_known;
    uint8_t bssid[6];
    bool gateway_mac_known;
    uint8_t gateway_mac[6];
    size_t request_count;
    size_t ssdp_responses;
} router_evidence_set_t;

typedef struct {
    void *context;
    int (*socket_open)(void *context, router_socket_kind_t kind);
    bool (*socket_set_timeout)(void *context, int socket_fd,
                               uint32_t timeout_ms);
    int64_t (*socket_send_to)(void *context, int socket_fd,
                              const uint8_t *bytes, size_t length,
                              uint32_t peer_ipv4, uint16_t peer_port);
    int64_t (*socket_recv_from)(void *context, int socket_fd,
                                uint8_t *bytes, size_t capacity,
                                uint32_t *peer_ipv4, uint16_t *peer_port);
    bool (*socket_connect)(void *context, int socket_fd,
                           uint32_t peer_ipv4, uint16_t peer_port,
                           uint32_t timeout_ms);
    int64_t (*socket_send)(void *context, int socket_fd,
                           const uint8_t *bytes, size_t length);
    int64_t (*socket_recv)(void *context, int socket_fd,
                           uint8_t *bytes, size_t capacity);
    void (*socket_close)(void *context, int socket_fd);
    uint64_t (*monotonic_ms)(void *context);
    bool (*cancelled)(void *context);
    bool (*oui_lookup)(void *context, const uint8_t mac[6],
                       char vendor[ROUTER_EVIDENCE_TEXT_MAX + 1U]);
    uint8_t *scratch;
    size_t scratch_capacity;
} router_audit_ops_t;

/* Invalid input and failed preconditions leave evidence unchanged. */
router_audit_result_t router_audit_collect(
    router_audit_mode_t mode,
    const router_network_context_t *network,
    const router_audit_ops_t *ops,
    router_evidence_set_t *evidence);

#ifdef __cplusplus
}
#endif

#endif
