#ifndef ROUTER_FINGERPRINT_H
#define ROUTER_FINGERPRINT_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ROUTER_VENDOR_MAX 64U
#define ROUTER_MODEL_MAX 96U
#define ROUTER_FIRMWARE_MAX 96U
#define ROUTER_EVIDENCE_MAX 8U
#define ROUTER_EVIDENCE_TEXT_MAX 192U

typedef enum {
    ROUTER_EVIDENCE_OUI = 0,
    ROUTER_EVIDENCE_DHCP,
    ROUTER_EVIDENCE_SSDP_SERVER,
    ROUTER_EVIDENCE_UPNP_STRUCTURED,
    ROUTER_EVIDENCE_HTTP_SERVER,
    ROUTER_EVIDENCE_HTTP_TITLE,
    ROUTER_EVIDENCE_SOURCE_COUNT
} router_evidence_source_t;

typedef enum {
    ROUTER_CONFIDENCE_UNKNOWN = 0,
    ROUTER_CONFIDENCE_PROBABLE,
    ROUTER_CONFIDENCE_CONFIRMED
} router_confidence_t;

typedef struct {
    router_evidence_source_t source;
    bool locally_administered_mac;
    char vendor[ROUTER_EVIDENCE_TEXT_MAX + 1U];
    char model[ROUTER_EVIDENCE_TEXT_MAX + 1U];
    char firmware[ROUTER_EVIDENCE_TEXT_MAX + 1U];
} router_evidence_t;

typedef struct {
    char vendor[ROUTER_VENDOR_MAX + 1U];
    char model[ROUTER_MODEL_MAX + 1U];
    char firmware[ROUTER_FIRMWARE_MAX + 1U];
    router_confidence_t confidence;
    bool conflict;
    bool truncated;
} router_fingerprint_t;

/* Invalid input leaves out unchanged. */
bool router_fingerprint_normalize(const router_evidence_t *items,
                                  size_t count,
                                  router_fingerprint_t *out);

#ifdef __cplusplus
}
#endif

#endif
