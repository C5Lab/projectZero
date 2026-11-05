#ifndef SAE_GUARD_PARSER_H
#define SAE_GUARD_PARSER_H

#include "wifi_security_frame.h"

typedef enum {
    SAE_GUARD_NOT_SAE = 0,
    SAE_GUARD_COMMIT,
    SAE_GUARD_CONFIRM,
    SAE_GUARD_ANTI_CLOGGING,
    SAE_GUARD_UNSUPPORTED_GROUP,
    SAE_GUARD_STATUS_ONLY,
    SAE_GUARD_MALFORMED
} sae_guard_frame_kind_t;

typedef enum {
    SAE_GUARD_PARSE_OK = 0,
    SAE_GUARD_SHORT_AUTH_BODY,
    SAE_GUARD_BAD_TRANSACTION,
    SAE_GUARD_SHORT_GROUP,
    SAE_GUARD_KNOWN_GROUP_UNDERSIZE,
    SAE_GUARD_CONFIRM_UNDERSIZE,
    SAE_GUARD_INPUT_TRUNCATED,
    SAE_GUARD_PROTECTED_BODY /* Reserved: hidden bodies are never SAE-attributed. */
} sae_guard_parse_reason_t;

/* Metadata only. The runtime adapter supplies channel/RSSI from its copied slot
 * after parsing. Never add SAE scalar, element, token, payload storage or views. */
typedef struct {
    uint8_t bssid[6], station[6];
    bool from_ap, retry;
    uint16_t sequence, transaction, status, group;
    uint16_t body_len;
    sae_guard_frame_kind_t kind;
    sae_guard_parse_reason_t reason;
    uint64_t timestamp_us;
    uint8_t channel;
    int8_t rssi;
} sae_guard_observation_t;

/* false clears out and means unrelated, protected, non-SAE or ambiguous identity.
 * A true result is bounded metadata; no Authentication bytes are retained. */
bool sae_guard_parse(const wifi_security_decoded_t *frame,
                     bool input_truncated, uint64_t timestamp_us,
                     sae_guard_observation_t *out);

#endif
