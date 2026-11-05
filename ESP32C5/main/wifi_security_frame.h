#ifndef WIFI_SECURITY_FRAME_H
#define WIFI_SECURITY_FRAME_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define WIFI_SECURITY_FRAME_COPY_MAX 1536U

typedef enum {
    WIFI_SEC_FRAME_UNSUPPORTED = 0,
    WIFI_SEC_FRAME_MGMT,
    WIFI_SEC_FRAME_AUTH,
    WIFI_SEC_FRAME_BEACON,
    WIFI_SEC_FRAME_PROBE_RESPONSE,
    WIFI_SEC_FRAME_DATA,
    WIFI_SEC_FRAME_EAPOL
} wifi_security_frame_kind_t;

typedef struct {
    wifi_security_frame_kind_t kind;
    uint8_t subtype;
    uint8_t addr1[6], addr2[6], addr3[6];
    uint8_t bssid[6], station[6];
    uint16_t sequence;
    bool retry, protected_frame, to_ds, from_ds, qos;
    const uint8_t *body;
    size_t body_len;
    const uint8_t *eapol;
    size_t eapol_len;
} wifi_security_decoded_t;

/* Input is an 802.11 MAC frame, without radiotap metadata. Returned views borrow
 * frame storage. The caller owns its lifetime and must not mutate it while used.
 * Protected bodies are never exposed. Ambiguous identities remain zero; false
 * clears a non-NULL output. EAPOL recognition validates SNAP, not EAPOL contents.
 */
bool wifi_security_decode(const uint8_t *frame, size_t length,
                          wifi_security_decoded_t *out);

#endif
