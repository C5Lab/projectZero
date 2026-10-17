#ifndef STA_MAC_POLICY_CORE_H
#define STA_MAC_POLICY_CORE_H

#include <stddef.h>
#include <stdint.h>

#define STA_MAC_POLICY_VERSION 1u
#define STA_MAC_POLICY_RECORD_SIZE 8u
#define STA_MAC_SIZE 6u

typedef enum {
    STA_MAC_MODE_FACTORY = 0,
    STA_MAC_MODE_RANDOM_PER_BOOT = 1,
    STA_MAC_MODE_FIXED = 2
} sta_mac_policy_mode_t;

/* In-memory representation only; never persist sizeof(this struct). */
typedef struct {
    uint8_t version;
    sta_mac_policy_mode_t mode;
    uint8_t mac[STA_MAC_SIZE];
} sta_mac_policy_record_t;

typedef enum {
    STA_MAC_POLICY_OK = 0,
    STA_MAC_POLICY_INVALID_ARGUMENT,
    STA_MAC_POLICY_WRONG_LENGTH,
    STA_MAC_POLICY_UNSUPPORTED_VERSION,
    STA_MAC_POLICY_INVALID_MODE,
    STA_MAC_POLICY_INVALID_FIXED_MAC,
    STA_MAC_POLICY_INVALID_TEXT,
    STA_MAC_POLICY_INVALID_PAYLOAD
} sta_mac_policy_status_t;

/* Outputs remain unchanged on error. Text must be a NUL-terminated string. */
sta_mac_policy_status_t sta_mac_fixed_validate(const uint8_t mac[STA_MAC_SIZE]);
sta_mac_policy_status_t sta_mac_fixed_parse(const char *text, uint8_t out[STA_MAC_SIZE]);
sta_mac_policy_status_t sta_mac_policy_validate(const sta_mac_policy_record_t *record);
sta_mac_policy_status_t sta_mac_policy_encode(const sta_mac_policy_record_t *record,
                                             uint8_t *out, size_t length);
sta_mac_policy_status_t sta_mac_policy_decode(const uint8_t *data, size_t length,
                                             sta_mac_policy_record_t *out);
/* One derivation, exactly six bytes; caching/entropy generation is adapter work. */
sta_mac_policy_status_t sta_mac_random_from_entropy(const uint8_t *entropy,
                                                   size_t length, uint8_t out[STA_MAC_SIZE]);

#endif
