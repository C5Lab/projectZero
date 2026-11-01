#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t bssid[6];
    uint8_t client[6];
} pmkid_identity_t;

typedef void (*pmkid_visitor_t)(const pmkid_identity_t *identity,
                                const uint8_t pmkid[16], void *context);

/* Parse a complete received 802.11 frame, optionally including its FCS.
 * No allocation or unaligned reads. Malformed elements produce no callbacks. */
size_t pmkid_parse_frame(const uint8_t *frame, size_t length,
                        pmkid_visitor_t visitor, void *context);

/* PMKID captures must not satisfy the legacy "handshake already exists" test. */
bool pmkid_is_capture_filename(const char *name);
