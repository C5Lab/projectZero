#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define WSC_FLAG_MORE_FRAGMENTS 0x01U
#define WSC_FLAG_LENGTH_FIELD 0x02U

typedef enum {
    WSC_FRAGMENT_INVALID = 0,
    WSC_FRAGMENT_OTHER,
    WSC_FRAGMENT_NEED_ACK,
    WSC_FRAGMENT_COMPLETE,
    WSC_FRAGMENT_OVERSIZE,
    WSC_FRAGMENT_TIMEOUT,
} wsc_fragment_result_t;

typedef struct {
    const uint8_t *payload;
    size_t length;
    uint8_t first_eap_id;
    uint8_t eap_id;
    uint8_t opcode;
} wsc_fragment_view_t;

typedef struct {
    uint8_t *storage;
    size_t capacity;
    size_t used;
    size_t expected;
    uint32_t timeout_ms;
    uint32_t last_activity_ms;
    uint32_t last_hash;
    size_t last_length;
    uint8_t last_eap_id;
    uint8_t first_eap_id;
    uint8_t opcode;
    uint8_t last_flags;
    bool active;
    bool completed;
} wsc_reassembly_t;

void wsc_reassembly_init(wsc_reassembly_t *state, uint8_t *storage,
                         size_t capacity, uint32_t timeout_ms);
void wsc_reassembly_reset(wsc_reassembly_t *state);
bool wsc_reassembly_active(const wsc_reassembly_t *state);
bool wsc_reassembly_expire(wsc_reassembly_t *state, uint32_t now_ms);
wsc_fragment_result_t wsc_reassembly_accept(wsc_reassembly_t *state,
                                             const uint8_t *frame, size_t length,
                                             uint32_t now_ms,
                                             wsc_fragment_view_t *view);
size_t wsc_build_fragment_ack(uint8_t eap_id, uint8_t *output, size_t capacity);
size_t wsc_materialize_message(const wsc_fragment_view_t *view,
                               uint8_t *output, size_t capacity);
