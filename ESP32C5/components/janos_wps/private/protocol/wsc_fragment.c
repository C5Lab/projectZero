#include "wsc_fragment.h"

#include <string.h>

typedef struct {
    uint8_t id;
    uint8_t opcode;
    uint8_t flags;
    uint16_t total;
    const uint8_t *payload;
    size_t payload_length;
} envelope_t;

static uint16_t be16(const uint8_t *value)
{
    return (uint16_t)(((uint16_t)value[0] << 8U) | value[1]);
}

static uint32_t fragment_hash(const uint8_t *data, size_t length)
{
    uint32_t hash = 2166136261U;
    for (size_t index = 0; index < length; index++) {
        hash ^= data[index];
        hash *= 16777619U;
    }
    return hash;
}

static bool parse_envelope(const uint8_t *frame, size_t length, envelope_t *envelope)
{
    if (frame == NULL || envelope == NULL || length < 18U ||
        frame[0] < 1U || frame[0] > 3U || frame[1] != 0U) return false;
    size_t eap_length = be16(frame + 2U);
    if (eap_length < 14U || eap_length + 4U != length ||
        frame[4] != 1U || be16(frame + 6U) != eap_length || frame[8] != 254U ||
        frame[9] != 0U || frame[10] != 0x37U || frame[11] != 0x2aU ||
        frame[12] != 0U || frame[13] != 0U || frame[14] != 0U || frame[15] != 1U ||
        (frame[17] & ~(WSC_FLAG_MORE_FRAGMENTS | WSC_FLAG_LENGTH_FIELD)) != 0U) return false;
    size_t payload_offset = 18U;
    uint16_t total = 0U;
    if ((frame[17] & WSC_FLAG_LENGTH_FIELD) != 0U) {
        if (length < 20U) return false;
        total = be16(frame + 18U);
        payload_offset = 20U;
    }
    envelope->id = frame[5];
    envelope->opcode = frame[16];
    envelope->flags = frame[17];
    envelope->total = total;
    envelope->payload = frame + payload_offset;
    envelope->payload_length = length - payload_offset;
    return true;
}

void wsc_reassembly_init(wsc_reassembly_t *state, uint8_t *storage,
                         size_t capacity, uint32_t timeout_ms)
{
    if (state == NULL) return;
    memset(state, 0, sizeof(*state));
    state->storage = storage;
    state->capacity = capacity;
    state->timeout_ms = timeout_ms;
}

void wsc_reassembly_reset(wsc_reassembly_t *state)
{
    if (state == NULL) return;
    if (state->storage != NULL && state->used != 0U) memset(state->storage, 0, state->used);
    state->used = 0U;
    state->expected = 0U;
    state->last_activity_ms = 0U;
    state->last_hash = 0U;
    state->last_length = 0U;
    state->last_eap_id = 0U;
    state->first_eap_id = 0U;
    state->opcode = 0U;
    state->last_flags = 0U;
    state->active = false;
    state->completed = false;
}

bool wsc_reassembly_active(const wsc_reassembly_t *state)
{
    return state != NULL && state->active;
}

bool wsc_reassembly_expire(wsc_reassembly_t *state, uint32_t now_ms)
{
    if (state == NULL || !state->active ||
        (uint32_t)(now_ms - state->last_activity_ms) <= state->timeout_ms) return false;
    wsc_reassembly_reset(state);
    return true;
}

static wsc_fragment_result_t fail_reset(wsc_reassembly_t *state,
                                        wsc_fragment_result_t result)
{
    wsc_reassembly_reset(state);
    return result;
}

static bool matches_last_fragment(const wsc_reassembly_t *state,
                                  const envelope_t *envelope, uint32_t hash)
{
    return envelope->id == state->last_eap_id &&
           envelope->flags == state->last_flags &&
           envelope->payload_length == state->last_length &&
           hash == state->last_hash && state->used >= state->last_length &&
           memcmp(state->storage + state->used - state->last_length,
                  envelope->payload, envelope->payload_length) == 0;
}

wsc_fragment_result_t wsc_reassembly_accept(wsc_reassembly_t *state,
                                             const uint8_t *frame, size_t length,
                                             uint32_t now_ms,
                                             wsc_fragment_view_t *view)
{
    if (state == NULL || state->storage == NULL || view == NULL) return WSC_FRAGMENT_INVALID;
    memset(view, 0, sizeof(*view));
    envelope_t envelope;
    if (!parse_envelope(frame, length, &envelope)) return fail_reset(state, WSC_FRAGMENT_INVALID);
    view->eap_id = envelope.id;
    view->opcode = envelope.opcode;
    if (envelope.opcode != 4U) return WSC_FRAGMENT_OTHER;

    if (state->active &&
        (uint32_t)(now_ms - state->last_activity_ms) > state->timeout_ms)
        return fail_reset(state, WSC_FRAGMENT_TIMEOUT);

    uint32_t hash = fragment_hash(envelope.payload, envelope.payload_length);
    if (state->completed && matches_last_fragment(state, &envelope, hash)) {
        view->first_eap_id = state->first_eap_id;
        view->payload = state->storage;
        view->length = state->used;
        return WSC_FRAGMENT_COMPLETE;
    }
    if (state->active && matches_last_fragment(state, &envelope, hash))
        return WSC_FRAGMENT_NEED_ACK;

    if (!state->active) {
        if (state->used != 0U || state->completed) wsc_reassembly_reset(state);
        if ((envelope.flags & WSC_FLAG_MORE_FRAGMENTS) == 0U) {
            if ((envelope.flags & WSC_FLAG_LENGTH_FIELD) != 0U &&
                envelope.total != envelope.payload_length) return WSC_FRAGMENT_INVALID;
            if (envelope.payload_length > state->capacity) return WSC_FRAGMENT_OVERSIZE;
            memcpy(state->storage, envelope.payload, envelope.payload_length);
            state->used = envelope.payload_length;
            state->expected = envelope.payload_length;
            state->last_activity_ms = now_ms;
            state->last_hash = hash;
            state->last_length = envelope.payload_length;
            state->last_eap_id = envelope.id;
            state->first_eap_id = envelope.id;
            state->opcode = envelope.opcode;
            state->last_flags = envelope.flags;
            state->completed = true;
            view->first_eap_id = envelope.id;
            view->payload = state->storage;
            view->length = envelope.payload_length;
            return WSC_FRAGMENT_COMPLETE;
        }
        if (envelope.payload_length == 0U ||
            (envelope.flags & WSC_FLAG_LENGTH_FIELD) == 0U ||
            envelope.total <= envelope.payload_length) return WSC_FRAGMENT_INVALID;
        if (envelope.total > state->capacity) return WSC_FRAGMENT_OVERSIZE;
        memcpy(state->storage, envelope.payload, envelope.payload_length);
        state->used = envelope.payload_length;
        state->expected = envelope.total;
        state->last_activity_ms = now_ms;
        state->last_hash = hash;
        state->last_length = envelope.payload_length;
        state->last_eap_id = envelope.id;
        state->first_eap_id = envelope.id;
        state->opcode = envelope.opcode;
        state->last_flags = envelope.flags;
        state->active = true;
        return WSC_FRAGMENT_NEED_ACK;
    }

    if ((envelope.flags & WSC_FLAG_LENGTH_FIELD) != 0U ||
        envelope.id == state->last_eap_id ||
        envelope.opcode != state->opcode ||
        envelope.payload_length > state->expected - state->used ||
        ((envelope.flags & WSC_FLAG_MORE_FRAGMENTS) != 0U &&
         envelope.payload_length == 0U))
        return fail_reset(state, WSC_FRAGMENT_INVALID);
    memcpy(state->storage + state->used, envelope.payload, envelope.payload_length);
    state->used += envelope.payload_length;
    state->last_activity_ms = now_ms;
    state->last_hash = hash;
    state->last_length = envelope.payload_length;
    state->last_eap_id = envelope.id;
    state->last_flags = envelope.flags;
    if ((envelope.flags & WSC_FLAG_MORE_FRAGMENTS) != 0U) {
        if (state->used >= state->expected) return fail_reset(state, WSC_FRAGMENT_INVALID);
        return WSC_FRAGMENT_NEED_ACK;
    }
    if (state->used != state->expected) return fail_reset(state, WSC_FRAGMENT_INVALID);
    view->payload = state->storage;
    view->length = state->used;
    view->first_eap_id = state->first_eap_id;
    state->active = false;
    state->completed = true;
    return WSC_FRAGMENT_COMPLETE;
}

size_t wsc_build_fragment_ack(uint8_t eap_id, uint8_t *output, size_t capacity)
{
    if (output == NULL || capacity < 18U) return 0U;
    memset(output, 0, 18U);
    output[0] = 1U; output[3] = 14U;
    output[4] = 2U; output[5] = eap_id; output[7] = 14U; output[8] = 254U;
    output[10] = 0x37U; output[11] = 0x2aU; output[15] = 1U;
    output[16] = 6U;
    return 18U;
}

size_t wsc_materialize_message(const wsc_fragment_view_t *view,
                               uint8_t *output, size_t capacity)
{
    if (view == NULL || view->payload == NULL || output == NULL ||
        view->length > UINT16_MAX - 14U || capacity < 18U ||
        view->length > capacity - 18U) return 0U;
    size_t length = 18U + view->length;
    uint16_t eap_length = (uint16_t)(14U + view->length);
    memset(output, 0, 18U);
    output[0] = 1U;
    output[2] = (uint8_t)(eap_length >> 8U);
    output[3] = (uint8_t)eap_length;
    output[4] = 1U;
    output[5] = view->eap_id;
    output[6] = output[2];
    output[7] = output[3];
    output[8] = 254U;
    output[10] = 0x37U;
    output[11] = 0x2aU;
    output[15] = 1U;
    output[16] = view->opcode;
    memcpy(output + 18U, view->payload, view->length);
    return length;
}
