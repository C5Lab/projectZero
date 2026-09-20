#include "crack_worker_transfer.h"
#include "crack_worker_core.h"

#include <limits.h>
#include <stddef.h>

#define CRACK_WORKER_PREPARE_BASE_MS 10000U
#define CRACK_WORKER_PREPARE_STEP_BYTES 262144ULL
#define CRACK_WORKER_PREPARE_STEP_MS 1000U
#define CRACK_WORKER_PREPARE_MAX_MS 600000U
#define CRACK_WORKER_PREPARE_MAX_STEPS \
    ((CRACK_WORKER_PREPARE_MAX_MS - CRACK_WORKER_PREPARE_BASE_MS) / \
     CRACK_WORKER_PREPARE_STEP_MS)

static uint32_t crack_worker_transfer_le32(const uint8_t bytes[4])
{
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static bool crack_worker_transfer_header_valid(const uint8_t header[16])
{
    return header[0] == 'F' && header[1] == 'T' && header[2] == 'B' &&
           header[3] == 1;
}

crack_worker_transfer_action_t crack_worker_transfer_classify(
    const crack_worker_transfer_state_t *state,
    const uint8_t header[16])
{
    if (state == NULL || header == NULL ||
        !crack_worker_transfer_header_valid(header)) {
        return CRACK_TRANSFER_INVALID;
    }

    uint32_t index = crack_worker_transfer_le32(header + 4);
    uint32_t length = crack_worker_transfer_le32(header + 8);
    uint32_t crc32 = crack_worker_transfer_le32(header + 12);
    bool fin = index == state->expected_index && length == 0 && crc32 == 0 &&
               state->offset == state->expected_size;

    if (length == 0) {
        if (!fin) return CRACK_TRANSFER_INVALID;
        return state->finalized ? CRACK_TRANSFER_DUPLICATE_FIN : CRACK_TRANSFER_FIN;
    }
    if (state->finalized || index == UINT32_MAX || state->offset > state->expected_size)
        return CRACK_TRANSFER_INVALID;

    if (index == state->expected_index && length <= state->block_size &&
        (uint64_t)length <= state->expected_size - state->offset) {
        return CRACK_TRANSFER_EXPECTED_DATA;
    }

    if (state->ack32 && state->have_last && state->expected_index > 0 &&
        index == state->expected_index - 1U && length == state->last_length &&
        crc32 == state->last_crc32) {
        return CRACK_TRANSFER_DUPLICATE_DATA;
    }
    return CRACK_TRANSFER_INVALID;
}

void crack_worker_transfer_commit_data(crack_worker_transfer_state_t *state,
                                       uint32_t index, uint32_t length,
                                       uint32_t payload_crc32)
{
    if (state == NULL || index == UINT32_MAX) return;

    state->offset += length;
    state->expected_index = index + 1U;
    state->last_committed_offset = state->offset;
    state->last_index = index;
    state->last_length = length;
    state->last_crc32 = payload_crc32;
    state->have_last = true;
}

bool crack_worker_transfer_finalize(crack_worker_transfer_state_t *state)
{
    if (state == NULL || state->finalized || state->offset != state->expected_size)
        return false;
    state->finalized = true;
    return true;
}

crack_worker_transfer_action_t crack_worker_transfer_cancel(
    crack_worker_transfer_state_t *state)
{
    (void)state;
    return CRACK_TRANSFER_CANCEL;
}

uint32_t crack_worker_prepare_ms(uint64_t resume_offset,
                                 bool *resume_allowed)
{
    uint64_t steps = resume_offset / CRACK_WORKER_PREPARE_STEP_BYTES;
    if (resume_offset % CRACK_WORKER_PREPARE_STEP_BYTES != 0) ++steps;
    if (steps > CRACK_WORKER_PREPARE_MAX_STEPS) {
        if (resume_allowed != NULL) *resume_allowed = false;
        return CRACK_WORKER_PREPARE_BASE_MS;
    }

    if (resume_allowed != NULL) *resume_allowed = true;
    return CRACK_WORKER_PREPARE_BASE_MS +
           (uint32_t)(steps * CRACK_WORKER_PREPARE_STEP_MS);
}

uint32_t crack_worker_first_byte_timeout(bool first_byte_pending,
                                         uint32_t prepare_ms,
                                         uint32_t rx_ms)
{
    if (!first_byte_pending || prepare_ms < rx_ms) return rx_ms;
    return prepare_ms;
}

static bool transfer_reply(const crack_worker_transfer_ops_t *ops, void *context,
                            uint8_t status, uint32_t index, uint64_t offset)
{
    uint8_t frame[CRACK_WORKER_ACK32_SIZE];
    return crack_worker_ack32_build(frame, index, status, offset) &&
           ops->reply(context, frame);
}

crack_worker_transfer_result_t crack_worker_transfer_apply(
    crack_worker_transfer_state_t *state, crack_worker_transfer_action_t action,
    const uint8_t header[16], const uint8_t *payload,
    const crack_worker_transfer_ops_t *ops, void *context, const char **reason)
{
    uint32_t index = crack_worker_transfer_le32(header + 4);
    uint32_t length = crack_worker_transfer_le32(header + 8);
    uint32_t crc = crack_worker_transfer_le32(header + 12);
    switch (action) {
    case CRACK_TRANSFER_EXPECTED_DATA:
        if (crack_worker_crc32_update(0, payload, length) != crc) {
            if (!transfer_reply(ops, context, 0x15, index, state->offset)) {
                *reason = "uart_write_failed";
                return CRACK_TRANSFER_FAILED;
            }
            return CRACK_TRANSFER_RETRY;
        }
        if (!ops->write(context, payload, length)) {
            *reason = "sd_write_failed";
            break;
        }
        ops->crc(context, payload, length);
        if (!ops->checkpoint(context, state->offset + length)) {
            *reason = "checkpoint_failed";
            break;
        }
        crack_worker_transfer_commit_data(state, index, length, crc);
        ops->progress(context, state->offset, state->expected_index);
        break;
    case CRACK_TRANSFER_DUPLICATE_DATA:
        /* The committed original is authoritative. Payload was consumed in
         * full by receive(), but must not be hashed or written a second time. */
        index = state->last_index;
        break;
    case CRACK_TRANSFER_FIN:
        if (!ops->finalize(context)) {
            *reason = "finalize_failed";
            break;
        }
        (void)crack_worker_transfer_finalize(state);
        break;
    case CRACK_TRANSFER_DUPLICATE_FIN:
        break;
    default:
        *reason = "invalid_header";
        break;
    }
    if (*reason != NULL) {
        if (!transfer_reply(ops, context, 0x18, index, state->offset))
            *reason = "uart_write_failed";
        return CRACK_TRANSFER_FAILED;
    }
    uint64_t offset = action == CRACK_TRANSFER_DUPLICATE_DATA ?
                      state->last_committed_offset : state->offset;
    if (!transfer_reply(ops, context, 0x06, index, offset)) {
        *reason = "uart_write_failed";
        return CRACK_TRANSFER_FAILED;
    }
    return CRACK_TRANSFER_APPLIED;
}

bool crack_worker_transfer_receive(crack_worker_transfer_state_t *state,
    crack_worker_transfer_session_t *session,
    uint8_t *payload, size_t payload_capacity,
    const crack_worker_transfer_ops_t *ops, void *context)
{
    uint32_t first_timeout = crack_worker_first_byte_timeout(
        true, session->prepare_ms, session->rx_ms);
    bool success = false;
    session->reason = NULL;
    session->duplicates = 0;
    session->phase = "preparing";
    if (payload == NULL || payload_capacity < state->block_size)
        session->reason = "invalid_buffer";
    while (session->reason == NULL) {
        uint8_t header[16];
        session->header_got = session->payload_got = session->payload_expected = 0;
        int result = ops->read(context, header, 1, first_timeout, &session->header_got);
        if (result <= 0) {
            if (result == 0 && state->finalized && session->header_got == 0) {
                success = true;
                break;
            }
            session->reason = result < 0 ? "uart_read_failed" : "block_timeout";
            break;
        }
        if (header[0] == 0x18) {
            (void)crack_worker_transfer_cancel(state);
            success = state->finalized;
            session->reason = success ? NULL : "cancelled";
            break;
        }
        size_t rest_got = 0;
        result = ops->read(context, header + 1, 15, session->rx_ms, &rest_got);
        session->header_got += rest_got;
        if (result <= 0) {
            session->reason = result < 0 ? "uart_read_failed" : "header_timeout";
            break;
        }
        crack_worker_transfer_action_t action = crack_worker_transfer_classify(state, header);
        uint32_t index = crack_worker_transfer_le32(header + 4);
        if (action == CRACK_TRANSFER_EXPECTED_DATA || action == CRACK_TRANSFER_DUPLICATE_DATA) {
            session->phase = "payload";
            session->payload_expected = crack_worker_transfer_le32(header + 8);
            result = ops->read(context, payload, session->payload_expected,
                               session->rx_ms, &session->payload_got);
            if (result <= 0) {
                session->reason = result < 0 ? "uart_read_failed" : "payload_timeout";
                if (!transfer_reply(ops, context, 0x18, index, state->offset))
                    session->reason = "uart_write_failed";
                break;
            }
        }
        crack_worker_transfer_result_t applied = crack_worker_transfer_apply(
            state, action, header, payload, ops, context, &session->reason);
        if (applied == CRACK_TRANSFER_FAILED) break;
        if (action == CRACK_TRANSFER_DUPLICATE_DATA) ++session->duplicates;
        /* The first-byte clock starts only once the entire reply is enqueued. */
        first_timeout = state->finalized ? CRACK_WORKER_FINISH_LINGER_MS :
                                          CRACK_WORKER_NEXT_HEADER_MS;
        session->phase = state->finalized ? "fin_linger" :
                         state->offset == state->expected_size ? "fin_wait" : "header";
    }
    if (success) session->reason = "synced";
    ops->terminal(context, success, session->reason);
    return success;
}
