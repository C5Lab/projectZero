#ifndef CRACK_WORKER_TRANSFER_H
#define CRACK_WORKER_TRANSFER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CRACK_TRANSFER_EXPECTED_DATA,
    CRACK_TRANSFER_DUPLICATE_DATA,
    CRACK_TRANSFER_FIN,
    CRACK_TRANSFER_DUPLICATE_FIN,
    CRACK_TRANSFER_CANCEL,
    CRACK_TRANSFER_INVALID,
} crack_worker_transfer_action_t;

typedef struct {
    uint64_t expected_size;
    uint64_t offset;
    uint64_t last_committed_offset;
    uint32_t expected_index;
    uint32_t block_size;
    uint32_t last_index;
    uint32_t last_length;
    uint32_t last_crc32;
    bool ack32;
    bool have_last;
    bool finalized;
} crack_worker_transfer_state_t;

crack_worker_transfer_action_t crack_worker_transfer_classify(
    const crack_worker_transfer_state_t *state,
    const uint8_t header[16]);
void crack_worker_transfer_commit_data(crack_worker_transfer_state_t *state,
                                       uint32_t index, uint32_t length,
                                       uint32_t payload_crc32);
bool crack_worker_transfer_finalize(crack_worker_transfer_state_t *state);
crack_worker_transfer_action_t crack_worker_transfer_cancel(
    crack_worker_transfer_state_t *state);
uint32_t crack_worker_prepare_ms(uint64_t resume_offset,
                                 bool *resume_allowed);
uint32_t crack_worker_first_byte_timeout(bool first_byte_pending,
                                         uint32_t prepare_ms,
                                         uint32_t rx_ms);

#define CRACK_WORKER_ACK_WAIT_MS 2000U
#define CRACK_WORKER_NEXT_HEADER_MS 7000U
#define CRACK_WORKER_FINISH_LINGER_MS 7000U

/* Storage callbacks are ordered write -> running CRC -> checkpoint -> commit
 * -> progress. checkpoint retains the caller's existing durability policy. */
typedef struct {
    int (*read)(void *, void *, size_t, uint32_t, size_t *);
    bool (*write)(void *, const uint8_t *, uint32_t);
    void (*crc)(void *, const uint8_t *, uint32_t);
    bool (*checkpoint)(void *, uint64_t);
    void (*progress)(void *, uint64_t, uint32_t);
    bool (*finalize)(void *);
    bool (*reply)(void *, const uint8_t[32]);
    void (*terminal)(void *, bool, const char *);
} crack_worker_transfer_ops_t;

typedef enum {
    CRACK_TRANSFER_APPLIED,
    CRACK_TRANSFER_RETRY,
    CRACK_TRANSFER_FAILED,
} crack_worker_transfer_result_t;

typedef struct {
    uint32_t prepare_ms;
    uint32_t rx_ms;
    const char *phase;
    const char *reason;
    size_t header_got, payload_got, payload_expected;
    unsigned duplicates;
} crack_worker_transfer_session_t;

crack_worker_transfer_result_t crack_worker_transfer_apply(
    crack_worker_transfer_state_t *state, crack_worker_transfer_action_t action,
    const uint8_t header[16], const uint8_t *payload,
    const crack_worker_transfer_ops_t *ops, void *context, const char **reason);
/* Caller reserves payload before emitting READY and retains ownership on every
 * exit. The receiver never allocates/frees it; capacity must cover block_size. */
bool crack_worker_transfer_receive(crack_worker_transfer_state_t *state,
    crack_worker_transfer_session_t *session,
    uint8_t *payload, size_t payload_capacity,
    const crack_worker_transfer_ops_t *ops, void *context);

#ifdef __cplusplus
}
#endif

#endif
