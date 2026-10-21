#ifndef CRACK_WORKER_CORE_H
#define CRACK_WORKER_CORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CRACK_WORKER_HCCAPX_SIGNATURE 0x58504348U
#define CRACK_WORKER_CORE_OK 0
#define CRACK_WORKER_CORE_ERROR (-1)
#define CRACK_WORKER_ACK32_SIZE 32U

typedef struct {
    uint64_t size;
    uint32_t crc32;
} crack_worker_file_id_t;

typedef struct {
    uint64_t expected_size;
    uint32_t expected_crc32;
    uint64_t offset;
    uint32_t prefix_crc32;
    uint32_t block_size;
} crack_worker_partial_checkpoint_t;

typedef struct __attribute__((packed)) {
    uint32_t signature;
    uint32_t version;
    uint8_t message_pair;
    uint8_t essid_len;
    uint8_t essid[32];
    uint8_t keyver;
    uint8_t keymic[16];
    uint8_t mac_ap[6];
    uint8_t nonce_ap[32];
    uint8_t mac_sta[6];
    uint8_t nonce_sta[32];
    uint16_t eapol_len;
    uint8_t eapol[256];
} crack_worker_hccapx_t;

typedef enum {
    CRACK_WORKER_LINE_CANDIDATE = 0,
    CRACK_WORKER_LINE_SKIPPED,
    CRACK_WORKER_LINE_END,
    CRACK_WORKER_LINE_IO_ERROR,
} crack_worker_line_result_t;

typedef struct {
    uint64_t safe_offset;
    uint64_t checked;
} crack_worker_progress_t;

typedef struct {
    const char *id;
    const char *capture_path;
    const char *wordlist_path;
    uint64_t range_start;
    uint64_t range_end;
} crack_worker_assignment_t;

typedef enum {
    CRACK_WORKER_START_NEW = 0,
    CRACK_WORKER_START_REPLAY,
    CRACK_WORKER_START_JOB_CONFLICT,
    CRACK_WORKER_START_BUSY,
} crack_worker_start_action_t;

bool crack_worker_job_id_valid(const char *job_id);
bool crack_worker_wordlist_name_allowed(const char *name);
bool crack_worker_hex_encode(const uint8_t *input, size_t input_len,
                             char *output, size_t output_size);
uint32_t crack_worker_crc32_update(uint32_t crc, const void *data, size_t size);
bool crack_worker_ack32_build(uint8_t frame[CRACK_WORKER_ACK32_SIZE],
                              uint32_t block_index, uint8_t status,
                              uint64_t committed_offset);
bool crack_worker_reply_mode_parse(int argc, const char *token,
                                   size_t *ack_size);
const char *crack_worker_capabilities(void);
bool crack_worker_ready_format(char *output, size_t capacity, const char *kind,
    uint64_t size, uint32_t crc, uint64_t offset, uint32_t prefix_crc,
    uint32_t block_size, uint32_t rx_ms, bool ack32, uint32_t prepare_ms);
bool crack_worker_prepare_resume(FILE **file, const char *part_path,
    const char *meta_path, uint64_t *offset, uint32_t *running_crc,
    uint64_t *checkpoint_offset, uint32_t *prepare_ms);
int crack_worker_file_id(const char *path, crack_worker_file_id_t *id);
bool crack_worker_file_id_equal(const crack_worker_file_id_t *a,
                                const crack_worker_file_id_t *b);
int crack_worker_verified_marker_write(const char *path, uint64_t size,
                                       uint32_t crc32, int64_t mtime);
bool crack_worker_verified_marker_matches(const char *path, uint64_t size,
                                          uint32_t crc32, int64_t mtime);
bool crack_worker_verified_file_matches(const char *file_path,
                                        const char *marker_path,
                                        uint64_t size, uint32_t crc32);
int crack_worker_partial_checkpoint_write(
    const char *path, const crack_worker_partial_checkpoint_t *checkpoint);
bool crack_worker_partial_checkpoint_read(
    const char *path, uint64_t expected_size, uint32_t expected_crc32,
    uint64_t actual_part_size, crack_worker_partial_checkpoint_t *checkpoint);
bool crack_worker_resume_prefix_allowed(uint64_t partial_size);
int crack_worker_seek_range_start(FILE *file, uint64_t requested,
                                  uint64_t *aligned);
crack_worker_line_result_t crack_worker_read_word(FILE *file, uint64_t end_offset,
                                                  char word[64],
                                                  uint64_t *line_start,
                                                  uint64_t *next_offset);
bool crack_worker_hccapx_valid(const crack_worker_hccapx_t *record);
void crack_worker_progress_begin(crack_worker_progress_t *progress,
                                 uint64_t aligned_offset);
void crack_worker_progress_commit(crack_worker_progress_t *progress,
                                  uint64_t next_offset,
                                  bool candidate_checked);
crack_worker_start_action_t crack_worker_start_classify(
    bool slot_occupied, bool running,
    const crack_worker_assignment_t *existing,
    const crack_worker_assignment_t *requested);

#ifdef __cplusplus
}
#endif

#endif
