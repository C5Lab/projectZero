#ifndef WIFI_SHIELD_JOURNAL_STORE_H
#define WIFI_SHIELD_JOURNAL_STORE_H

#include "wifi_shield_journal.h"

#define WIFI_SHIELD_JOURNAL_CHECKPOINT_RECORDS 32U

/* All hooks run synchronously in the owning writer context. open_exclusive
 * MUST create a new file without truncating an existing path (O_EXCL semantics).
 * rename_no_replace MUST fail if the destination exists. No removal hook exists.
 * close consumes the handle on both success and failure, like fclose; it is
 * never retried. write returns actual bytes accepted, in the range [0,length].
 * mkdir creates the directory tree or succeeds if it already exists. */
typedef struct {
    void *context;
    bool (*mount)(void *context);
    bool (*mkdir)(void *context, const char *path);
    void *(*open_exclusive)(void *context, const char *path);
    size_t (*write)(void *context, void *handle, const char *line, size_t length);
    bool (*flush)(void *context, void *handle);
    bool (*fsync_file)(void *context, void *handle);
    bool (*close)(void *context, void *handle);
    bool (*sync_sd)(void *context);
    bool (*rename_no_replace)(void *context, const char *from, const char *to);
    /* Optional V2 sidecar hooks. They are never used for evidence JSONL.
     * open_replace truncates only the disposable latest-pointer temporary;
     * rename_replace replaces only /sdcard/lab/shield/00-LATEST.txt. */
    void *(*open_replace)(void *context, const char *path);
    bool (*rename_replace)(void *context, const char *from, const char *to);
} wifi_shield_journal_store_hooks_t;

/* Fixed caller-owned state. Zero-initialize once per accepted session, only
 * after the previous writer has finished. No shared/global state or allocation.
 * The owner serializes every API call, including snapshot/notice acknowledgement.
 * The owner may clear status.degraded_notice_pending after successful delivery;
 * later errors in this session never re-arm it. Other fields are core-owned. */
typedef struct {
    wifi_shield_journal_store_hooks_t hooks;
    wifi_shield_journal_status_t status;
    char final_path[WIFI_SHIELD_JOURNAL_PATH_MAX];
    void *handle;
    uint64_t quota_bytes;
    uint32_t records_since_checkpoint;
    bool attempted, finished, start_written, terminal_written;
} wifi_shield_journal_store_t;

/* One mount/open attempt per zero-initialized state; a repeated start is a no-op
 * returning false. IDs and quota must be nonzero and every hook is required.
 * Status path is the generated intended .part path even if opening fails. */
bool wifi_shield_journal_store_start(wifi_shield_journal_store_t *store,
    const wifi_shield_journal_store_hooks_t *hooks, uint32_t boot_id,
    uint32_t session_id, uint64_t quota_bytes);

/* Input must be successful Task 4 encoder output and matching record type; it
 * is consumed immediately, never retained or parsed as arbitrary JSON. length
 * excludes NUL and includes LF. Requires start first, at most one terminal last.
 * A short write counts actual bytes but not a complete record. Exact quota fits;
 * a record exceeding the remaining quota is dropped whole, never partly written.
 * Every campaign transition, provisional uncertainty record, and each bounded
 * batch of WIFI_SHIELD_JOURNAL_CHECKPOINT_RECORDS records is flushed, file-
 * synced and SD-synced. Any first write/input/checkpoint error stops admission
 * until the next accepted session. */
bool wifi_shield_journal_store_append(wifi_shield_journal_store_t *store,
    wifi_shield_journal_type_t type, const char *line, size_t length);

/* Idempotent best-effort cleanup, even after quota/write failure. Clean rename
 * requires a stored start and terminal plus every durability step succeeding:
 * flush -> file sync -> close -> SD sync -> no-replace rename -> final SD sync.
 * Nonclean/missing-terminal sessions retain .part as INCOMPLETE. Existing error
 * and quota states survive cleanup. A failed final SD sync leaves the actual
 * .jsonl path visible with DEGRADED, never claims FINALIZED, never rolls back. */
void wifi_shield_journal_store_finish(wifi_shield_journal_store_t *store, bool clean);

wifi_shield_journal_status_t wifi_shield_journal_store_status(
    const wifi_shield_journal_store_t *store);

#endif
