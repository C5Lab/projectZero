#ifndef ARTIFACT_INVENTORY_CORE_H
#define ARTIFACT_INVENTORY_CORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define AI_ID_MAX 32U
#define AI_NAME_MAX 255U
#define AI_PATH_MAX 512U
#define AI_LINE_MAX 1024U
#define AI_PAGE_MAX 32U
#define AI_ENTRIES_MAX 256U
#define AI_SCAN_MAX 4096U
#define AI_INSPECT_MAX UINT64_C(16777216)
#define AI_TIMEOUT_MS UINT64_C(30000)

typedef enum { AI_CAPABILITIES, AI_LIST, AI_INSPECT, AI_CANCEL } ai_operation_t;
typedef enum { AI_HANDSHAKES, AI_PCAPS } ai_scope_t;
typedef struct {
    ai_operation_t operation;
    char id[AI_ID_MAX + 1];
    ai_scope_t scope;
    uint32_t cursor, limit, snapshot, entry;
} ai_request_t;

typedef struct {
    uint64_t size, mtime, ctime, device, inode;
    uint32_t mtime_ns, ctime_ns;
} ai_metadata_t;

typedef struct {
    char name[AI_NAME_MAX + 1];
    ai_metadata_t metadata;
    /* Volatile inspection cache, never shared with transfer .verified files. */
    uint32_t cache_tag, crc32, cache_check;
    uint8_t validation, reason;
} ai_entry_t;

typedef struct {
    char root[AI_PATH_MAX - AI_NAME_MAX - 16];
    uint32_t snapshot, count;
    ai_scope_t scope;
    bool limited;
    ai_entry_t entries[AI_ENTRIES_MAX];
} ai_inventory_t;

typedef struct {
    void (*emit)(void *user, const char *line);
    bool (*cancelled)(void *user);
    uint64_t (*now_ms)(void *user);
    void (*yield)(void *user);
    void (*finishing)(void *user);
    void *user;
} ai_hooks_t;

/* root is trusted application configuration, never a CLI argument.
 * Caller serializes ai_run; cancellation is polled only through hooks. */
bool ai_inventory_init(ai_inventory_t *inventory, const char *root);
bool ai_parse_command(int argc, const char *const *argv, ai_request_t *request);
bool ai_run(ai_inventory_t *inventory, const ai_request_t *request, const ai_hooks_t *hooks);

#endif
