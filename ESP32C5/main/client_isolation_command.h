#ifndef CLIENT_ISOLATION_COMMAND_H
#define CLIENT_ISOLATION_COMMAND_H

#include "client_isolation_runtime.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CLIENT_ISOLATION_LINE_MAX 512U

typedef struct {
    bool connected;
    uint8_t bssid[6];
    uint32_t local_ipv4;
    uint32_t netmask;
    uint32_t gateway_ipv4;
    uint32_t interface_id;
} client_isolation_sta_snapshot_t;

typedef bool (*client_isolation_snapshot_fn)(
    void *context, client_isolation_sta_snapshot_t *snapshot);
typedef client_isolation_conclusion_t (*client_isolation_run_fn)(
    void *context, const client_isolation_config_t *config,
    client_isolation_result_t *result);
typedef bool (*client_isolation_write_fn)(
    void *context, const char *line, size_t length);
typedef void (*client_isolation_history_free_fn)(void *context);

typedef struct {
    client_isolation_snapshot_fn snapshot;
    client_isolation_run_fn run;
    client_isolation_write_fn write;
    client_isolation_history_free_fn history_free;
    void *context;
} client_isolation_hooks_t;

void client_isolation_command_init(const client_isolation_hooks_t *hooks);
int client_isolation_command(int argc, char **argv);
bool client_isolation_busy(void);
void client_isolation_scrub_cli_token(char *argument);

#ifdef __cplusplus
}
#endif

#endif
