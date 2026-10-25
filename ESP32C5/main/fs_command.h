#ifndef JANOS_FS_COMMAND_H
#define JANOS_FS_COMMAND_H

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

typedef struct {
    esp_err_t (*mount_sd)(void);
    int (*send_file)(const char *absolute_path);
    void (*transfer_active)(bool active);
    uint32_t (*current_baud)(void);
    void (*sync_sd)(void);
} fs_command_hooks_t;

void fs_command_init(const fs_command_hooks_t *hooks);
int fs_command_handle(int argc, char **argv);

#endif
