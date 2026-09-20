#ifndef CRACK_WORKER_H
#define CRACK_WORKER_H

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

typedef esp_err_t (*crack_worker_ensure_sd_fn)(void);
typedef void (*crack_worker_transfer_active_fn)(bool active);
typedef uint32_t (*crack_worker_current_baud_fn)(void);

void crack_worker_init(crack_worker_ensure_sd_fn ensure_sd,
                       crack_worker_transfer_active_fn transfer_active,
                       crack_worker_current_baud_fn current_baud);
int crack_worker_command(int argc, char **argv);
void crack_worker_cancel_all(void);

#endif
