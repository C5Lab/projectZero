#ifndef LAB_SECRET_H
#define LAB_SECRET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define LAB_SECRET_TTL_MS 300000u

typedef void (*lab_secret_wipe_fn)(void *memory, size_t length);

typedef enum { LAB_SECRET_EMPTY, LAB_SECRET_AVAILABLE, LAB_SECRET_EXPIRED } lab_secret_state_t;

typedef struct {
    lab_secret_state_t state;
    uint32_t operation_id;
    uint64_t remaining_ms;
} lab_secret_info_t;

typedef struct {
    char pin[9];
    char network_key[65];
    uint32_t operation_id;
    uint64_t created_ms;
    bool available;
    lab_secret_wipe_fn wipe;
} lab_secret_vault_t;

void lab_secret_init(lab_secret_vault_t *vault, lab_secret_wipe_fn wipe);
bool lab_secret_store(lab_secret_vault_t *vault, const char *pin,
                      const char *network_key, uint32_t operation_id,
                      uint64_t now_ms);
lab_secret_info_t lab_secret_status(lab_secret_vault_t *vault, uint64_t now_ms);
bool lab_secret_take(lab_secret_vault_t *vault, uint64_t now_ms,
                     char *pin, size_t pin_capacity,
                     char *network_key, size_t key_capacity,
                     uint32_t *operation_id);
void lab_secret_erase(lab_secret_vault_t *vault);

#endif
