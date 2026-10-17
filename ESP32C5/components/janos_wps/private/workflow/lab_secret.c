#include "lab_secret.h"

#include <string.h>

static void fallback_wipe(void *memory, size_t length)
{
    volatile unsigned char *p = memory;
    while (length--) *p++ = 0;
}

void lab_secret_init(lab_secret_vault_t *vault, lab_secret_wipe_fn wipe)
{
    if (!vault) return;
    fallback_wipe(vault, sizeof(*vault));
    vault->wipe = wipe ? wipe : fallback_wipe;
}

void lab_secret_erase(lab_secret_vault_t *vault)
{
    if (!vault) return;
    lab_secret_wipe_fn wipe = vault->wipe ? vault->wipe : fallback_wipe;
    wipe(vault, sizeof(*vault));
    vault->wipe = wipe;
}

bool lab_secret_store(lab_secret_vault_t *vault, const char *pin,
                      const char *network_key, uint32_t operation_id,
                      uint64_t now_ms)
{
    if (!vault || !pin || !network_key || strlen(pin) != 8 ||
        strlen(network_key) >= sizeof(vault->network_key)) return false;
    lab_secret_wipe_fn wipe = vault->wipe ? vault->wipe : fallback_wipe;
    lab_secret_erase(vault);
    vault->wipe = wipe;
    memcpy(vault->pin, pin, 9);
    memcpy(vault->network_key, network_key, strlen(network_key) + 1u);
    vault->operation_id = operation_id;
    vault->created_ms = now_ms;
    vault->available = true;
    return true;
}

lab_secret_info_t lab_secret_status(lab_secret_vault_t *vault, uint64_t now_ms)
{
    lab_secret_info_t info = {LAB_SECRET_EMPTY, 0, 0};
    if (!vault || !vault->available) return info;
    uint64_t age = now_ms >= vault->created_ms ? now_ms - vault->created_ms : UINT64_MAX;
    if (age >= LAB_SECRET_TTL_MS) {
        lab_secret_erase(vault);
        info.state = LAB_SECRET_EXPIRED;
        return info;
    }
    info.state = LAB_SECRET_AVAILABLE;
    info.operation_id = vault->operation_id;
    info.remaining_ms = LAB_SECRET_TTL_MS - age;
    return info;
}

bool lab_secret_take(lab_secret_vault_t *vault, uint64_t now_ms,
                     char *pin, size_t pin_capacity,
                     char *network_key, size_t key_capacity,
                     uint32_t *operation_id)
{
    lab_secret_info_t info = lab_secret_status(vault, now_ms);
    if (info.state != LAB_SECRET_AVAILABLE || !pin || pin_capacity < 9 ||
        !network_key || key_capacity <= strlen(vault->network_key) || !operation_id)
        return false;
    memcpy(pin, vault->pin, 9);
    memcpy(network_key, vault->network_key, strlen(vault->network_key) + 1u);
    *operation_id = vault->operation_id;
    lab_secret_erase(vault);
    return true;
}
