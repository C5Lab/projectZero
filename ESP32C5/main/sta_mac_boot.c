#include "sta_mac_boot.h"

#include <string.h>

static sta_mac_policy_record_t factory_policy(void)
{
    sta_mac_policy_record_t policy = {STA_MAC_POLICY_VERSION, STA_MAC_MODE_FACTORY, {0}};
    return policy;
}

static bool same_policy(const sta_mac_policy_record_t *a, const sta_mac_policy_record_t *b)
{
    if (a->version != b->version || a->mode != b->mode) return false;
    return a->mode != STA_MAC_MODE_FIXED || memcmp(a->mac, b->mac, STA_MAC_SIZE) == 0;
}

sta_mac_boot_status_t sta_mac_boot_init(sta_mac_boot_state_t *state,
                                        const sta_mac_policy_store_t *store,
                                        const uint8_t factory_mac[STA_MAC_SIZE],
                                        sta_mac_boot_entropy_fn entropy,
                                        void *entropy_context)
{
    if (!state || !store || !factory_mac) return STA_MAC_BOOT_INVALID_ARGUMENT;

    memset(state, 0, sizeof(*state));
    state->store = *store;
    state->configured_policy = factory_policy();
    state->boot_policy = state->configured_policy;
    memcpy(state->effective_mac, factory_mac, STA_MAC_SIZE);

    sta_mac_policy_record_t loaded;
    state->load_result = sta_mac_policy_load(&state->store, &loaded);
    switch (state->load_result.status) {
    case STA_MAC_STORE_OK:
        state->record_health = STA_MAC_BOOT_RECORD_VALID;
        state->configured_policy = loaded;
        state->boot_policy = loaded;
        break;
    case STA_MAC_STORE_MISSING_NAMESPACE:
    case STA_MAC_STORE_MISSING_KEY:
        state->record_health = STA_MAC_BOOT_RECORD_MISSING;
        break;
    case STA_MAC_STORE_INVALID_RECORD:
        state->record_health = STA_MAC_BOOT_RECORD_INVALID;
        break;
    default:
        state->record_health = STA_MAC_BOOT_RECORD_READ_ERROR;
        return STA_MAC_BOOT_STORE_ERROR;
    }
    state->configured_known = state->load_result.status != STA_MAC_STORE_INVALID_RECORD;

    switch (state->boot_policy.mode) {
    case STA_MAC_MODE_FACTORY:
        break;
    case STA_MAC_MODE_FIXED:
        memcpy(state->effective_mac, state->boot_policy.mac, STA_MAC_SIZE);
        break;
    case STA_MAC_MODE_RANDOM_PER_BOOT: {
        uint8_t bytes[STA_MAC_SIZE];
        if (!entropy || !entropy(entropy_context, bytes) ||
            sta_mac_random_from_entropy(bytes, sizeof(bytes), state->effective_mac) != STA_MAC_POLICY_OK)
            return STA_MAC_BOOT_ENTROPY_ERROR;
        break;
    }
    default:
        return STA_MAC_BOOT_STORE_ERROR;
    }

    state->ready = true;
    return STA_MAC_BOOT_OK;
}

sta_mac_store_result_t sta_mac_boot_save(sta_mac_boot_state_t *state,
                                         const sta_mac_policy_record_t *record)
{
    if (!state || !record)
        return (sta_mac_store_result_t){STA_MAC_STORE_INVALID_ARGUMENT, STA_MAC_POLICY_OK};

    sta_mac_policy_record_t normalized = *record;
    if (normalized.mode != STA_MAC_MODE_FIXED)
        memset(normalized.mac, 0, STA_MAC_SIZE);
    sta_mac_store_result_t result = sta_mac_policy_save(&state->store, &normalized);
    if (result.status == STA_MAC_STORE_OK) {
        state->configured_policy = normalized;
        state->configured_known = true;
        state->pending_reboot = !same_policy(&state->configured_policy, &state->boot_policy);
    }
    return result;
}

sta_mac_boot_apply_status_t sta_mac_boot_apply(const sta_mac_boot_state_t *state,
                                               const sta_mac_boot_driver_t *driver)
{
    if (!state || !driver || !driver->set_sta_mac || !driver->get_sta_mac)
        return STA_MAC_BOOT_APPLY_INVALID_ARGUMENT;
    if (!state->ready) return STA_MAC_BOOT_APPLY_NOT_READY;
    if (!driver->set_sta_mac(driver->context, state->effective_mac))
        return STA_MAC_BOOT_APPLY_SET_FAILED;
    uint8_t actual[STA_MAC_SIZE];
    if (!driver->get_sta_mac(driver->context, actual))
        return STA_MAC_BOOT_APPLY_READ_FAILED;
    return memcmp(actual, state->effective_mac, STA_MAC_SIZE) == 0 ?
        STA_MAC_BOOT_APPLY_OK : STA_MAC_BOOT_APPLY_MISMATCH;
}
