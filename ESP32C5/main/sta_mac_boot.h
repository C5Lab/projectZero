#ifndef STA_MAC_BOOT_H
#define STA_MAC_BOOT_H

#include "sta_mac_policy_store.h"

#include <stdbool.h>

typedef enum {
    STA_MAC_BOOT_RECORD_VALID = 0,
    STA_MAC_BOOT_RECORD_MISSING,
    STA_MAC_BOOT_RECORD_INVALID,
    STA_MAC_BOOT_RECORD_READ_ERROR
} sta_mac_boot_record_health_t;

typedef enum {
    STA_MAC_BOOT_OK = 0,
    STA_MAC_BOOT_INVALID_ARGUMENT,
    STA_MAC_BOOT_STORE_ERROR,
    STA_MAC_BOOT_ENTROPY_ERROR
} sta_mac_boot_status_t;

typedef bool (*sta_mac_boot_entropy_fn)(void *context, uint8_t out[STA_MAC_SIZE]);

typedef struct {
    /* The store is copied; its context must remain valid for subsequent saves. */
    sta_mac_policy_store_t store;
    sta_mac_policy_record_t configured_policy;
    sta_mac_policy_record_t boot_policy;
    uint8_t effective_mac[STA_MAC_SIZE];
    sta_mac_boot_record_health_t record_health;
    sta_mac_store_result_t load_result;
    /* False only when boot could not determine the persisted selection. */
    bool configured_known;
    bool ready;
    bool pending_reboot;
} sta_mac_boot_state_t;

/* Initialize once per application boot, after NVS setup and before radio start.
 * A read error leaves a visible factory fallback but ready=false. */
sta_mac_boot_status_t sta_mac_boot_init(sta_mac_boot_state_t *state,
                                        const sta_mac_policy_store_t *store,
                                        const uint8_t factory_mac[STA_MAC_SIZE],
                                        sta_mac_boot_entropy_fn entropy,
                                        void *entropy_context);

/* Persist first; only a successful commit updates configured_policy. The
 * running boot policy and effective MAC never change. */
sta_mac_store_result_t sta_mac_boot_save(sta_mac_boot_state_t *state,
                                         const sta_mac_policy_record_t *record);

typedef struct {
    void *context;
    bool (*set_sta_mac)(void *context, const uint8_t mac[STA_MAC_SIZE]);
    bool (*get_sta_mac)(void *context, uint8_t mac[STA_MAC_SIZE]);
} sta_mac_boot_driver_t;

typedef enum {
    STA_MAC_BOOT_APPLY_OK = 0,
    STA_MAC_BOOT_APPLY_INVALID_ARGUMENT,
    STA_MAC_BOOT_APPLY_NOT_READY,
    STA_MAC_BOOT_APPLY_SET_FAILED,
    STA_MAC_BOOT_APPLY_READ_FAILED,
    STA_MAC_BOOT_APPLY_MISMATCH
} sta_mac_boot_apply_status_t;

/* Call after STA mode selection and before each Wi-Fi start, while stopped. */
sta_mac_boot_apply_status_t sta_mac_boot_apply(const sta_mac_boot_state_t *state,
                                               const sta_mac_boot_driver_t *driver);

#endif
