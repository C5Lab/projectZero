#ifndef STA_MAC_POLICY_NVS_H
#define STA_MAC_POLICY_NVS_H

#include "sta_mac_policy_store.h"

/* Production NVS implementation of the portable STA MAC policy store. */
const sta_mac_policy_store_t *sta_mac_policy_nvs_store(void);

#endif
