#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

size_t wps_build_nack(uint8_t *out, size_t cap, uint8_t eap_id,
                      const uint8_t enrollee_nonce[16],
                      const uint8_t registrar_nonce[16], bool wsc2);
bool wps_parse_config_error(const uint8_t *frame, size_t len,
                            uint16_t *config_error);
