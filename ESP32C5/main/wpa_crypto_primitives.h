#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define JANOS_WPA_EAPOL_MAX 256U

bool janos_wpa_ptk_sha1(const uint8_t pmk[32], const uint8_t aa[6],
                        const uint8_t spa[6], const uint8_t anonce[32],
                        const uint8_t snonce[32], uint8_t ptk[64]);

bool janos_wpa_eapol_mic_v2(const uint8_t kck[16], const uint8_t *eapol,
                            size_t eapol_len, uint8_t mic[16]);

bool janos_wpa_pmkid(const uint8_t pmk[32], const uint8_t aa[6],
                     const uint8_t spa[6], uint8_t pmkid[16]);

void janos_wpa_zeroize(void *buffer, size_t length);
