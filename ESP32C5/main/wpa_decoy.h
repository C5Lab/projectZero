#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define WPA_DECOY_FRAME_MAX 256U

typedef struct {
    uint8_t bssid[6];
    uint8_t sta[6];
    uint8_t pmk[32];
    uint8_t anonce[32];
    uint8_t snonce[32];
    uint64_t replay_counter;
} wpa_decoy_material_t;

typedef struct {
    uint8_t m1[WPA_DECOY_FRAME_MAX];
    size_t m1_len;
    uint8_t m2[WPA_DECOY_FRAME_MAX];
    size_t m2_len;
} wpa_decoy_pair_t;

bool wpa_decoy_build_pair(const wpa_decoy_material_t *material,
                          wpa_decoy_pair_t *out);

bool wpa_decoy_build_pmkid_m1(const wpa_decoy_material_t *material,
                              uint8_t out[WPA_DECOY_FRAME_MAX],
                              size_t *out_len);
