#ifndef CRACK_WORKER_SW_SHA1_H
#define CRACK_WORKER_SW_SHA1_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
typedef bool (*crack_worker_sw_checkpoint_fn)(void *context);
int crack_worker_sw_derive_pmk(const char *password, const uint8_t *ssid,
                               size_t ssid_length, uint8_t pmk[32],
                               crack_worker_sw_checkpoint_fn checkpoint,
                               void *checkpoint_context);
int crack_worker_sw_hmac_sha1(const uint8_t *key, size_t key_length,
                              const uint8_t *data, size_t data_length,
                              uint8_t output[20]);
#endif
