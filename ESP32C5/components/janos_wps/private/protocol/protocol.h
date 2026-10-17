#pragma once
#include <stddef.h>
#include <stdint.h>
enum probe_message { PROBE_INVALID, PROBE_OTHER, PROBE_IDENTITY, PROBE_M1, PROBE_FRAGMENT, PROBE_FAILURE };
enum probe_message probe_parse(const uint8_t *data, size_t length, uint8_t *id);
size_t probe_identity(uint8_t id, uint8_t *out, size_t capacity);
