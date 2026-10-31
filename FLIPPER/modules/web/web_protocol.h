#ifndef LAB_C5_WEB_PROTOCOL_H
#define LAB_C5_WEB_PROTOCOL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Tokens point into the input chunk and are valid only during the callback.
 * Every byte is emitted exactly once, in order. CR, LF and '>' are separate
 * one-byte tokens; consecutive LF tokens retain blank lines. Data tokens may
 * be split at arbitrary UART chunk boundaries. No line buffer is allocated.
 */
typedef enum {
    C5WebRxTokenData,
    C5WebRxTokenCarriageReturn,
    C5WebRxTokenLineFeed,
    C5WebRxTokenPrompt,
} C5WebRxTokenKind;

typedef void (*C5WebRxTokenCallback)(
    void* context,
    C5WebRxTokenKind kind,
    const uint8_t* bytes,
    size_t length);

void c5_web_rx_feed(
    const uint8_t* bytes,
    size_t length,
    C5WebRxTokenCallback callback,
    void* context);

/* Writes exactly first + LF + second + LF; no terminator is appended.
 * capacity is the maximum number of wire bytes, e.g. C5_MODULE_RAW_TX_MAX.
 * Both commands must be nonempty and contain no NUL, CR or LF. On failure,
 * output is unchanged and *out_length is zero. Input must not overlap output.
 */
bool c5_web_batch_two(
    char* output,
    size_t capacity,
    const char* first,
    size_t first_length,
    const char* second,
    size_t second_length,
    size_t* out_length);

#endif
