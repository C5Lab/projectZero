#include "web_protocol.h"

#include <string.h>

void c5_web_rx_feed(
    const uint8_t* bytes,
    size_t length,
    C5WebRxTokenCallback callback,
    void* context) {
    if(!bytes || !callback || length == 0) return;

    size_t start = 0;
    for(size_t i = 0; i < length; ++i) {
        C5WebRxTokenKind kind;
        if(bytes[i] == '\r') {
            kind = C5WebRxTokenCarriageReturn;
        } else if(bytes[i] == '\n') {
            kind = C5WebRxTokenLineFeed;
        } else if(bytes[i] == '>') {
            kind = C5WebRxTokenPrompt;
        } else {
            continue;
        }

        if(i > start) callback(context, C5WebRxTokenData, bytes + start, i - start);
        callback(context, kind, bytes + i, 1);
        start = i + 1;
    }

    if(start < length) callback(context, C5WebRxTokenData, bytes + start, length - start);
}

static bool c5_web_command_is_valid(const char* command, size_t length) {
    for(size_t i = 0; i < length; ++i) {
        if(command[i] == '\0' || command[i] == '\r' || command[i] == '\n') return false;
    }
    return true;
}

bool c5_web_batch_two(
    char* output,
    size_t capacity,
    const char* first,
    size_t first_length,
    const char* second,
    size_t second_length,
    size_t* out_length) {
    if(out_length) *out_length = 0;
    if(!output || !first || !second || !out_length || !first_length || !second_length ||
       capacity < 4 || first_length > capacity - 2 ||
       second_length > capacity - first_length - 2 ||
       !c5_web_command_is_valid(first, first_length) ||
       !c5_web_command_is_valid(second, second_length)) {
        return false;
    }

    memcpy(output, first, first_length);
    output[first_length] = '\n';
    memcpy(output + first_length + 1, second, second_length);
    output[first_length + 1 + second_length] = '\n';
    *out_length = first_length + second_length + 2;
    return true;
}
