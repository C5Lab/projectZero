/* Host-only contract test:
 * cc -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined \
 *   tests/test_web_protocol.c modules/web/web_protocol.c -o /tmp/c5_web_protocol_test
 * /tmp/c5_web_protocol_test
 */
#include "../modules/web/web_protocol.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    uint8_t received[64];
    C5WebRxTokenKind kinds[16];
    size_t lengths[16];
    size_t received_length;
    size_t token_count;
} RxCapture;

static void capture_token(
    void* context,
    C5WebRxTokenKind kind,
    const uint8_t* bytes,
    size_t length) {
    RxCapture* capture = context;
    assert(bytes);
    assert(length > 0);
    assert(capture->token_count < sizeof(capture->kinds) / sizeof(capture->kinds[0]));
    assert(capture->received_length + length <= sizeof(capture->received));

    capture->kinds[capture->token_count] = kind;
    capture->lengths[capture->token_count++] = length;
    memcpy(capture->received + capture->received_length, bytes, length);
    capture->received_length += length;
}

static void test_rx_keeps_blank_lines_cr_and_split_prompt(void) {
    static const uint8_t chunk1[] = {'r', 'o', 'w', '\r'};
    static const uint8_t chunk2[] = {'\n', '\n'};
    static const uint8_t chunk3[] = {'>'};
    static const uint8_t chunk4[] = {'\r', '\n', 'A', '>'};
    static const uint8_t expected[] = {'r', 'o', 'w', '\r', '\n', '\n', '>', '\r', '\n', 'A', '>'};
    static const C5WebRxTokenKind kinds[] = {
        C5WebRxTokenData,
        C5WebRxTokenCarriageReturn,
        C5WebRxTokenLineFeed,
        C5WebRxTokenLineFeed,
        C5WebRxTokenPrompt,
        C5WebRxTokenCarriageReturn,
        C5WebRxTokenLineFeed,
        C5WebRxTokenData,
        C5WebRxTokenPrompt,
    };
    static const size_t lengths[] = {3, 1, 1, 1, 1, 1, 1, 1, 1};
    RxCapture capture = {0};

    c5_web_rx_feed(chunk1, sizeof(chunk1), capture_token, &capture);
    c5_web_rx_feed(chunk2, sizeof(chunk2), capture_token, &capture);
    c5_web_rx_feed(chunk3, sizeof(chunk3), capture_token, &capture);
    c5_web_rx_feed(chunk4, sizeof(chunk4), capture_token, &capture);

    assert(capture.received_length == sizeof(expected));
    assert(memcmp(capture.received, expected, sizeof(expected)) == 0);
    assert(capture.token_count == sizeof(kinds) / sizeof(kinds[0]));
    assert(memcmp(capture.kinds, kinds, sizeof(kinds)) == 0);
    assert(memcmp(capture.lengths, lengths, sizeof(lengths)) == 0);
}

static void test_rx_zero_length_or_missing_callback_has_no_effect(void) {
    static const uint8_t data[] = {'A', '\n'};
    RxCapture capture = {0};
    c5_web_rx_feed(NULL, 0, capture_token, &capture);
    c5_web_rx_feed(data, 0, capture_token, &capture);
    c5_web_rx_feed(data, sizeof(data), NULL, &capture);
    assert(capture.token_count == 0);
}

static void test_two_commands_form_one_exact_batch(void) {
    static const char first[] = "select_html portal.html";
    static const char second[] = "start_evil_twin";
    static const char expected[] = "select_html portal.html\nstart_evil_twin\n";
    char output[sizeof(expected) + 2] = {0};
    size_t length = 0;

    assert(c5_web_batch_two(
        output,
        sizeof(expected) - 1,
        first,
        sizeof(first) - 1,
        second,
        sizeof(second) - 1,
        &length));
    assert(length == sizeof(expected) - 1);
    assert(memcmp(output, expected, length) == 0);
    assert(output[length] == '\0');
}

static void test_batch_rejects_overflow_and_control_bytes_without_writing(void) {
    char output[8];
    size_t length;
    const char bad_nul[] = {'a', '\0', 'b'};
    memset(output, 0x5a, sizeof(output));

    length = 99;
    assert(!c5_web_batch_two(output, 3, "a", 1, "b", 1, &length));
    assert(length == 0 && output[0] == 0x5a);

    length = 99;
    assert(!c5_web_batch_two(output, sizeof(output), "a\nb", 3, "c", 1, &length));
    assert(length == 0 && output[0] == 0x5a);

    length = 99;
    assert(!c5_web_batch_two(output, sizeof(output), "a", 1, "b\rc", 3, &length));
    assert(length == 0 && output[0] == 0x5a);

    length = 99;
    assert(!c5_web_batch_two(output, sizeof(output), bad_nul, sizeof(bad_nul), "b", 1, &length));
    assert(length == 0 && output[0] == 0x5a);

    length = 99;
    assert(!c5_web_batch_two(output, sizeof(output), "", 0, "b", 1, &length));
    assert(length == 0 && output[0] == 0x5a);
}

int main(void) {
    test_rx_keeps_blank_lines_cr_and_split_prompt();
    test_rx_zero_length_or_missing_callback_has_no_effect();
    test_two_commands_form_one_exact_batch();
    test_batch_rejects_overflow_and_control_bytes_without_writing();
    puts("web protocol host tests: PASS");
    return 0;
}
