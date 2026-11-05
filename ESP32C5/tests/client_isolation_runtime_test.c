#include "client_isolation_runtime.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#define TEST_LOCAL_IP UINT32_C(0xC000020A)
#define TEST_PEER_IP UINT32_C(0xC0000214)
#define TEST_OTHER_IP UINT32_C(0xC0000263)
#define TEST_PORT 48731U
#define MAX_EVENTS 400U

typedef enum {
    EVENT_TIMEOUT = 0,
    EVENT_VALID,
    EVENT_BAD_TAG,
    EVENT_WRONG_SOURCE,
    EVENT_WRONG_PORT,
    EVENT_WRONG_SEQUENCE,
    EVENT_WRONG_RUN,
    EVENT_WRONG_NONCE,
    EVENT_PRIOR_REPLY,
    EVENT_RECEIVE_ERROR,
} event_kind_t;

typedef struct {
    event_kind_t kind;
    uint32_t advance_ms;
} fake_event_t;

typedef struct {
    uint64_t now_ms;
    bool clock_backwards;
    bool open_ok;
    bool bind_ok;
    bool close_ok;
    int fail_send_call;
    int fail_random_call;
    int cancel_at_check;
    uint32_t send_advance_ms;
    uint32_t open_advance_ms;
    bool repeat_nonce;
    bool fill_unrelated_forever;
    fake_event_t events[MAX_EVENTS];
    size_t event_count;
    size_t event_index;
    unsigned open_calls;
    unsigned bind_calls;
    unsigned send_calls;
    unsigned receive_calls;
    unsigned close_calls;
    unsigned cancel_checks;
    unsigned random_calls;
    unsigned telemetry_invalid;
    unsigned telemetry_unrelated;
    uint32_t sent_ip;
    uint16_t sent_port;
    uint32_t max_timeout_ms;
    uint64_t requested_timeout_total_ms;
    bool nonce_reused;
    uint8_t previous_nonce[JISO_NONCE_BYTES];
    bool have_previous_nonce;
    jiso_message_t last_challenge;
    jiso_message_t prior_challenge;
    bool have_prior;
    uint8_t token[JISO_TOKEN_BYTES];
    jiso_crypto_t crypto;
} fake_t;

static void fake_reset(fake_t *fake)
{
    memset(fake, 0, sizeof(*fake));
    fake->open_ok = true;
    fake->bind_ok = true;
    fake->close_ok = true;
    fake->fail_send_call = -1;
    fake->fail_random_call = -1;
    fake->cancel_at_check = -1;
    for (size_t index = 0U; index < JISO_TOKEN_BYTES; ++index) {
        fake->token[index] = (uint8_t)(index + 1U);
    }
}

static bool fake_hmac(void *context,
                      const uint8_t token[JISO_TOKEN_BYTES],
                      const uint8_t *data,
                      size_t length,
                      uint8_t digest[JISO_SHA256_BYTES])
{
    (void)context;
    if (token == NULL || data == NULL || digest == NULL) return false;
    for (size_t index = 0U; index < JISO_SHA256_BYTES; ++index) {
        uint8_t value = token[index % JISO_TOKEN_BYTES] ^ (uint8_t)(index * 17U);
        for (size_t offset = index; offset < length; offset += JISO_SHA256_BYTES) {
            value = (uint8_t)((value << 1U) | (value >> 7U));
            value ^= data[offset];
        }
        digest[index] = value;
    }
    return true;
}

static bool fake_socket_open(void *context, int *socket_handle)
{
    fake_t *fake = context;
    ++fake->open_calls;
    fake->now_ms += fake->open_advance_ms;
    if (!fake->open_ok) return false;
    *socket_handle = 7;
    return true;
}

static bool fake_socket_bind(void *context, int socket_handle, uint32_t local_ipv4)
{
    fake_t *fake = context;
    ++fake->bind_calls;
    return fake->bind_ok && socket_handle == 7 && local_ipv4 == TEST_LOCAL_IP;
}

static bool fake_random(void *context, uint8_t *bytes, size_t length)
{
    fake_t *fake = context;
    ++fake->random_calls;
    if ((int)fake->random_calls == fake->fail_random_call) return false;
    if (bytes == NULL || (length != 8U && length != JISO_NONCE_BYTES)) return false;
    unsigned generation = fake->repeat_nonce && length == JISO_NONCE_BYTES &&
                          fake->random_calls >= 3U ? 2U : fake->random_calls;
    for (size_t index = 0U; index < length; ++index) {
        bytes[index] = (uint8_t)(generation * 31U + index + 1U);
    }
    return true;
}

static bool fake_send(void *context,
                      int socket_handle,
                      uint32_t peer_ipv4,
                      uint16_t peer_port,
                      const uint8_t *packet,
                      size_t length)
{
    fake_t *fake = context;
    ++fake->send_calls;
    fake->now_ms += fake->send_advance_ms;
    fake->sent_ip = peer_ipv4;
    fake->sent_port = peer_port;
    if (socket_handle != 7 || length != JISO_PACKET_BYTES ||
        (int)fake->send_calls == fake->fail_send_call) return false;
    jiso_message_t decoded = {0};
    if (!jiso_decode(packet, length, fake->token, &fake->crypto, &decoded)) return false;
    if (fake->have_previous_nonce &&
        memcmp(fake->previous_nonce, decoded.nonce, JISO_NONCE_BYTES) == 0) {
        fake->nonce_reused = true;
    }
    memcpy(fake->previous_nonce, decoded.nonce, JISO_NONCE_BYTES);
    fake->have_previous_nonce = true;
    if (fake->send_calls > 1U) {
        fake->prior_challenge = fake->last_challenge;
        fake->have_prior = true;
    }
    fake->last_challenge = decoded;
    return peer_ipv4 == TEST_PEER_IP && peer_port == TEST_PORT;
}

static client_isolation_receive_t fake_receive(
    void *context,
    int socket_handle,
    uint32_t timeout_ms,
    uint8_t *packet,
    size_t capacity,
    size_t *length,
    uint32_t *source_ipv4,
    uint16_t *source_port)
{
    fake_t *fake = context;
    ++fake->receive_calls;
    assert(socket_handle == 7);
    assert(timeout_ms > 0U && timeout_ms <= CLIENT_ISOLATION_PROBE_TIMEOUT_MS);
    fake->requested_timeout_total_ms += timeout_ms;
    if (timeout_ms > fake->max_timeout_ms) fake->max_timeout_ms = timeout_ms;

    fake_event_t event = {EVENT_TIMEOUT, timeout_ms};
    if (fake->event_index < fake->event_count) {
        event = fake->events[fake->event_index++];
    } else if (fake->fill_unrelated_forever) {
        event.kind = EVENT_WRONG_SOURCE;
        event.advance_ms = 0U;
    }
    if (fake->clock_backwards) {
        fake->now_ms = fake->now_ms == 0U ? UINT64_MAX : fake->now_ms - 1U;
        fake->clock_backwards = false;
    } else {
        fake->now_ms += event.advance_ms;
    }
    if (event.kind == EVENT_TIMEOUT) return CLIENT_ISOLATION_RECEIVE_TIMEOUT;
    if (event.kind == EVENT_RECEIVE_ERROR) return CLIENT_ISOLATION_RECEIVE_ERROR;

    assert(packet != NULL && capacity >= JISO_PACKET_BYTES && length != NULL);
    jiso_message_t reply = event.kind == EVENT_PRIOR_REPLY && fake->have_prior ?
                           fake->prior_challenge : fake->last_challenge;
    reply.type = JISO_REPLY;
    if (event.kind == EVENT_WRONG_SEQUENCE) ++reply.sequence;
    if (event.kind == EVENT_WRONG_RUN) ++reply.run_id;
    if (event.kind == EVENT_WRONG_NONCE) reply.nonce[0] ^= 0x5AU;
    assert(jiso_encode(packet, &reply, fake->token, &fake->crypto));
    if (event.kind == EVENT_BAD_TAG) packet[JISO_PACKET_BYTES - 1U] ^= 0x80U;
    *length = JISO_PACKET_BYTES;
    *source_ipv4 = event.kind == EVENT_WRONG_SOURCE ? TEST_OTHER_IP : TEST_PEER_IP;
    *source_port = event.kind == EVENT_WRONG_PORT ? (uint16_t)(TEST_PORT + 1U) :
                                                   TEST_PORT;
    return CLIENT_ISOLATION_RECEIVE_DATAGRAM;
}

static bool fake_close(void *context, int socket_handle)
{
    fake_t *fake = context;
    ++fake->close_calls;
    return fake->close_ok && socket_handle == 7;
}

static uint64_t fake_monotonic_ms(void *context)
{
    return ((fake_t *)context)->now_ms;
}

static bool fake_cancelled(void *context)
{
    fake_t *fake = context;
    ++fake->cancel_checks;
    return fake->cancel_at_check > 0 &&
           (int)fake->cancel_checks >= fake->cancel_at_check;
}

static void fake_telemetry(void *context,
                           client_isolation_telemetry_t event,
                           uint32_t sequence)
{
    fake_t *fake = context;
    (void)sequence;
    if (event == CLIENT_ISOLATION_TELEMETRY_INVALID_REPLY) ++fake->telemetry_invalid;
    if (event == CLIENT_ISOLATION_TELEMETRY_UNRELATED_DATAGRAM) ++fake->telemetry_unrelated;
}

static client_isolation_ops_t make_ops(fake_t *fake)
{
    fake->crypto.hmac_sha256 = fake_hmac;
    fake->crypto.context = fake;
    client_isolation_ops_t ops = {
        .socket_open = fake_socket_open,
        .socket_bind = fake_socket_bind,
        .random_fill = fake_random,
        .send_datagram = fake_send,
        .receive_datagram = fake_receive,
        .socket_close = fake_close,
        .monotonic_ms = fake_monotonic_ms,
        .cancelled = fake_cancelled,
        .telemetry = fake_telemetry,
        .crypto = &fake->crypto,
        .context = fake,
    };
    return ops;
}

static client_isolation_config_t make_config(const fake_t *fake, uint8_t count)
{
    client_isolation_config_t config = {
        .local_ipv4 = TEST_LOCAL_IP,
        .peer_ipv4 = TEST_PEER_IP,
        .peer_port = TEST_PORT,
        .probe_count = count,
    };
    memcpy(config.token, fake->token, JISO_TOKEN_BYTES);
    return config;
}

static client_isolation_result_t run(fake_t *fake, uint8_t count)
{
    client_isolation_ops_t ops = make_ops(fake);
    client_isolation_config_t config = make_config(fake, count);
    client_isolation_result_t result;
    memset(&result, 0xA5, sizeof(result));
    client_isolation_conclusion_t conclusion = client_isolation_run(&config, &ops, &result);
    assert(result.conclusion == conclusion);
    return result;
}

static void add_event(fake_t *fake, event_kind_t kind, uint32_t advance_ms)
{
    assert(fake->event_count < MAX_EVENTS);
    fake->events[fake->event_count++] = (fake_event_t){kind, advance_ms};
}

static void test_zero_one_three_replies_and_fresh_nonce(void)
{
    fake_t fake;
    fake_reset(&fake);
    client_isolation_result_t result = run(&fake, 3U);
    assert(result.conclusion == ISO_AUDIT_INCONCLUSIVE_NO_REPLY);
    assert(result.probes_sent == 3U && result.authenticated_replies == 0U);
    assert(fake.open_calls == 1U && fake.bind_calls == 1U && fake.close_calls == 1U);

    fake_reset(&fake);
    add_event(&fake, EVENT_VALID, 17U);
    result = run(&fake, 1U);
    assert(result.conclusion == ISO_AUDIT_PEER_REACHABLE);
    assert(result.authenticated_replies == 1U && result.probes_sent == 1U);
    assert(result.probe_result_count == 1U);
    assert(result.probes[0].rtt_known && result.probes[0].rtt_ms == 17U);
    assert(fake.sent_ip == TEST_PEER_IP && fake.sent_port == TEST_PORT);

    fake_reset(&fake);
    add_event(&fake, EVENT_VALID, 1U);
    add_event(&fake, EVENT_VALID, 1U);
    add_event(&fake, EVENT_VALID, 1U);
    result = run(&fake, 3U);
    assert(result.conclusion == ISO_AUDIT_PEER_REACHABLE);
    assert(result.authenticated_replies == 3U && result.probes_sent == 3U);
    assert(!fake.nonce_reused && fake.random_calls == 4U);
}

static void test_invalid_unrelated_reordered_and_deadline(void)
{
    fake_t fake;
    fake_reset(&fake);
    add_event(&fake, EVENT_BAD_TAG, 1U);
    add_event(&fake, EVENT_WRONG_SOURCE, 1U);
    add_event(&fake, EVENT_WRONG_PORT, 1U);
    add_event(&fake, EVENT_WRONG_SEQUENCE, 1U);
    add_event(&fake, EVENT_WRONG_RUN, 1U);
    add_event(&fake, EVENT_WRONG_NONCE, 1U);
    add_event(&fake, EVENT_VALID, 1U);
    client_isolation_result_t result = run(&fake, 1U);
    assert(result.conclusion == ISO_AUDIT_PEER_REACHABLE);
    assert(result.datagrams_received == 7U && result.invalid_replies == 4U);
    assert(result.unrelated_datagrams == 2U && result.authenticated_replies == 1U);
    assert(fake.telemetry_invalid == 4U && fake.telemetry_unrelated == 2U);

    fake_reset(&fake);
    add_event(&fake, EVENT_VALID, 1U);
    add_event(&fake, EVENT_PRIOR_REPLY, 1U);
    add_event(&fake, EVENT_VALID, 1U);
    result = run(&fake, 2U);
    assert(result.conclusion == ISO_AUDIT_PEER_REACHABLE);
    assert(result.authenticated_replies == 2U && result.invalid_replies == 1U);

    fake_reset(&fake);
    add_event(&fake, EVENT_VALID, CLIENT_ISOLATION_PROBE_TIMEOUT_MS);
    result = run(&fake, 1U);
    assert(result.conclusion == ISO_AUDIT_INCONCLUSIVE_NO_REPLY);
    assert(result.datagrams_received == 1U && result.authenticated_replies == 0U);
}

static void test_error_cancel_and_proof_precedence(void)
{
    fake_t fake;
    fake_reset(&fake);
    fake.open_ok = false;
    client_isolation_result_t result = run(&fake, 1U);
    assert(result.conclusion == ISO_AUDIT_LOCAL_ERROR && fake.close_calls == 0U);

    fake_reset(&fake);
    fake.bind_ok = false;
    result = run(&fake, 1U);
    assert(result.conclusion == ISO_AUDIT_LOCAL_ERROR && fake.close_calls == 1U);

    fake_reset(&fake);
    fake.fail_send_call = 1;
    result = run(&fake, 1U);
    assert(result.conclusion == ISO_AUDIT_LOCAL_ERROR && fake.close_calls == 1U);

    fake_reset(&fake);
    add_event(&fake, EVENT_RECEIVE_ERROR, 1U);
    result = run(&fake, 1U);
    assert(result.conclusion == ISO_AUDIT_LOCAL_ERROR && fake.close_calls == 1U);

    fake_reset(&fake);
    fake.cancel_at_check = 1;
    result = run(&fake, 1U);
    assert(result.conclusion == ISO_AUDIT_CANCELLED && fake.close_calls == 1U);

    fake_reset(&fake);
    fake.cancel_at_check = 1;
    fake.close_ok = false;
    result = run(&fake, 1U);
    assert(result.conclusion == ISO_AUDIT_LOCAL_ERROR && result.cancelled);

    fake_reset(&fake);
    fake.close_ok = false;
    result = run(&fake, 1U);
    assert(result.conclusion == ISO_AUDIT_LOCAL_ERROR);

    fake_reset(&fake);
    add_event(&fake, EVENT_VALID, 1U);
    fake.fail_send_call = 2;
    result = run(&fake, 3U);
    assert(result.conclusion == ISO_AUDIT_PEER_REACHABLE);
    assert(result.authenticated_replies == 1U && result.local_errors == 1U);

    fake_reset(&fake);
    add_event(&fake, EVENT_VALID, 1U);
    fake.close_ok = false;
    result = run(&fake, 1U);
    assert(result.conclusion == ISO_AUDIT_PEER_REACHABLE);
    assert(result.authenticated_replies == 1U && result.local_errors == 1U);

    fake_reset(&fake);
    fake.fail_random_call = 1;
    result = run(&fake, 1U);
    assert(result.conclusion == ISO_AUDIT_LOCAL_ERROR && fake.close_calls == 1U);

    fake_reset(&fake);
    fake.fail_random_call = 2;
    result = run(&fake, 1U);
    assert(result.conclusion == ISO_AUDIT_LOCAL_ERROR && fake.send_calls == 0U);

    fake_reset(&fake);
    add_event(&fake, EVENT_VALID, 1U);
    fake.cancel_at_check = 4;
    result = run(&fake, 2U);
    assert(result.conclusion == ISO_AUDIT_PEER_REACHABLE);
    assert(result.authenticated_replies == 1U && result.cancelled);

    fake_reset(&fake);
    fake.repeat_nonce = true;
    result = run(&fake, 2U);
    assert(result.conclusion == ISO_AUDIT_LOCAL_ERROR);
    assert(result.probes_sent == 1U && result.local_errors == 1U);
}

static void test_stagnant_backwards_and_hard_receive_bound(void)
{
    fake_t fake;
    fake_reset(&fake);
    fake.fill_unrelated_forever = true;
    client_isolation_result_t result = run(&fake, CLIENT_ISOLATION_MAX_COUNT);
    assert(result.conclusion == ISO_AUDIT_INCONCLUSIVE_NO_REPLY);
    assert(fake.receive_calls == CLIENT_ISOLATION_MAX_COUNT *
                                 CLIENT_ISOLATION_MAX_RX_PER_PROBE);
    assert(fake.requested_timeout_total_ms <=
           CLIENT_ISOLATION_TOTAL_TIMEOUT_MS);
    assert(result.datagrams_received == fake.receive_calls);
    assert(fake.max_timeout_ms <=
           (CLIENT_ISOLATION_PROBE_TIMEOUT_MS +
            CLIENT_ISOLATION_MAX_RX_PER_PROBE - 1U) /
           CLIENT_ISOLATION_MAX_RX_PER_PROBE);
    assert(result.clock_anomaly && fake.close_calls == 1U);

    fake_reset(&fake);
    for (size_t index = 0U;
         index < CLIENT_ISOLATION_MAX_COUNT *
                 CLIENT_ISOLATION_MAX_RX_PER_PROBE;
         ++index) {
        add_event(&fake, EVENT_WRONG_SOURCE, 1U);
    }
    result = run(&fake, CLIENT_ISOLATION_MAX_COUNT);
    assert(result.conclusion == ISO_AUDIT_INCONCLUSIVE_NO_REPLY);
    assert(fake.receive_calls == CLIENT_ISOLATION_MAX_COUNT *
                                 CLIENT_ISOLATION_MAX_RX_PER_PROBE);
    assert(fake.requested_timeout_total_ms <=
           CLIENT_ISOLATION_TOTAL_TIMEOUT_MS);
    assert(fake.close_calls == 1U);

    fake_reset(&fake);
    fake.fill_unrelated_forever = true;
    add_event(&fake, EVENT_WRONG_SOURCE, 500U);
    add_event(&fake, EVENT_WRONG_SOURCE, 0U);
    result = run(&fake, 1U);
    assert(result.conclusion == ISO_AUDIT_INCONCLUSIVE_NO_REPLY);
    assert(fake.receive_calls == CLIENT_ISOLATION_MAX_RX_PER_PROBE);
    assert(fake.requested_timeout_total_ms <=
           CLIENT_ISOLATION_PROBE_TIMEOUT_MS);
    assert(result.clock_anomaly && fake.close_calls == 1U);

    fake_reset(&fake);
    fake.now_ms = 100U;
    fake.clock_backwards = true;
    add_event(&fake, EVENT_TIMEOUT, 0U);
    result = run(&fake, 1U);
    assert(result.conclusion == ISO_AUDIT_LOCAL_ERROR);
    assert(result.clock_anomaly && fake.receive_calls == 1U);

    fake_reset(&fake);
    fake.now_ms = UINT64_MAX - 10U;
    add_event(&fake, EVENT_TIMEOUT, 20U);
    result = run(&fake, 1U);
    assert(result.conclusion == ISO_AUDIT_LOCAL_ERROR && result.clock_anomaly);

    fake_reset(&fake);
    fake.send_advance_ms = CLIENT_ISOLATION_TOTAL_TIMEOUT_MS;
    result = run(&fake, 3U);
    assert(result.conclusion == ISO_AUDIT_INCONCLUSIVE_NO_REPLY);
    assert(result.total_deadline_reached && result.probes_sent == 1U);
    assert(fake.receive_calls == 0U);

    fake_reset(&fake);
    fake.open_advance_ms = CLIENT_ISOLATION_TOTAL_TIMEOUT_MS;
    result = run(&fake, 3U);
    assert(result.conclusion == ISO_AUDIT_INCONCLUSIVE_NO_REPLY);
    assert(result.total_deadline_reached && result.probes_sent == 0U);
    assert(fake.open_calls == 1U && fake.bind_calls == 1U &&
           fake.close_calls == 1U);
}

static void test_invalid_inputs_are_atomic_and_open_nothing(void)
{
    fake_t fake;
    fake_reset(&fake);
    client_isolation_ops_t ops = make_ops(&fake);
    client_isolation_config_t config = make_config(&fake, 0U);
    client_isolation_result_t result;
    memset(&result, 0xA5, sizeof(result));
    assert(client_isolation_run(&config, &ops, &result) == ISO_AUDIT_LOCAL_ERROR);
    assert(result.conclusion == ISO_AUDIT_LOCAL_ERROR && result.local_errors == 1U);
    assert(result.probes_sent == 0U && fake.open_calls == 0U);

    config = make_config(&fake, 1U);
    memset(config.token, 0, sizeof(config.token));
    memset(&result, 0xA5, sizeof(result));
    assert(client_isolation_run(&config, &ops, &result) == ISO_AUDIT_LOCAL_ERROR);
    assert(result.probes_sent == 0U && result.local_errors == 1U);
}

int main(void)
{
    test_zero_one_three_replies_and_fresh_nonce();
    test_invalid_unrelated_reordered_and_deadline();
    test_error_cancel_and_proof_precedence();
    test_stagnant_backwards_and_hard_receive_bound();
    test_invalid_inputs_are_atomic_and_open_nothing();
    puts("PASS: bounded isolation runtime, precedence, deadlines, cleanup");
    return 0;
}
