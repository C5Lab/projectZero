#include "client_isolation_runtime.h"

#include <limits.h>
#include <string.h>

typedef struct {
    uint8_t token[JISO_TOKEN_BYTES];
    uint8_t run_id_bytes[8];
    uint8_t nonce_history[CLIENT_ISOLATION_MAX_COUNT][JISO_NONCE_BYTES];
    uint8_t tx_packet[JISO_PACKET_BYTES];
    uint8_t rx_packet[JISO_PACKET_BYTES];
    jiso_message_t challenge;
    jiso_message_t reply;
    uint64_t run_started_ms;
    uint64_t last_time_ms;
    uint64_t conservative_elapsed_ms;
    uint64_t run_id;
    size_t nonce_count;
    int socket_handle;
    bool socket_owned;
    bool clock_initialized;
} client_isolation_state_t;

static void secure_zero(void *memory, size_t size)
{
    volatile uint8_t *bytes = memory;
    while (size > 0U) {
        *bytes++ = 0U;
        --size;
    }
}

static bool bytes_not_zero(const uint8_t *bytes, size_t length)
{
    uint8_t aggregate = 0U;
    if (bytes == NULL || length == 0U) return false;
    for (size_t index = 0U; index < length; ++index) aggregate |= bytes[index];
    return aggregate != 0U;
}

static uint64_t read_u64_be(const uint8_t bytes[8])
{
    uint64_t value = 0U;
    for (size_t index = 0U; index < 8U; ++index) {
        value = (value << 8U) | (uint64_t)bytes[index];
    }
    return value;
}

static bool config_valid(const client_isolation_config_t *config)
{
    return config != NULL && config->local_ipv4 != 0U &&
           config->peer_ipv4 != 0U && config->peer_ipv4 != config->local_ipv4 &&
           config->peer_port >= 1024U && config->probe_count >= 1U &&
           config->probe_count <= CLIENT_ISOLATION_MAX_COUNT &&
           bytes_not_zero(config->token, JISO_TOKEN_BYTES);
}

static bool ops_valid(const client_isolation_ops_t *ops)
{
    return ops != NULL && ops->socket_open != NULL &&
           ops->socket_bind != NULL && ops->random_fill != NULL &&
           ops->send_datagram != NULL && ops->receive_datagram != NULL &&
           ops->socket_close != NULL && ops->monotonic_ms != NULL &&
           ops->cancelled != NULL && ops->crypto != NULL &&
           ops->crypto->hmac_sha256 != NULL;
}

static void add_local_error(client_isolation_result_t *result)
{
    if (result->local_errors < UINT32_MAX) ++result->local_errors;
}

static bool read_time(const client_isolation_ops_t *ops,
                      client_isolation_state_t *state,
                      client_isolation_result_t *result,
                      uint64_t *now_ms)
{
    uint64_t now = ops->monotonic_ms(ops->context);
    if (state->clock_initialized && now < state->last_time_ms) {
        result->clock_anomaly = true;
        add_local_error(result);
        return false;
    }
    state->clock_initialized = true;
    state->last_time_ms = now;
    *now_ms = now;
    return true;
}

static uint64_t elapsed_since(uint64_t now, uint64_t started)
{
    return now - started;
}

static uint64_t effective_elapsed(uint64_t now,
                                  uint64_t started,
                                  uint64_t conservative_now,
                                  uint64_t conservative_started)
{
    uint64_t real_elapsed = elapsed_since(now, started);
    uint64_t conservative_elapsed = conservative_now - conservative_started;
    return real_elapsed > conservative_elapsed ? real_elapsed :
                                                 conservative_elapsed;
}

static void synchronize_conservative_time(client_isolation_state_t *state,
                                          uint64_t now_ms)
{
    uint64_t real_elapsed = elapsed_since(now_ms, state->run_started_ms);
    if (real_elapsed > state->conservative_elapsed_ms) {
        state->conservative_elapsed_ms = real_elapsed;
    }
}

static bool charge_receive_grant(client_isolation_state_t *state,
                                 uint32_t requested_ms)
{
    if (state->conservative_elapsed_ms > CLIENT_ISOLATION_TOTAL_TIMEOUT_MS ||
        requested_ms > CLIENT_ISOLATION_TOTAL_TIMEOUT_MS -
                       state->conservative_elapsed_ms) {
        return false;
    }
    state->conservative_elapsed_ms += requested_ms;
    return true;
}

static bool nonce_is_fresh(const client_isolation_state_t *state,
                           const uint8_t nonce[JISO_NONCE_BYTES])
{
    if (!bytes_not_zero(nonce, JISO_NONCE_BYTES)) return false;
    for (size_t index = 0U; index < state->nonce_count; ++index) {
        if (jiso_constant_time_equal(state->nonce_history[index], nonce,
                                     JISO_NONCE_BYTES, NULL)) {
            return false;
        }
    }
    return true;
}

static void report_telemetry(const client_isolation_ops_t *ops,
                             client_isolation_telemetry_t event,
                             uint32_t sequence)
{
    if (ops->telemetry != NULL) ops->telemetry(ops->context, event, sequence);
}

static client_isolation_conclusion_t choose_conclusion(
    const client_isolation_result_t *result)
{
    if (result->authenticated_replies > 0U) return ISO_AUDIT_PEER_REACHABLE;
    if (result->local_errors > 0U) return ISO_AUDIT_LOCAL_ERROR;
    if (result->cancelled) return ISO_AUDIT_CANCELLED;
    return ISO_AUDIT_INCONCLUSIVE_NO_REPLY;
}

client_isolation_conclusion_t client_isolation_run(
    const client_isolation_config_t *config,
    const client_isolation_ops_t *ops,
    client_isolation_result_t *result)
{
    client_isolation_result_t candidate = {0};
    client_isolation_state_t state = {0};
    bool stop = false;

    candidate.conclusion = ISO_AUDIT_LOCAL_ERROR;
    state.socket_handle = -1;
    if (result == NULL) return ISO_AUDIT_LOCAL_ERROR;
    if (!config_valid(config) || !ops_valid(ops)) {
        add_local_error(&candidate);
        *result = candidate;
        return candidate.conclusion;
    }

    memcpy(state.token, config->token, sizeof(state.token));
    if (!read_time(ops, &state, &candidate, &state.run_started_ms)) goto done;
    if (!ops->socket_open(ops->context, &state.socket_handle)) {
        add_local_error(&candidate);
        goto done;
    }
    if (state.socket_handle < 0) {
        add_local_error(&candidate);
        goto done;
    }
    state.socket_owned = true;
    if (!ops->socket_bind(ops->context, state.socket_handle,
                          config->local_ipv4)) {
        add_local_error(&candidate);
        goto done;
    }
    if (ops->cancelled(ops->context)) {
        candidate.cancelled = true;
        goto done;
    }
    if (!ops->random_fill(ops->context, state.run_id_bytes,
                          sizeof(state.run_id_bytes)) ||
        !bytes_not_zero(state.run_id_bytes, sizeof(state.run_id_bytes))) {
        add_local_error(&candidate);
        goto done;
    }
    state.run_id = read_u64_be(state.run_id_bytes);
    candidate.run_id = state.run_id;

    for (uint32_t sequence = 0U; sequence < config->probe_count && !stop;
         ++sequence) {
        uint64_t now_ms = 0U;
        uint64_t probe_started_ms = 0U;
        uint64_t probe_conservative_started_ms = 0U;
        uint32_t local_errors_before = candidate.local_errors;
        client_isolation_probe_result_t *probe =
            &candidate.probes[candidate.probe_result_count++];
        probe->sequence = sequence;
        if (ops->cancelled(ops->context)) {
            candidate.cancelled = true;
            break;
        }
        if (!read_time(ops, &state, &candidate, &now_ms)) break;
        synchronize_conservative_time(&state, now_ms);
        if (effective_elapsed(now_ms, state.run_started_ms,
                              state.conservative_elapsed_ms, 0U) >=
            CLIENT_ISOLATION_TOTAL_TIMEOUT_MS) {
            candidate.total_deadline_reached = true;
            break;
        }
        probe_started_ms = now_ms;
        probe_conservative_started_ms = state.conservative_elapsed_ms;

        memset(&state.challenge, 0, sizeof(state.challenge));
        state.challenge.type = JISO_CHALLENGE;
        state.challenge.run_id = state.run_id;
        state.challenge.sequence = sequence;
        if (!ops->random_fill(ops->context, state.challenge.nonce,
                              sizeof(state.challenge.nonce)) ||
            !nonce_is_fresh(&state, state.challenge.nonce)) {
            add_local_error(&candidate);
            break;
        }
        memcpy(state.nonce_history[state.nonce_count++], state.challenge.nonce,
               JISO_NONCE_BYTES);
        if (!jiso_encode(state.tx_packet, &state.challenge, state.token,
                         ops->crypto) ||
            !ops->send_datagram(ops->context, state.socket_handle,
                                config->peer_ipv4, config->peer_port,
                                state.tx_packet, sizeof(state.tx_packet))) {
            add_local_error(&candidate);
            break;
        }
        ++candidate.probes_sent;
        probe->sent = true;

        for (uint32_t received = 0U;
             received < CLIENT_ISOLATION_MAX_RX_PER_PROBE; ++received) {
            uint64_t probe_elapsed_ms;
            uint64_t total_elapsed_ms;
            uint64_t probe_remaining_ms;
            uint64_t total_remaining_ms;
            uint64_t grant_available_ms;
            uint32_t timeout_ms;
            uint32_t attempts_remaining;
            uint64_t receive_started_ms;
            size_t length = 0U;
            uint32_t source_ipv4 = 0U;
            uint16_t source_port = 0U;

            if (ops->cancelled(ops->context)) {
                candidate.cancelled = true;
                stop = true;
                break;
            }
            if (!read_time(ops, &state, &candidate, &now_ms)) {
                stop = true;
                break;
            }
            synchronize_conservative_time(&state, now_ms);
            probe_elapsed_ms = effective_elapsed(
                now_ms, probe_started_ms, state.conservative_elapsed_ms,
                probe_conservative_started_ms);
            total_elapsed_ms = effective_elapsed(
                now_ms, state.run_started_ms, state.conservative_elapsed_ms,
                0U);
            if (total_elapsed_ms >= CLIENT_ISOLATION_TOTAL_TIMEOUT_MS) {
                candidate.total_deadline_reached = true;
                stop = true;
                break;
            }
            if (probe_elapsed_ms >= CLIENT_ISOLATION_PROBE_TIMEOUT_MS) break;
            probe_remaining_ms = CLIENT_ISOLATION_PROBE_TIMEOUT_MS -
                                 probe_elapsed_ms;
            total_remaining_ms = CLIENT_ISOLATION_TOTAL_TIMEOUT_MS -
                                 total_elapsed_ms;
            grant_available_ms = probe_remaining_ms < total_remaining_ms ?
                                 probe_remaining_ms : total_remaining_ms;
            attempts_remaining = CLIENT_ISOLATION_MAX_RX_PER_PROBE - received;
            timeout_ms = (uint32_t)(grant_available_ms / attempts_remaining);
            if (grant_available_ms % attempts_remaining != 0U) ++timeout_ms;
            if (timeout_ms == 0U ||
                !charge_receive_grant(&state, timeout_ms)) {
                add_local_error(&candidate);
                stop = true;
                break;
            }

            memset(state.rx_packet, 0, sizeof(state.rx_packet));
            receive_started_ms = now_ms;
            client_isolation_receive_t receive = ops->receive_datagram(
                ops->context, state.socket_handle, timeout_ms, state.rx_packet,
                sizeof(state.rx_packet), &length, &source_ipv4, &source_port);
            if (receive == CLIENT_ISOLATION_RECEIVE_ERROR) {
                add_local_error(&candidate);
                stop = true;
                break;
            }
            if (receive != CLIENT_ISOLATION_RECEIVE_DATAGRAM) {
                if (receive != CLIENT_ISOLATION_RECEIVE_TIMEOUT) {
                    add_local_error(&candidate);
                    stop = true;
                    break;
                }
            }
            if (receive == CLIENT_ISOLATION_RECEIVE_DATAGRAM) {
                ++candidate.datagrams_received;
                ++probe->datagrams_received;
            }

            if (!read_time(ops, &state, &candidate, &now_ms)) {
                stop = true;
                break;
            }
            synchronize_conservative_time(&state, now_ms);
            if (now_ms == receive_started_ms) {
                candidate.clock_anomaly = true;
            }
            if (effective_elapsed(now_ms, state.run_started_ms,
                                  state.conservative_elapsed_ms, 0U) >=
                CLIENT_ISOLATION_TOTAL_TIMEOUT_MS) {
                candidate.total_deadline_reached = true;
                stop = true;
                break;
            }
            if (effective_elapsed(now_ms, probe_started_ms,
                                  state.conservative_elapsed_ms,
                                  probe_conservative_started_ms) >=
                CLIENT_ISOLATION_PROBE_TIMEOUT_MS) {
                break;
            }
            if (receive == CLIENT_ISOLATION_RECEIVE_TIMEOUT) continue;
            if (source_ipv4 != config->peer_ipv4 ||
                source_port != config->peer_port) {
                ++candidate.unrelated_datagrams;
                ++probe->unrelated_datagrams;
                report_telemetry(ops,
                    CLIENT_ISOLATION_TELEMETRY_UNRELATED_DATAGRAM, sequence);
                continue;
            }
            memset(&state.reply, 0, sizeof(state.reply));
            if (!jiso_decode(state.rx_packet, length, state.token, ops->crypto,
                             &state.reply) ||
                !jiso_reply_matches(&state.challenge, &state.reply)) {
                ++candidate.invalid_replies;
                ++probe->invalid_replies;
                report_telemetry(ops, CLIENT_ISOLATION_TELEMETRY_INVALID_REPLY,
                                 sequence);
                continue;
            }
            ++candidate.authenticated_replies;
            ++probe->authenticated_replies;
            probe->rtt_known = true;
            uint64_t rtt = elapsed_since(now_ms, probe_started_ms);
            probe->rtt_ms = rtt > UINT32_MAX ? UINT32_MAX : (uint32_t)rtt;
            break;
        }
        if (probe->sent && probe->authenticated_replies == 0U &&
            candidate.local_errors == local_errors_before &&
            !candidate.cancelled) {
            probe->timed_out = true;
            if (candidate.probe_timeouts < UINT32_MAX)
                ++candidate.probe_timeouts;
        }
    }

done:
    if (state.socket_owned &&
        !ops->socket_close(ops->context, state.socket_handle)) {
        add_local_error(&candidate);
    }
    if (state.clock_initialized && state.last_time_ms >= state.run_started_ms) {
        uint64_t duration = effective_elapsed(
            state.last_time_ms, state.run_started_ms,
            state.conservative_elapsed_ms, 0U);
        candidate.duration_ms = duration > UINT32_MAX ? UINT32_MAX :
                                                        (uint32_t)duration;
    }
    candidate.conclusion = choose_conclusion(&candidate);
    *result = candidate;
    secure_zero(&state, sizeof(state));
    return candidate.conclusion;
}
