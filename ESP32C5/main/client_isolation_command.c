#include "client_isolation_command.h"

#include <inttypes.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    bool available;
    client_isolation_conclusion_t conclusion;
    uint32_t probes_sent;
    uint32_t authenticated_replies;
    uint32_t invalid_replies;
    uint32_t probe_timeouts;
    uint32_t duration_ms;
} client_isolation_last_t;

static client_isolation_hooks_t command_hooks;
static atomic_bool command_initialized = ATOMIC_VAR_INIT(false);
static atomic_bool command_busy = ATOMIC_VAR_INIT(false);
static atomic_uint last_sequence = ATOMIC_VAR_INIT(0U);
static atomic_bool last_available = ATOMIC_VAR_INIT(false);
static atomic_int last_conclusion = ATOMIC_VAR_INIT(ISO_AUDIT_LOCAL_ERROR);
static atomic_uint last_probes_sent = ATOMIC_VAR_INIT(0U);
static atomic_uint last_authenticated_replies = ATOMIC_VAR_INIT(0U);
static atomic_uint last_invalid_replies = ATOMIC_VAR_INIT(0U);
static atomic_uint last_probe_timeouts = ATOMIC_VAR_INIT(0U);
static atomic_uint last_duration_ms = ATOMIC_VAR_INIT(0U);

static void secure_zero(void *memory, size_t size)
{
    volatile uint8_t *bytes = memory;
    while (size > 0U) {
        *bytes++ = 0U;
        --size;
    }
}

void client_isolation_scrub_cli_token(char *argument)
{
    if (argument == NULL) return;
    volatile char *cursor = argument;
    while (*cursor != '\0') *cursor++ = '\0';
}

static bool bssid_nonzero(const uint8_t bssid[6])
{
    uint8_t value = 0U;
    for (size_t index = 0U; index < 6U; ++index) value |= bssid[index];
    return value != 0U;
}

static bool netmask_prefix_valid(uint32_t netmask)
{
    bool saw_zero = false;
    unsigned ones = 0U;
    for (unsigned bit = 0U; bit < 32U; ++bit) {
        bool set = (netmask & (UINT32_C(1) << (31U - bit))) != 0U;
        if (!set) saw_zero = true;
        else {
            if (saw_zero) return false;
            ++ones;
        }
    }
    return ones >= 1U && ones <= 30U;
}

static bool snapshot_valid(const client_isolation_sta_snapshot_t *snapshot)
{
    if (snapshot == NULL || !snapshot->connected ||
        !bssid_nonzero(snapshot->bssid) || snapshot->local_ipv4 == 0U ||
        snapshot->gateway_ipv4 == 0U || snapshot->interface_id == 0U ||
        !netmask_prefix_valid(snapshot->netmask)) return false;
    uint32_t network = snapshot->local_ipv4 & snapshot->netmask;
    uint32_t broadcast = network | ~snapshot->netmask;
    return snapshot->local_ipv4 != network &&
           snapshot->local_ipv4 != broadcast &&
           snapshot->gateway_ipv4 != network &&
           snapshot->gateway_ipv4 != broadcast &&
           (snapshot->gateway_ipv4 & snapshot->netmask) == network;
}

static bool snapshot_equal(const client_isolation_sta_snapshot_t *left,
                           const client_isolation_sta_snapshot_t *right)
{
    return left->connected == right->connected &&
           memcmp(left->bssid, right->bssid, 6U) == 0 &&
           left->local_ipv4 == right->local_ipv4 &&
           left->netmask == right->netmask &&
           left->gateway_ipv4 == right->gateway_ipv4 &&
           left->interface_id == right->interface_id;
}

static bool parse_ipv4(const char *text, uint32_t *address)
{
    if (text == NULL || address == NULL) return false;
    uint32_t value = 0U;
    const char *cursor = text;
    for (unsigned field = 0U; field < 4U; ++field) {
        if (*cursor < '0' || *cursor > '9') return false;
        unsigned octet = 0U;
        unsigned digits = 0U;
        while (*cursor >= '0' && *cursor <= '9') {
            octet = octet * 10U + (unsigned)(*cursor - '0');
            if (octet > 255U || ++digits > 3U) return false;
            ++cursor;
        }
        value = (value << 8U) | octet;
        if (field < 3U) {
            if (*cursor++ != '.') return false;
        } else if (*cursor != '\0') return false;
    }
    *address = value;
    return true;
}

static bool peer_valid(uint32_t peer,
                       const client_isolation_sta_snapshot_t *snapshot)
{
    uint32_t network = snapshot->local_ipv4 & snapshot->netmask;
    uint32_t broadcast = network | ~snapshot->netmask;
    uint8_t first = (uint8_t)(peer >> 24U);
    return peer != 0U && peer != UINT32_MAX && first != 0U && first < 224U &&
           peer != snapshot->local_ipv4 && peer != snapshot->gateway_ipv4 &&
           peer != network && peer != broadcast &&
           (peer & snapshot->netmask) == network;
}

static int hex_value(char character)
{
    if (character >= '0' && character <= '9') return character - '0';
    if (character >= 'a' && character <= 'f') return character - 'a' + 10;
    if (character >= 'A' && character <= 'F') return character - 'A' + 10;
    return -1;
}

static bool parse_token(const char *text, uint8_t token[JISO_TOKEN_BYTES])
{
    uint8_t aggregate = 0U;
    if (text == NULL || strlen(text) != 2U * JISO_TOKEN_BYTES) return false;
    for (size_t index = 0U; index < JISO_TOKEN_BYTES; ++index) {
        int high = hex_value(text[index * 2U]);
        int low = hex_value(text[index * 2U + 1U]);
        if (high < 0 || low < 0) {
            secure_zero(token, JISO_TOKEN_BYTES);
            return false;
        }
        token[index] = (uint8_t)((unsigned)high << 4U | (unsigned)low);
        aggregate |= token[index];
    }
    if (aggregate == 0U) {
        secure_zero(token, JISO_TOKEN_BYTES);
        return false;
    }
    return true;
}

static bool parse_u32_range(const char *text, uint32_t minimum,
                            uint32_t maximum, uint32_t *value)
{
    uint32_t parsed = 0U;
    if (text == NULL || text[0] == '\0' || value == NULL) return false;
    for (const char *cursor = text; *cursor != '\0'; ++cursor) {
        if (*cursor < '0' || *cursor > '9') return false;
        unsigned digit = (unsigned)(*cursor - '0');
        if (parsed > (UINT32_MAX - digit) / 10U) return false;
        parsed = parsed * 10U + digit;
    }
    if (parsed < minimum || parsed > maximum) return false;
    *value = parsed;
    return true;
}

static void format_ipv4(uint32_t address, char output[16])
{
    (void)snprintf(output, 16U, "%u.%u.%u.%u",
        (unsigned)(address >> 24U), (unsigned)((address >> 16U) & 0xFFU),
        (unsigned)((address >> 8U) & 0xFFU), (unsigned)(address & 0xFFU));
}

static const char *outcome_name(client_isolation_conclusion_t conclusion)
{
    switch (conclusion) {
    case ISO_AUDIT_PEER_REACHABLE: return "peer_reachable";
    case ISO_AUDIT_LOCAL_ERROR: return "local_error";
    case ISO_AUDIT_CANCELLED: return "cancelled";
    case ISO_AUDIT_INCONCLUSIVE_NO_REPLY:
    default: return "inconclusive_no_reply";
    }
}

static bool classifications_valid(uint32_t received, uint32_t authenticated,
                                  uint32_t invalid, uint32_t unrelated)
{
    if (authenticated > received) return false;
    uint32_t remaining = received - authenticated;
    if (invalid > remaining) return false;
    remaining -= invalid;
    return unrelated == remaining;
}

static bool result_valid(const client_isolation_result_t *result,
                         uint8_t requested_count)
{
    if (result == NULL || requested_count == 0U ||
        result->probe_result_count > CLIENT_ISOLATION_MAX_COUNT ||
        result->probe_result_count > requested_count ||
        result->probes_sent > requested_count ||
        result->probe_timeouts > requested_count ||
        result->probe_timeouts > result->probes_sent ||
        (result->probe_result_count > 0U && result->run_id == 0U)) return false;
    if (!classifications_valid(result->datagrams_received,
                               result->authenticated_replies,
                               result->invalid_replies,
                               result->unrelated_datagrams))
        return false;
    client_isolation_conclusion_t expected = ISO_AUDIT_INCONCLUSIVE_NO_REPLY;
    if (result->authenticated_replies > 0U)
        expected = ISO_AUDIT_PEER_REACHABLE;
    else if (result->local_errors > 0U)
        expected = ISO_AUDIT_LOCAL_ERROR;
    else if (result->cancelled)
        expected = ISO_AUDIT_CANCELLED;
    if (result->conclusion != expected) return false;
    uint64_t sent_sum = 0U;
    uint64_t received_sum = 0U;
    uint64_t authenticated_sum = 0U;
    uint64_t invalid_sum = 0U;
    uint64_t unrelated_sum = 0U;
    uint64_t timeout_sum = 0U;
    for (uint8_t index = 0U; index < result->probe_result_count; ++index) {
        const client_isolation_probe_result_t *probe = &result->probes[index];
        if (probe->sequence != index || probe->sequence >= requested_count ||
            probe->authenticated_replies > 1U ||
            !classifications_valid(probe->datagrams_received,
                                   probe->authenticated_replies,
                                   probe->invalid_replies,
                                   probe->unrelated_datagrams))
            return false;
        if (!probe->sent &&
            (probe->datagrams_received != 0U ||
             probe->authenticated_replies != 0U ||
             probe->invalid_replies != 0U ||
             probe->unrelated_datagrams != 0U || probe->timed_out ||
             probe->rtt_known || probe->rtt_ms != 0U)) return false;
        if (probe->authenticated_replies != 0U) {
            if (!probe->sent || probe->timed_out || !probe->rtt_known)
                return false;
        } else if (probe->rtt_known || probe->rtt_ms != 0U) return false;
        if (probe->timed_out && !probe->sent) return false;
        sent_sum += probe->sent ? 1U : 0U;
        received_sum += probe->datagrams_received;
        authenticated_sum += probe->authenticated_replies;
        invalid_sum += probe->invalid_replies;
        unrelated_sum += probe->unrelated_datagrams;
        timeout_sum += probe->timed_out ? 1U : 0U;
    }
    return sent_sum == result->probes_sent &&
           received_sum == result->datagrams_received &&
           authenticated_sum == result->authenticated_replies &&
           invalid_sum == result->invalid_replies &&
           unrelated_sum == result->unrelated_datagrams &&
           timeout_sum == result->probe_timeouts;
}

static bool emit_line(const char *format, ...)
{
    char line[CLIENT_ISOLATION_LINE_MAX];
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    if (length <= 0 || (size_t)length >= sizeof(line)) return false;
    bool written = command_hooks.write(command_hooks.context, line,
                                       (size_t)length);
    secure_zero(line, sizeof(line));
    return written;
}

static void save_last(const client_isolation_result_t *result)
{
    atomic_fetch_add_explicit(&last_sequence, 1U, memory_order_acq_rel);
    atomic_store_explicit(&last_conclusion, (int)result->conclusion,
                          memory_order_relaxed);
    atomic_store_explicit(&last_probes_sent, result->probes_sent,
                          memory_order_relaxed);
    atomic_store_explicit(&last_authenticated_replies,
                          result->authenticated_replies, memory_order_relaxed);
    atomic_store_explicit(&last_invalid_replies, result->invalid_replies,
                          memory_order_relaxed);
    atomic_store_explicit(&last_probe_timeouts, result->probe_timeouts,
                          memory_order_relaxed);
    atomic_store_explicit(&last_duration_ms, result->duration_ms,
                          memory_order_relaxed);
    atomic_store_explicit(&last_available, true, memory_order_relaxed);
    atomic_fetch_add_explicit(&last_sequence, 1U, memory_order_release);
}

static bool load_last(client_isolation_last_t *copy)
{
    for (unsigned attempt = 0U; attempt < 8U; ++attempt) {
        unsigned before = atomic_load_explicit(&last_sequence,
                                               memory_order_acquire);
        if ((before & 1U) != 0U) continue;
        copy->available = atomic_load_explicit(&last_available,
                                               memory_order_relaxed);
        copy->conclusion = (client_isolation_conclusion_t)
            atomic_load_explicit(&last_conclusion, memory_order_relaxed);
        copy->probes_sent = atomic_load_explicit(&last_probes_sent,
                                                 memory_order_relaxed);
        copy->authenticated_replies = atomic_load_explicit(
            &last_authenticated_replies, memory_order_relaxed);
        copy->invalid_replies = atomic_load_explicit(&last_invalid_replies,
                                                     memory_order_relaxed);
        copy->probe_timeouts = atomic_load_explicit(&last_probe_timeouts,
                                                    memory_order_relaxed);
        copy->duration_ms = atomic_load_explicit(&last_duration_ms,
                                                 memory_order_relaxed);
        atomic_thread_fence(memory_order_acquire);
        if (before == atomic_load_explicit(&last_sequence,
                                           memory_order_relaxed)) return true;
    }
    return false;
}

void client_isolation_command_init(const client_isolation_hooks_t *hooks)
{
    if (hooks == NULL || hooks->snapshot == NULL || hooks->run == NULL ||
        hooks->write == NULL || hooks->history_free == NULL) {
        atomic_store_explicit(&command_initialized, false,
                              memory_order_release);
        return;
    }
    command_hooks = *hooks;
    atomic_store_explicit(&last_available, false, memory_order_relaxed);
    atomic_store_explicit(&last_conclusion, ISO_AUDIT_LOCAL_ERROR,
                          memory_order_relaxed);
    atomic_store_explicit(&last_probes_sent, 0U, memory_order_relaxed);
    atomic_store_explicit(&last_authenticated_replies, 0U,
                          memory_order_relaxed);
    atomic_store_explicit(&last_invalid_replies, 0U, memory_order_relaxed);
    atomic_store_explicit(&last_probe_timeouts, 0U, memory_order_relaxed);
    atomic_store_explicit(&last_duration_ms, 0U, memory_order_relaxed);
    atomic_store_explicit(&last_sequence, 0U, memory_order_release);
    atomic_store_explicit(&command_busy, false, memory_order_release);
    atomic_store_explicit(&command_initialized, true, memory_order_release);
}

bool client_isolation_busy(void)
{
    return atomic_load_explicit(&command_busy, memory_order_acquire);
}

static int command_status(void)
{
    client_isolation_last_t copy = {0};
    if (!load_last(&copy)) return 1;
    if (!copy.available)
        return emit_line("[ISO_AUDIT/1] STATUS AVAILABLE=0\r\n") ? 0 : 1;
    return emit_line(
        "[ISO_AUDIT/1] STATUS AVAILABLE=1 SENT=%" PRIu32
        " VALID=%" PRIu32 " INVALID=%" PRIu32 " TIMEOUTS=%" PRIu32
        " DURATION_MS=%" PRIu32 " OUTCOME=%s\r\n",
        copy.probes_sent, copy.authenticated_replies,
        copy.invalid_replies, copy.probe_timeouts,
        copy.duration_ms, outcome_name(copy.conclusion)) ? 0 : 1;
}

static int command_start(int argc, char **argv)
{
    int return_code = 1;
    uint8_t token[JISO_TOKEN_BYTES] = {0};
    client_isolation_sta_snapshot_t first = {0};
    client_isolation_sta_snapshot_t second = {0};
    client_isolation_config_t config = {0};
    client_isolation_result_t result = {0};
    uint32_t peer = 0U;
    uint32_t port = CLIENT_ISOLATION_DEFAULT_PORT;
    uint32_t count = CLIENT_ISOLATION_DEFAULT_COUNT;
    bool port_seen = false;
    bool count_seen = false;
    bool acquired = false;

    if (argc >= 4 && argv[3] != NULL) {
        bool token_valid = parse_token(argv[3], token);
        client_isolation_scrub_cli_token(argv[3]);
        command_hooks.history_free(command_hooks.context);
        if (!token_valid) goto cleanup;
    } else {
        command_hooks.history_free(command_hooks.context);
        goto cleanup;
    }
    if (argc < 4 || !parse_ipv4(argv[2], &peer)) goto cleanup;
    for (int index = 4; index < argc; index += 2) {
        if (index + 1 >= argc) goto cleanup;
        if (strcmp(argv[index], "--port") == 0 && !port_seen) {
            if (!parse_u32_range(argv[index + 1], 1024U, 65535U, &port))
                goto cleanup;
            port_seen = true;
        } else if (strcmp(argv[index], "--count") == 0 && !count_seen) {
            if (!parse_u32_range(argv[index + 1], 1U,
                                 CLIENT_ISOLATION_MAX_COUNT, &count))
                goto cleanup;
            count_seen = true;
        } else goto cleanup;
    }
    bool expected = false;
    if (!atomic_compare_exchange_strong_explicit(
            &command_busy, &expected, true, memory_order_acq_rel,
            memory_order_acquire)) goto cleanup;
    acquired = true;
    if (!command_hooks.snapshot(command_hooks.context, &first) ||
        !snapshot_valid(&first) || !peer_valid(peer, &first)) goto cleanup;
    if (!command_hooks.snapshot(command_hooks.context, &second) ||
        !snapshot_valid(&second) || !snapshot_equal(&first, &second))
        goto cleanup;

    config.local_ipv4 = first.local_ipv4;
    config.peer_ipv4 = peer;
    config.peer_port = (uint16_t)port;
    config.probe_count = (uint8_t)count;
    memcpy(config.token, token, sizeof(config.token));
    result.conclusion = command_hooks.run(command_hooks.context, &config,
                                          &result);
    if (!result_valid(&result, config.probe_count)) goto cleanup;
    save_last(&result);

    char local[16];
    char peer_text[16];
    format_ipv4(first.local_ipv4, local);
    format_ipv4(peer, peer_text);
    if (!emit_line(
        "[ISO_AUDIT/1] BEGIN BSSID=%02X:%02X:%02X:%02X:%02X:%02X"
        " LOCAL=%s PEER=%s PORT=%u COUNT=%u RUN=%016" PRIX64 "\r\n",
        first.bssid[0], first.bssid[1], first.bssid[2], first.bssid[3],
        first.bssid[4], first.bssid[5], local, peer_text, (unsigned)port,
        (unsigned)count, result.run_id)) goto cleanup;
    for (uint8_t index = 0U; index < result.probe_result_count; ++index) {
        const client_isolation_probe_result_t *probe = &result.probes[index];
        char rtt[16] = "unknown";
        if (probe->rtt_known)
            (void)snprintf(rtt, sizeof(rtt), "%" PRIu32, probe->rtt_ms);
        if (!emit_line(
            "[ISO_AUDIT/1] PROBE SEQ=%" PRIu32 " SEND=%s VALID=%" PRIu32
            " INVALID=%" PRIu32 " TIMEOUT=%u RTT_MS=%s\r\n",
            probe->sequence, probe->sent ? "ok" : "error",
            probe->authenticated_replies, probe->invalid_replies,
            probe->timed_out ? 1U : 0U, rtt)) goto cleanup;
    }
    if (!emit_line(
        "[ISO_AUDIT/1] END SENT=%" PRIu32 " VALID=%" PRIu32
        " INVALID=%" PRIu32 " TIMEOUTS=%" PRIu32
        " DURATION_MS=%" PRIu32 " OUTCOME=%s\r\n",
        result.probes_sent, result.authenticated_replies,
        result.invalid_replies, result.probe_timeouts, result.duration_ms,
        outcome_name(result.conclusion))) goto cleanup;
    return_code = result.conclusion == ISO_AUDIT_LOCAL_ERROR ? 1 : 0;

cleanup:
    secure_zero(token, sizeof(token));
    secure_zero(config.token, sizeof(config.token));
    if (acquired)
        atomic_store_explicit(&command_busy, false, memory_order_release);
    return return_code;
}

int client_isolation_command(int argc, char **argv)
{
    if (!atomic_load_explicit(&command_initialized, memory_order_acquire) ||
        argc < 2 || argv == NULL || argv[1] == NULL) return 1;
    if (strcmp(argv[1], "status") == 0)
        return argc == 2 ? command_status() : 1;
    if (strcmp(argv[1], "start") == 0) return command_start(argc, argv);
    return 1;
}
