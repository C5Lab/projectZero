#include "client_isolation_command.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    client_isolation_sta_snapshot_t snapshot;
    client_isolation_result_t result;
    char output[8192];
    size_t output_length;
    unsigned snapshot_calls;
    unsigned run_calls;
    unsigned history_frees;
    unsigned write_calls;
    unsigned fail_write_at;
    bool drift_on_recheck;
    uint16_t expected_port;
    uint8_t expected_count;
} fixture_t;

static bool snapshot_hook(void *context, client_isolation_sta_snapshot_t *snapshot)
{
    fixture_t *fixture = context;
    ++fixture->snapshot_calls;
    *snapshot = fixture->snapshot;
    if (fixture->drift_on_recheck && fixture->snapshot_calls == 2U)
        snapshot->gateway_ipv4 = UINT32_C(0xC0A80102);
    return true;
}

static client_isolation_conclusion_t run_hook(
    void *context, const client_isolation_config_t *config,
    client_isolation_result_t *result)
{
    fixture_t *fixture = context;
    ++fixture->run_calls;
    assert(config->local_ipv4 == UINT32_C(0xC0A8010A));
    assert(config->peer_ipv4 == UINT32_C(0xC0A80114));
    assert(config->peer_port == fixture->expected_port);
    assert(config->probe_count == fixture->expected_count);
    assert(config->token[0] == 0x00U && config->token[15] == 0xFFU);
    *result = fixture->result;
    return result->conclusion;
}

static bool write_hook(void *context, const char *line, size_t length)
{
    fixture_t *fixture = context;
    ++fixture->write_calls;
    if (fixture->fail_write_at != 0U &&
        fixture->write_calls == fixture->fail_write_at) return false;
    if (length == 0U || fixture->output_length + length >= sizeof(fixture->output))
        return false;
    memcpy(fixture->output + fixture->output_length, line, length);
    fixture->output_length += length;
    fixture->output[fixture->output_length] = '\0';
    return true;
}

static void history_free_hook(void *context)
{
    fixture_t *fixture = context;
    ++fixture->history_frees;
}

static client_isolation_sta_snapshot_t valid_snapshot(void)
{
    client_isolation_sta_snapshot_t snapshot = {
        .connected = true,
        .bssid = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55},
        .local_ipv4 = UINT32_C(0xC0A8010A),
        .netmask = UINT32_C(0xFFFFFF00),
        .gateway_ipv4 = UINT32_C(0xC0A80101),
        .interface_id = 1U,
    };
    return snapshot;
}

static fixture_t fixture_defaults(void)
{
    fixture_t fixture = {0};
    fixture.snapshot = valid_snapshot();
    fixture.expected_port = 48732U;
    fixture.expected_count = 2U;
    fixture.result.conclusion = ISO_AUDIT_PEER_REACHABLE;
    fixture.result.run_id = UINT64_C(0x0102030405060708);
    fixture.result.probes_sent = 2U;
    fixture.result.datagrams_received = 2U;
    fixture.result.authenticated_replies = 1U;
    fixture.result.invalid_replies = 1U;
    fixture.result.probe_timeouts = 1U;
    fixture.result.duration_ms = 1234U;
    fixture.result.probe_result_count = 2U;
    fixture.result.probes[0] = (client_isolation_probe_result_t){
        .sequence = 0U, .sent = true, .timed_out = true,
    };
    fixture.result.probes[1] = (client_isolation_probe_result_t){
        .sequence = 1U, .sent = true, .datagrams_received = 2U,
        .authenticated_replies = 1U,
        .invalid_replies = 1U, .rtt_known = true, .rtt_ms = 17U,
    };
    return fixture;
}

static void init_fixture(fixture_t *fixture)
{
    client_isolation_hooks_t hooks = {
        .snapshot = snapshot_hook,
        .run = run_hook,
        .write = write_hook,
        .history_free = history_free_hook,
        .context = fixture,
    };
    client_isolation_command_init(&hooks);
}

static int run_start(fixture_t *fixture, const char *peer, const char *token,
                     const char *port, const char *count, char token_copy[65])
{
    snprintf(token_copy, 65U, "%s", token);
    char *argv[] = {"client_isolation_audit", "start", (char *)peer,
                    token_copy, "--port", (char *)port, "--count",
                    (char *)count};
    init_fixture(fixture);
    return client_isolation_command(8, argv);
}

static void assert_token_wiped(const char *token)
{
    for (size_t index = 0U; index < 32U; ++index) assert(token[index] == '\0');
}

static void test_success_and_status(void)
{
    fixture_t fixture = fixture_defaults();
    char token[65];
    assert(run_start(&fixture, "192.168.1.20",
                     "00112233445566778899AABBCCDDEEFF",
                     "48732", "2", token) == 0);
    assert_token_wiped(token);
    assert(fixture.history_frees == 1U);
    assert(fixture.snapshot_calls == 2U);
    assert(fixture.run_calls == 1U);
    assert(strstr(fixture.output,
        "[ISO_AUDIT/1] BEGIN BSSID=02:11:22:33:44:55 LOCAL=192.168.1.10 PEER=192.168.1.20 PORT=48732 COUNT=2 RUN=0102030405060708\r\n") != NULL);
    assert(strstr(fixture.output,
        "[ISO_AUDIT/1] PROBE SEQ=0 SEND=ok VALID=0 INVALID=0 TIMEOUT=1 RTT_MS=unknown\r\n") != NULL);
    assert(strstr(fixture.output,
        "[ISO_AUDIT/1] PROBE SEQ=1 SEND=ok VALID=1 INVALID=1 TIMEOUT=0 RTT_MS=17\r\n") != NULL);
    assert(strstr(fixture.output,
        "[ISO_AUDIT/1] END SENT=2 VALID=1 INVALID=1 TIMEOUTS=1 DURATION_MS=1234 OUTCOME=peer_reachable\r\n") != NULL);
    assert(strstr(fixture.output, "001122") == NULL);

    fixture.output_length = 0U;
    fixture.output[0] = '\0';
    char *status[] = {"client_isolation_audit", "status"};
    assert(client_isolation_command(2, status) == 0);
    assert(strstr(fixture.output,
        "[ISO_AUDIT/1] STATUS AVAILABLE=1 SENT=2 VALID=1 INVALID=1 TIMEOUTS=1 DURATION_MS=1234 OUTCOME=peer_reachable\r\n") != NULL);
}

static void test_default_port_and_count(void)
{
    fixture_t fixture = fixture_defaults();
    fixture.expected_port = CLIENT_ISOLATION_DEFAULT_PORT;
    fixture.expected_count = CLIENT_ISOLATION_DEFAULT_COUNT;
    init_fixture(&fixture);
    char token[] = "00112233445566778899AABBCCDDEEFF";
    char *argv[] = {"client_isolation_audit", "start", "192.168.1.20", token};
    assert(client_isolation_command(4, argv) == 0);
    assert_token_wiped(token);
    assert(strstr(fixture.output, " PORT=48731 COUNT=3 ") != NULL);
}

static void test_rejections_scrub_before_io(void)
{
    const char *bad_peers[] = {
        "router.local", "2001:db8::1", "192.168.1.10", "192.168.1.1",
        "192.168.1.0", "192.168.1.255", "224.0.0.1", "192.168.2.20",
        "0.0.0.0", "255.255.255.255",
    };
    for (size_t index = 0U; index < sizeof(bad_peers) / sizeof(bad_peers[0]); ++index) {
        fixture_t fixture = fixture_defaults();
        char token[65];
        assert(run_start(&fixture, bad_peers[index],
                         "00112233445566778899AABBCCDDEEFF",
                         "48731", "3", token) == 1);
        assert_token_wiped(token);
        assert(fixture.history_frees == 1U);
        assert(fixture.run_calls == 0U);
    }

    const char *bad_tokens[] = {
        "", "0011", "00112233445566778899AABBCCDDEEFG",
        "00000000000000000000000000000000",
    };
    for (size_t index = 0U; index < sizeof(bad_tokens) / sizeof(bad_tokens[0]); ++index) {
        fixture_t fixture = fixture_defaults();
        char token[65];
        assert(run_start(&fixture, "192.168.1.20", bad_tokens[index],
                         "48731", "3", token) == 1);
        for (size_t byte = 0U; byte < strlen(bad_tokens[index]); ++byte)
            assert(token[byte] == '\0');
        assert(fixture.run_calls == 0U);
    }
}

static void test_snapshot_and_option_failures(void)
{
    fixture_t fixture = fixture_defaults();
    char token[65];
    fixture.snapshot.netmask = UINT32_C(0xFF00FF00);
    assert(run_start(&fixture, "192.168.1.20",
                     "00112233445566778899AABBCCDDEEFF",
                     "48731", "3", token) == 1);
    assert(fixture.run_calls == 0U);

    fixture = fixture_defaults();
    fixture.snapshot.connected = false;
    assert(run_start(&fixture, "192.168.1.20",
                     "00112233445566778899AABBCCDDEEFF",
                     "48731", "3", token) == 1);

    fixture = fixture_defaults();
    init_fixture(&fixture);
    char mutable_token[] = "00112233445566778899AABBCCDDEEFF";
    char *duplicate[] = {"client_isolation_audit", "start", "192.168.1.20",
        mutable_token, "--port", "48731", "--port", "48732"};
    assert(client_isolation_command(8, duplicate) == 1);
    assert_token_wiped(mutable_token);
    assert(fixture.run_calls == 0U);

    const char *bad_ports[] = {"1023", "65536", "-1", "x"};
    for (size_t i = 0U; i < 4U; ++i) {
        fixture = fixture_defaults();
        assert(run_start(&fixture, "192.168.1.20",
                         "00112233445566778899AABBCCDDEEFF",
                         bad_ports[i], "3", token) == 1);
    }
    const char *bad_counts[] = {"0", "11", "-1", "x"};
    for (size_t i = 0U; i < 4U; ++i) {
        fixture = fixture_defaults();
        assert(run_start(&fixture, "192.168.1.20",
                         "00112233445566778899AABBCCDDEEFF",
                         "48731", bad_counts[i], token) == 1);
    }
}

static void test_snapshot_drift_and_output_failure(void)
{
    fixture_t fixture = fixture_defaults();
    fixture.drift_on_recheck = true;
    char drift_token[65];
    assert(run_start(&fixture, "192.168.1.20",
                     "00112233445566778899AABBCCDDEEFF",
                     "48732", "2", drift_token) == 1);
    assert_token_wiped(drift_token);
    assert(fixture.snapshot_calls == 2U);
    assert(fixture.run_calls == 0U);
    assert(!client_isolation_busy());

    fixture = fixture_defaults();
    fixture.fail_write_at = 2U;
    char token_copy[65];
    assert(run_start(&fixture, "192.168.1.20",
                     "00112233445566778899AABBCCDDEEFF",
                     "48732", "2", token_copy) == 1);
    assert_token_wiped(token_copy);
    assert(!client_isolation_busy());

    fixture = fixture_defaults();
    fixture.result.probe_result_count = CLIENT_ISOLATION_MAX_COUNT + 1U;
    assert(run_start(&fixture, "192.168.1.20",
                     "00112233445566778899AABBCCDDEEFF",
                     "48732", "2", token_copy) == 1);
    assert_token_wiped(token_copy);
    assert(!client_isolation_busy());
}

static void assert_hostile_result_rejected(fixture_t *fixture)
{
    char token[65];
    assert(run_start(fixture, "192.168.1.20",
                     "00112233445566778899AABBCCDDEEFF",
                     "48732", "2", token) == 1);
    assert_token_wiped(token);
    assert(fixture->run_calls == 1U);
    assert(fixture->output_length == 0U);
    assert(!client_isolation_busy());

    char *status[] = {"client_isolation_audit", "status"};
    assert(client_isolation_command(2, status) == 0);
    assert(strcmp(fixture->output,
                  "[ISO_AUDIT/1] STATUS AVAILABLE=0\r\n") == 0);
}

static void test_hostile_runtime_evidence_is_rejected_atomically(void)
{
    fixture_t fixture = fixture_defaults();
    fixture.result.datagrams_received = 1U;
    assert_hostile_result_rejected(&fixture);

    fixture = fixture_defaults();
    fixture.result.probes[1].datagrams_received = 1U;
    assert_hostile_result_rejected(&fixture);

    fixture = fixture_defaults();
    fixture.result.invalid_replies = 2U;
    assert_hostile_result_rejected(&fixture);

    fixture = fixture_defaults();
    fixture.result.probes[1].authenticated_replies = 0U;
    assert_hostile_result_rejected(&fixture);

    fixture = fixture_defaults();
    fixture.result.probes[1].sent = false;
    assert_hostile_result_rejected(&fixture);

    fixture = fixture_defaults();
    fixture.result.probes[0].rtt_known = true;
    fixture.result.probes[0].rtt_ms = 99U;
    assert_hostile_result_rejected(&fixture);

    fixture = fixture_defaults();
    fixture.result.probes[1].timed_out = true;
    fixture.result.probe_timeouts = 2U;
    assert_hostile_result_rejected(&fixture);

    fixture = fixture_defaults();
    fixture.result.probes_sent = 1U;
    assert_hostile_result_rejected(&fixture);

    fixture = fixture_defaults();
    fixture.result.probe_timeouts = 0U;
    assert_hostile_result_rejected(&fixture);

    fixture = fixture_defaults();
    fixture.result.authenticated_replies = 0U;
    fixture.result.conclusion = ISO_AUDIT_PEER_REACHABLE;
    assert_hostile_result_rejected(&fixture);

    fixture = fixture_defaults();
    fixture.result.run_id = 0U;
    assert_hostile_result_rejected(&fixture);
}

static void test_legitimate_early_error_and_cancel_are_publishable(void)
{
    fixture_t fixture = fixture_defaults();
    memset(&fixture.result, 0, sizeof(fixture.result));
    fixture.result.conclusion = ISO_AUDIT_LOCAL_ERROR;
    fixture.result.local_errors = 1U;
    char token[65];
    assert(run_start(&fixture, "192.168.1.20",
                     "00112233445566778899AABBCCDDEEFF",
                     "48732", "2", token) == 1);
    assert(strstr(fixture.output, " RUN=0000000000000000\r\n") != NULL);
    assert(strstr(fixture.output, " OUTCOME=local_error\r\n") != NULL);

    fixture = fixture_defaults();
    memset(&fixture.result, 0, sizeof(fixture.result));
    fixture.result.conclusion = ISO_AUDIT_CANCELLED;
    fixture.result.cancelled = true;
    fixture.result.run_id = UINT64_C(0x1112131415161718);
    fixture.result.probe_result_count = 1U;
    fixture.result.probes[0].sequence = 0U;
    assert(run_start(&fixture, "192.168.1.20",
                     "00112233445566778899AABBCCDDEEFF",
                     "48732", "2", token) == 0);
    assert(strstr(fixture.output, "PROBE SEQ=0 SEND=error") != NULL);
    assert(strstr(fixture.output, " OUTCOME=cancelled\r\n") != NULL);
}

int main(void)
{
    test_success_and_status();
    test_default_port_and_count();
    test_rejections_scrub_before_io();
    test_snapshot_and_option_failures();
    test_snapshot_drift_and_output_failure();
    test_hostile_runtime_evidence_is_rejected_atomically();
    test_legitimate_early_error_and_cancel_are_publishable();
    puts("PASS: client isolation CLI, hygiene, records");
    return 0;
}
