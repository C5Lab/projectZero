#include "router_audit_core.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#define IP(a, b, c, d) (((uint32_t)(a) << 24U) | ((uint32_t)(b) << 16U) | \
                        ((uint32_t)(c) << 8U) | (uint32_t)(d))

typedef struct {
    const char *udp[6];
    uint32_t udp_ip[6];
    size_t udp_count;
    size_t udp_index;
    const char *tcp[2];
    size_t tcp_offset[2];
    size_t tcp_chunk;
    unsigned open_udp;
    unsigned open_tcp;
    unsigned send_to_calls;
    unsigned recv_from_calls;
    unsigned connect_calls;
    unsigned send_calls;
    unsigned recv_calls;
    unsigned close_calls;
    uint32_t last_ip;
    uint16_t last_port;
    char requests[2][512];
    char udp_request[256];
    size_t udp_request_length;
    size_t request_length[2];
    uint64_t now_ms;
    bool stagnant_clock;
    bool cancelled;
    bool fail_connect;
    bool zero_send;
    bool repeat_tcp;
    unsigned cancel_after_receives;
    unsigned clock_calls;
    unsigned clock_backwards_at;
    uint64_t udp_timeout_granted;
    uint64_t tcp_timeout_granted[2];
    uint32_t udp_last_timeout;
    uint32_t tcp_last_timeout[2];
} fake_io_t;

static int fake_open(void *context, router_socket_kind_t kind)
{
    fake_io_t *io = context;
    if (kind == ROUTER_SOCKET_UDP) {
        ++io->open_udp;
        return 1;
    }
    ++io->open_tcp;
    return (int)(10U + io->open_tcp - 1U);
}

static bool fake_set_timeout(void *context, int socket_fd, uint32_t timeout_ms)
{
    fake_io_t *io = context;
    if (socket_fd == 1) {
        io->udp_timeout_granted += timeout_ms;
        io->udp_last_timeout = timeout_ms;
    } else {
        size_t stream = (size_t)(socket_fd - 10);
        assert(stream < 2U);
        io->tcp_timeout_granted[stream] += timeout_ms;
        io->tcp_last_timeout[stream] = timeout_ms;
    }
    return timeout_ms > 0U && timeout_ms <= ROUTER_NETWORK_TIMEOUT_MS;
}

static int64_t fake_send_to(void *context, int socket_fd,
                            const uint8_t *bytes, size_t length,
                            uint32_t peer_ipv4, uint16_t peer_port)
{
    fake_io_t *io = context;
    assert(socket_fd == 1);
    assert(bytes != NULL && length > 0U);
    ++io->send_to_calls;
    io->last_ip = peer_ipv4;
    io->last_port = peer_port;
    assert(length < sizeof(io->udp_request));
    memcpy(io->udp_request, bytes, length);
    io->udp_request[length] = '\0';
    io->udp_request_length = length;
    return io->zero_send ? 0 : (int64_t)length;
}

static int64_t fake_recv_from(void *context, int socket_fd,
                              uint8_t *bytes, size_t capacity,
                              uint32_t *peer_ipv4, uint16_t *peer_port)
{
    fake_io_t *io = context;
    size_t length;
    assert(socket_fd == 1);
    ++io->recv_from_calls;
    if (io->udp_index >= io->udp_count) return ROUTER_IO_TIMEOUT;
    length = strlen(io->udp[io->udp_index]);
    assert(length <= capacity);
    memcpy(bytes, io->udp[io->udp_index], length);
    *peer_ipv4 = io->udp_ip[io->udp_index];
    *peer_port = 1900U;
    ++io->udp_index;
    return (int64_t)length;
}

static bool fake_connect(void *context, int socket_fd, uint32_t peer_ipv4,
                         uint16_t peer_port, uint32_t timeout_ms)
{
    fake_io_t *io = context;
    size_t stream = (size_t)(socket_fd - 10);
    assert(stream < 2U);
    ++io->connect_calls;
    io->last_ip = peer_ipv4;
    io->last_port = peer_port;
    return !io->fail_connect && timeout_ms == io->tcp_last_timeout[stream];
}

static int64_t fake_send(void *context, int socket_fd,
                         const uint8_t *bytes, size_t length)
{
    fake_io_t *io = context;
    size_t stream = (size_t)(socket_fd - 10);
    size_t chunk = length > 20U ? 20U : length;
    assert(stream < 2U);
    ++io->send_calls;
    if (io->zero_send) return 0;
    assert(io->request_length[stream] + chunk < sizeof(io->requests[stream]));
    memcpy(io->requests[stream] + io->request_length[stream], bytes, chunk);
    io->request_length[stream] += chunk;
    io->requests[stream][io->request_length[stream]] = '\0';
    return (int64_t)chunk;
}

static int64_t fake_recv(void *context, int socket_fd,
                         uint8_t *bytes, size_t capacity)
{
    fake_io_t *io = context;
    size_t stream = (size_t)(socket_fd - 10);
    size_t remaining;
    size_t chunk;
    assert(stream < 2U);
    ++io->recv_calls;
    if (io->tcp[stream] == NULL) return ROUTER_IO_ERROR;
    remaining = strlen(io->tcp[stream]) - io->tcp_offset[stream];
    if (remaining == 0U) {
        if (!io->repeat_tcp) return 0;
        chunk = io->tcp_chunk > 0U ? io->tcp_chunk : capacity;
        if (chunk > capacity) chunk = capacity;
        memset(bytes, 'A', chunk);
        return (int64_t)chunk;
    }
    chunk = remaining;
    if (io->tcp_chunk > 0U && chunk > io->tcp_chunk) chunk = io->tcp_chunk;
    if (chunk > capacity) chunk = capacity;
    memcpy(bytes, io->tcp[stream] + io->tcp_offset[stream], chunk);
    io->tcp_offset[stream] += chunk;
    return (int64_t)chunk;
}

static void fake_close(void *context, int socket_fd)
{
    fake_io_t *io = context;
    (void)socket_fd;
    ++io->close_calls;
}

static uint64_t fake_now(void *context)
{
    fake_io_t *io = context;
    uint64_t value = io->now_ms;
    ++io->clock_calls;
    if (io->clock_backwards_at != 0U &&
        io->clock_calls == io->clock_backwards_at) {
        return value < 2U ? 0U : value - 2U;
    }
    if (!io->stagnant_clock) ++io->now_ms;
    return value;
}

static bool fake_cancelled(void *context)
{
    fake_io_t *io = context;
    return io->cancelled ||
           (io->cancel_after_receives != 0U &&
            io->recv_from_calls >= io->cancel_after_receives);
}

static bool fake_oui(void *context, const uint8_t mac[6],
                     char vendor[ROUTER_EVIDENCE_TEXT_MAX + 1U])
{
    (void)context;
    (void)mac;
    memcpy(vendor, "Acme", 5U);
    return true;
}

static router_audit_ops_t ops(fake_io_t *io, uint8_t *scratch, size_t capacity)
{
    router_audit_ops_t result;
    memset(&result, 0, sizeof(result));
    result.context = io;
    result.socket_open = fake_open;
    result.socket_set_timeout = fake_set_timeout;
    result.socket_send_to = fake_send_to;
    result.socket_recv_from = fake_recv_from;
    result.socket_connect = fake_connect;
    result.socket_send = fake_send;
    result.socket_recv = fake_recv;
    result.socket_close = fake_close;
    result.monotonic_ms = fake_now;
    result.cancelled = fake_cancelled;
    result.oui_lookup = fake_oui;
    result.scratch = scratch;
    result.scratch_capacity = capacity;
    return result;
}

static router_network_context_t network(void)
{
    router_network_context_t value;
    memset(&value, 0, sizeof(value));
    value.sta_connected = true;
    value.local_ipv4 = IP(192, 0, 2, 100);
    value.netmask_ipv4 = IP(255, 255, 255, 0);
    value.gateway_ipv4 = IP(192, 0, 2, 1);
    value.bssid_known = true;
    value.bssid[0] = 0x00U;
    value.bssid[1] = 0x11U;
    value.bssid[2] = 0x22U;
    value.gateway_mac_known = true;
    memcpy(value.gateway_mac, value.bssid, sizeof(value.gateway_mac));
    memcpy(value.dhcp_vendor, "Acme", 5U);
    return value;
}

static void test_passive_has_zero_network_io(void)
{
    fake_io_t io;
    uint8_t scratch[ROUTER_AUDIT_SCRATCH_MIN];
    router_audit_ops_t hooks;
    router_network_context_t net = network();
    router_evidence_set_t out;
    router_fingerprint_t fingerprint;
    memset(&io, 0, sizeof(io));
    hooks = ops(&io, scratch, sizeof(scratch));

    assert(router_audit_collect(ROUTER_AUDIT_PASSIVE, &net, &hooks, &out) ==
           ROUTER_AUDIT_RESULT_OK);
    assert(io.open_udp == 0U && io.open_tcp == 0U && io.send_to_calls == 0U);
    assert(out.request_count == 0U);
    assert(out.bssid_known && out.gateway_mac_known);
    assert(out.gateway_ipv4 == net.gateway_ipv4);
    assert(out.count == 3U); /* BSSID OUI, gateway OUI, DHCP metadata. */
    assert(router_fingerprint_normalize(out.items, out.count, &fingerprint));
    assert(strcmp(fingerprint.vendor, "acme") == 0);
}

static void test_standard_is_gateway_only_and_collects_structured_evidence(void)
{
    static const char ssdp[] =
        "HTTP/1.1 200 OK\r\n"
        "LOCATION: http://192.0.2.1/device.xml\r\n"
        "SERVER: Router X RX1\r\n\r\n";
    static const char xml[] =
        "<?xml version=\"1.0\"?><root xmlns=\"urn:schemas-upnp-org:device-1-0\">"
        "<device><manufacturer>Acme</manufacturer>"
        "<modelName>Router X</modelName><modelNumber>RX1</modelNumber>"
        "<firmwareVersion>3.2.1</firmwareVersion></device></root>";
    char get_response[1024];
    static const char head_response[] =
        "HTTP/1.0 200 OK\r\nServer: Router X RX1\r\nContent-Length: 0\r\n\r\n";
    fake_io_t io;
    uint8_t scratch[ROUTER_AUDIT_SCRATCH_MIN];
    router_audit_ops_t hooks;
    router_network_context_t net = network();
    router_evidence_set_t out;
    router_fingerprint_t fingerprint;
    int written;

    memset(&io, 0, sizeof(io));
    written = snprintf(get_response, sizeof(get_response),
                       "HTTP/1.0 200 OK\r\nContent-Length: %u\r\n\r\n%s",
                       (unsigned)strlen(xml), xml);
    assert(written > 0 && (size_t)written < sizeof(get_response));
    io.udp[0] = ssdp;
    io.udp_ip[0] = net.gateway_ipv4;
    io.udp_count = 1U;
    io.tcp[0] = get_response;
    io.tcp[1] = head_response;
    io.tcp_chunk = 128U; /* Exercise bounded partial reads and writes. */
    hooks = ops(&io, scratch, sizeof(scratch));

    assert(router_audit_collect(ROUTER_AUDIT_STANDARD_OWNED, &net, &hooks, &out) ==
           ROUTER_AUDIT_RESULT_OK);
    assert(io.open_udp == 1U && io.open_tcp == 2U);
    assert(io.send_to_calls == 1U && io.recv_from_calls <= ROUTER_SSDP_RESPONSE_MAX);
    assert(io.last_ip == net.gateway_ipv4);
    assert(strstr(io.udp_request, "HOST: 192.0.2.1:1900") != NULL);
    assert(strstr(io.udp_request, "239.255.255.250") == NULL);
    assert(io.connect_calls == 2U);
    assert(io.udp_timeout_granted <= ROUTER_NETWORK_TIMEOUT_MS);
    assert(io.tcp_timeout_granted[0] <= ROUTER_NETWORK_TIMEOUT_MS);
    assert(io.tcp_timeout_granted[1] <= ROUTER_NETWORK_TIMEOUT_MS);
    assert(io.last_ip == net.gateway_ipv4 && io.last_port == 80U);
    assert(strstr(io.requests[0], "GET /device.xml HTTP/1.0\r\n") != NULL);
    assert(strstr(io.requests[1], "HEAD / HTTP/1.0\r\n") != NULL);
    assert(out.request_count == 3U);
    assert(out.ssdp_responses == 1U);
    assert(out.error_mask == 0U);
    assert(router_fingerprint_normalize(out.items, out.count, &fingerprint));
    assert(strcmp(fingerprint.vendor, "acme") == 0);
    assert(strcmp(fingerprint.model, "router x rx1") == 0);
    assert(strcmp(fingerprint.firmware, "3 2 1") == 0);
    assert(fingerprint.confidence == ROUTER_CONFIDENCE_CONFIRMED);
}

static void run_rejected_location(const char *location)
{
    char response[512];
    fake_io_t io;
    uint8_t scratch[ROUTER_AUDIT_SCRATCH_MIN];
    router_audit_ops_t hooks;
    router_network_context_t net = network();
    router_evidence_set_t out;
    int written;

    memset(&io, 0, sizeof(io));
    written = snprintf(response, sizeof(response),
                       "HTTP/1.1 200 OK\r\nLOCATION: %s\r\n\r\n", location);
    assert(written > 0 && (size_t)written < sizeof(response));
    io.udp[0] = response;
    io.udp_ip[0] = net.gateway_ipv4;
    io.udp_count = 1U;
    io.tcp[0] = "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n"; /* HEAD only. */
    hooks = ops(&io, scratch, sizeof(scratch));
    assert(router_audit_collect(ROUTER_AUDIT_STANDARD_OWNED, &net, &hooks, &out) ==
           ROUTER_AUDIT_RESULT_PARTIAL);
    assert(io.open_tcp == 1U && io.connect_calls == 1U);
    assert(out.request_count == 2U);
    assert((out.error_mask & ROUTER_AUDIT_ERROR_LOCATION) != 0U);
}

static void test_hostile_locations_and_wrong_sources_are_rejected(void)
{
    static const char response[] =
        "HTTP/1.1 200 OK\r\nLOCATION: http://192.0.2.1/device.xml\r\n\r\n";
    fake_io_t io;
    uint8_t scratch[ROUTER_AUDIT_SCRATCH_MIN];
    router_audit_ops_t hooks;
    router_network_context_t net = network();
    router_evidence_set_t out;

    run_rejected_location("https://192.0.2.1/device.xml");
    run_rejected_location("http://router.local/device.xml");
    run_rejected_location("http://192.0.2.2/device.xml");
    run_rejected_location("http://192.0.2.1:81/device.xml");
    run_rejected_location("http://user@192.0.2.1/device.xml");
    run_rejected_location("http://192.0.2.1/device.xml?x=1");
    run_rejected_location("http://192.0.2.1/device.xml#x");

    memset(&io, 0, sizeof(io));
    io.udp[0] = response;
    io.udp_ip[0] = IP(192, 0, 2, 2);
    io.udp_count = 1U;
    io.tcp[0] = "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n";
    hooks = ops(&io, scratch, sizeof(scratch));
    assert(router_audit_collect(ROUTER_AUDIT_STANDARD_OWNED, &net, &hooks, &out) ==
           ROUTER_AUDIT_RESULT_PARTIAL);
    assert(io.open_tcp == 1U); /* HEAD only; wrong-source LOCATION is ignored. */
    assert(out.request_count == 2U);
    assert((out.error_mask & ROUTER_AUDIT_ERROR_SSDP_SOURCE) != 0U);
}

static void test_malformed_chunked_duplicate_and_redirect_responses(void)
{
    static const char ssdp[] =
        "HTTP/1.1 200 OK\r\nLOCATION: http://192.0.2.1/device.xml\r\n\r\n";
    static const char duplicate_xml[] =
        "HTTP/1.0 200 OK\r\nContent-Length: 102\r\n\r\n"
        "<root><modelName>A</modelName><modelName>B</modelName>"
        "<firmwareVersion>1</firmwareVersion></root>";
    fake_io_t io;
    char malformed_response[512];
    uint8_t scratch[ROUTER_AUDIT_SCRATCH_MIN];
    router_audit_ops_t hooks;
    router_network_context_t net = network();
    router_evidence_set_t out;

    memset(&io, 0, sizeof(io));
    io.udp[0] = ssdp;
    io.udp_ip[0] = net.gateway_ipv4;
    io.udp_count = 1U;
    io.tcp[0] = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
    io.tcp[1] = "HTTP/1.1 302 Found\r\nLocation: http://192.0.2.2/\r\n\r\n";
    hooks = ops(&io, scratch, sizeof(scratch));
    assert(router_audit_collect(ROUTER_AUDIT_STANDARD_OWNED, &net, &hooks, &out) ==
           ROUTER_AUDIT_RESULT_PARTIAL);
    assert((out.error_mask & ROUTER_AUDIT_ERROR_HTTP) != 0U);
    assert((out.error_mask & ROUTER_AUDIT_ERROR_XML) != 0U);

    memset(&io, 0, sizeof(io));
    {
        static const char duplicate_direct_body[] =
            "<root><device><manufacturer>Acme</manufacturer>"
            "<modelName>Router A</modelName><modelName>Router B</modelName>"
            "<firmwareVersion>1</firmwareVersion></device></root>";
        int written = snprintf(malformed_response, sizeof(malformed_response),
                               "HTTP/1.0 200 OK\r\nContent-Length: %u\r\n\r\n%s",
                               (unsigned)strlen(duplicate_direct_body),
                               duplicate_direct_body);
        assert(written > 0 && (size_t)written < sizeof(malformed_response));
    }
    io.udp[0] = ssdp;
    io.udp_ip[0] = net.gateway_ipv4;
    io.udp_count = 1U;
    io.tcp[0] = malformed_response;
    io.tcp[1] = "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n";
    hooks = ops(&io, scratch, sizeof(scratch));
    assert(router_audit_collect(ROUTER_AUDIT_STANDARD_OWNED, &net, &hooks, &out) ==
           ROUTER_AUDIT_RESULT_PARTIAL);
    assert((out.error_mask & ROUTER_AUDIT_ERROR_XML) != 0U);

    memset(&io, 0, sizeof(io));
    {
        static const char sibling_devices_body[] =
            "<root><device><manufacturer>Acme</manufacturer>"
            "<modelName>Router A</modelName><firmwareVersion>1</firmwareVersion>"
            "</device><device><manufacturer>Acme</manufacturer>"
            "<modelName>Router B</modelName><firmwareVersion>2</firmwareVersion>"
            "</device></root>";
        int written = snprintf(malformed_response, sizeof(malformed_response),
                               "HTTP/1.0 200 OK\r\nContent-Length: %u\r\n\r\n%s",
                               (unsigned)strlen(sibling_devices_body),
                               sibling_devices_body);
        assert(written > 0 && (size_t)written < sizeof(malformed_response));
    }
    io.udp[0] = ssdp;
    io.udp_ip[0] = net.gateway_ipv4;
    io.udp_count = 1U;
    io.tcp[0] = malformed_response;
    io.tcp[1] = "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n";
    hooks = ops(&io, scratch, sizeof(scratch));
    assert(router_audit_collect(ROUTER_AUDIT_STANDARD_OWNED, &net, &hooks, &out) ==
           ROUTER_AUDIT_RESULT_PARTIAL);
    assert((out.error_mask & ROUTER_AUDIT_ERROR_XML) != 0U);

    memset(&io, 0, sizeof(io));
    {
        static const char nested_body[] =
            "<root xmlns=\"urn:schemas-upnp-org:device-1-0\"><device>"
            "<service><manufacturer>Acme</manufacturer>"
            "<modelName>Router X</modelName><firmwareVersion>1</firmwareVersion>"
            "</service></device></root>";
        int written = snprintf(malformed_response, sizeof(malformed_response),
                               "HTTP/1.0 200 OK\r\nContent-Length: %u\r\n\r\n%s",
                               (unsigned)strlen(nested_body), nested_body);
        assert(written > 0 && (size_t)written < sizeof(malformed_response));
    }
    io.udp[0] = ssdp;
    io.udp_ip[0] = net.gateway_ipv4;
    io.udp_count = 1U;
    io.tcp[0] = malformed_response;
    io.tcp[1] = "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n";
    hooks = ops(&io, scratch, sizeof(scratch));
    assert(router_audit_collect(ROUTER_AUDIT_STANDARD_OWNED, &net, &hooks, &out) ==
           ROUTER_AUDIT_RESULT_PARTIAL);
    assert((out.error_mask & ROUTER_AUDIT_ERROR_XML) != 0U);

    memset(&io, 0, sizeof(io));
    {
        static const char nested_device_body[] =
            "<root><device><device><manufacturer>Acme</manufacturer>"
            "<modelName>Router X</modelName><firmwareVersion>1</firmwareVersion>"
            "</device></device></root>";
        int written = snprintf(malformed_response, sizeof(malformed_response),
                               "HTTP/1.0 200 OK\r\nContent-Length: %u\r\n\r\n%s",
                               (unsigned)strlen(nested_device_body), nested_device_body);
        assert(written > 0 && (size_t)written < sizeof(malformed_response));
    }
    io.udp[0] = ssdp;
    io.udp_ip[0] = net.gateway_ipv4;
    io.udp_count = 1U;
    io.tcp[0] = malformed_response;
    io.tcp[1] = "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n";
    hooks = ops(&io, scratch, sizeof(scratch));
    assert(router_audit_collect(ROUTER_AUDIT_STANDARD_OWNED, &net, &hooks, &out) ==
           ROUTER_AUDIT_RESULT_PARTIAL);
    assert((out.error_mask & ROUTER_AUDIT_ERROR_XML) != 0U);

    memset(&io, 0, sizeof(io));
    io.udp[0] = ssdp;
    io.udp_ip[0] = net.gateway_ipv4;
    io.udp_count = 1U;
    io.tcp[0] = duplicate_xml;
    io.tcp[1] = "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n";
    hooks = ops(&io, scratch, sizeof(scratch));
    assert(router_audit_collect(ROUTER_AUDIT_STANDARD_OWNED, &net, &hooks, &out) ==
           ROUTER_AUDIT_RESULT_PARTIAL);
    assert((out.error_mask & ROUTER_AUDIT_ERROR_XML) != 0U);

    memset(&io, 0, sizeof(io));
    {
        static const char malformed_body[] =
            "<root><device><service><manufacturer>Acme</manufacturer>"
            "<modelName>Router X</modelName><firmwareVersion>1</firmwareVersion>"
            "</device></root>";
        int written = snprintf(malformed_response, sizeof(malformed_response),
                               "HTTP/1.0 200 OK\r\nContent-Length: %u\r\n\r\n%s",
                               (unsigned)strlen(malformed_body), malformed_body);
        assert(written > 0 && (size_t)written < sizeof(malformed_response));
    }
    io.udp[0] = ssdp;
    io.udp_ip[0] = net.gateway_ipv4;
    io.udp_count = 1U;
    io.tcp[0] = malformed_response;
    io.tcp[1] = "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n";
    hooks = ops(&io, scratch, sizeof(scratch));
    assert(router_audit_collect(ROUTER_AUDIT_STANDARD_OWNED, &net, &hooks, &out) ==
           ROUTER_AUDIT_RESULT_PARTIAL);
    assert((out.error_mask & ROUTER_AUDIT_ERROR_XML) != 0U);
}

static void test_preconditions_cancellation_and_bounded_stagnant_io(void)
{
    fake_io_t io;
    uint8_t scratch[ROUTER_AUDIT_SCRATCH_MIN];
    router_audit_ops_t hooks;
    router_network_context_t net = network();
    router_evidence_set_t out;
    router_evidence_set_t sentinel;

    memset(&io, 0, sizeof(io));
    hooks = ops(&io, scratch, sizeof(scratch));
    memset(&sentinel, 0xA5, sizeof(sentinel));
    out = sentinel;
    net.gateway_ipv4 = IP(224, 0, 0, 1);
    assert(router_audit_collect(ROUTER_AUDIT_PASSIVE, &net, &hooks, &out) ==
           ROUTER_AUDIT_RESULT_PRECONDITION);
    assert(memcmp(&out, &sentinel, sizeof(out)) == 0);
    assert(io.open_udp == 0U && io.open_tcp == 0U);

    net = network();
    memset(net.dhcp_vendor, 'x', sizeof(net.dhcp_vendor));
    out = sentinel;
    assert(router_audit_collect(ROUTER_AUDIT_PASSIVE, &net, &hooks, &out) ==
           ROUTER_AUDIT_RESULT_PRECONDITION);
    assert(memcmp(&out, &sentinel, sizeof(out)) == 0);
    assert(io.open_udp == 0U && io.open_tcp == 0U);

    net = network();
    io.cancelled = true;
    assert(router_audit_collect(ROUTER_AUDIT_STANDARD_OWNED, &net, &hooks, &out) ==
           ROUTER_AUDIT_RESULT_CANCELLED);
    assert(io.open_udp == 0U && io.open_tcp == 0U);

    memset(&io, 0, sizeof(io));
    io.stagnant_clock = true;
    io.zero_send = true;
    hooks = ops(&io, scratch, sizeof(scratch));
    assert(router_audit_collect(ROUTER_AUDIT_STANDARD_OWNED, &net, &hooks, &out) ==
           ROUTER_AUDIT_RESULT_PARTIAL);
    assert(io.send_to_calls == 1U);
    assert(io.open_tcp == 1U); /* HEAD remains bounded after SSDP send failure. */
    assert(io.send_calls <= ROUTER_IO_OPERATION_MAX);
}

static void test_ssdp_four_response_cap_and_midflight_cancel(void)
{
    static const char response[] =
        "HTTP/1.1 200 OK\r\nSERVER: Router X\r\n\r\n";
    fake_io_t io;
    uint8_t scratch[ROUTER_AUDIT_SCRATCH_MIN];
    router_audit_ops_t hooks;
    router_network_context_t net = network();
    router_evidence_set_t out;
    size_t index;

    memset(&io, 0, sizeof(io));
    for (index = 0U; index < 6U; ++index) {
        io.udp[index] = response;
        io.udp_ip[index] = net.gateway_ipv4;
    }
    io.udp_count = 6U;
    io.tcp[0] = "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n";
    io.stagnant_clock = true;
    hooks = ops(&io, scratch, sizeof(scratch));
    assert(router_audit_collect(ROUTER_AUDIT_STANDARD_OWNED, &net, &hooks, &out) ==
           ROUTER_AUDIT_RESULT_OK);
    assert(io.recv_from_calls == ROUTER_SSDP_RESPONSE_MAX);
    assert(out.ssdp_responses == ROUTER_SSDP_RESPONSE_MAX);
    assert(io.udp_timeout_granted <= ROUTER_NETWORK_TIMEOUT_MS);
    assert(io.tcp_timeout_granted[0] <= ROUTER_NETWORK_TIMEOUT_MS);

    memset(&io, 0, sizeof(io));
    io.udp[0] = response;
    io.udp_ip[0] = net.gateway_ipv4;
    io.udp_count = 1U;
    io.cancel_after_receives = 1U;
    hooks = ops(&io, scratch, sizeof(scratch));
    assert(router_audit_collect(ROUTER_AUDIT_STANDARD_OWNED, &net, &hooks, &out) ==
           ROUTER_AUDIT_RESULT_CANCELLED);
    assert(io.open_tcp == 0U);
    assert(io.close_calls == 1U);
}

static void test_backwards_clock_and_oversized_header_fail_bounded(void)
{
    static char oversized[ROUTER_HTTP_HEADER_MAX + 32U];
    static const char ssdp[] =
        "HTTP/1.1 200 OK\r\nLOCATION: http://192.0.2.1/device.xml\r\n\r\n";
    fake_io_t io;
    uint8_t scratch[ROUTER_AUDIT_SCRATCH_MIN];
    router_audit_ops_t hooks;
    router_network_context_t net = network();
    router_evidence_set_t out;

    memset(oversized, 'A', sizeof(oversized) - 1U);
    oversized[sizeof(oversized) - 1U] = '\0';
    memset(&io, 0, sizeof(io));
    io.udp[0] = ssdp;
    io.udp_ip[0] = net.gateway_ipv4;
    io.udp_count = 1U;
    io.tcp[0] = oversized;
    io.tcp[1] = "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n";
    io.tcp_chunk = 512U;
    io.repeat_tcp = true;
    hooks = ops(&io, scratch, sizeof(scratch));
    assert(router_audit_collect(ROUTER_AUDIT_STANDARD_OWNED, &net, &hooks, &out) ==
           ROUTER_AUDIT_RESULT_PARTIAL);
    assert((out.error_mask & ROUTER_AUDIT_ERROR_HTTP) != 0U);
    assert(io.recv_calls < 10U); /* Header limit, not the generic I/O cap, stops it. */

    memset(&io, 0, sizeof(io));
    io.clock_backwards_at = 3U;
    io.udp[0] = ssdp;
    io.udp_ip[0] = net.gateway_ipv4;
    io.udp_count = 1U;
    io.tcp[0] = "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n";
    hooks = ops(&io, scratch, sizeof(scratch));
    assert(router_audit_collect(ROUTER_AUDIT_STANDARD_OWNED, &net, &hooks, &out) ==
           ROUTER_AUDIT_RESULT_PARTIAL);
    assert((out.error_mask & ROUTER_AUDIT_ERROR_CLOCK) != 0U);

    memset(&io, 0, sizeof(io));
    io.now_ms = UINT64_MAX - 1000U;
    hooks = ops(&io, scratch, sizeof(scratch));
    assert(router_audit_collect(ROUTER_AUDIT_STANDARD_OWNED, &net, &hooks, &out) ==
           ROUTER_AUDIT_RESULT_PARTIAL);
    assert((out.error_mask & ROUTER_AUDIT_ERROR_CLOCK) != 0U);
    assert(io.send_to_calls == 0U && io.connect_calls == 0U);
    assert(io.udp_timeout_granted == 0U && io.tcp_timeout_granted[0] == 0U);
}

int main(void)
{
    test_passive_has_zero_network_io();
    test_standard_is_gateway_only_and_collects_structured_evidence();
    test_hostile_locations_and_wrong_sources_are_rejected();
    test_malformed_chunked_duplicate_and_redirect_responses();
    test_preconditions_cancellation_and_bounded_stagnant_io();
    test_ssdp_four_response_cap_and_midflight_cancel();
    test_backwards_clock_and_oversized_header_fail_bounded();
    puts("PASS: bounded gateway-only router discovery");
    return 0;
}
