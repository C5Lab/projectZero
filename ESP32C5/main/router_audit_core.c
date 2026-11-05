#include "router_audit_core.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

#define ROUTER_SSDP_PORT 1900U
#define ROUTER_HTTP_PORT 80U
#define ROUTER_HTTP_TIMED_OPERATION_MAX 10U

typedef enum {
    STEP_OK = 0,
    STEP_ERROR,
    STEP_CANCELLED,
    STEP_CLOCK
} step_result_t;

typedef struct {
    uint64_t last_ms;
    uint64_t due_ms;
    uint32_t grant_remaining_ms;
    size_t operations_remaining;
} clock_guard_t;

typedef struct {
    unsigned status;
    bool location_present;
    char location[ROUTER_LOCATION_PATH_MAX + 64U];
    bool server_present;
    char server[ROUTER_EVIDENCE_TEXT_MAX + 1U];
    bool content_length_present;
    size_t content_length;
    bool transfer_encoding_present;
} http_fields_t;

typedef struct {
    bool present;
    bool conflict;
    char path[ROUTER_LOCATION_PATH_MAX + 1U];
} location_candidate_t;

static bool bounded_string(const char *value, size_t maximum, size_t *length)
{
    size_t index;

    if (value == NULL || length == NULL) return false;
    for (index = 0U; index <= maximum; ++index) {
        if (value[index] == '\0') {
            *length = index;
            return true;
        }
    }
    return false;
}

static bool copy_text(char *destination, size_t maximum, const char *source)
{
    size_t length;

    if (!bounded_string(source, maximum, &length)) return false;
    memcpy(destination, source, length + 1U);
    return true;
}

static bool mac_valid(const uint8_t mac[6])
{
    static const uint8_t zero[6] = {0U};
    static const uint8_t broadcast[6] = {
        0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU};

    return memcmp(mac, zero, sizeof(zero)) != 0 &&
           memcmp(mac, broadcast, sizeof(broadcast)) != 0 &&
           (mac[0] & 0x01U) == 0U;
}

static bool ipv4_unicast(uint32_t address)
{
    uint8_t first = (uint8_t)(address >> 24U);

    return address != 0U && address != UINT32_MAX && first != 0U &&
           first < 224U && first != 127U;
}

static bool netmask_contiguous(uint32_t mask)
{
    uint32_t inverse;

    if (mask == 0U || mask == UINT32_MAX) return false;
    inverse = ~mask;
    return (inverse & (inverse + 1U)) == 0U;
}

static bool network_valid(const router_network_context_t *network)
{
    uint32_t network_address;
    uint32_t broadcast_address;
    size_t ignored;

    if (network == NULL || !network->sta_connected ||
        !ipv4_unicast(network->local_ipv4) ||
        !ipv4_unicast(network->gateway_ipv4) ||
        !netmask_contiguous(network->netmask_ipv4) ||
        !bounded_string(network->dhcp_vendor, ROUTER_EVIDENCE_TEXT_MAX,
                        &ignored) ||
        !bounded_string(network->dhcp_model, ROUTER_EVIDENCE_TEXT_MAX,
                        &ignored)) {
        return false;
    }
    network_address = network->local_ipv4 & network->netmask_ipv4;
    broadcast_address = network_address | ~network->netmask_ipv4;
    if ((network->gateway_ipv4 & network->netmask_ipv4) != network_address ||
        network->local_ipv4 == network->gateway_ipv4 ||
        network->local_ipv4 == network_address ||
        network->local_ipv4 == broadcast_address ||
        network->gateway_ipv4 == network_address ||
        network->gateway_ipv4 == broadcast_address) {
        return false;
    }
    if ((network->bssid_known && !mac_valid(network->bssid)) ||
        (network->gateway_mac_known && !mac_valid(network->gateway_mac))) {
        return false;
    }
    return true;
}

static bool add_evidence(router_evidence_set_t *set,
                         router_evidence_source_t source,
                         bool locally_administered,
                         const char *vendor,
                         const char *model,
                         const char *firmware)
{
    router_evidence_t item;
    router_fingerprint_t validation;

    if (set->count >= ROUTER_EVIDENCE_MAX) {
        set->error_mask |= ROUTER_AUDIT_ERROR_CAPACITY;
        return false;
    }
    memset(&item, 0, sizeof(item));
    item.source = source;
    item.locally_administered_mac = locally_administered;
    if ((vendor != NULL && !copy_text(item.vendor, ROUTER_EVIDENCE_TEXT_MAX, vendor)) ||
        (model != NULL && !copy_text(item.model, ROUTER_EVIDENCE_TEXT_MAX, model)) ||
        (firmware != NULL &&
         !copy_text(item.firmware, ROUTER_EVIDENCE_TEXT_MAX, firmware))) {
        set->error_mask |= ROUTER_AUDIT_ERROR_CAPACITY;
        return false;
    }
    if (!router_fingerprint_normalize(&item, 1U, &validation)) {
        set->error_mask |= ROUTER_AUDIT_ERROR_EVIDENCE;
        return false;
    }
    set->items[set->count++] = item;
    return true;
}

static bool add_oui(router_evidence_set_t *set,
                    const router_audit_ops_t *ops,
                    const uint8_t mac[6])
{
    char vendor[ROUTER_EVIDENCE_TEXT_MAX + 1U];
    size_t ignored;

    if ((mac[0] & 0x02U) != 0U || ops->oui_lookup == NULL) return true;
    memset(vendor, 0, sizeof(vendor));
    if (!ops->oui_lookup(ops->context, mac, vendor)) return true;
    if (!bounded_string(vendor, ROUTER_EVIDENCE_TEXT_MAX, &ignored)) {
        set->error_mask |= ROUTER_AUDIT_ERROR_CAPACITY;
        return false;
    }
    return add_evidence(set, ROUTER_EVIDENCE_OUI, false, vendor, NULL, NULL);
}

static bool collect_passive(const router_network_context_t *network,
                            const router_audit_ops_t *ops,
                            router_evidence_set_t *set)
{
    size_t vendor_length;
    size_t model_length;

    set->gateway_ipv4 = network->gateway_ipv4;
    set->bssid_known = network->bssid_known;
    if (network->bssid_known) {
        memcpy(set->bssid, network->bssid, sizeof(set->bssid));
        (void)add_oui(set, ops, network->bssid);
    }
    set->gateway_mac_known = network->gateway_mac_known;
    if (network->gateway_mac_known) {
        memcpy(set->gateway_mac, network->gateway_mac, sizeof(set->gateway_mac));
        (void)add_oui(set, ops, network->gateway_mac);
    }
    if (!bounded_string(network->dhcp_vendor, ROUTER_EVIDENCE_TEXT_MAX,
                        &vendor_length) ||
        !bounded_string(network->dhcp_model, ROUTER_EVIDENCE_TEXT_MAX,
                        &model_length)) {
        return false;
    }
    if (vendor_length > 0U || model_length > 0U) {
        (void)add_evidence(set, ROUTER_EVIDENCE_DHCP, false,
                           network->dhcp_vendor, network->dhcp_model, NULL);
    }
    return true;
}

static bool ops_valid(router_audit_mode_t mode, const router_audit_ops_t *ops)
{
    if (ops == NULL) return false;
    if (mode == ROUTER_AUDIT_PASSIVE) return true;
    return mode == ROUTER_AUDIT_STANDARD_OWNED &&
           ops->socket_open != NULL && ops->socket_set_timeout != NULL &&
           ops->socket_send_to != NULL && ops->socket_recv_from != NULL &&
           ops->socket_connect != NULL && ops->socket_send != NULL &&
           ops->socket_recv != NULL && ops->socket_close != NULL &&
           ops->monotonic_ms != NULL && ops->cancelled != NULL &&
           ops->scratch != NULL &&
           ops->scratch_capacity >= ROUTER_AUDIT_SCRATCH_MIN;
}

static bool clock_begin(const router_audit_ops_t *ops, clock_guard_t *guard,
                        size_t operation_budget)
{
    guard->last_ms = ops->monotonic_ms(ops->context);
    if (guard->last_ms > UINT64_MAX - ROUTER_NETWORK_TIMEOUT_MS ||
        operation_budget == 0U) return false;
    guard->due_ms = guard->last_ms + ROUTER_NETWORK_TIMEOUT_MS;
    guard->grant_remaining_ms = ROUTER_NETWORK_TIMEOUT_MS;
    guard->operations_remaining = operation_budget;
    return true;
}

static step_result_t clock_check(const router_audit_ops_t *ops,
                                 clock_guard_t *guard)
{
    uint64_t now;

    if (ops->cancelled(ops->context)) return STEP_CANCELLED;
    now = ops->monotonic_ms(ops->context);
    if (now < guard->last_ms) return STEP_CLOCK;
    guard->last_ms = now;
    return now >= guard->due_ms ? STEP_ERROR : STEP_OK;
}

static step_result_t prepare_timed_io(const router_audit_ops_t *ops,
                                      int socket_fd,
                                      clock_guard_t *guard,
                                      uint32_t *granted_timeout_ms)
{
    step_result_t result = clock_check(ops, guard);
    uint64_t observed_remaining;
    uint32_t available;
    uint32_t grant;

    if (result != STEP_OK || guard->operations_remaining == 0U ||
        guard->grant_remaining_ms == 0U) return result != STEP_OK ? result : STEP_ERROR;
    observed_remaining = guard->due_ms - guard->last_ms;
    available = guard->grant_remaining_ms;
    if (observed_remaining < available) available = (uint32_t)observed_remaining;
    if (available == 0U) return STEP_ERROR;
    grant = (available + (uint32_t)guard->operations_remaining - 1U) /
            (uint32_t)guard->operations_remaining;
    if (grant == 0U || grant > available) return STEP_ERROR;
    guard->grant_remaining_ms = available - grant;
    --guard->operations_remaining;
    if (!ops->socket_set_timeout(ops->context, socket_fd, grant)) return STEP_ERROR;
    if (granted_timeout_ms != NULL) *granted_timeout_ms = grant;
    return STEP_OK;
}

static bool ascii_equal(const uint8_t *bytes, size_t length, const char *text)
{
    size_t index;

    if (strlen(text) != length) return false;
    for (index = 0U; index < length; ++index) {
        uint8_t left = bytes[index];
        uint8_t right = (uint8_t)text[index];
        if (left >= (uint8_t)'A' && left <= (uint8_t)'Z') left += 32U;
        if (right >= (uint8_t)'A' && right <= (uint8_t)'Z') right += 32U;
        if (left != right) return false;
    }
    return true;
}

static const uint8_t *find_bytes(const uint8_t *bytes, size_t length,
                                 const char *needle)
{
    size_t needle_length = strlen(needle);
    size_t index;

    if (needle_length == 0U || needle_length > length) return NULL;
    for (index = 0U; index + needle_length <= length; ++index) {
        if (memcmp(&bytes[index], needle, needle_length) == 0) return &bytes[index];
    }
    return NULL;
}

static bool find_header_end(const uint8_t *bytes, size_t length, size_t *end)
{
    const uint8_t *match = find_bytes(bytes, length, "\r\n\r\n");

    if (match == NULL) return false;
    *end = (size_t)(match - bytes) + 4U;
    return true;
}

static bool header_value_copy(char *destination, size_t maximum,
                              const uint8_t *bytes, size_t length)
{
    size_t start = 0U;
    size_t end = length;
    size_t index;

    while (start < end && (bytes[start] == (uint8_t)' ' ||
                           bytes[start] == (uint8_t)'\t')) {
        ++start;
    }
    while (end > start && (bytes[end - 1U] == (uint8_t)' ' ||
                           bytes[end - 1U] == (uint8_t)'\t')) {
        --end;
    }
    if (end - start > maximum) return false;
    for (index = start; index < end; ++index) {
        if (bytes[index] < 0x20U || bytes[index] == 0x7FU) return false;
    }
    memcpy(destination, &bytes[start], end - start);
    destination[end - start] = '\0';
    return true;
}

static bool parse_size(const uint8_t *bytes, size_t length, size_t *value)
{
    size_t start = 0U;
    size_t end = length;
    size_t result = 0U;
    size_t index;

    while (start < end && (bytes[start] == (uint8_t)' ' ||
                           bytes[start] == (uint8_t)'\t')) ++start;
    while (end > start && (bytes[end - 1U] == (uint8_t)' ' ||
                           bytes[end - 1U] == (uint8_t)'\t')) --end;
    if (start == end) return false;
    for (index = start; index < end; ++index) {
        unsigned digit;
        if (bytes[index] < (uint8_t)'0' || bytes[index] > (uint8_t)'9') {
            return false;
        }
        digit = (unsigned)(bytes[index] - (uint8_t)'0');
        if (result > (SIZE_MAX - digit) / 10U) return false;
        result = result * 10U + digit;
    }
    *value = result;
    return true;
}

static bool parse_http_header(const uint8_t *bytes, size_t header_length,
                              http_fields_t *fields)
{
    size_t line_start = 0U;
    size_t line_end;
    bool first = true;

    if (header_length < 4U || header_length > ROUTER_HTTP_HEADER_MAX) return false;
    memset(fields, 0, sizeof(*fields));
    while (line_start + 1U < header_length) {
        const uint8_t *crlf = find_bytes(&bytes[line_start],
                                         header_length - line_start, "\r\n");
        size_t colon;
        size_t name_length;
        size_t value_start;

        if (crlf == NULL) return false;
        line_end = (size_t)(crlf - bytes);
        if (first) {
            size_t line_length = line_end - line_start;
            size_t status_index;
            if (line_length < 12U ||
                (memcmp(bytes, "HTTP/1.0 ", 9U) != 0 &&
                 memcmp(bytes, "HTTP/1.1 ", 9U) != 0) ||
                bytes[9] < (uint8_t)'0' || bytes[9] > (uint8_t)'9' ||
                bytes[10] < (uint8_t)'0' || bytes[10] > (uint8_t)'9' ||
                bytes[11] < (uint8_t)'0' || bytes[11] > (uint8_t)'9' ||
                (line_length > 12U && bytes[12] != (uint8_t)' ')) {
                return false;
            }
            for (status_index = 12U; status_index < line_length; ++status_index) {
                if (bytes[status_index] < 0x20U ||
                    bytes[status_index] == 0x7FU) return false;
            }
            fields->status = (unsigned)(bytes[9] - (uint8_t)'0') * 100U +
                             (unsigned)(bytes[10] - (uint8_t)'0') * 10U +
                             (unsigned)(bytes[11] - (uint8_t)'0');
            first = false;
            line_start = line_end + 2U;
            continue;
        }
        if (line_end == line_start) return line_end + 2U == header_length;
        if (bytes[line_start] == (uint8_t)' ' ||
            bytes[line_start] == (uint8_t)'\t') return false;
        colon = line_start;
        while (colon < line_end && bytes[colon] != (uint8_t)':') ++colon;
        if (colon == line_start || colon == line_end) return false;
        name_length = colon - line_start;
        value_start = colon + 1U;
        {
            size_t name_index;
            for (name_index = 0U; name_index < name_length; ++name_index) {
                uint8_t byte = bytes[line_start + name_index];
                if (!((byte >= (uint8_t)'0' && byte <= (uint8_t)'9') ||
                      (byte >= (uint8_t)'A' && byte <= (uint8_t)'Z') ||
                      (byte >= (uint8_t)'a' && byte <= (uint8_t)'z') ||
                      byte == (uint8_t)'-')) {
                    return false;
                }
            }
        }

        if (ascii_equal(&bytes[line_start], name_length, "location")) {
            if (fields->location_present ||
                !header_value_copy(fields->location,
                                   sizeof(fields->location) - 1U,
                                   &bytes[value_start], line_end - value_start)) {
                return false;
            }
            fields->location_present = true;
        } else if (ascii_equal(&bytes[line_start], name_length, "server")) {
            if (fields->server_present ||
                !header_value_copy(fields->server,
                                   ROUTER_EVIDENCE_TEXT_MAX,
                                   &bytes[value_start], line_end - value_start)) {
                return false;
            }
            fields->server_present = true;
        } else if (ascii_equal(&bytes[line_start], name_length,
                               "content-length")) {
            if (fields->content_length_present ||
                !parse_size(&bytes[value_start], line_end - value_start,
                            &fields->content_length)) {
                return false;
            }
            fields->content_length_present = true;
        } else if (ascii_equal(&bytes[line_start], name_length,
                               "transfer-encoding")) {
            char value[32];
            if (fields->transfer_encoding_present ||
                !header_value_copy(value, sizeof(value) - 1U,
                                   &bytes[value_start], line_end - value_start) ||
                value[0] == '\0') {
                return false;
            }
            fields->transfer_encoding_present = true;
        } else {
            size_t index;
            for (index = value_start; index < line_end; ++index) {
                if ((bytes[index] < 0x20U && bytes[index] != (uint8_t)'\t') ||
                    bytes[index] == 0x7FU) return false;
            }
        }
        line_start = line_end + 2U;
    }
    return false;
}

static void ipv4_text(uint32_t address, char output[16])
{
    (void)snprintf(output, 16U, "%u.%u.%u.%u",
                   (unsigned)((address >> 24U) & 0xFFU),
                   (unsigned)((address >> 16U) & 0xFFU),
                   (unsigned)((address >> 8U) & 0xFFU),
                   (unsigned)(address & 0xFFU));
}

static bool parse_location(const char *location, uint32_t gateway,
                           char path[ROUTER_LOCATION_PATH_MAX + 1U])
{
    char host[16];
    char authority[24];
    size_t length;
    size_t authority_length = 0U;
    size_t path_length;
    size_t index;
    const char *cursor;

    if (!bounded_string(location, sizeof(((http_fields_t *)0)->location) - 1U,
                        &length) || length < 8U ||
        memcmp(location, "http://", 7U) != 0) {
        return false;
    }
    cursor = location + 7U;
    while (cursor[authority_length] != '\0' &&
           cursor[authority_length] != '/') {
        if (authority_length + 1U >= sizeof(authority)) return false;
        authority[authority_length] = cursor[authority_length];
        ++authority_length;
    }
    authority[authority_length] = '\0';
    if (cursor[authority_length] != '/') return false;
    ipv4_text(gateway, host);
    if (strcmp(authority, host) != 0) {
        char host_port[24];
        int written = snprintf(host_port, sizeof(host_port), "%s:80", host);
        if (written <= 0 || (size_t)written >= sizeof(host_port) ||
            strcmp(authority, host_port) != 0) return false;
    }
    cursor += authority_length;
    path_length = strlen(cursor);
    if (path_length == 0U || path_length > ROUTER_LOCATION_PATH_MAX) return false;
    for (index = 0U; index < path_length; ++index) {
        uint8_t byte = (uint8_t)cursor[index];
        if (byte < 0x21U || byte > 0x7EU || byte == (uint8_t)'?' ||
            byte == (uint8_t)'#' || byte == (uint8_t)'\\' ||
            byte == (uint8_t)'@') return false;
    }
    memcpy(path, cursor, path_length + 1U);
    return true;
}

static step_result_t send_all(const router_audit_ops_t *ops, int socket_fd,
                              const uint8_t *bytes, size_t length,
                              clock_guard_t *clock)
{
    size_t offset = 0U;
    size_t operations = 0U;

    while (offset < length && operations < ROUTER_IO_OPERATION_MAX) {
        int64_t sent;
        step_result_t check = prepare_timed_io(ops, socket_fd, clock, NULL);
        if (check != STEP_OK) return check;
        sent = ops->socket_send(ops->context, socket_fd,
                                &bytes[offset], length - offset);
        if (sent <= 0 || (uint64_t)sent > (uint64_t)(length - offset)) {
            return STEP_ERROR;
        }
        offset += (size_t)sent;
        ++operations;
    }
    return offset == length ? STEP_OK : STEP_ERROR;
}

static step_result_t receive_http(const router_audit_ops_t *ops, int socket_fd,
                                  bool expect_body, clock_guard_t *clock,
                                  size_t *total, size_t *header_end,
                                  http_fields_t *fields)
{
    size_t used = 0U;
    size_t operations = 0U;
    bool header_parsed = false;
    const size_t limit = ROUTER_AUDIT_SCRATCH_MIN - 1U;

    while (operations < ROUTER_IO_OPERATION_MAX) {
        int64_t received;
        step_result_t check = prepare_timed_io(ops, socket_fd, clock, NULL);
        if (check != STEP_OK) return check;
        if (used >= limit) return STEP_ERROR;
        received = ops->socket_recv(ops->context, socket_fd,
                                    &ops->scratch[used], limit - used);
        ++operations;
        if (received < 0 || (uint64_t)received > (uint64_t)(limit - used)) {
            return STEP_ERROR;
        }
        if (received == 0) return STEP_ERROR;
        used += (size_t)received;
        ops->scratch[used] = '\0';
        if (!header_parsed && used > ROUTER_HTTP_HEADER_MAX) return STEP_ERROR;
        if (!header_parsed && find_header_end(ops->scratch, used, header_end)) {
            if (!parse_http_header(ops->scratch, *header_end, fields) ||
                fields->status != 200U || fields->transfer_encoding_present) {
                return STEP_ERROR;
            }
            header_parsed = true;
            if (!expect_body) {
                *total = used;
                return STEP_OK;
            }
            if (!fields->content_length_present ||
                fields->content_length > ROUTER_UPNP_XML_MAX) {
                return STEP_ERROR;
            }
        }
        if (header_parsed && expect_body) {
            size_t expected = *header_end + fields->content_length;
            if (used == expected) {
                *total = used;
                return STEP_OK;
            }
            if (used > expected) return STEP_ERROR;
        }
    }
    return STEP_ERROR;
}

static step_result_t http_request(const router_audit_ops_t *ops,
                                  uint32_t gateway, const char *request,
                                  bool expect_body, size_t *total,
                                  size_t *header_end, http_fields_t *fields,
                                  bool *request_sent)
{
    int socket_fd;
    step_result_t result = STEP_ERROR;
    clock_guard_t clock;
    uint32_t connect_timeout_ms;

    if (request_sent != NULL) *request_sent = false;
    socket_fd = ops->socket_open(ops->context, ROUTER_SOCKET_TCP);
    if (socket_fd < 0) return STEP_ERROR;
    if (!clock_begin(ops, &clock, ROUTER_HTTP_TIMED_OPERATION_MAX)) {
        ops->socket_close(ops->context, socket_fd);
        return STEP_CLOCK;
    }
    result = prepare_timed_io(ops, socket_fd, &clock, &connect_timeout_ms);
    if (result != STEP_OK ||
        !ops->socket_connect(ops->context, socket_fd, gateway,
                             ROUTER_HTTP_PORT, connect_timeout_ms)) {
        ops->socket_close(ops->context, socket_fd);
        return result == STEP_OK ? STEP_ERROR : result;
    }
    result = send_all(ops, socket_fd, (const uint8_t *)request,
                      strlen(request), &clock);
    if (result == STEP_OK) {
        if (request_sent != NULL) *request_sent = true;
        result = receive_http(ops, socket_fd, expect_body, &clock,
                              total, header_end, fields);
    }
    ops->socket_close(ops->context, socket_fd);
    return result;
}

static bool copy_xml_value(const uint8_t *start, size_t value_length,
                           char output[ROUTER_EVIDENCE_TEXT_MAX + 1U])
{
    size_t left;
    size_t right;
    size_t index;

    left = 0U;
    right = value_length;
    while (left < right && (start[left] == (uint8_t)' ' ||
                            start[left] == (uint8_t)'\t' ||
                            start[left] == (uint8_t)'\r' ||
                            start[left] == (uint8_t)'\n')) ++left;
    while (right > left && (start[right - 1U] == (uint8_t)' ' ||
                            start[right - 1U] == (uint8_t)'\t' ||
                            start[right - 1U] == (uint8_t)'\r' ||
                            start[right - 1U] == (uint8_t)'\n')) --right;
    if (right - left > ROUTER_EVIDENCE_TEXT_MAX) return false;
    for (index = left; index < right; ++index) {
        if (start[index] == (uint8_t)'<' || start[index] == (uint8_t)'&' ||
            (start[index] < 0x20U && start[index] != (uint8_t)'\t' &&
             start[index] != (uint8_t)'\r' && start[index] != (uint8_t)'\n') ||
            start[index] == 0x7FU) return false;
    }
    memcpy(output, &start[left], right - left);
    output[right - left] = '\0';
    return true;
}

static size_t utf8_length(const uint8_t *bytes, size_t remaining)
{
    uint8_t first = bytes[0];

    if (first < 0x80U) return 1U;
    if (first >= 0xC2U && first <= 0xDFU) {
        return remaining >= 2U && bytes[1] >= 0x80U && bytes[1] <= 0xBFU
                   ? 2U : 0U;
    }
    if (first >= 0xE0U && first <= 0xEFU) {
        if (remaining < 3U || bytes[2] < 0x80U || bytes[2] > 0xBFU) return 0U;
        if (first == 0xE0U) {
            return bytes[1] >= 0xA0U && bytes[1] <= 0xBFU ? 3U : 0U;
        }
        if (first == 0xEDU) {
            return bytes[1] >= 0x80U && bytes[1] <= 0x9FU ? 3U : 0U;
        }
        return bytes[1] >= 0x80U && bytes[1] <= 0xBFU ? 3U : 0U;
    }
    if (first >= 0xF0U && first <= 0xF4U) {
        if (remaining < 4U || bytes[2] < 0x80U || bytes[2] > 0xBFU ||
            bytes[3] < 0x80U || bytes[3] > 0xBFU) return 0U;
        if (first == 0xF0U) {
            return bytes[1] >= 0x90U && bytes[1] <= 0xBFU ? 4U : 0U;
        }
        if (first == 0xF4U) {
            return bytes[1] >= 0x80U && bytes[1] <= 0x8FU ? 4U : 0U;
        }
        return bytes[1] >= 0x80U && bytes[1] <= 0xBFU ? 4U : 0U;
    }
    return 0U;
}

static bool utf8_valid(const uint8_t *bytes, size_t length)
{
    size_t offset = 0U;

    while (offset < length) {
        size_t sequence = utf8_length(&bytes[offset], length - offset);
        if (sequence == 0U) return false;
        offset += sequence;
    }
    return true;
}

static bool xml_space(uint8_t byte)
{
    return byte == (uint8_t)' ' || byte == (uint8_t)'\t' ||
           byte == (uint8_t)'\r' || byte == (uint8_t)'\n';
}

static bool xml_name_start(uint8_t byte)
{
    return (byte >= (uint8_t)'A' && byte <= (uint8_t)'Z') ||
           (byte >= (uint8_t)'a' && byte <= (uint8_t)'z') ||
           byte == (uint8_t)'_' || byte == (uint8_t)':';
}

static bool xml_name_continue(uint8_t byte)
{
    return xml_name_start(byte) ||
           (byte >= (uint8_t)'0' && byte <= (uint8_t)'9') ||
           byte == (uint8_t)'-' || byte == (uint8_t)'.';
}

static void skip_xml_space(const uint8_t *xml, size_t length, size_t *position)
{
    while (*position < length && xml_space(xml[*position])) ++*position;
}

static bool parse_xml_name(const uint8_t *xml, size_t length,
                           size_t *position, char output[33])
{
    size_t start = *position;
    size_t name_length;

    if (start >= length || !xml_name_start(xml[start])) return false;
    ++*position;
    while (*position < length && xml_name_continue(xml[*position])) ++*position;
    name_length = *position - start;
    if (name_length > 32U) return false;
    memcpy(output, &xml[start], name_length);
    output[name_length] = '\0';
    return true;
}

static bool xml_document_well_formed(const uint8_t *xml, size_t length)
{
    char stack[16][33];
    size_t depth = 0U;
    size_t position = 0U;
    bool root_seen = false;

    if (!utf8_valid(xml, length)) return false;
    skip_xml_space(xml, length, &position);
    if (position + 5U <= length && memcmp(&xml[position], "<?xml", 5U) == 0) {
        const uint8_t *end = find_bytes(&xml[position], length - position, "?>");
        if (end == NULL || (size_t)(end - &xml[position]) + 2U > 128U) {
            return false;
        }
        position = (size_t)(end - xml) + 2U;
        skip_xml_space(xml, length, &position);
    }
    while (position < length) {
        if (xml[position] != (uint8_t)'<') {
            size_t sequence;
            if (depth == 0U || xml[position] == (uint8_t)'&' ||
                (xml[position] < 0x20U && !xml_space(xml[position])) ||
                xml[position] == 0x7FU) return false;
            sequence = utf8_length(&xml[position], length - position);
            if (sequence == 0U) return false;
            position += sequence;
            continue;
        }
        if (position + 1U >= length || xml[position + 1U] == (uint8_t)'!' ||
            xml[position + 1U] == (uint8_t)'?') return false;
        if (xml[position + 1U] == (uint8_t)'/') {
            char name[33];
            position += 2U;
            if (!parse_xml_name(xml, length, &position, name)) return false;
            skip_xml_space(xml, length, &position);
            if (position >= length || xml[position] != (uint8_t)'>' ||
                depth == 0U || strcmp(name, stack[depth - 1U]) != 0) return false;
            --depth;
            ++position;
            if (depth == 0U) {
                skip_xml_space(xml, length, &position);
                return root_seen && position == length;
            }
            continue;
        }
        {
            char name[33];
            bool self_closing = false;
            ++position;
            if (!parse_xml_name(xml, length, &position, name)) return false;
            for (;;) {
                char attribute[33];
                uint8_t quote;
                skip_xml_space(xml, length, &position);
                if (position >= length) return false;
                if (xml[position] == (uint8_t)'>') {
                    ++position;
                    break;
                }
                if (xml[position] == (uint8_t)'/' && position + 1U < length &&
                    xml[position + 1U] == (uint8_t)'>') {
                    position += 2U;
                    self_closing = true;
                    break;
                }
                if (!parse_xml_name(xml, length, &position, attribute)) return false;
                skip_xml_space(xml, length, &position);
                if (position >= length || xml[position] != (uint8_t)'=') return false;
                ++position;
                skip_xml_space(xml, length, &position);
                if (position >= length ||
                    (xml[position] != (uint8_t)'\'' &&
                     xml[position] != (uint8_t)'\"')) return false;
                quote = xml[position++];
                while (position < length && xml[position] != quote) {
                    if (xml[position] == (uint8_t)'<' ||
                        xml[position] == (uint8_t)'&' ||
                        (xml[position] < 0x20U && !xml_space(xml[position])) ||
                        xml[position] == 0x7FU) return false;
                    ++position;
                }
                if (position >= length) return false;
                ++position;
            }
            if (depth == 0U) {
                if (root_seen || strcmp(name, "root") != 0 || self_closing) {
                    return false;
                }
                root_seen = true;
            }
            if (!self_closing) {
                if (depth >= sizeof(stack) / sizeof(stack[0])) return false;
                memcpy(stack[depth], name, strlen(name) + 1U);
                ++depth;
            }
        }
    }
    return root_seen && depth == 0U;
}

typedef struct {
    bool closing;
    bool self_closing;
    bool has_attributes;
    char name[33];
    size_t end;
} xml_tag_t;

static bool read_xml_tag(const uint8_t *xml, size_t length,
                         size_t start, xml_tag_t *tag)
{
    size_t position;
    size_t after_name;
    uint8_t quote = 0U;
    size_t last_non_space;

    if (start >= length || xml[start] != (uint8_t)'<' || tag == NULL) return false;
    memset(tag, 0, sizeof(*tag));
    position = start + 1U;
    if (position < length && xml[position] == (uint8_t)'/') {
        tag->closing = true;
        ++position;
    }
    if (!parse_xml_name(xml, length, &position, tag->name)) return false;
    after_name = position;
    skip_xml_space(xml, length, &position);
    if (tag->closing) {
        if (position >= length || xml[position] != (uint8_t)'>') return false;
        tag->end = position + 1U;
        return true;
    }
    tag->has_attributes = position > after_name && position < length &&
                          xml[position] != (uint8_t)'>' &&
                          xml[position] != (uint8_t)'/';
    last_non_space = position;
    for (; position < length; ++position) {
        uint8_t byte = xml[position];
        if (quote != 0U) {
            if (byte == quote) quote = 0U;
            continue;
        }
        if (byte == (uint8_t)'\'' || byte == (uint8_t)'\"') {
            quote = byte;
            tag->has_attributes = true;
            continue;
        }
        if (byte == (uint8_t)'>') {
            tag->self_closing = last_non_space < position &&
                                xml[last_non_space] == (uint8_t)'/';
            tag->end = position + 1U;
            return true;
        }
        if (!xml_space(byte)) last_non_space = position;
        if (byte != (uint8_t)'/') tag->has_attributes = true;
    }
    return false;
}

static bool locate_direct_element(const uint8_t *xml, size_t length,
                                  const char *target,
                                  const uint8_t **body, size_t *body_length)
{
    size_t position = 0U;
    size_t depth = 0U;
    bool found = false;
    bool closed = false;
    const uint8_t *start = NULL;

    while (position < length) {
        const uint8_t *next = memchr(&xml[position], '<', length - position);
        size_t tag_start;
        xml_tag_t tag;

        if (next == NULL) break;
        tag_start = (size_t)(next - xml);
        if (!read_xml_tag(xml, length, tag_start, &tag)) return false;
        if (tag.closing) {
            if (depth == 0U) return false;
            --depth;
            if (found && !closed && depth == 0U) {
                if (strcmp(tag.name, target) != 0) return false;
                *body = start;
                *body_length = tag_start - (size_t)(start - xml);
                closed = true;
            }
        } else if (strcmp(tag.name, target) == 0) {
            if (depth != 0U || found || tag.self_closing || tag.has_attributes) {
                return false;
            }
            found = true;
            start = &xml[tag.end];
            ++depth;
        } else if (!tag.self_closing) {
            ++depth;
        }
        position = tag.end;
    }
    return found && closed && depth == 0U;
}

static int identity_field_index(const char *name)
{
    if (strcmp(name, "manufacturer") == 0) return 0;
    if (strcmp(name, "modelName") == 0) return 1;
    if (strcmp(name, "modelNumber") == 0) return 2;
    if (strcmp(name, "firmwareVersion") == 0) return 3;
    return -1;
}

static bool extract_direct_identity(
    const uint8_t *xml, size_t length,
    char manufacturer[ROUTER_EVIDENCE_TEXT_MAX + 1U],
    char model_name[ROUTER_EVIDENCE_TEXT_MAX + 1U],
    char model_number[ROUTER_EVIDENCE_TEXT_MAX + 1U],
    char firmware[ROUTER_EVIDENCE_TEXT_MAX + 1U])
{
    char *outputs[4] = {manufacturer, model_name, model_number, firmware};
    bool seen[4] = {false, false, false, false};
    size_t position = 0U;
    size_t depth = 0U;

    memset(manufacturer, 0, ROUTER_EVIDENCE_TEXT_MAX + 1U);
    memset(model_name, 0, ROUTER_EVIDENCE_TEXT_MAX + 1U);
    memset(model_number, 0, ROUTER_EVIDENCE_TEXT_MAX + 1U);
    memset(firmware, 0, ROUTER_EVIDENCE_TEXT_MAX + 1U);
    while (position < length) {
        const uint8_t *next = memchr(&xml[position], '<', length - position);
        size_t tag_start;
        xml_tag_t tag;
        int field;

        if (next == NULL) break;
        tag_start = (size_t)(next - xml);
        if (!read_xml_tag(xml, length, tag_start, &tag)) return false;
        field = identity_field_index(tag.name);
        if (tag.closing) {
            if (depth == 0U || field >= 0) return false;
            --depth;
            position = tag.end;
            continue;
        }
        if (strcmp(tag.name, "device") == 0) return false;
        if (field >= 0) {
            const uint8_t *closing_start;
            xml_tag_t closing;
            if (depth != 0U || seen[field] || tag.self_closing ||
                tag.has_attributes) return false;
            closing_start = memchr(&xml[tag.end], '<', length - tag.end);
            if (closing_start == NULL ||
                !read_xml_tag(xml, length,
                              (size_t)(closing_start - xml), &closing) ||
                !closing.closing || strcmp(closing.name, tag.name) != 0 ||
                !copy_xml_value(&xml[tag.end],
                                (size_t)(closing_start - &xml[tag.end]),
                                outputs[field])) {
                return false;
            }
            seen[field] = true;
            position = closing.end;
            continue;
        }
        if (!tag.self_closing) ++depth;
        position = tag.end;
    }
    return depth == 0U;
}

static bool parse_xml(const uint8_t *xml, size_t length,
                      router_evidence_t *item)
{
    char manufacturer[ROUTER_EVIDENCE_TEXT_MAX + 1U];
    char model_name[ROUTER_EVIDENCE_TEXT_MAX + 1U];
    char model_number[ROUTER_EVIDENCE_TEXT_MAX + 1U];
    char firmware[ROUTER_EVIDENCE_TEXT_MAX + 1U];
    const uint8_t *device_start;
    const uint8_t *root_open_end;
    const uint8_t *root_close;
    const uint8_t *content;
    size_t content_length;
    size_t device_length;
    size_t position = 0U;
    int written;

    if (length == 0U || memchr(xml, '\0', length) != NULL ||
        !xml_document_well_formed(xml, length)) return false;
    while (position < length &&
           (xml[position] == (uint8_t)' ' || xml[position] == (uint8_t)'\t' ||
            xml[position] == (uint8_t)'\r' || xml[position] == (uint8_t)'\n')) {
        ++position;
    }
    if (position + 5U <= length &&
        memcmp(&xml[position], "<?xml", 5U) == 0) {
        const uint8_t *declaration_end = find_bytes(
            &xml[position], length - position, "?>");
        size_t declaration_length;
        size_t index;
        if (declaration_end == NULL || position + 5U >= length ||
            (xml[position + 5U] != (uint8_t)' ' &&
             xml[position + 5U] != (uint8_t)'\t' &&
             xml[position + 5U] != (uint8_t)'?' &&
             xml[position + 5U] != (uint8_t)'\r' &&
             xml[position + 5U] != (uint8_t)'\n')) return false;
        declaration_length = (size_t)(declaration_end - &xml[position]) + 2U;
        if (declaration_length > 128U) return false;
        for (index = position; index < position + declaration_length; ++index) {
            if ((xml[index] < 0x20U && xml[index] != (uint8_t)'\t' &&
                 xml[index] != (uint8_t)'\r' && xml[index] != (uint8_t)'\n') ||
                xml[index] == 0x7FU) return false;
        }
        position += declaration_length;
        while (position < length &&
               (xml[position] == (uint8_t)' ' ||
                xml[position] == (uint8_t)'\t' ||
                xml[position] == (uint8_t)'\r' ||
                xml[position] == (uint8_t)'\n')) ++position;
    }
    if (position + 6U > length || memcmp(&xml[position], "<root", 5U) != 0 ||
        (xml[position + 5U] != (uint8_t)'>' &&
         xml[position + 5U] != (uint8_t)' ' &&
         xml[position + 5U] != (uint8_t)'\t')) return false;
    root_open_end = memchr(&xml[position], '>', length - position);
    if (root_open_end == NULL ||
        (size_t)(root_open_end - &xml[position]) > 256U) return false;
    {
        const uint8_t *cursor;
        for (cursor = &xml[position]; cursor < root_open_end; ++cursor) {
            if (*cursor == (uint8_t)'<' && cursor != &xml[position]) return false;
            if (*cursor == (uint8_t)'&' || *cursor == 0x7FU ||
                (*cursor < 0x20U && *cursor != (uint8_t)'\t' &&
                 *cursor != (uint8_t)'\r' && *cursor != (uint8_t)'\n')) {
                return false;
            }
        }
    }
    content = root_open_end + 1U;
    root_close = find_bytes(content, length - (size_t)(content - xml), "</root>");
    if (root_close == NULL) return false;
    position = (size_t)(root_close - xml) + strlen("</root>");
    while (position < length &&
           (xml[position] == (uint8_t)' ' || xml[position] == (uint8_t)'\t' ||
            xml[position] == (uint8_t)'\r' || xml[position] == (uint8_t)'\n')) {
        ++position;
    }
    if (position != length) return false;
    content_length = (size_t)(root_close - content);
    if (find_bytes(content, content_length, "<!") != NULL ||
        find_bytes(content, content_length, "<?") != NULL) return false;
    if (!locate_direct_element(content, content_length, "device",
                               &device_start, &device_length) ||
        !extract_direct_identity(device_start, device_length,
                                 manufacturer, model_name,
                                 model_number, firmware)) {
        return false;
    }
    memset(item, 0, sizeof(*item));
    item->source = ROUTER_EVIDENCE_UPNP_STRUCTURED;
    memcpy(item->vendor, manufacturer, strlen(manufacturer) + 1U);
    memcpy(item->firmware, firmware, strlen(firmware) + 1U);
    if (model_name[0] != '\0' && model_number[0] != '\0') {
        written = snprintf(item->model, sizeof(item->model), "%s %s",
                           model_name, model_number);
        if (written <= 0 || (size_t)written >= sizeof(item->model)) return false;
    } else if (model_name[0] != '\0') {
        memcpy(item->model, model_name, strlen(model_name) + 1U);
    } else {
        memcpy(item->model, model_number, strlen(model_number) + 1U);
    }
    return item->vendor[0] != '\0' || item->model[0] != '\0' ||
           item->firmware[0] != '\0';
}

static void collect_ssdp(const router_network_context_t *network,
                         const router_audit_ops_t *ops,
                         router_evidence_set_t *set,
                         location_candidate_t *location,
                         bool *cancelled)
{
    static const char request_suffix[] =
        "\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\n"
        "ST: upnp:rootdevice\r\n\r\n";
    char request[192];
    char gateway_text[16];
    int socket_fd;
    int written;
    size_t response_index;
    clock_guard_t clock;

    *cancelled = false;
    ipv4_text(network->gateway_ipv4, gateway_text);
    written = snprintf(request, sizeof(request),
                       "M-SEARCH * HTTP/1.1\r\nHOST: %s:1900%s",
                       gateway_text, request_suffix);
    if (written <= 0 || (size_t)written >= sizeof(request)) {
        set->error_mask |= ROUTER_AUDIT_ERROR_SSDP_IO;
        return;
    }
    socket_fd = ops->socket_open(ops->context, ROUTER_SOCKET_UDP);
    if (socket_fd < 0) {
        set->error_mask |= ROUTER_AUDIT_ERROR_SSDP_IO;
        return;
    }
    if (!clock_begin(ops, &clock, ROUTER_SSDP_RESPONSE_MAX + 1U)) {
        set->error_mask |= ROUTER_AUDIT_ERROR_CLOCK;
        ops->socket_close(ops->context, socket_fd);
        return;
    }
    {
        step_result_t check = prepare_timed_io(ops, socket_fd, &clock, NULL);
        if (check == STEP_CANCELLED) {
            *cancelled = true;
            ops->socket_close(ops->context, socket_fd);
            return;
        }
        if (check == STEP_CLOCK) set->error_mask |= ROUTER_AUDIT_ERROR_CLOCK;
        if (check != STEP_OK || ops->socket_send_to(ops->context, socket_fd,
                            (const uint8_t *)request, (size_t)written,
                            network->gateway_ipv4, ROUTER_SSDP_PORT) != written) {
            set->error_mask |= ROUTER_AUDIT_ERROR_SSDP_IO;
            ops->socket_close(ops->context, socket_fd);
            return;
        }
        ++set->request_count;
    }
    for (response_index = 0U; response_index < ROUTER_SSDP_RESPONSE_MAX;
         ++response_index) {
        uint32_t source_ip = 0U;
        uint16_t source_port = 0U;
        int64_t received;
        size_t header_end;
        http_fields_t fields;
        step_result_t check = prepare_timed_io(ops, socket_fd, &clock, NULL);

        if (check == STEP_CANCELLED) {
            *cancelled = true;
            break;
        }
        if (check == STEP_CLOCK) {
            set->error_mask |= ROUTER_AUDIT_ERROR_CLOCK;
            break;
        }
        if (check == STEP_ERROR) break;
        received = ops->socket_recv_from(ops->context, socket_fd,
                                         ops->scratch,
                                         ROUTER_HTTP_HEADER_MAX,
                                         &source_ip, &source_port);
        if (received == ROUTER_IO_TIMEOUT) break;
        if (received < 0 || received > (int64_t)ROUTER_HTTP_HEADER_MAX) {
            set->error_mask |= ROUTER_AUDIT_ERROR_SSDP_IO;
            break;
        }
        if (source_ip != network->gateway_ipv4) {
            set->error_mask |= ROUTER_AUDIT_ERROR_SSDP_SOURCE;
            continue;
        }
        ++set->ssdp_responses;
        if (!find_header_end(ops->scratch, (size_t)received, &header_end) ||
            header_end != (size_t)received ||
            !parse_http_header(ops->scratch, header_end, &fields) ||
            fields.status != 200U || fields.transfer_encoding_present) {
            set->error_mask |= ROUTER_AUDIT_ERROR_SSDP_PARSE;
            continue;
        }
        if (fields.server_present) {
            (void)add_evidence(set, ROUTER_EVIDENCE_SSDP_SERVER, false,
                               NULL, fields.server, NULL);
        }
        if (fields.location_present) {
            char path[ROUTER_LOCATION_PATH_MAX + 1U];
            if (!parse_location(fields.location, network->gateway_ipv4, path)) {
                set->error_mask |= ROUTER_AUDIT_ERROR_LOCATION;
            } else if (!location->present) {
                location->present = true;
                memcpy(location->path, path, strlen(path) + 1U);
            } else if (strcmp(location->path, path) != 0) {
                location->conflict = true;
                set->error_mask |= ROUTER_AUDIT_ERROR_LOCATION;
            }
        }
    }
    ops->socket_close(ops->context, socket_fd);
}

static step_result_t collect_location(const router_network_context_t *network,
                                      const router_audit_ops_t *ops,
                                      router_evidence_set_t *set,
                                      const char *path)
{
    char gateway_text[16];
    char request[384];
    size_t total = 0U;
    size_t header_end = 0U;
    http_fields_t fields;
    router_evidence_t item;
    bool request_sent = false;
    int written;
    step_result_t result;

    ipv4_text(network->gateway_ipv4, gateway_text);
    written = snprintf(request, sizeof(request),
                       "GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n",
                       path, gateway_text);
    if (written <= 0 || (size_t)written >= sizeof(request)) return STEP_ERROR;
    result = http_request(ops, network->gateway_ipv4, request, true,
                          &total, &header_end, &fields, &request_sent);
    if (request_sent) ++set->request_count;
    if (result != STEP_OK) return result;
    if (!parse_xml(&ops->scratch[header_end], total - header_end, &item)) {
        set->error_mask |= ROUTER_AUDIT_ERROR_XML;
        return STEP_ERROR;
    }
    (void)add_evidence(set, item.source, item.locally_administered_mac,
                       item.vendor, item.model, item.firmware);
    return STEP_OK;
}

static step_result_t collect_head(const router_network_context_t *network,
                                  const router_audit_ops_t *ops,
                                  router_evidence_set_t *set)
{
    char gateway_text[16];
    char request[192];
    size_t total = 0U;
    size_t header_end = 0U;
    http_fields_t fields;
    bool request_sent = false;
    int written;
    step_result_t result;

    ipv4_text(network->gateway_ipv4, gateway_text);
    written = snprintf(request, sizeof(request),
                       "HEAD / HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n",
                       gateway_text);
    if (written <= 0 || (size_t)written >= sizeof(request)) return STEP_ERROR;
    result = http_request(ops, network->gateway_ipv4, request, false,
                          &total, &header_end, &fields, &request_sent);
    if (request_sent) ++set->request_count;
    (void)total;
    (void)header_end;
    if (result == STEP_OK && fields.server_present) {
        (void)add_evidence(set, ROUTER_EVIDENCE_HTTP_SERVER, false,
                           NULL, fields.server, NULL);
    }
    return result;
}

router_audit_result_t router_audit_collect(
    router_audit_mode_t mode,
    const router_network_context_t *network,
    const router_audit_ops_t *ops,
    router_evidence_set_t *evidence)
{
    location_candidate_t location;
    bool cancelled = false;
    step_result_t step;

    if (evidence == NULL || !ops_valid(mode, ops) ||
        (mode != ROUTER_AUDIT_PASSIVE && mode != ROUTER_AUDIT_STANDARD_OWNED)) {
        return ROUTER_AUDIT_RESULT_INVALID;
    }
    if (!network_valid(network)) return ROUTER_AUDIT_RESULT_PRECONDITION;
    memset(evidence, 0, sizeof(*evidence));
    if (!collect_passive(network, ops, evidence)) {
        memset(evidence, 0, sizeof(*evidence));
        return ROUTER_AUDIT_RESULT_INVALID;
    }
    if (mode == ROUTER_AUDIT_PASSIVE) {
        return evidence->error_mask == 0U ? ROUTER_AUDIT_RESULT_OK
                                          : ROUTER_AUDIT_RESULT_PARTIAL;
    }
    if (ops->cancelled(ops->context)) {
        return ROUTER_AUDIT_RESULT_CANCELLED;
    }

    memset(&location, 0, sizeof(location));
    collect_ssdp(network, ops, evidence, &location, &cancelled);
    if (cancelled) {
        return ROUTER_AUDIT_RESULT_CANCELLED;
    }
    if (location.present && !location.conflict) {
        step = collect_location(network, ops, evidence, location.path);
        if (step == STEP_CANCELLED) {
            return ROUTER_AUDIT_RESULT_CANCELLED;
        }
        if (step == STEP_CLOCK) {
            evidence->error_mask |= ROUTER_AUDIT_ERROR_CLOCK;
        } else if (step != STEP_OK) {
            evidence->error_mask |= ROUTER_AUDIT_ERROR_HTTP |
                                    ROUTER_AUDIT_ERROR_XML;
        }
    }
    step = collect_head(network, ops, evidence);
    if (step == STEP_CANCELLED) {
        return ROUTER_AUDIT_RESULT_CANCELLED;
    }
    if (step == STEP_CLOCK) {
        evidence->error_mask |= ROUTER_AUDIT_ERROR_CLOCK;
    } else if (step != STEP_OK) {
        evidence->error_mask |= ROUTER_AUDIT_ERROR_HTTP;
    }
    return evidence->error_mask == 0U ? ROUTER_AUDIT_RESULT_OK
                                      : ROUTER_AUDIT_RESULT_PARTIAL;
}
