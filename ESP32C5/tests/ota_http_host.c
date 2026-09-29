/* Simulated ESP-IDF transport around the verbatim production ota_http_get. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int esp_err_t;
enum { ESP_OK = 0, ESP_FAIL = -1, ESP_ERR_INVALID_ARG = -2,
       ESP_ERR_NO_MEM = -3, ESP_ERR_INVALID_SIZE = -4, MALLOC_CAP_SPIRAM = 1 };
typedef enum { HTTP_TRANSPORT_UNKNOWN, HTTP_TRANSPORT_OVER_TCP,
               HTTP_TRANSPORT_OVER_SSL } esp_http_client_transport_t;
typedef struct {
    const char *url;
    int timeout_ms;
    void (*crt_bundle_attach)(void);
} esp_http_client_config_t;
typedef struct { esp_http_client_transport_t transport; } fake_client_t;
typedef fake_client_t *esp_http_client_handle_t;

#define TAG "http-host"
static const char *scenario;
static int opens, closes, cleanups, redirects, reads, allocations;
static fake_client_t client_state;
static void test_log(const char *tag, const char *fmt, ...) { (void)tag; (void)fmt; }
#define MY_LOG_INFO test_log
static const char *esp_err_to_name(esp_err_t err) { (void)err; return "simulated"; }
static void esp_crt_bundle_attach(void) {}

static void *heap_caps_calloc(size_t count, size_t size, int capability) {
    if (capability != MALLOC_CAP_SPIRAM) exit(2);
    void *result = calloc(count, size);
    if (result) allocations++;
    return result;
}
static void tracked_free(void *pointer) {
    if (pointer) { allocations--; free(pointer); }
}
static esp_http_client_handle_t esp_http_client_init(const esp_http_client_config_t *config) {
    if (!config->url || config->timeout_ms != 10000 || !config->crt_bundle_attach) exit(2);
    client_state.transport = HTTP_TRANSPORT_OVER_SSL;
    return &client_state;
}
static esp_err_t esp_http_client_set_header(esp_http_client_handle_t client,
                                             const char *key, const char *value) {
    (void)client; (void)key; (void)value; return ESP_OK;
}
static esp_err_t esp_http_client_open(esp_http_client_handle_t client, int write_len) {
    (void)client;
    if (write_len != 0) exit(2);
    opens++;
    reads = 0;
    if (strcmp(scenario, "open_timeout") == 0 ||
        (strcmp(scenario, "open_after_redirect") == 0 && opens == 2)) return ESP_FAIL;
    return ESP_OK;
}
static int redirect_limit(void) {
    if (strcmp(scenario, "redirect") == 0 || strcmp(scenario, "downgrade") == 0 ||
        strcmp(scenario, "missing_location") == 0 || strcmp(scenario, "redirect_error") == 0 ||
        strcmp(scenario, "open_after_redirect") == 0) return 1;
    if (strcmp(scenario, "five_redirects") == 0) return 5;
    if (strcmp(scenario, "redirect_loop") == 0) return 6;
    return 0;
}
static int64_t esp_http_client_fetch_headers(esp_http_client_handle_t client) {
    (void)client;
    if (strcmp(scenario, "headers_timeout") == 0) return -1;
    if (opens <= redirect_limit()) return 0;
    if (strcmp(scenario, "short_body") == 0) return 10;
    if (strcmp(scenario, "incomplete_chunked") == 0 ||
        strcmp(scenario, "complete_chunked") == 0) return 0;
    if (strcmp(scenario, "binary") == 0) return 4;
    return 7;
}
static int esp_http_client_get_status_code(esp_http_client_handle_t client) {
    (void)client;
    return opens <= redirect_limit() ? 302 : 200;
}
static esp_err_t esp_http_client_set_redirection(esp_http_client_handle_t client) {
    if (strcmp(scenario, "missing_location") == 0 ||
        strcmp(scenario, "redirect_error") == 0) return ESP_FAIL;
    redirects++;
    if (strcmp(scenario, "downgrade") == 0) client->transport = HTTP_TRANSPORT_OVER_TCP;
    return ESP_OK;
}
static esp_http_client_transport_t esp_http_client_get_transport_type(esp_http_client_handle_t client) {
    return client->transport;
}
static int64_t esp_http_client_get_content_length(esp_http_client_handle_t client) {
    (void)client;
    if (strcmp(scenario, "short_body") == 0) return 10;
    if (strcmp(scenario, "incomplete_chunked") == 0 ||
        strcmp(scenario, "complete_chunked") == 0) return -1;
    if (strcmp(scenario, "binary") == 0) return 4;
    return 7;
}
static int esp_http_client_read(esp_http_client_handle_t client, char *buffer, int len) {
    (void)client;
    if (strcmp(scenario, "read_error") == 0) return -1;
    if (reads++) return 0;
    const char *body = strcmp(scenario, "binary") == 0 ? "A\0BC" : "payload";
    int size = strcmp(scenario, "binary") == 0 ? 4 : 7;
    if (len < size) exit(2);
    memcpy(buffer, body, (size_t)size);
    return size;
}
static bool esp_http_client_is_complete_data_received(esp_http_client_handle_t client) {
    (void)client;
    return strcmp(scenario, "incomplete_chunked") != 0;
}
static esp_err_t esp_http_client_close(esp_http_client_handle_t client) {
    (void)client; closes++; return ESP_OK;
}
static esp_err_t esp_http_client_cleanup(esp_http_client_handle_t client) {
    (void)client; cleanups++; return ESP_OK;
}

#define free tracked_free
#include "ota_http_production.inc"
#undef free

int main(int argc, char **argv) {
    (void)esp_http_client_set_redirection;
    (void)esp_http_client_get_transport_type;
    (void)esp_http_client_get_content_length;
    (void)esp_http_client_is_complete_data_received;
    if (argc != 2) return 2;
    scenario = argv[1];
    char *body = NULL;
    size_t length = 0;
    esp_err_t status;
    if (strcmp(scenario, "invalid_args") == 0) {
        status = ota_http_get(NULL, &body, &length);
    } else {
        status = ota_http_get("https://github.com/release/projectZero.bin", &body, &length);
    }
    printf("status=%d\nopens=%d\ncloses=%d\ncleanup=%d\nredirects=%d\n",
           status, opens, closes, cleanups, redirects);
    printf("body=%s\nlength=%zu\n", body ? "payload" : "null", length);
    if (body && strcmp(scenario, "binary") == 0) {
        printf("bytes_hex=");
        for (size_t index = 0; index < length; index++) printf("%02X", (unsigned char)body[index]);
        printf("\n");
    }
    if (body) tracked_free(body);
    if (allocations != 0) { fprintf(stderr, "allocation leak: %d\n", allocations); return 3; }
    return 0;
}
