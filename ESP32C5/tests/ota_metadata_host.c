/* Real release functions from main.c and real cJSON; only network/WiFi are simulated. */
#include <stdbool.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "cJSON.h"

typedef int esp_err_t;
enum { ESP_OK = 0, ESP_FAIL = -1, ESP_ERR_INVALID_ARG = -2,
       ESP_ERR_INVALID_SIZE = -3, ESP_ERR_NOT_FOUND = -6 };
#define TAG "metadata-host"

static int http_calls;
static char requested_url[512];
static const char *fixture;
static void test_log(const char *tag, const char *fmt, ...) { (void)tag; (void)fmt; }
#define MY_LOG_INFO test_log
static bool ensure_wifi_mode(void) { return true; }
static bool ota_is_connected(void) { return true; }
static const char *esp_err_to_name(esp_err_t err) { (void)err; return "simulated"; }

static const char *response_body(void) {
    if (strcmp(fixture, "malformed") == 0) return "{not json";
    if (strcmp(fixture, "missing_tag") == 0)
        return "{\"assets\":[{\"name\":\"projectZero.bin\",\"browser_download_url\":\"https://github.com/elpadrino26/janosrf-web-flasher/releases/download/v1.2.3/projectZero.bin\"}]}";
    if (strcmp(fixture, "missing_asset") == 0)
        return "{\"tag_name\":\"v1.2.3\",\"assets\":[]}";
    if (strcmp(fixture, "wrong_asset") == 0)
        return "{\"tag_name\":\"v1.2.3\",\"assets\":[{\"name\":\"bootloader.bin\",\"browser_download_url\":\"https://github.com/elpadrino26/janosrf-web-flasher/releases/download/v1.2.3/bootloader.bin\"}]}";
    if (strcmp(fixture, "missing_download") == 0)
        return "{\"tag_name\":\"v1.2.3\",\"assets\":[{\"name\":\"projectZero.bin\"}]}";
    if (strcmp(fixture, "draft") == 0)
        return "{\"tag_name\":\"v1.2.3\",\"draft\":true,\"assets\":[{\"name\":\"projectZero.bin\",\"browser_download_url\":\"https://github.com/elpadrino26/janosrf-web-flasher/releases/download/v1.2.3/projectZero.bin\"}]}";
    if (strcmp(fixture, "classic_download") == 0)
        return "{\"tag_name\":\"v1.2.3\",\"assets\":[{\"name\":\"projectZero.bin\",\"browser_download_url\":\"https://github.com/C5Lab/projectZero/releases/download/v1.2.3/projectZero.bin\"}]}";
    if (strcmp(fixture, "http_download") == 0)
        return "{\"tag_name\":\"v1.2.3\",\"assets\":[{\"name\":\"projectZero.bin\",\"browser_download_url\":\"http://github.com/elpadrino26/janosrf-web-flasher/releases/download/v1.2.3/projectZero.bin\"}]}";
    if (strcmp(fixture, "other_repo_download") == 0)
        return "{\"tag_name\":\"v1.2.3\",\"assets\":[{\"name\":\"projectZero.bin\",\"browser_download_url\":\"https://github.com/elpadrino26/other-repo/releases/download/v1.2.3/projectZero.bin\"}]}";
    if (strcmp(fixture, "good_classic") == 0)
        return "{\"tag_name\":\"v1.2.3\",\"draft\":false,\"assets\":[{\"name\":\"bootloader.bin\",\"browser_download_url\":\"https://github.com/C5Lab/projectZero/releases/download/v1.2.3/bootloader.bin\"},{\"name\":\"projectZero.bin\",\"browser_download_url\":\"https://github.com/C5Lab/projectZero/releases/download/v1.2.3/projectZero.bin\"}]}";
    if (strcmp(fixture, "listing") == 0)
        return "[{\"tag_name\":\"v1.2.3\",\"name\":\"Release 1.2.3\",\"draft\":false,\"prerelease\":false,\"published_at\":\"2026-09-29T00:00:00Z\"}]";
    return "{\"tag_name\":\"v1.2.3\",\"draft\":false,\"assets\":[{\"name\":\"bootloader.bin\",\"browser_download_url\":\"https://github.com/elpadrino26/janosrf-web-flasher/releases/download/v1.2.3/bootloader.bin\"},{\"name\":\"projectZero.bin\",\"browser_download_url\":\"https://github.com/elpadrino26/janosrf-web-flasher/releases/download/v1.2.3/projectZero.bin\"}]}";
}

static esp_err_t ota_http_get(const char *url, char **out_buf, size_t *out_len) {
    http_calls++;
    snprintf(requested_url, sizeof(requested_url), "%s", url);
    if (strcmp(fixture, "http_fail") == 0) return ESP_FAIL;
    const char *body = response_body();
    *out_len = strlen(body);
    *out_buf = malloc(*out_len + 1);
    if (!*out_buf) return ESP_FAIL;
    memcpy(*out_buf, body, *out_len + 1);
    return ESP_OK;
}

#include "ota_metadata_production.inc"

int main(int argc, char **argv) {
    (void)ota_parse_version;
    if (argc != 7) return 2;
    const char *mode = argv[1];
    bool rf = strcmp(argv[2], "1") == 0;
    const char *tag = strcmp(argv[3], "_") == 0 ? NULL : argv[3];
    if (strcmp(argv[3], "EMPTY") == 0) tag = "";
    fixture = argv[4];
    size_t url_len = (size_t)strtoul(argv[5], NULL, 10);
    size_t tag_len = (size_t)strtoul(argv[6], NULL, 10);
    if (url_len > 512 || tag_len > 128) return 2;
    char url[512] = {0};
    char out_tag[128] = {0};
    esp_err_t status;
    if (strcmp(mode, "url") == 0 || strcmp(mode, "url_list") == 0) {
        status = ota_build_release_api_url(rf, tag, strcmp(mode, "url_list") == 0,
                                           url, url_len);
    } else if (strcmp(mode, "fetch") == 0) {
        status = ota_fetch_release(rf, tag, url, url_len, out_tag, tag_len);
    } else if (strcmp(mode, "list") == 0) {
        char *args_rf[] = {"ota_list", "rf"};
        char *args_classic[] = {"ota_list"};
        status = cmd_ota_list(rf ? 2 : 1, rf ? args_rf : args_classic);
    } else if (strcmp(mode, "list_invalid") == 0) {
        char *args[] = {"ota_list", "unknown"};
        status = cmd_ota_list(2, args);
    } else {
        return 2;
    }
    printf("status=%d\n", status);
    printf("calls=%d\n", http_calls);
    printf("request=%s\n", requested_url);
    printf("url=%s\n", url);
    printf("tag=%s\n", out_tag);
    return 0;
}
