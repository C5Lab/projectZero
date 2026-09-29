/* Host adapter for production functions extracted from main.c at test time.
 * Only ESP-IDF/FreeRTOS/NVS and release metadata I/O are replaced here.
 * No firmware, network, serial port or physical flash is touched.
 */
#include <ctype.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#define strcasecmp _stricmp
#else
#include <strings.h>
#endif

typedef int esp_err_t;
typedef int nvs_handle_t;
typedef int BaseType_t;
typedef uint32_t TickType_t;
typedef void *esp_https_ota_handle_t;
typedef int esp_ota_img_states_t;
typedef struct { char project_name[32], version[32], idf_ver[32]; } esp_app_desc_t;
typedef struct { const char *label; uint32_t address; } esp_partition_t;
typedef struct { int unused; } esp_netif_t;
typedef struct { struct { uint32_t addr; } ip; } esp_netif_ip_info_t;
typedef struct { int unused; } wifi_ap_record_t;
typedef struct {
    const char *url;
    int timeout_ms, buffer_size, buffer_size_tx;
    void (*crt_bundle_attach)(void);
} esp_http_client_config_t;
typedef struct { esp_http_client_config_t *http_config; } esp_https_ota_config_t;

enum { ESP_OK = 0, ESP_FAIL = -1, ESP_ERR_INVALID_ARG = -2,
       ESP_ERR_INVALID_SIZE = -3, ESP_ERR_INVALID_STATE = -4, ESP_ERR_TIMEOUT = -5,
       ESP_ERR_HTTPS_OTA_IN_PROGRESS = 1, ESP_OTA_IMG_UNDEFINED = 0,
       ESP_OTA_IMG_PENDING_VERIFY = 1, ESP_OTA_IMG_VALID = 2,
       NVS_READONLY = 0, NVS_READWRITE = 1, pdPASS = 1 };
#define pdMS_TO_TICKS(ms) ((TickType_t)(ms))
#define TAG "test"

static bool ota_check_in_progress;
static char ota_channel[8] = "main";
static bool associated = true, has_ip = true, has_netif = true, ip_ok = true, mode_ok = true;
static bool fail_alloc, fail_task, fail_metadata, stalled, image_complete = true;
static int fail_nvs, fail_stage, command_result, value;
static int started, begins, performs, finishes, aborts, restarts, allocations, marks;
static int image_state = ESP_OTA_IMG_PENDING_VERIFY, state_error;
static bool ota_handle_live;
static TickType_t ticks;
static const char *route = "none", *release_tag = "99.0.0", *image_project = "projectZero";
static const char *image_version = "99.0.0";
static char requested_tag[128], requested_url[512], events[2048];
static char persisted_channel[8] = "main", pending_channel[8] = "main";
static esp_netif_t netif;
static esp_partition_t target = { "ota_1", 0x410000 };
static void (*scheduled)(void *);
static void *scheduled_arg;
static jmp_buf restart_jump;

static void require(bool condition, const char *message) {
    if (!condition) { fprintf(stderr, "adapter contract violation: %s\n", message); exit(2); }
}
static void event(const char *name) {
    require(strlen(events) + strlen(name) + 2 < sizeof(events), "event overflow");
    strcat(events, name); strcat(events, ",");
}
static void test_log(const char *tag, const char *fmt, ...) {
    (void)tag; (void)fmt;
}
#define MY_LOG_INFO test_log
static const char *esp_err_to_name(esp_err_t err) { (void)err; return "simulated"; }
static void esp_crt_bundle_attach(void) {}
static void ota_log_resources(const char *phase) { (void)phase; }
static void ota_led_start(void) {}
static void ota_led_stop(void) {}
static void oled_display_update_full(const char *a, const char *b, const char *c, const char *d) {
    (void)a; (void)b; (void)c; (void)d;
}
static bool ensure_wifi_mode(void) { return mode_ok; }
static esp_err_t esp_wifi_sta_get_ap_info(wifi_ap_record_t *info) {
    (void)info; return associated ? ESP_OK : ESP_FAIL;
}
static esp_netif_t *esp_netif_get_handle_from_ifkey(const char *key) {
    require(strcmp(key, "WIFI_STA_DEF") == 0, "wrong network interface");
    return has_netif ? &netif : NULL;
}
static esp_err_t esp_netif_get_ip_info(esp_netif_t *iface, esp_netif_ip_info_t *info) {
    require(iface == &netif, "invalid network interface");
    info->ip.addr = has_ip ? 1 : 0;
    return ip_ok ? ESP_OK : ESP_FAIL;
}
static void *tracked_calloc(size_t n, size_t size) {
    if (fail_alloc) return NULL;
    void *p = calloc(n, size);
    if (p) allocations++;
    return p;
}
static void tracked_free(void *p) {
    if (p) { require(allocations > 0, "unbalanced free"); allocations--; free(p); }
}
static BaseType_t xTaskCreate(void (*fn)(void *), const char *name, unsigned stack,
                             void *arg, unsigned priority, void *handle) {
    (void)name; (void)stack; (void)priority; (void)handle;
    if (fail_task) return 0;
    require(!scheduled, "second concurrent OTA worker");
    scheduled = fn; scheduled_arg = arg; started++;
    return pdPASS;
}
static void vTaskDelete(void *task) { require(task == NULL, "deleting foreign task"); }
static void vTaskDelay(TickType_t delay) { ticks += delay; }
static TickType_t xTaskGetTickCount(void) { return ticks; }
static void safe_restart(void) { event("restart"); restarts++; longjmp(restart_jump, 1); }

static esp_err_t ota_fetch_latest_release(char *url, size_t url_len, char *tag, size_t tag_len) {
    route = "latest";
    if (fail_metadata) return ESP_FAIL;
    snprintf(url, url_len, "https://fixture.invalid/latest.bin");
    snprintf(tag, tag_len, "%s", release_tag);
    return ESP_OK;
}
static esp_err_t ota_fetch_release_by_tag(const char *wanted, char *url, size_t url_len,
                                        char *tag, size_t tag_len) {
    route = "tag";
    snprintf(requested_tag, sizeof(requested_tag), "%s", wanted);
    snprintf(url, url_len, "https://fixture.invalid/tag.bin");
    snprintf(tag, tag_len, "%s", wanted);
    return fail_metadata ? ESP_FAIL : ESP_OK;
}
static const esp_partition_t *esp_ota_get_next_update_partition(const esp_partition_t *part) {
    require(part == NULL, "unexpected explicit update partition"); return &target;
}
static const esp_partition_t *esp_ota_get_running_partition(void) { return &target; }
static esp_err_t esp_ota_get_state_partition(const esp_partition_t *part, esp_ota_img_states_t *state) {
    (void)part; *state = image_state; return state_error ? ESP_FAIL : ESP_OK;
}
static esp_err_t esp_ota_mark_app_valid_cancel_rollback(void) { marks++; return ESP_OK; }

static esp_err_t esp_https_ota_begin(const esp_https_ota_config_t *config, esp_https_ota_handle_t *handle) {
    event("begin"); begins++;
    require(config->http_config->crt_bundle_attach != NULL, "missing TLS certificate validation");
    snprintf(requested_url, sizeof(requested_url), "%s", config->http_config->url);
    if (fail_stage == 1) return ESP_FAIL;
    require(!ota_handle_live, "overlapping OTA handles");
    ota_handle_live = true; *handle = &ota_handle_live;
    return ESP_OK;
}
static void check_handle(esp_https_ota_handle_t handle) {
    require(handle == &ota_handle_live && ota_handle_live, "use of closed OTA handle");
}
static esp_err_t esp_https_ota_get_img_desc(esp_https_ota_handle_t handle, esp_app_desc_t *desc) {
    check_handle(handle); event("desc");
    if (fail_stage == 2) return ESP_FAIL;
    snprintf(desc->project_name, sizeof(desc->project_name), "%s", image_project);
    snprintf(desc->version, sizeof(desc->version), "%s", image_version);
    snprintf(desc->idf_ver, sizeof(desc->idf_ver), "host-fixture");
    return ESP_OK;
}
static esp_err_t esp_https_ota_abort(esp_https_ota_handle_t handle) {
    check_handle(handle); event("abort"); aborts++; ota_handle_live = false; return ESP_OK;
}
static int esp_https_ota_get_image_size(esp_https_ota_handle_t handle) { check_handle(handle); return 1024; }
static esp_err_t esp_https_ota_perform(esp_https_ota_handle_t handle) {
    check_handle(handle); event("perform"); performs++;
    if (fail_stage == 3) return ESP_FAIL;
    if (stalled) { ticks += 30000; return ESP_ERR_HTTPS_OTA_IN_PROGRESS; }
    return performs % 3 == 0 ? ESP_OK : ESP_ERR_HTTPS_OTA_IN_PROGRESS;
}
static int esp_https_ota_get_image_len_read(esp_https_ota_handle_t handle) {
    check_handle(handle); return stalled ? 0 : (performs % 3 == 0 ? 1024 : (performs % 3) * 256);
}
static bool esp_https_ota_is_complete_data_received(esp_https_ota_handle_t handle) {
    check_handle(handle); event("complete"); return image_complete;
}
static esp_err_t esp_https_ota_finish(esp_https_ota_handle_t handle) {
    check_handle(handle); event("finish"); finishes++; ota_handle_live = false;
    return fail_stage == 4 ? ESP_FAIL : ESP_OK;
}

static esp_err_t nvs_open(const char *ns, int mode, nvs_handle_t *handle) {
    require(strcmp(ns, "ota") == 0, "wrong NVS namespace");
    (void)mode; *handle = 1; return fail_nvs == 1 ? ESP_FAIL : ESP_OK;
}
static esp_err_t nvs_set_str(nvs_handle_t handle, const char *key, const char *text) {
    (void)handle; require(strcmp(key, "channel") == 0, "wrong NVS key");
    if (fail_nvs == 2) return ESP_FAIL;
    snprintf(pending_channel, sizeof(pending_channel), "%s", text); return ESP_OK;
}
static esp_err_t nvs_commit(nvs_handle_t handle) {
    (void)handle; if (fail_nvs == 3) return ESP_FAIL;
    strcpy(persisted_channel, pending_channel); return ESP_OK;
}
static esp_err_t nvs_get_str(nvs_handle_t handle, const char *key, char *out, size_t *len) {
    (void)handle; require(strcmp(key, "channel") == 0, "wrong NVS key");
    if (fail_nvs == 4) return ESP_FAIL;
    if (*len < strlen(persisted_channel) + 1) return ESP_ERR_INVALID_SIZE;
    strcpy(out, persisted_channel); *len = strlen(out) + 1; return ESP_OK;
}
static void nvs_close(nvs_handle_t handle) { (void)handle; }

static void ota_check_task(void *arg);
static bool ota_save_channel_to_nvs(const char *channel);
#define calloc tracked_calloc
#define free tracked_free
#include "ota_production.inc"
#undef calloc
#undef free

static void run_worker(void) {
    if (!scheduled) return;
    void (*fn)(void *) = scheduled;
    void *arg = scheduled_arg;
    scheduled = NULL; scheduled_arg = NULL;
    if (setjmp(restart_jump) == 0) fn(arg);
    require(!ota_handle_live, "OTA handle leaked");
}

int main(int argc, char **argv) {
    require(argc == 2, "scenario required");
    const char *s = argv[1];
    char *check[] = { "ota_check", NULL, NULL };
    int check_argc = 1;
    bool do_check = true;
    if (!strcmp(s, "equal")) release_tag = JANOS_VERSION;
    else if (!strcmp(s, "older")) release_tag = "0.0.1";
    else if (!strcmp(s, "bad_version")) release_tag = "not-a-version";
    else if (!strcmp(s, "dev")) { strcpy(ota_channel, "dev"); image_version = "0.0.1"; }
    else if (!strcmp(s, "dev_latest") || !strcmp(s, "dev_latest_equal")) {
        strcpy(ota_channel, "dev"); check[1] = "latest"; check_argc = 2;
        if (!strcmp(s, "dev_latest_equal")) release_tag = JANOS_VERSION;
    } else if (!strcmp(s, "tag_older")) { check[1] = "1.0.0"; check_argc = 2; image_version = "1.0.0"; }
    else if (!strcmp(s, "uppercase") || !strcmp(s, "uppercase_reload")) {
        char *args[] = { "ota_channel", "DEV" };
        command_result = cmd_ota_channel(2, args);
        require(command_result == 0, "uppercase command rejected unexpectedly");
        if (!strcmp(s, "uppercase_reload")) { strcpy(ota_channel, "main"); ota_load_channel_from_nvs(); }
    } else if (!strncmp(s, "nvs_", 4) || !strcmp(s, "invalid_channel")) {
        do_check = false;
        if (!strcmp(s, "nvs_open_fail")) fail_nvs = 1;
        if (!strcmp(s, "nvs_set_fail")) fail_nvs = 2;
        if (!strcmp(s, "nvs_commit_fail")) fail_nvs = 3;
        if (!strcmp(s, "nvs_missing")) { fail_nvs = 4; ota_load_channel_from_nvs(); }
        else if (!strcmp(s, "nvs_invalid")) { strcpy(persisted_channel, "bogus"); ota_load_channel_from_nvs(); }
        else {
            char *args[] = { "ota_channel", !strcmp(s, "invalid_channel") ? "bogus" : "dev" };
            command_result = cmd_ota_channel(2, args);
            if (!strcmp(s, "nvs_roundtrip")) { strcpy(ota_channel, "main"); ota_load_channel_from_nvs(); }
        }
    } else if (!strcmp(s, "invalid_args")) check_argc = 3;
    else if (!strcmp(s, "offline")) associated = false;
    else if (!strcmp(s, "no_ip")) has_ip = false;
    else if (!strcmp(s, "no_netif")) has_netif = false;
    else if (!strcmp(s, "ip_error")) ip_ok = false;
    else if (!strcmp(s, "wifi_mode_fail")) mode_ok = false;
    else if (!strcmp(s, "alloc_fail")) fail_alloc = true;
    else if (!strcmp(s, "task_fail")) fail_task = true;
    else if (!strcmp(s, "metadata_fail")) fail_metadata = true;
    else if (!strcmp(s, "begin_fail")) fail_stage = 1;
    else if (!strcmp(s, "descriptor_fail")) fail_stage = 2;
    else if (!strcmp(s, "wrong_project")) image_project = "other-project";
    else if (!strcmp(s, "perform_fail") || !strcmp(s, "retry")) fail_stage = 3;
    else if (!strcmp(s, "incomplete")) image_complete = false;
    else if (!strcmp(s, "finish_fail")) fail_stage = 4;
    else if (!strcmp(s, "stall")) stalled = true;
    else if (!strcmp(s, "version_mismatch")) image_version = "0.0.1";
    else if (!strcmp(s, "numeric_versions")) {
        do_check = false;
        value = ota_is_newer_version("1.9.9", "v1.10.0") && ota_is_newer_version("1.99.99", "2.0.0") &&
                !ota_is_newer_version("2.0.0", "1.99.99") && !ota_is_newer_version("1.7.5", "1.7.5");
    } else if (!strcmp(s, "null_version")) {
        do_check = false; value = ota_is_newer_version(NULL, "1.0.0") || ota_is_newer_version("1.0.0", "bad");
    } else if (!strcmp(s, "malformed_version")) {
        do_check = false; int a, b, c; value = ota_parse_version("1.7.xyz", &a, &b, &c);
    } else if (!strcmp(s, "prerelease")) {
        do_check = false; value = ota_is_newer_version("1.7.6-rc1", "1.7.6");
    } else if (!strcmp(s, "pending") || !strcmp(s, "valid") || !strcmp(s, "state_fail")) {
        do_check = false;
        if (!strcmp(s, "valid")) image_state = ESP_OTA_IMG_VALID;
        if (!strcmp(s, "state_fail")) state_error = 1;
        ota_mark_valid_if_pending();
    } else if (!strcmp(s, "url") || !strcmp(s, "url_too_small")) {
        do_check = false;
        value = ota_build_branch_url(requested_url, !strcmp(s, "url") ? sizeof(requested_url) : 2);
    } else if (!strcmp(s, "long_tag")) {
        static char long_tag[100]; memset(long_tag, 'x', sizeof(long_tag) - 1);
        check[1] = long_tag; check_argc = 2;
    } else require(!strcmp(s, "newer") || !strcmp(s, "busy") || !strcmp(s, "disconnect_before_task"), "unknown scenario");

    if (do_check) {
        command_result = cmd_ota_check(check_argc, check);
        if (!strcmp(s, "busy")) command_result = cmd_ota_check(check_argc, check);
        if (!strcmp(s, "disconnect_before_task")) associated = false;
        run_worker();
        if (!strcmp(s, "retry")) {
            require(!ota_check_in_progress && allocations == 0, "failed update not cleaned up");
            fail_stage = 0; command_result = cmd_ota_check(check_argc, check); run_worker();
        }
    }
    printf("route=%s\nurl=%s\ntag=%s\nchannel=%s\ntarget=%s\nevents=%s\n", route, requested_url, requested_tag, ota_channel, target.label, events);
    printf("command=%d\nvalue=%d\nstarted=%d\nbegin=%d\nperform=%d\nfinish=%d\nabort=%d\nrestart=%d\nbusy=%d\nallocs=%d\nmark=%d\n",
           command_result, value, started, begins, performs, finishes, aborts, restarts, ota_check_in_progress, allocations, marks);
    return 0;
}
