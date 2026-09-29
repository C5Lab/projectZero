/* Host substitutes only hardware/framework initialization around production
 * app_main statements and the production OTA confirmation helper. */
#include <assert.h>
#include <setjmp.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

typedef int esp_err_t;
typedef int esp_ota_img_states_t;
typedef struct { const char *label; } esp_partition_t;
typedef struct { int unused; } esp_console_repl_t;
typedef struct { int task_stack_size; const char *prompt; int max_cmdline_length; } esp_console_repl_config_t;
typedef struct { int baud_rate; } esp_console_dev_uart_config_t;
typedef struct {
    const char *(*busy_reason)(void);
    esp_err_t (*prepare_wifi)(void);
    int (*baud_rate)(void);
    void (*tx_activity)(void);
} wifi_analyzer_hooks_t;

enum { ESP_OK = 0, ESP_FAIL = -1, ESP_OTA_IMG_UNDEFINED = 0,
       ESP_OTA_IMG_PENDING_VERIFY = 1, ESP_OTA_IMG_VALID = 2,
       ESP_ERR_NOT_FOUND = -2 };
#define TAG "test"
#define JANOS_UART_DEFAULT_BAUD 115200
#define ESP_CONSOLE_REPL_CONFIG_DEFAULT() ((esp_console_repl_config_t){0})
#define ESP_CONSOLE_DEV_UART_CONFIG_DEFAULT() ((esp_console_dev_uart_config_t){0})
#define pdMS_TO_TICKS(ms) (ms)
static void test_log(const char *tag, const char *fmt, ...) { (void)tag; (void)fmt; }
#define MY_LOG_INFO test_log

static char events[256];
static int mark_count, image_state, abort_count, fail_at, mark_error, state_error;
static int set_boot_count, restart_count, command_result;
static jmp_buf abort_jump;
static esp_partition_t running = { "ota_1" };
static void *janos_command_mutex;
static int janos_command_mutex_storage;
typedef struct {
    unsigned long long pin_bit_mask;
    int mode, pull_up_en, pull_down_en, intr_type;
} gpio_config_t;
enum { BOOT_BUTTON_GPIO = 9, GPIO_MODE_INPUT = 1, GPIO_PULLUP_ENABLE = 1,
       GPIO_PULLDOWN_DISABLE = 0, GPIO_INTR_DISABLE = 0,
       ESP_PARTITION_TYPE_APP = 1, ESP_PARTITION_SUBTYPE_APP_OTA_0 = 16,
       ESP_PARTITION_SUBTYPE_APP_OTA_1 = 17 };

static void event(const char *value) {
    if (strlen(events) + strlen(value) + 2 >= sizeof(events)) abort();
    strcat(events, value);
    strcat(events, ",");
}
static void check(esp_err_t err) {
    if (err != ESP_OK) { abort_count++; longjmp(abort_jump, 1); }
}
#define ESP_ERROR_CHECK(expr) check((expr))

static void ota_load_channel_from_nvs(void) { event("nvs"); }
static void wpasec_load_key_from_nvs(void) {}
static void wigle_load_key_from_nvs(void) {}
static void wdgwars_load_key_from_nvs(void) {}
static void ota_log_boot_info(void) { event("boot_info"); }
static const esp_partition_t *esp_ota_get_running_partition(void) { return &running; }
static esp_err_t esp_ota_get_state_partition(const esp_partition_t *part, esp_ota_img_states_t *state) {
    assert(part == &running);
    event("state");
    if (state_error) return state_error;
    *state = image_state;
    return ESP_OK;
}
static esp_err_t esp_ota_mark_app_valid_cancel_rollback(void) {
    event("mark");
    mark_count++;
    return mark_error ? ESP_FAIL : ESP_OK;
}
static const char *esp_err_to_name(esp_err_t err) { (void)err; return "failure"; }
static esp_err_t uart_baud_control_init(void) {
    event("uart");
    return fail_at == 1 ? ESP_FAIL : ESP_OK;
}
static void *xSemaphoreCreateRecursiveMutexStatic(void *storage) { return storage; }
static const char *analyzer_host_busy_reason(void) { return NULL; }
static esp_err_t analyzer_host_prepare_wifi(void) { return ESP_OK; }
static int uart_baud_current(void) { return JANOS_UART_DEFAULT_BAUD; }
static void uart_baud_note_activity(void) {}
static esp_err_t init_sd_card(void) { event("sd"); return ESP_FAIL; }
static void uart_baud_set_file_transfer_active(bool active) { (void)active; }
static void wifi_analyzer_init(const wifi_analyzer_hooks_t *hooks) { (void)hooks; }
static void crack_worker_init(esp_err_t (*sd)(void), void (*transfer)(bool), int (*baud)(void)) {
    (void)sd; (void)transfer; (void)baud;
}
static void esp_console_register_help_command(void) {}
static void register_commands(void) { event("commands"); }
static esp_err_t esp_console_new_repl_uart(const esp_console_dev_uart_config_t *hw,
                                           const esp_console_repl_config_t *cfg,
                                           esp_console_repl_t **out) {
    static esp_console_repl_t repl;
    (void)hw; (void)cfg;
    event("repl_create");
    if (fail_at == 2) return ESP_FAIL;
    *out = &repl;
    return ESP_OK;
}
static void linenoiseSetHintsCallback(void *callback) { (void)callback; }
static void janos_console_hint(void) {}
typedef void linenoiseHintsCallback;
static esp_err_t esp_console_start_repl(esp_console_repl_t *repl) {
    assert(repl);
    event("repl_start");
    return fail_at == 3 ? ESP_FAIL : ESP_OK;
}
static void vTaskDelay(int ticks) { (void)ticks; }
static esp_err_t gpio_config(const gpio_config_t *cfg) {
    assert(cfg->pin_bit_mask == (1ULL << BOOT_BUTTON_GPIO));
    event("gpio");
    return fail_at == 4 ? ESP_FAIL : ESP_OK;
}
static const esp_partition_t *esp_partition_find_first(int type, int subtype, const char *label) {
    (void)label;
    assert(type == ESP_PARTITION_TYPE_APP);
    assert(subtype == ESP_PARTITION_SUBTYPE_APP_OTA_0);
    return &running;
}
static esp_err_t esp_ota_set_boot_partition(const esp_partition_t *part) {
    assert(part == &running);
    set_boot_count++;
    return ESP_OK;
}
static void safe_restart(void) { restart_count++; }

#include "ota_boot_production.inc"

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    image_state = ESP_OTA_IMG_PENDING_VERIFY;
    if (strcmp(argv[1], "valid") == 0) image_state = ESP_OTA_IMG_VALID;
    else if (strcmp(argv[1], "legacy") == 0) image_state = ESP_OTA_IMG_UNDEFINED;
    else if (strcmp(argv[1], "no_otadata") == 0) state_error = ESP_ERR_NOT_FOUND;
    else if (strcmp(argv[1], "state_fail") == 0) state_error = ESP_FAIL;
    else if (strcmp(argv[1], "uart_fail") == 0) fail_at = 1;
    else if (strcmp(argv[1], "repl_create_fail") == 0) fail_at = 2;
    else if (strcmp(argv[1], "repl_start_fail") == 0) fail_at = 3;
    else if (strcmp(argv[1], "gpio_fail") == 0) fail_at = 4;
    else if (strcmp(argv[1], "mark_fail") == 0) mark_error = 1;
    else if (strcmp(argv[1], "boot_before_ready") == 0) {}
    else if (strcmp(argv[1], "boot_after_ready") == 0) {}
    else if (strcmp(argv[1], "boot_mark_fail") == 0) mark_error = 1;
    else if (strcmp(argv[1], "pending") != 0) return 2;
    if (setjmp(abort_jump) == 0) {
        if (strcmp(argv[1], "boot_before_ready") != 0) run_startup_slice();
        if (strncmp(argv[1], "boot_", 5) == 0) {
            char *args[] = { "ota_boot", "ota_0" };
            command_result = cmd_ota_boot(2, args);
        }
    }
    printf("events=%s\nmark=%d\naborted=%d\nstate=%d\nready=%d\nset_boot=%d\nrestart=%d\ncommand=%d\n",
           events, mark_count, abort_count, image_state, (int)ota_boot_is_ready(),
           set_boot_count, restart_count, command_result);
    return 0;
}
