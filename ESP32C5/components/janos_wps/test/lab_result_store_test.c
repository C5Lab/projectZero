#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "lab_result_store.h"

typedef struct { unsigned calls; bool grant; } gate_fixture_t;
static bool commit_gate(void *context, uint32_t operation_id)
{
    gate_fixture_t *fixture = context;
    assert(operation_id != 0U);
    ++fixture->calls;
    return fixture->grant;
}

typedef struct {
    bool fail_backup;
    bool fail_promotion;
    bool fail_restore;
    bool fail_temp_remove;
    unsigned fail_path_query;
    unsigned path_queries;
} fs_fixture_t;

static bool has_suffix(const char *text, const char *suffix)
{
    size_t text_len = strlen(text), suffix_len = strlen(suffix);
    return text_len >= suffix_len &&
           strcmp(text + text_len - suffix_len, suffix) == 0;
}

static int fixture_rename(void *context, const char *from, const char *to)
{
    fs_fixture_t *fixture = context;
    if ((fixture->fail_backup && has_suffix(to, ".bak") &&
         !has_suffix(from, ".bak")) ||
        (fixture->fail_promotion && has_suffix(from, ".tmp")) ||
        (fixture->fail_restore && has_suffix(from, ".bak"))) {
        return -1;
    }
    return rename(from, to);
}

static int fixture_remove(void *context, const char *path)
{
    fs_fixture_t *fixture = context;
    if (fixture->fail_temp_remove && has_suffix(path, ".tmp")) return -1;
    return remove(path);
}

static lab_store_path_state_t fixture_path_state(void *context,
                                                 const char *path)
{
    fs_fixture_t *fixture = context;
    ++fixture->path_queries;
    if (fixture->fail_path_query == fixture->path_queries)
        return LAB_STORE_PATH_ERROR;
    struct stat info;
    if (stat(path, &info) == 0) return LAB_STORE_PATH_EXISTS;
    return errno == ENOENT ? LAB_STORE_PATH_MISSING : LAB_STORE_PATH_ERROR;
}

#ifdef _WIN32
#include <direct.h>
#define MAKE_DIR(path) _mkdir(path)
#else
#include <sys/stat.h>
#define MAKE_DIR(path) mkdir(path, 0700)
#endif

static void read_text(const char *path, char *output, size_t capacity)
{
    FILE *file = fopen(path, "rb");
    assert(file != NULL);
    size_t count = fread(output, 1, capacity - 1U, file);
    assert(!ferror(file));
    output[count] = '\0';
    assert(fclose(file) == 0);
}

int main(int argc, char **argv)
{
    assert(argc == 2);
    const char *root = argv[1];
    (void)MAKE_DIR(root);

    lab_result_record_t result = {
        .bssid = {0x68, 0xff, 0x7b, 0xcd, 0xfc, 0x40},
        .ssid = "Lab \"AP\"",
        .pin = "12345670",
        .network_key = (const uint8_t *)"key\\value",
        .network_key_len = 9,
        .recovery_source = "pixie_mode_4",
        .manufacturer = "TP-Link",
        .model_name = "TL-WR840N",
        .model_number = "V6",
        .device_name = "Lab Router",
        .operation_id = 17,
        .authenticated_m7 = true,
    };
    assert(lab_result_store_success(root, &result) == LAB_STORE_OK);

    char path[512];
    assert(snprintf(path, sizeof(path),
                    "%s/results/wps_68-ff-7b-cd-fc-40.json", root) > 0);
    char text[2048];
    read_text(path, text, sizeof(text));
    assert(strstr(text, "\"schema\":1") != NULL);
    assert(strstr(text, "\"authenticated_m7\":true") != NULL);
    assert(strstr(text, "\"ssid\":\"Lab \\\"AP\\\"\"") != NULL);
    assert(strstr(text, "\"pin\":\"12345670\"") != NULL);
    assert(strstr(text, "\"network_key\":\"key\\\\value\"") != NULL);
    assert(strstr(text, "\"manufacturer\":\"TP-Link\"") != NULL);

    /* Cancellation is decided exactly once, after durable temp write and
     * before either the existing final or its backup is touched. */
    gate_fixture_t gate = {.grant = false};
    result.operation_id = 18U;
    result.network_key = (const uint8_t *)"replacement";
    result.network_key_len = 11U;
    assert(lab_result_store_success_gated(
        root, &result, commit_gate, &gate, NULL, NULL) == LAB_STORE_CANCELLED);
    assert(gate.calls == 1U);
    read_text(path, text, sizeof(text));
    assert(strstr(text, "\"operation_id\":17") != NULL);
    assert(strstr(text, "replacement") == NULL);

    result.bssid[5] = 0x41U;
    gate = (gate_fixture_t){.grant = false};
    assert(lab_result_store_success_gated(
        root, &result, commit_gate, &gate, NULL, NULL) == LAB_STORE_CANCELLED);
    assert(gate.calls == 1U);
    assert(snprintf(path, sizeof(path),
                    "%s/results/wps_68-ff-7b-cd-fc-41.json", root) > 0);
    assert(fopen(path, "rb") == NULL);
    result.bssid[5] = 0x40U;
    assert(snprintf(path, sizeof(path),
                    "%s/results/wps_68-ff-7b-cd-fc-40.json", root) > 0);

    /* Backup and promotion failures preserve the old authenticated result.
     * A failed backup restore leaves a recoverable .bak for the next call. */
    const lab_store_file_ops_t file_ops = {
        .rename_path = fixture_rename,
        .remove_path = fixture_remove,
        .path_state = fixture_path_state,
    };

    /* A denied commit whose unlink fails is reported as I/O failure and the
     * durable temp artifact is truncated before the failed unlink. */
    gate = (gate_fixture_t){.grant = false};
    fs_fixture_t fs = {.fail_temp_remove = true};
    assert(lab_result_store_success_gated(
        root, &result, commit_gate, &gate, &file_ops, &fs) ==
        LAB_STORE_IO_ERROR);
    char temporary[520];
    assert(snprintf(temporary, sizeof(temporary), "%s.tmp", path) > 0);
    struct stat temporary_info;
    assert(stat(temporary, &temporary_info) == 0);
    assert(temporary_info.st_size == 0);
    assert(remove(temporary) == 0);
    read_text(path, text, sizeof(text));
    assert(strstr(text, "\"operation_id\":17") != NULL);

    /* A stat error is not equivalent to a missing final/backup.  The
     * replacement stops without touching the existing authenticated file. */
    gate = (gate_fixture_t){.grant = true};
    fs = (fs_fixture_t){.fail_path_query = 1U};
    assert(lab_result_store_success_gated(
        root, &result, commit_gate, &gate, &file_ops, &fs) ==
        LAB_STORE_IO_ERROR);
    read_text(path, text, sizeof(text));
    assert(strstr(text, "\"operation_id\":17") != NULL);

    gate = (gate_fixture_t){.grant = true};
    fs = (fs_fixture_t){.fail_backup = true};
    assert(lab_result_store_success_gated(
        root, &result, commit_gate, &gate, &file_ops, &fs) == LAB_STORE_IO_ERROR);
    read_text(path, text, sizeof(text));
    assert(strstr(text, "\"operation_id\":17") != NULL);

    gate = (gate_fixture_t){.grant = true};
    fs = (fs_fixture_t){.fail_promotion = true};
    assert(lab_result_store_success_gated(
        root, &result, commit_gate, &gate, &file_ops, &fs) == LAB_STORE_IO_ERROR);
    read_text(path, text, sizeof(text));
    assert(strstr(text, "\"operation_id\":17") != NULL);

    char backup[520];
    assert(snprintf(backup, sizeof(backup), "%s.bak", path) > 0);
    gate = (gate_fixture_t){.grant = true};
    fs = (fs_fixture_t){.fail_promotion = true, .fail_restore = true};
    assert(lab_result_store_success_gated(
        root, &result, commit_gate, &gate, &file_ops, &fs) == LAB_STORE_IO_ERROR);
    assert(fopen(path, "rb") == NULL);
    FILE *recoverable = fopen(backup, "rb");
    assert(recoverable != NULL);
    assert(fclose(recoverable) == 0);

    /* The next bounded attempt repairs the interrupted replacement before it
     * tries to promote its own temp file. */
    gate = (gate_fixture_t){.grant = true};
    fs = (fs_fixture_t){.fail_promotion = true};
    assert(lab_result_store_success_gated(
        root, &result, commit_gate, &gate, &file_ops, &fs) == LAB_STORE_IO_ERROR);
    read_text(path, text, sizeof(text));
    assert(strstr(text, "\"operation_id\":17") != NULL);

    result.authenticated_m7 = false;
    assert(lab_result_store_success(root, &result) == LAB_STORE_INVALID);

    lab_device_observation_t observation = {
        .bssid = {0x78, 0x44, 0x76, 0xf1, 0xb0, 0x88},
        .ssid = "Pure Rental Apartments",
        .stage = "adapter_open",
        .reason = "timeout",
        .manufacturer = "Realtek",
        .model_name = "RTL8xxx",
        .device_name = "TOTOLINK",
    };
    assert(lab_result_store_observation(root, &observation) == LAB_STORE_OK);
    assert(lab_result_store_observation(root, &observation) == LAB_STORE_DUPLICATE);
    assert(snprintf(path, sizeof(path), "%s/unknown_devices.jsonl", root) > 0);
    read_text(path, text, sizeof(text));
    assert(strstr(text, "\"oui\":\"78:44:76\"") != NULL);
    assert(strstr(text, "\"ssid\":\"Pure Rental Apartments\"") != NULL);
    assert(strstr(text, "\"manufacturer\":\"Realtek\"") != NULL);
    assert(strstr(text, "12345670") == NULL);
    assert(strstr(text, "key\\\\value") == NULL);
    assert(strchr(text, '\n') != NULL);

    puts("PASS: WPS lab result store");
    return 0;
}
