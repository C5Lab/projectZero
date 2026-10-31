#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    bool locked;
    unsigned acquires;
    unsigned releases;
} FuriMutex;

typedef struct {
    uint8_t bytes[512];
    size_t length;
    unsigned writes;
    unsigned waits;
    bool called_unlocked;
} FuriHalSerialHandle;

enum { FuriWaitForever = 0xffffffffu };

static FuriMutex* active_mutex;

static int furi_mutex_acquire(FuriMutex* mutex, uint32_t timeout) {
    (void)timeout;
    if(mutex->locked) return -1;
    mutex->locked = true;
    mutex->acquires++;
    return 0;
}

static int furi_mutex_release(FuriMutex* mutex) {
    if(!mutex->locked) return -1;
    mutex->locked = false;
    mutex->releases++;
    return 0;
}

static void furi_hal_serial_tx(FuriHalSerialHandle* serial, const uint8_t* data, size_t length) {
    if(!active_mutex->locked || serial->length + length > sizeof(serial->bytes)) {
        serial->called_unlocked = true;
        return;
    }
    memcpy(serial->bytes + serial->length, data, length);
    serial->length += length;
    serial->writes++;
}

static void furi_hal_serial_tx_wait_complete(FuriHalSerialHandle* serial) {
    if(!active_mutex->locked) serial->called_unlocked = true;
    serial->waits++;
}

#include "../command_io.h"

#define CHECK(condition) \
    do { \
        if(!(condition)) { \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); \
            return 1; \
        } \
    } while(0)

static int test_serial_line(const char* command) {
    FuriMutex mutex = {0};
    FuriHalSerialHandle serial = {0};
    active_mutex = &mutex;

    size_t command_length = strlen(command);
    lab_c5_serial_write_line(&serial, &mutex, command, command_length);

    CHECK(!serial.called_unlocked);
    CHECK(!mutex.locked);
    CHECK(mutex.acquires == 1 && mutex.releases == 1);
    CHECK(serial.writes == 2 && serial.waits == 1);
    CHECK(serial.length == command_length + 1);
    CHECK(memcmp(serial.bytes, command, command_length) == 0);
    CHECK(serial.bytes[command_length] == '\n');
    return 0;
}

static int test_log_line(const char* command, size_t capacity, bool expect_truncation) {
    struct {
        uint8_t before;
        char line[96];
        uint8_t after;
    } guarded = {.before = 0xa5, .after = 0x5a};
    memset(guarded.line, 0xcc, sizeof(guarded.line));

    size_t length = lab_c5_format_tx_log(guarded.line, capacity, command, strlen(command));
    CHECK(length > 0 && length < capacity);
    CHECK(length == strlen(guarded.line));
    CHECK(guarded.line[length - 1] == '\n');
    CHECK(strncmp(guarded.line, "TX: ", 4) == 0);
    CHECK(guarded.before == 0xa5 && guarded.after == 0x5a);
    if(capacity < sizeof(guarded.line)) CHECK((uint8_t)guarded.line[capacity] == 0xcc);
    if(expect_truncation) {
        CHECK(length >= 4);
        CHECK(memcmp(guarded.line + length - 4, "...\n", 4) == 0);
    } else {
        CHECK(length == strlen(command) + 5);
    }
    return 0;
}

int main(void) {
    char long_command[256];
    memset(long_command, 'A', sizeof(long_command) - 1);
    long_command[sizeof(long_command) - 1] = '\0';
    char near_limit[92];
    memset(near_limit, 'B', sizeof(near_limit) - 1);
    near_limit[sizeof(near_limit) - 1] = '\0';

    CHECK(test_serial_line("ping") == 0);
    CHECK(test_serial_line("led read") == 0);
    CHECK(test_serial_line(long_command) == 0);
    CHECK(test_log_line("ping", 96, false) == 0);
    near_limit[90] = '\0';
    CHECK(test_log_line(near_limit, 96, false) == 0);
    near_limit[90] = 'B';
    CHECK(test_log_line(near_limit, 96, true) == 0);
    CHECK(test_log_line(long_command, 96, true) == 0);
    CHECK(test_log_line(long_command, 9, true) == 0);
    puts("command_io tests passed");
    return 0;
}
