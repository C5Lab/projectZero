#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "lab_secret.h"

static unsigned wipes;
static void observed_wipe(void *memory, size_t length)
{
    memset(memory, 0, length);
    ++wipes;
}

int main(void)
{
    lab_secret_vault_t vault;
    lab_secret_init(&vault, observed_wipe);
    lab_secret_info_t info = lab_secret_status(&vault, 10);
    assert(info.state == LAB_SECRET_EMPTY);

    assert(lab_secret_store(&vault, "12345670", "lab-key", 7, 1000));
    info = lab_secret_status(&vault, 1001);
    assert(info.state == LAB_SECRET_AVAILABLE && info.operation_id == 7);
    assert(info.remaining_ms == LAB_SECRET_TTL_MS - 1);
    assert(lab_secret_status(&vault, 301000).state == LAB_SECRET_EXPIRED);
    assert(lab_secret_status(&vault, 301000).state == LAB_SECRET_EMPTY);

    assert(lab_secret_store(&vault, "12345670", "first", 8, 400000));
    unsigned before = wipes;
    assert(lab_secret_store(&vault, "00000000", "second", 9, 400001));
    assert(wipes > before);
    char pin[9], key[65];
    uint32_t operation = 0;
    assert(lab_secret_take(&vault, 400002, pin, sizeof(pin), key, sizeof(key), &operation));
    assert(strcmp(pin, "00000000") == 0 && strcmp(key, "second") == 0 && operation == 9);
    assert(lab_secret_status(&vault, 400002).state == LAB_SECRET_EMPTY);
    memset(pin, 0, sizeof(pin));
    memset(key, 0, sizeof(key));

    assert(lab_secret_store(&vault, "12345670", "erase", 10, 500000));
    lab_secret_erase(&vault);
    assert(lab_secret_status(&vault, 500001).state == LAB_SECRET_EMPTY);
    puts("PASS: WPS lab secret vault");
    return 0;
}
