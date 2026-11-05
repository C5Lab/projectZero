#include "wifi_shield_channel.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static const wifi_shield_target_t fixtures[] = {
    {{2, 0, 0, 0, 0, 1}, 11, "first", true},
    {{2, 0, 0, 0, 0, 2}, 1, "second", false},
    {{2, 0, 0, 0, 0, 3}, 11, "duplicate channel", false},
    {{2, 0, 0, 0, 0, 4}, 6, "fourth", false},
};
static const uint8_t unknown[6] = {2, 0, 0, 0, 0, 99};

static void expect_empty(wifi_shield_channel_plan_t *plan)
{
    assert(plan->target_count == 0 && plan->channel_count == 0);
    assert(!plan->locked);
    assert(wifi_shield_channel_next(plan) == 0);
    assert(!wifi_shield_target_selected(plan, fixtures[0].bssid));
    assert(!wifi_shield_channel_lock(plan, fixtures[0].bssid, 11));
    assert(strcmp(wifi_shield_channel_coverage(plan), "none") == 0);
}

static void invalid_inputs(void)
{
    wifi_shield_channel_plan_t plan;
    wifi_shield_target_t bad[2];
    assert(!wifi_shield_channel_plan_init(NULL, fixtures, 1));
    assert(!wifi_shield_channel_plan_init(&plan, NULL, 1));
    expect_empty(&plan);
    assert(!wifi_shield_channel_plan_init(&plan, fixtures, 0));
    expect_empty(&plan);
    assert(!wifi_shield_channel_plan_init(&plan, NULL, 0));
    assert(!wifi_shield_channel_plan_init(&plan, fixtures, 65));
    expect_empty(&plan);
    memcpy(bad, fixtures, sizeof(bad));
    memset(bad[1].bssid, 0, 6);
    assert(!wifi_shield_channel_plan_init(&plan, bad, 2));
    expect_empty(&plan);
    memcpy(bad, fixtures, sizeof(bad));
    bad[1].bssid[0] = 1;
    assert(!wifi_shield_channel_plan_init(&plan, bad, 2));
    memset(bad[1].bssid, 255, 6);
    assert(!wifi_shield_channel_plan_init(&plan, bad, 2));
    memcpy(bad, fixtures, sizeof(bad));
    memcpy(bad[1].bssid, bad[0].bssid, 6);
    assert(!wifi_shield_channel_plan_init(&plan, bad, 2));
    memcpy(bad, fixtures, sizeof(bad));
    bad[1].channel = 0;
    assert(!wifi_shield_channel_plan_init(&plan, bad, 2));
    expect_empty(&plan);
    assert(!wifi_shield_target_selected(NULL, unknown));
    assert(!wifi_shield_target_selected(&plan, NULL));
    assert(wifi_shield_channel_next(NULL) == 0);
    assert(!wifi_shield_channel_lock(NULL, unknown, 1));
    assert(!wifi_shield_channel_lock(&plan, NULL, 1));
    wifi_shield_channel_release(NULL);
    assert(strcmp(wifi_shield_channel_coverage(NULL), "none") == 0);
    assert(wifi_shield_channel_plan_init(&plan, fixtures, 4));
    assert(wifi_shield_channel_lock(&plan, fixtures[0].bssid, 11));
    assert(!wifi_shield_channel_plan_init(&plan, bad, 2));
    expect_empty(&plan);
}

static void immutable_schedule_and_lock(void)
{
    wifi_shield_channel_plan_t plan;
    wifi_shield_target_t inputs[4];
    memcpy(inputs, fixtures, sizeof(inputs));
    /* Core preserves bounded SSID bytes; platform owns evidence sanitization. */
    memset(inputs[0].ssid, 'x', 33);
    inputs[0].ssid[2] = '\n';
    assert(wifi_shield_channel_plan_init(&plan, inputs, 4));
    assert(memcmp(plan.targets[0].ssid, inputs[0].ssid, 33) == 0);
    assert(plan.targets[0].wpa2_psk_ccmp);
    memset(inputs, 0, sizeof(inputs));
    assert(wifi_shield_target_selected(&plan, fixtures[0].bssid));
    assert(wifi_shield_target_selected(&plan, fixtures[3].bssid));
    assert(!wifi_shield_target_selected(&plan, unknown));
    assert(plan.target_count == 4 && plan.channel_count == 3);
    assert(strcmp(wifi_shield_channel_coverage(&plan), "sampled") == 0);
    assert(wifi_shield_channel_next(&plan) == 11);
    assert(!wifi_shield_channel_lock(&plan, unknown, 1));
    assert(!wifi_shield_channel_lock(&plan, fixtures[0].bssid, 1));
    assert(!wifi_shield_channel_lock(&plan, fixtures[0].bssid, 0));
    assert(wifi_shield_channel_next(&plan) == 1);
    assert(wifi_shield_channel_lock(&plan, fixtures[2].bssid, 11));
    assert(wifi_shield_channel_next(&plan) == 11);
    assert(wifi_shield_channel_next(&plan) == 11);
    assert(!wifi_shield_channel_lock(&plan, fixtures[2].bssid, 6));
    assert(wifi_shield_channel_next(&plan) == 11);
    assert(strcmp(wifi_shield_channel_coverage(&plan), "sampled") == 0);
    wifi_shield_channel_release(&plan);
    wifi_shield_channel_release(&plan);
    assert(wifi_shield_channel_next(&plan) == 6);
    assert(wifi_shield_channel_next(&plan) == 11);
    assert(wifi_shield_channel_next(&plan) == 1);
    assert(wifi_shield_channel_next(&plan) == 6);
    assert(wifi_shield_channel_lock(&plan, fixtures[3].bssid, 6));
    assert(wifi_shield_channel_next(&plan) == 6);
    wifi_shield_channel_release(&plan);
    assert(wifi_shield_channel_next(&plan) == 11);
}

static void capacity_and_single_channel(void)
{
    wifi_shield_channel_plan_t plan;
    wifi_shield_target_t inputs[64];
    for (size_t i = 0; i < 64; ++i) {
        inputs[i] = fixtures[0];
        inputs[i].bssid[5] = (uint8_t)(i + 1);
    }
    assert(wifi_shield_channel_plan_init(&plan, inputs, 64));
    assert(wifi_shield_target_selected(&plan, inputs[63].bssid));
    assert(plan.target_count == 64 && plan.channel_count == 1);
    assert(strcmp(wifi_shield_channel_coverage(&plan), "continuous") == 0);
    for (size_t i = 0; i < 130; ++i)
        assert(wifi_shield_channel_next(&plan) == 11);
    assert(wifi_shield_channel_lock(&plan, inputs[63].bssid, 11));
    wifi_shield_channel_release(&plan);
    assert(wifi_shield_channel_next(&plan) == 11);
    /* Channel policy is the platform's responsibility; nonzero is sufficient. */
    for (size_t i = 0; i < 64; ++i)
        inputs[i].channel = (uint8_t)(i + 1);
    assert(wifi_shield_channel_plan_init(&plan, inputs, 64));
    assert(plan.channel_count == 64);
    assert(wifi_shield_channel_next(&plan) == 1);
    for (size_t i = 2; i <= 63; ++i)
        assert(wifi_shield_channel_next(&plan) == i);
    assert(wifi_shield_channel_next(&plan) == 64);
    assert(wifi_shield_channel_next(&plan) == 1);
}

int main(void)
{
    invalid_inputs();
    immutable_schedule_and_lock();
    capacity_and_single_channel();
    puts("wifi shield channel: PASS");
    return 0;
}
