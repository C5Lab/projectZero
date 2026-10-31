#include "../modules/web/web_lists.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static uint32_t feed(C5WebList* list, const char* data) {
    return c5_web_list_feed(list, (const uint8_t*)data, strlen(data));
}

static void test_portal_ssid_entries_prompt_and_missing(void) {
    C5WebSsidEntry entries[2] = {0};
    C5WebList list;
    assert(c5_web_list_begin(&list, C5WebListPortalSsids, entries, 2));
    assert(feed(&list, "SSID presets from ssid.txt:\r\n1 Home Net\r\n2 Guest\n") & C5WebListEventEntries);
    assert(list.active && list.count == 2);
    assert(entries[0].id == 1 && strcmp(entries[0].ssid, "Home Net") == 0);
    assert(entries[1].id == 2 && strcmp(entries[1].ssid, "Guest") == 0);
    assert(feed(&list, ">") & C5WebListEventDone);
    assert(!list.active && !list.missing);

    assert(c5_web_list_begin(&list, C5WebListPortalSsids, entries, 2));
    assert(feed(&list, "ssid.txt not found\n") & C5WebListEventDone);
    assert(list.missing && list.count == 0);
    assert(feed(&list, ">") == 0);
}

static void test_html_and_probe_formats(void) {
    C5WebHtmlEntry html[1] = {0};
    C5WebList list;
    assert(c5_web_list_begin(&list, C5WebListHtml, html, 1));
    assert(feed(&list, "HTML files found on SD card:\n17 login.html  \n18 ignored.html\n\n") & C5WebListEventDone);
    assert(list.count == 1 && html[0].id == 17 && strcmp(html[0].name, "login.html") == 0);

    C5WebProbeEntry probes[3] = {0};
    assert(c5_web_list_begin(&list, C5WebListKarmaProbes, probes, 3));
    assert(feed(&list, "1 Home\n2 Guest\n3 Home\n>") & C5WebListEventDone);
    assert(list.count == 2);
    assert(probes[0].id == 3 && strcmp(probes[0].name, "Home") == 0);
    assert(probes[1].id == 2 && strcmp(probes[1].name, "Guest") == 0);
}

static void test_password_formats_and_fragmentation(void) {
    C5WebPassEntry passes[2] = {0};
    C5WebList list;
    assert(c5_web_list_begin(&list, C5WebListEvilPasswords, passes, 2));
    assert(feed(&list, "\"Hidden\", \"secret\"\n\"Cafe\", \"123") & C5WebListEventEntries);
    assert(feed(&list, "45678\"\n>") & C5WebListEventDone);
    assert(list.count == 2 && passes[0].id == 1 && passes[1].id == 2);
    assert(strcmp(passes[0].ssid, "Hidden") == 0);
    assert(strcmp(passes[1].pass, "12345678") == 0);

    C5WebTextLine lines[3] = {0};
    assert(c5_web_list_begin(&list, C5WebListPasswordsText, lines, 3));
    assert(feed(&list, "TX: show_pass portal\n\"AX4\", \"password=zupa\"\n\"BRW\", \"password=abc\"\n>") & C5WebListEventDone);
    assert(list.count == 2 && strcmp(lines[0], "\"AX4\", \"password=zupa\"") == 0);
    assert(strcmp(lines[1], "\"BRW\", \"password=abc\"") == 0);
    assert(list.max_line_length == strlen(lines[0]));
}

static void test_gt_inside_ssid_and_probe_name_is_not_prompt(void) {
    C5WebList list;
    C5WebSsidEntry ssids[2] = {0};
    assert(c5_web_list_begin(&list, C5WebListPortalSsids, ssids, 2));
    assert(feed(&list, "SSID presets from ssid.txt:\n1 Home") == 0);
    assert(feed(&list, ">Guest\n2 Cafe\n") & C5WebListEventEntries);
    assert(list.active && list.count == 2);
    assert(strcmp(ssids[0].ssid, "Home>Guest") == 0);
    assert(feed(&list, ">") & C5WebListEventDone);

    C5WebProbeEntry probes[2] = {0};
    assert(c5_web_list_begin(&list, C5WebListKarmaProbes, probes, 2));
    assert(feed(&list, "1 Phone>Hotspot\n2 Cafe\n") & C5WebListEventEntries);
    assert(list.active && list.count == 2);
    assert(strcmp(probes[0].name, "Phone>Hotspot") == 0);
    assert(feed(&list, ">") & C5WebListEventDone);
}

static void test_gt_inside_password_is_not_prompt(void) {
    C5WebList list;
    C5WebPassEntry passes[2] = {0};
    assert(c5_web_list_begin(&list, C5WebListEvilPasswords, passes, 2));
    assert(feed(&list, "\"Lab\", \"p>ass\"\n\"Cafe\", \"secret\"\n") &
           C5WebListEventEntries);
    assert(list.active && list.count == 2);
    assert(strcmp(passes[0].pass, "p>ass") == 0);
    assert(feed(&list, ">") & C5WebListEventDone);

    C5WebTextLine lines[2] = {0};
    assert(c5_web_list_begin(&list, C5WebListPasswordsText, lines, 2));
    assert(feed(&list, "Lab: p>ass\nCafe: secret\n") & C5WebListEventEntries);
    assert(list.active && list.count == 2);
    assert(strcmp(lines[0], "Lab: p>ass") == 0);
    assert(feed(&list, ">") & C5WebListEventDone);
}

static void test_invalid_inputs(void) {
    C5WebList list = {0};
    C5WebSsidEntry entries[1] = {0};
    assert(!c5_web_list_begin(&list, C5WebListPortalSsids, NULL, 1));
    assert(!c5_web_list_begin(&list, C5WebListPortalSsids, entries, 0));
    assert(!c5_web_list_begin(&list, C5WebListPortalSsids, entries, 49));
    assert(c5_web_list_begin(&list, C5WebListPortalSsids, entries, 1));
    assert(!c5_web_list_begin(&list, C5WebListPortalSsids, NULL, 1));
    assert(!list.active);
    assert(c5_web_list_begin(&list, C5WebListPortalSsids, entries, 1));
    assert(c5_web_list_feed(&list, NULL, 1) == 0);
    assert(c5_web_list_feed(NULL, (const uint8_t*)"x", 1) == 0);
    c5_web_list_end(&list);
    assert(!list.active && feed(&list, "1 ignored\n") == 0);
}

static void test_firmware_error_reply_still_finishes_at_prompt(void) {
    C5WebList list;
    C5WebProbeEntry probes[1] = {0};
    assert(c5_web_list_begin(&list, C5WebListKarmaProbes, probes, 1));
    assert(feed(&list, "No probe requests captured. Use 'start_sniffer' to collect data.\n") == 0);
    assert(feed(&list, ">") & C5WebListEventDone);
    assert(!list.active && list.count == 0);

    C5WebHtmlEntry html[1] = {0};
    assert(c5_web_list_begin(&list, C5WebListHtml, html, 1));
    assert(feed(&list, "Failed to initialize SD card: ESP_FAIL\n>") & C5WebListEventDone);
    assert(!list.active && list.count == 0);
}

static void test_overlong_line_does_not_create_false_entry(void) {
    C5WebList list;
    C5WebSsidEntry entries[2] = {0};
    assert(c5_web_list_begin(&list, C5WebListPortalSsids, entries, 2));
    char reply[220];
    memset(reply, 'x', 165);
    strcpy(reply + 165, "1 phantom\n2 real\n>");
    assert(feed(&list, reply) & C5WebListEventDone);
    assert(list.count == 1 && entries[0].id == 2);
    assert(strcmp(entries[0].ssid, "real") == 0);

    assert(c5_web_list_begin(&list, C5WebListPortalSsids, entries, 2));
    memset(reply, 'x', 165);
    strcpy(reply + 165, "1 phantom>");
    assert(feed(&list, reply) & C5WebListEventDone);
    assert(list.count == 0);

    assert(c5_web_list_begin(&list, C5WebListPortalSsids, entries, 2));
    assert(feed(&list, "SSID presets from ssid.txt:\n") == 0);
    memset(reply, 'x', 165);
    strcpy(reply + 165, "1 phantom\n2 real\n>");
    assert(feed(&list, reply) & C5WebListEventDone);
    assert(list.count == 1 && entries[0].id == 2);
}

int main(void) {
    test_portal_ssid_entries_prompt_and_missing();
    test_html_and_probe_formats();
    test_password_formats_and_fragmentation();
    test_gt_inside_ssid_and_probe_name_is_not_prompt();
    test_gt_inside_password_is_not_prompt();
    test_invalid_inputs();
    test_firmware_error_reply_still_finishes_at_prompt();
    test_overlong_line_does_not_create_false_entry();
    puts("Web list tests passed");
    return 0;
}
