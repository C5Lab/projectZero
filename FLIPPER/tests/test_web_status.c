#include "../modules/web/web_status.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    C5WebStatusEvent events[4];
    size_t count;
} EventCapture;

static void capture_event(void* context, C5WebStatusEvent event) {
    EventCapture* capture = context;
    assert(capture->count < 4);
    capture->events[capture->count++] = event;
}

static void feed(C5WebStatus* status, const char* text, EventCapture* events) {
    size_t length = strlen(text);
    for(size_t i = 0; i < length;) {
        size_t chunk = (i % 4) + 1;
        if(chunk > length - i) chunk = length - i;
        c5_web_status_feed(status, (const uint8_t*)text + i, chunk, capture_event, events);
        i += chunk;
    }
}

static void test_portal_status_from_firmware_logs(void) {
    C5WebStatus status = {0};
    EventCapture events = {0};
    c5_web_status_reset(&status, C5WebStatusPortal);
    assert(status.client_count == -1);
    feed(&status, "> I (1234) wifi: Starting captive portal with SSID: Łódź\r\n", &events);
    assert(strcmp(status.ssid, "Lodz") == 0);
    feed(&status, "AP Name: Lab Guest\nPortal: Client count = 2\n", &events);
    assert(strcmp(status.ssid, "Lab Guest") == 0 && status.client_count == 2);
    feed(&status, "Portal password received: topsecret\n", &events);
    assert(status.password_count == 1 && strcmp(status.last_password, "topsecret") == 0);
    feed(&status, "Password: second\n", &events);
    assert(status.password_count == 2 && strcmp(status.last_password, "second") == 0);
    feed(&status, "Received POST data: google_user=lab+user&password=x\n", &events);
    assert(status.username_count == 1 && strcmp(status.last_username, "lab user") == 0);
    feed(&status, "Received POST data: other=x&email=mail%40lab.test\n", &events);
    assert(status.username_count == 2 && strcmp(status.last_username, "mail%40lab.test") == 0);
    feed(&status, "Received POST data: username=second&google_user=preferred\n", &events);
    assert(status.username_count == 3 && strcmp(status.last_username, "preferred") == 0);
    assert(events.count == 0);
    feed(&status, "Portal: Client count = nonsense\n", &events);
    assert(status.client_count == 2);
    c5_web_status_reset(&status, C5WebStatusPortal);
    assert(status.client_count == -1 && status.password_count == 0 && status.username_count == 0);
}

static void test_evil_status_stages_and_events(void) {
    C5WebStatus status = {0};
    EventCapture events = {0};
    c5_web_status_reset(&status, C5WebStatusEvilTwin);
    feed(&status, "Starting captive portal for Evil Twin attack on: Lab5\n", &events);
    assert(strcmp(status.ssid, "Lab5") == 0 && strcmp(status.note, "Portal") == 0);
    feed(&status, "AP Name: Lab5 Guest\nCaptive portal started successfully\n", &events);
    assert(strcmp(status.ssid, "Lab5 Guest") == 0 && strcmp(status.note, "Portal") == 0);
    feed(&status, "Deauth attack started.\nPortal: Client count = 1\n", &events);
    assert(strcmp(status.note, "Deauth") == 0 && status.client_count == 1);
    feed(&status, "Portal password received: firstguess\n", &events);
    assert(status.password_count == 1 && strcmp(status.last_password, "firstguess") == 0);
    assert(strcmp(status.note, "Received") == 0);
    feed(&status, "Stopping deauth attack to attempt connection...\n", &events);
    assert(strcmp(status.note, "Checking") == 0);
    feed(&status, "Resuming deauth attack - password was incorrect.\n", &events);
    assert(strcmp(status.note, "Wrong") == 0 && status.password_count == 0);
    assert(status.last_password[0] == '\0');
    assert(events.count == 1 && events.events[0] == C5WebStatusBadPassword);
    feed(&status, "Deauth attack resumed successfully.\n", &events);
    assert(strcmp(status.note, "Deauth") == 0);
    feed(&status, "Attempting to connect, connectAttemptCount=2\n", &events);
    assert(strcmp(status.note, "Checking") == 0);
    feed(&status, "Attempting to connect to SSID='Other' with password='x'\n", &events);
    assert(strcmp(status.ssid, "Other") == 0 && strcmp(status.note, "Checking") == 0);
    feed(&status, "Wi-Fi: connected to SSID='Other' with password='x'\n", &events);
    assert(strcmp(status.note, "Verified") == 0);
    feed(&status, "Evil twin: connection failed, wrong password?\n", &events);
    assert(strcmp(status.note, "Wrong") == 0);
    feed(&status, "Password verified! Shutting down Evil Twin portal...\n", &events);
    assert(strcmp(status.note, "Verified") == 0);
    feed(&status, "Password saved to eviltwin.txt\n", &events);
    assert(events.count == 2 && events.events[1] == C5WebStatusPasswordSaved);
    feed(&status, "Evil Twin portal shut down successfully!\n", &events);
    assert(strcmp(status.note, "Stopped") == 0);
    c5_web_status_reset(&status, C5WebStatusEvilTwin);
    assert(status.client_count == -1 && status.note[0] == '\0');
}

static void test_bounded_line_and_nonmatching_mode(void) {
    C5WebStatus status = {0};
    EventCapture events = {0};
    c5_web_status_reset(&status, C5WebStatusPortal);
    char oversized[320];
    memset(oversized, 'A', sizeof(oversized) - 2);
    oversized[sizeof(oversized) - 2] = '\n';
    oversized[sizeof(oversized) - 1] = '\0';
    feed(&status, oversized, &events);
    feed(&status, "Portal: Client count = 3\n", &events);
    assert(status.client_count == 3);
    feed(&status, "Password saved to eviltwin.txt\n", &events);
    assert(events.count == 0);
}

int main(void) {
    test_portal_status_from_firmware_logs();
    test_evil_status_stages_and_events();
    test_bounded_line_and_nonmatching_mode();
    puts("Web status tests passed");
    return 0;
}
