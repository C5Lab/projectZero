#include "../modules/web/web_overlay.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static int positions[16][2];
static Font active_font;
static Font fonts[16];

void canvas_set_color(Canvas* canvas, Color color) {
    (void)canvas;
    (void)color;
}

void canvas_set_font(Canvas* canvas, Font font) {
    (void)canvas;
    active_font = font;
}

static void record(Canvas* canvas, int x, int y, const char* text) {
    assert(canvas->line_count < 16);
    size_t index = canvas->line_count++;
    snprintf(canvas->lines[index], sizeof(canvas->lines[index]), "%s", text);
    positions[index][0] = x;
    positions[index][1] = y;
    fonts[index] = active_font;
}

void canvas_draw_str(Canvas* canvas, int x, int y, const char* text) {
    record(canvas, x, y, text);
}

void canvas_draw_str_aligned(
    Canvas* canvas,
    int x,
    int y,
    Align horizontal,
    Align vertical,
    const char* text) {
    assert(horizontal == AlignCenter && vertical == AlignCenter);
    record(canvas, x, y, text);
}

static void assert_row(const Canvas* canvas, size_t index, const char* value, int x, int y) {
    assert(index < canvas->line_count);
    assert(strcmp(canvas->lines[index], value) == 0);
    assert(positions[index][0] == x && positions[index][1] == y);
}

static void test_portal_fallback_and_status(void) {
    Canvas canvas = {0};
    C5WebOverlayView view = {.fallback_ssid = "Guest Portal"};
    c5_web_overlay_draw_portal(&canvas, &view);
    assert(canvas.line_count == 5);
    assert_row(&canvas, 0, "Portal On", 2, 12);
    assert_row(&canvas, 1, "Guest Portal", 64, 24);
    assert(fonts[1] == FontPrimary);
    assert_row(&canvas, 2, "Clients: --", 64, 36);
    assert_row(&canvas, 3, "Passwords: 0", 64, 48);
    assert_row(&canvas, 4, "Usernames: 0", 64, 60);

    C5WebStatus status = {0};
    c5_web_status_reset(&status, C5WebStatusPortal);
    strcpy(status.ssid, "Status SSID");
    status.client_count = 3;
    status.password_count = 2;
    status.username_count = 1;
    canvas = (Canvas){0};
    view.status = &status;
    c5_web_overlay_draw_portal(&canvas, &view);
    assert_row(&canvas, 1, "Status SSID", 64, 24);
    assert_row(&canvas, 2, "Clients: 3", 64, 36);
    assert_row(&canvas, 3, "Passwords: 2", 64, 48);
    assert_row(&canvas, 4, "Usernames: 1", 64, 60);
}

static void test_title_scroll_clamps_to_legacy_window(void) {
    Canvas canvas = {0};
    C5WebOverlayView view = {
        .fallback_ssid = "ignored",
        .scroll_title = "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        .scroll_offset = 3,
    };
    c5_web_overlay_draw_evil_twin(&canvas, &view);
    assert_row(&canvas, 1, "DEFGHIJKLMNOPQRSTUVWXY", 64, 24);
    canvas = (Canvas){0};
    view.scroll_offset = 999;
    c5_web_overlay_draw_evil_twin(&canvas, &view);
    assert_row(&canvas, 1, "EFGHIJKLMNOPQRSTUVWXYZ", 64, 24);
}

static void test_evil_stage_and_password_truncation(void) {
    C5WebStatus status = {0};
    c5_web_status_reset(&status, C5WebStatusEvilTwin);
    strcpy(status.ssid, "Evil Guest");
    status.client_count = 4;
    status.password_count = 2;
    strcpy(status.last_password, "abcdefghijklmnopq");
    strcpy(status.note, "Checking");
    C5WebOverlayView view = {.status = &status, .fallback_ssid = "fallback"};
    Canvas canvas = {0};
    c5_web_overlay_draw_evil_twin(&canvas, &view);
    assert(canvas.line_count == 5);
    assert_row(&canvas, 0, "Evil Twin", 2, 12);
    assert_row(&canvas, 1, "Evil Guest", 64, 24);
    assert_row(&canvas, 2, "Clients: 4", 64, 36);
    assert_row(&canvas, 3, "Stage: Checking", 64, 48);
    assert_row(&canvas, 4, "Pass: abcdefghijklmn.", 64, 60);

    canvas = (Canvas){0};
    status.password_count = 0;
    status.note[0] = '\0';
    c5_web_overlay_draw_evil_twin(&canvas, &view);
    assert_row(&canvas, 3, "Stage: --", 64, 48);
    assert_row(&canvas, 4, "Pass: --", 64, 60);
}

int main(void) {
    test_portal_fallback_and_status();
    test_title_scroll_clamps_to_legacy_window();
    test_evil_stage_and_password_truncation();
    puts("Web overlay tests passed");
    return 0;
}
