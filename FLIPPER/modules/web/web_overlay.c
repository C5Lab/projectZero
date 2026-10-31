#include "web_overlay.h"

#include <stdio.h>
#include <string.h>

#define C5_WEB_OVERLAY_DISPLAY_WIDTH 128
#define C5_WEB_OVERLAY_TITLE_CHAR_LIMIT 22u

static void c5_web_overlay_truncate(char* text, size_t maximum) {
    size_t length = strlen(text);
    if(length <= maximum) return;
    if(maximum == 1) {
        text[0] = '\0';
    } else {
        text[maximum - 1] = '.';
        text[maximum] = '\0';
    }
}

static const char* c5_web_overlay_ssid(const C5WebOverlayView* view) {
    if(view->status && view->status->ssid[0]) return view->status->ssid;
    if(view->fallback_ssid && view->fallback_ssid[0]) return view->fallback_ssid;
    return "--";
}

static void c5_web_overlay_draw_title(Canvas* canvas, const C5WebOverlayView* view) {
    const char* title = view->scroll_title && view->scroll_title[0]
                            ? view->scroll_title
                            : c5_web_overlay_ssid(view);
    size_t length = strlen(title);
    size_t limit = C5_WEB_OVERLAY_TITLE_CHAR_LIMIT;
    canvas_set_font(canvas, FontPrimary);
    if(length <= limit) {
        canvas_draw_str_aligned(
            canvas, C5_WEB_OVERLAY_DISPLAY_WIDTH / 2, 24, AlignCenter, AlignCenter, title);
    } else {
        size_t maximum_offset = length - limit;
        size_t offset = view->scroll_offset > maximum_offset ? maximum_offset : view->scroll_offset;
        char window[C5_WEB_OVERLAY_TITLE_CHAR_LIMIT + 1];
        memcpy(window, title + offset, limit);
        window[limit] = '\0';
        canvas_draw_str_aligned(
            canvas, C5_WEB_OVERLAY_DISPLAY_WIDTH / 2, 24, AlignCenter, AlignCenter, window);
    }
}

static void c5_web_overlay_draw_clients(Canvas* canvas, const C5WebStatus* status) {
    char line[32];
    if(status && status->client_count >= 0) {
        snprintf(line, sizeof(line), "Clients: %ld", (long)status->client_count);
    } else {
        snprintf(line, sizeof(line), "Clients: --");
    }
    canvas_draw_str_aligned(
        canvas, C5_WEB_OVERLAY_DISPLAY_WIDTH / 2, 36, AlignCenter, AlignCenter, line);
}

void c5_web_overlay_draw_portal(Canvas* canvas, const C5WebOverlayView* view) {
    if(!canvas || !view) return;
    const C5WebStatus* status = view->status;
    if(status && status->mode != C5WebStatusPortal) status = NULL;
    C5WebOverlayView shown = *view;
    shown.status = status;

    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str(canvas, 2, 12, "Portal On");
    c5_web_overlay_draw_title(canvas, &shown);
    canvas_set_font(canvas, FontSecondary);
    c5_web_overlay_draw_clients(canvas, status);

    char line[32];
    snprintf(
        line,
        sizeof(line),
        "Passwords: %lu",
        (unsigned long)(status ? status->password_count : 0));
    canvas_draw_str_aligned(
        canvas, C5_WEB_OVERLAY_DISPLAY_WIDTH / 2, 48, AlignCenter, AlignCenter, line);
    snprintf(
        line,
        sizeof(line),
        "Usernames: %lu",
        (unsigned long)(status ? status->username_count : 0));
    canvas_draw_str_aligned(
        canvas, C5_WEB_OVERLAY_DISPLAY_WIDTH / 2, 60, AlignCenter, AlignCenter, line);
}

void c5_web_overlay_draw_evil_twin(Canvas* canvas, const C5WebOverlayView* view) {
    if(!canvas || !view) return;
    const C5WebStatus* status = view->status;
    if(status && status->mode != C5WebStatusEvilTwin) status = NULL;
    C5WebOverlayView shown = *view;
    shown.status = status;

    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str(canvas, 2, 12, "Evil Twin");
    c5_web_overlay_draw_title(canvas, &shown);
    canvas_set_font(canvas, FontSecondary);
    c5_web_overlay_draw_clients(canvas, status);

    char stage[32];
    snprintf(
        stage,
        sizeof(stage),
        "Stage: %s",
        status && status->note[0] ? status->note : "--");
    c5_web_overlay_truncate(stage, 21);
    canvas_draw_str_aligned(
        canvas, C5_WEB_OVERLAY_DISPLAY_WIDTH / 2, 48, AlignCenter, AlignCenter, stage);

    char password[64];
    if(!status || status->password_count == 0 || status->last_password[0] == '\0') {
        snprintf(password, sizeof(password), "Pass: --");
    } else if(status->password_count == 1) {
        snprintf(password, sizeof(password), "Pass: %.*s", 16, status->last_password);
    } else {
        snprintf(
            password,
            sizeof(password),
            "Pass: %.*s (%lu)",
            16,
            status->last_password,
            (unsigned long)status->password_count);
    }
    c5_web_overlay_truncate(password, 21);
    canvas_draw_str_aligned(
        canvas, C5_WEB_OVERLAY_DISPLAY_WIDTH / 2, 60, AlignCenter, AlignCenter, password);
}
