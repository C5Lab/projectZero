#ifndef LAB_C5_WEB_OVERLAY_H
#define LAB_C5_WEB_OVERLAY_H

#include "web_status.h"

#include <gui/canvas.h>
#include <stddef.h>

typedef struct {
    const C5WebStatus* status;
    /* Portal: configured SSID. Evil Twin: first selected scanner SSID. */
    const char* fallback_ssid;
    /* Optional title maintained by the module's scroll tick. */
    const char* scroll_title;
    size_t scroll_offset;
} C5WebOverlayView;

/* Draws five text rows, without modifying status or scroll state. */
void c5_web_overlay_draw_portal(Canvas* canvas, const C5WebOverlayView* view);
void c5_web_overlay_draw_evil_twin(Canvas* canvas, const C5WebOverlayView* view);

#endif
