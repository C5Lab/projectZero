#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize I2C bus, SSD1306 panel, and LVGL for the 0.96" OLED display.
 * Must be called after PSRAM init. Starts the LVGL timer task.
 */
void oled_display_init(void);

/**
 * Update the OLED display with two lines of text (thread-safe).
 * @param line1  Top line – command/mode name (may be NULL to keep previous)
 * @param line2  Bottom line – SSID / parameter (may be NULL or "" to clear)
 */
void oled_display_update(const char *line1, const char *line2);

#ifdef __cplusplus
}
#endif
