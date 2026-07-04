#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Detected display type after auto-probing I2C buses.
 */
typedef enum {
    DISPLAY_NONE = 0,       /**< No display found on any I2C bus          */
    DISPLAY_SSD1306,        /**< SSD1306 0.96" OLED 128x64 (GPIO 25/26)  */
    DISPLAY_SH1107,         /**< SH1107 1.3"  OLED 128x64 (GPIO 8/9)    */
    DISPLAY_SH1106,         /**< SH1106 1.3"  OLED 128x64 (GPIO 8/9)    */
    DISPLAY_UNIT_LCD,       /**< M5 Unit LCD 1.14" ST7789 (GPIO 8/9)     */
    DISPLAY_ST7735,         /**< LILYGO T-Dongle-C5 ST7735 SPI LCD 160x80 */
} display_type_t;

/**
 * Auto-detect and initialise the connected display.
 *
 * Probes two I2C buses in sequence:
 *   1. GPIO 25/26, addr 0x3C/0x3D (raw 0x78/0x7A accepted) → SSD1306 (via esp_lcd + LVGL)
 *   2. GPIO 8/9,   addr 0x3C → SH1107 / SH1106 (raw I2C framebuffer)
 *   3. GPIO 8/9,   addr 0x3E → Unit LCD (I2C command interface)
 *   4. Optional fallback on GPIO 8/9 for SSD1306 (controlled by OLED_PREFER_SSD1306_ON_BUS_B)
 *
 * SH1106/SH1107 can share the same 7-bit address (0x3C).
 * Default detection on bus B prefers SH110x (OLED_PREFER_SSD1306_ON_BUS_B=0).
 * SH1106/SH1107 order is controlled by OLED_PREFER_SH1106 (default: SH1107 first).
 *
 * Pin/address defaults can be overridden by OLED_* compile-time defines.
 *
 * Must be called after PSRAM init. Shows "Monster !" splash on success.
 */
void oled_display_init(void);

/**
 * Force display type used by init.
 * DISPLAY_NONE means auto-detect mode.
 */
void oled_display_set_forced_type(display_type_t type);

/**
 * Get currently configured forced display type.
 * DISPLAY_NONE means auto-detect mode.
 */
display_type_t oled_display_get_forced_type(void);

/**
 * Return the display type detected during init.
 */
display_type_t oled_display_get_type(void);

/**
 * Return detected display I2C address (7-bit). Returns 0 when not detected.
 */
uint8_t oled_display_get_i2c_addr_7bit(void);

/**
 * Return detected display I2C address in raw form (8-bit style if configured).
 * Returns 0 when not detected.
 */
uint8_t oled_display_get_i2c_addr_raw(void);

/**
 * Update the display with two lines of text (thread-safe).
 * Lines 3 and 4 are cleared. Backward-compatible shortcut.
 */
void oled_display_update(const char *line1, const char *line2);

/**
 * Update all four lines of the display (thread-safe).
 * Pass NULL to keep any line's previous content.
 * SSD1306: auto-scrolls long text via LVGL.
 * SH1107 / SH1106 / Unit LCD: truncates with "..." if too long.
 */
void oled_display_update_full(const char *line1, const char *line2,
                              const char *line3, const char *line4);

/**
 * Clear all four lines of the display.
 */
void oled_display_clear(void);

/* ---- ST7735 bring-up debug hooks (used by the `lcd` CLI command) ---- */
void oled_st7735_dbg_backlight(int on);
void oled_st7735_dbg_fill(uint16_t color);
void oled_st7735_dbg_madctl(int madctl, int invert);
void oled_st7735_dbg_offset(int col, int row);

#ifdef __cplusplus
}
#endif
