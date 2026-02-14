/*
 * OLED Display module – SSD1306 0.96" 128x64 via I2C + LVGL 9
 *
 * All LVGL-related memory (draw buffer, task stack) is allocated from PSRAM.
 * The intermediate SSD1306 bitmap buffer stays in internal RAM for I2C safety.
 */

#include "oled_display.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/lock.h>
#include <sys/param.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_timer.h"
#include "esp_lcd_panel_io.h"
#include "esp_lcd_panel_ops.h"
#include "esp_lcd_panel_vendor.h"
#include "esp_err.h"
#include "esp_log.h"
#include "esp_heap_caps.h"
#include "driver/i2c_master.h"

#include "lvgl.h"

static const char *TAG = "oled";

/* ── Pin / hardware configuration ──────────────────────────────────────── */
#define OLED_I2C_PORT             0
#define OLED_PIN_SDA              25
#define OLED_PIN_SCL              26
#define OLED_I2C_FREQ_HZ          (400 * 1000)
#define OLED_I2C_ADDR             0x3C
#define OLED_H_RES                128
#define OLED_V_RES                64
#define OLED_CMD_BITS             8
#define OLED_PARAM_BITS           8

/* ── LVGL tunables ─────────────────────────────────────────────────────── */
#define LVGL_TICK_PERIOD_MS       5
#define LVGL_TASK_STACK_SIZE      (4 * 1024)
#define LVGL_TASK_PRIORITY        2
#define LVGL_PALETTE_SIZE         8          /* LVGL reserves 2×4 bytes for I1 palette */
#define LVGL_TASK_MAX_DELAY_MS    500
#define LVGL_TASK_MIN_DELAY_MS    (1000 / CONFIG_FREERTOS_HZ)

/* ── Intermediate page-format buffer for SSD1306 (internal RAM) ──────── */
static uint8_t oled_buffer[OLED_H_RES * OLED_V_RES / 8];

/* ── Thread safety ─────────────────────────────────────────────────────── */
static _lock_t lvgl_api_lock;

/* ── LVGL objects ──────────────────────────────────────────────────────── */
static lv_display_t *s_display = NULL;
static lv_obj_t     *s_label_line1 = NULL;
static lv_obj_t     *s_label_line2 = NULL;

/* ── Flush callback: convert LVGL I1 bitmap → SSD1306 page format ───── */
static void oled_flush_cb(lv_display_t *disp, const lv_area_t *area, uint8_t *px_map)
{
    esp_lcd_panel_handle_t panel = lv_display_get_user_data(disp);

    /* Skip the 8-byte palette that LVGL prepends for I1 format */
    px_map += LVGL_PALETTE_SIZE;

    uint16_t hor_res = lv_display_get_physical_horizontal_resolution(disp);
    int x1 = area->x1;
    int x2 = area->x2;
    int y1 = area->y1;
    int y2 = area->y2;

    for (int y = y1; y <= y2; y++) {
        for (int x = x1; x <= x2; x++) {
            /* MSB-first bit order in LVGL I1 row buffer.
             * bit=1 means palette[1] (white), bit=0 means palette[0] (black).
             * Direct mapping: LVGL white → SSD1306 pixel ON, LVGL black → OFF. */
            bool chroma = (px_map[(hor_res >> 3) * y + (x >> 3)] & (1 << (7 - (x % 8))));

            /* SSD1306 page format: 8 vertical pixels per byte, LSB = top */
            uint8_t *buf = oled_buffer + hor_res * (y >> 3) + x;
            if (chroma) {
                (*buf) |= (1 << (y % 8));    /* white → pixel ON  */
            } else {
                (*buf) &= ~(1 << (y % 8));   /* black → pixel OFF */
            }
        }
    }

    esp_lcd_panel_draw_bitmap(panel, x1, y1, x2 + 1, y2 + 1, oled_buffer);
}

/* ── I2C transfer-done ISR → tell LVGL the flush finished ────────────── */
static bool oled_flush_ready_cb(esp_lcd_panel_io_handle_t io,
                                esp_lcd_panel_io_event_data_t *edata,
                                void *user_ctx)
{
    lv_display_t *disp = (lv_display_t *)user_ctx;
    lv_display_flush_ready(disp);
    return false;
}

/* ── LVGL tick callback (called from esp_timer ISR context) ──────────── */
static void lvgl_tick_cb(void *arg)
{
    lv_tick_inc(LVGL_TICK_PERIOD_MS);
}

/* ── LVGL timer handler task ─────────────────────────────────────────── */
static void lvgl_task(void *arg)
{
    ESP_LOGI(TAG, "LVGL task started");
    uint32_t time_till_next_ms = 0;
    while (1) {
        _lock_acquire(&lvgl_api_lock);
        time_till_next_ms = lv_timer_handler();
        _lock_release(&lvgl_api_lock);

        time_till_next_ms = MAX(time_till_next_ms, LVGL_TASK_MIN_DELAY_MS);
        time_till_next_ms = MIN(time_till_next_ms, LVGL_TASK_MAX_DELAY_MS);
        usleep(1000 * time_till_next_ms);
    }
}

/* ── Build the two-line UI ───────────────────────────────────────────── */
static void build_ui(lv_display_t *disp)
{
    lv_obj_t *scr = lv_display_get_screen_active(disp);

    /* Black background (SSD1306 pixels OFF = dark OLED) */
    lv_obj_set_style_bg_color(scr, lv_color_black(), 0);
    lv_obj_set_style_bg_opa(scr, LV_OPA_COVER, 0);
    lv_obj_set_style_pad_all(scr, 0, 0);

    /* Line 1 – command / mode name (top, crisp 8px bitmap font) */
    s_label_line1 = lv_label_create(scr);
    lv_label_set_long_mode(s_label_line1, LV_LABEL_LONG_CLIP);
    lv_obj_set_width(s_label_line1, OLED_H_RES);
    lv_obj_set_style_text_font(s_label_line1, &lv_font_unscii_8, 0);
    lv_obj_set_style_text_color(s_label_line1, lv_color_white(), 0);
    lv_obj_align(s_label_line1, LV_ALIGN_TOP_LEFT, 0, 0);
    lv_label_set_text(s_label_line1, "JanOS");

    /* Line 2 – SSID / parameter (below line 1) */
    s_label_line2 = lv_label_create(scr);
    lv_label_set_long_mode(s_label_line2, LV_LABEL_LONG_SCROLL_CIRCULAR);
    lv_obj_set_width(s_label_line2, OLED_H_RES);
    lv_obj_set_style_text_font(s_label_line2, &lv_font_unscii_8, 0);
    lv_obj_set_style_text_color(s_label_line2, lv_color_white(), 0);
    lv_obj_align(s_label_line2, LV_ALIGN_TOP_LEFT, 0, 12);
    lv_label_set_text(s_label_line2, "Ready");
}

/* ══════════════════════════════════════════════════════════════════════ */
/*                          PUBLIC  API                                  */
/* ══════════════════════════════════════════════════════════════════════ */

void oled_display_init(void)
{
    /* ── 1. I2C master bus ─────────────────────────────────────────── */
    ESP_LOGI(TAG, "Init I2C bus (SDA=%d SCL=%d)", OLED_PIN_SDA, OLED_PIN_SCL);
    i2c_master_bus_handle_t i2c_bus = NULL;
    i2c_master_bus_config_t bus_cfg = {
        .clk_source = I2C_CLK_SRC_DEFAULT,
        .glitch_ignore_cnt = 7,
        .i2c_port = OLED_I2C_PORT,
        .sda_io_num = OLED_PIN_SDA,
        .scl_io_num = OLED_PIN_SCL,
        .flags.enable_internal_pullup = true,
    };
    ESP_ERROR_CHECK(i2c_new_master_bus(&bus_cfg, &i2c_bus));

    /* ── 2. LCD panel IO (I2C) ─────────────────────────────────────── */
    ESP_LOGI(TAG, "Install SSD1306 panel IO");
    esp_lcd_panel_io_handle_t io_handle = NULL;
    esp_lcd_panel_io_i2c_config_t io_cfg = {
        .dev_addr = OLED_I2C_ADDR,
        .scl_speed_hz = OLED_I2C_FREQ_HZ,
        .control_phase_bytes = 1,
        .lcd_cmd_bits = OLED_CMD_BITS,
        .lcd_param_bits = OLED_PARAM_BITS,
        .dc_bit_offset = 6,                  /* SSD1306 datasheet */
    };
    ESP_ERROR_CHECK(esp_lcd_new_panel_io_i2c(i2c_bus, &io_cfg, &io_handle));

    /* ── 3. SSD1306 panel driver ───────────────────────────────────── */
    ESP_LOGI(TAG, "Install SSD1306 panel driver");
    esp_lcd_panel_handle_t panel = NULL;
    esp_lcd_panel_ssd1306_config_t ssd1306_cfg = {
        .height = OLED_V_RES,
    };
    esp_lcd_panel_dev_config_t panel_cfg = {
        .bits_per_pixel = 1,
        .reset_gpio_num = -1,
        .vendor_config = &ssd1306_cfg,
    };
    ESP_ERROR_CHECK(esp_lcd_new_panel_ssd1306(io_handle, &panel_cfg, &panel));
    ESP_ERROR_CHECK(esp_lcd_panel_reset(panel));
    ESP_ERROR_CHECK(esp_lcd_panel_init(panel));
    ESP_ERROR_CHECK(esp_lcd_panel_disp_on_off(panel, true));

    /* ── 4. LVGL init ──────────────────────────────────────────────── */
    ESP_LOGI(TAG, "Initialize LVGL");
    lv_init();

    s_display = lv_display_create(OLED_H_RES, OLED_V_RES);
    lv_display_set_user_data(s_display, panel);

    /* Draw buffer in PSRAM (128×64/8 + 8 palette = 1032 bytes) */
    size_t draw_buf_sz = OLED_H_RES * OLED_V_RES / 8 + LVGL_PALETTE_SIZE;
    void *draw_buf = heap_caps_calloc(1, draw_buf_sz, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!draw_buf) {
        ESP_LOGW(TAG, "PSRAM alloc failed for LVGL draw buf, falling back to internal");
        draw_buf = heap_caps_calloc(1, draw_buf_sz, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    }
    assert(draw_buf);

    lv_display_set_color_format(s_display, LV_COLOR_FORMAT_I1);
    lv_display_set_buffers(s_display, draw_buf, NULL, draw_buf_sz, LV_DISPLAY_RENDER_MODE_FULL);
    lv_display_set_flush_cb(s_display, oled_flush_cb);

    /* Flush-done callback (signals LVGL that I2C transfer finished) */
    const esp_lcd_panel_io_callbacks_t cbs = {
        .on_color_trans_done = oled_flush_ready_cb,
    };
    esp_lcd_panel_io_register_event_callbacks(io_handle, &cbs, s_display);

    /* ── 5. LVGL tick timer ────────────────────────────────────────── */
    const esp_timer_create_args_t tick_args = {
        .callback = &lvgl_tick_cb,
        .name = "lvgl_tick",
    };
    esp_timer_handle_t tick_timer = NULL;
    ESP_ERROR_CHECK(esp_timer_create(&tick_args, &tick_timer));
    ESP_ERROR_CHECK(esp_timer_start_periodic(tick_timer, LVGL_TICK_PERIOD_MS * 1000));

    /* ── 6. LVGL handler task ──────────────────────────────────────── */
    xTaskCreate(lvgl_task, "LVGL", LVGL_TASK_STACK_SIZE, NULL,
                LVGL_TASK_PRIORITY, NULL);

    /* ── 7. Build the UI ───────────────────────────────────────────── */
    _lock_acquire(&lvgl_api_lock);
    build_ui(s_display);
    _lock_release(&lvgl_api_lock);

    ESP_LOGI(TAG, "OLED display ready (128x64 SSD1306)");
}

void oled_display_update(const char *line1, const char *line2)
{
    if (!s_display) return;          /* init not called yet */

    _lock_acquire(&lvgl_api_lock);
    if (line1 && s_label_line1) {
        lv_label_set_text(s_label_line1, line1);
    }
    if (line2 && s_label_line2) {
        lv_label_set_text(s_label_line2, line2);
    }
    _lock_release(&lvgl_api_lock);
}
