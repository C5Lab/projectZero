/*
 * Multi-display module - SSD1306 / SH1107 / SH1106 / M5 Unit LCD
 *
 * Auto-detects which display is connected by probing two I2C buses:
 *   Bus A (GPIO 25/26):  SSD1306 0.96" 128x64  -> esp_lcd + LVGL 9
 *   Bus B (GPIO 8/9):    SH1107 1.3"  128x64   -> raw I2C framebuffer + 5x7 font
 *                        SH1106 1.3"  128x64   -> raw I2C framebuffer + 5x7 font
 *                        M5 Unit LCD 1.14"      -> I2C command interface + 5x7 font
 *
 * Public API is identical for all display types.
 */

#include "oled_display.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
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
#include "driver/spi_master.h"
#include "driver/gpio.h"
#include "board_spi.h"

#include "lvgl.h"

static const char *TAG = "display";

#define I2C_ADDR_TO_7BIT(addr) ((uint8_t)(((addr) > 0x77) ? ((addr) >> 1) : (addr)))
#define I2C_ADDR_TO_RAW(addr)  ((uint8_t)(((addr) > 0x77) ? (addr) : ((addr) << 1)))

/*
 * Wiring guide (wire color -> signal):
 *   Black  -> GND
 *   Red    -> VCC
 *   Yellow -> SDA
 *   White  -> SCL
 *
 * GPIO mapping:
 *   SSD1306 bus A (default): SDA=GPIO25, SCL=GPIO26
 *   Alternate bus B (default): SDA=GPIO8, SCL=GPIO9
 */

/* ====================================================================== */
/*                     I2C  /  HW  CONFIGURATION                          */
/* ====================================================================== */

/* --- Bus A: SSD1306 board (0.96" OLED) --- */
#ifndef OLED_BUS_A_SDA_GPIO
#define OLED_BUS_A_SDA_GPIO     25
#endif
#ifndef OLED_BUS_A_SCL_GPIO
#define OLED_BUS_A_SCL_GPIO     26
#endif
#ifndef OLED_BUS_A_I2C_PORT
#define OLED_BUS_A_I2C_PORT     I2C_NUM_0
#endif
#ifndef OLED_SSD1306_I2C_ADDR
#define OLED_SSD1306_I2C_ADDR   0x3C
#endif
#ifndef OLED_SSD1306_I2C_ADDR_ALT
#define OLED_SSD1306_I2C_ADDR_ALT 0x3D
#endif
#ifndef OLED_SSD1306_I2C_FREQ_HZ
#define OLED_SSD1306_I2C_FREQ_HZ (400 * 1000)
#endif

/* --- Bus B: SH1107 / SH1106 / Unit LCD board --- */
#ifndef OLED_BUS_B_SDA_GPIO
#define OLED_BUS_B_SDA_GPIO     8
#endif
#ifndef OLED_BUS_B_SCL_GPIO
#define OLED_BUS_B_SCL_GPIO     9
#endif
#ifndef OLED_BUS_B_I2C_PORT
#define OLED_BUS_B_I2C_PORT     I2C_NUM_0
#endif
#ifndef OLED_SH1107_I2C_ADDR
#define OLED_SH1107_I2C_ADDR    0x3C
#endif
#ifndef OLED_SH1107_I2C_FREQ_HZ
#define OLED_SH1107_I2C_FREQ_HZ 100000
#endif
#ifndef OLED_PREFER_SH1106
#define OLED_PREFER_SH1106      0
#endif
#ifndef OLED_PREFER_SSD1306_ON_BUS_B
#define OLED_PREFER_SSD1306_ON_BUS_B 0
#endif
#ifndef OLED_OVERLAP_UNKNOWN_PREFERS_SH110X
#define OLED_OVERLAP_UNKNOWN_PREFERS_SH110X 1
#endif
#ifndef OLED_SH1106_I2C_ADDR
#define OLED_SH1106_I2C_ADDR    0x78
#endif
#ifndef OLED_SH1106_I2C_FREQ_HZ
#define OLED_SH1106_I2C_FREQ_HZ 100000
#endif
#ifndef OLED_UNIT_LCD_I2C_ADDR
#define OLED_UNIT_LCD_I2C_ADDR  0x3E
#endif
#ifndef OLED_UNIT_LCD_I2C_FREQ_HZ
#define OLED_UNIT_LCD_I2C_FREQ_HZ 400000
#endif

/* --- LILYGO T-Dongle-C5 ST7735 SPI LCD (0.96" 80x160 panel, used landscape) --- */
/* Bus pins come from board_spi.h (shared SPI2). Only the panel-private lines here. */
#ifndef ST7735_CS_GPIO
#define ST7735_CS_GPIO          10
#endif
#ifndef ST7735_DC_GPIO
#define ST7735_DC_GPIO          3   /* RS / data-command */
#endif
#ifndef ST7735_RST_GPIO
#define ST7735_RST_GPIO         1
#endif
#ifndef ST7735_BL_GPIO
#define ST7735_BL_GPIO          0   /* backlight */
#endif
/* T-Dongle-C5 backlight is ACTIVE-LOW (confirmed on hardware: GPIO0=0 -> lit). */
#ifndef ST7735_BL_ON
#define ST7735_BL_ON            0
#endif
#ifndef ST7735_BL_OFF
#define ST7735_BL_OFF           1
#endif
#ifndef ST7735_PCLK_HZ
#define ST7735_PCLK_HZ          (20 * 1000 * 1000)
#endif
/* Landscape geometry: 160 wide x 80 tall. */
#ifndef ST7735_W
#define ST7735_W                160
#endif
#ifndef ST7735_H
#define ST7735_H                80
#endif
/* Panel RAM offsets for the common 0.96" 80x160 module in landscape orientation.
 * If the image is shifted, tune these two (portrait module is 26/1 -> swapped here). */
#ifndef ST7735_COL_OFFSET
#define ST7735_COL_OFFSET       1
#endif
#ifndef ST7735_ROW_OFFSET
#define ST7735_ROW_OFFSET       26
#endif
/* MADCTL for landscape; flip MY/MX/MV bits here if mirrored/upside-down. */
#ifndef ST7735_MADCTL
#define ST7735_MADCTL           0x60   /* MV|MX -> landscape, RGB order */
#endif
/* Text layout: 5x7 font scaled x2 -> 6 lines worth of room; we use 4 lines. */
#ifndef ST7735_TEXT_SCALE
#define ST7735_TEXT_SCALE       2
#endif
#ifndef ST7735_COLOR_STATUS
#define ST7735_COLOR_STATUS     1   /* color-code lines by keyword like the Unit LCD */
#endif
/* Flush in horizontal bands so each SPI DMA transfer stays small (shared bus).
 * ST7735_W * ST7735_FLUSH_ROWS * 2 must be <= BOARD_SPI_MAX_TRANSFER. */
#ifndef ST7735_FLUSH_ROWS
#define ST7735_FLUSH_ROWS       8   /* 160*8*2 = 2560 bytes per band */
#endif
#define ST7735_BAND_BYTES       (ST7735_W * ST7735_FLUSH_ROWS * 2)

#define BUS_A_SDA               OLED_BUS_A_SDA_GPIO
#define BUS_A_SCL               OLED_BUS_A_SCL_GPIO
#define BUS_A_PORT              OLED_BUS_A_I2C_PORT
#define SSD1306_I2C_ADDR_RAW    I2C_ADDR_TO_RAW(OLED_SSD1306_I2C_ADDR)
#define SSD1306_I2C_ADDR        I2C_ADDR_TO_7BIT(OLED_SSD1306_I2C_ADDR)
#define SSD1306_I2C_ADDR_ALT_RAW I2C_ADDR_TO_RAW(OLED_SSD1306_I2C_ADDR_ALT)
#define SSD1306_I2C_ADDR_ALT    I2C_ADDR_TO_7BIT(OLED_SSD1306_I2C_ADDR_ALT)
#define SSD1306_I2C_FREQ_HZ     OLED_SSD1306_I2C_FREQ_HZ

#define BUS_B_SDA               OLED_BUS_B_SDA_GPIO
#define BUS_B_SCL               OLED_BUS_B_SCL_GPIO
#define BUS_B_PORT              OLED_BUS_B_I2C_PORT
#define SH1107_I2C_ADDR_RAW     I2C_ADDR_TO_RAW(OLED_SH1107_I2C_ADDR)
#define SH1107_I2C_ADDR         I2C_ADDR_TO_7BIT(OLED_SH1107_I2C_ADDR)
#define SH1107_I2C_FREQ_HZ      OLED_SH1107_I2C_FREQ_HZ
#define SH1106_I2C_ADDR_RAW     I2C_ADDR_TO_RAW(OLED_SH1106_I2C_ADDR)
#define SH1106_I2C_ADDR         I2C_ADDR_TO_7BIT(OLED_SH1106_I2C_ADDR)
#define SH1106_I2C_FREQ_HZ      OLED_SH1106_I2C_FREQ_HZ
#define UNIT_LCD_I2C_ADDR_RAW   I2C_ADDR_TO_RAW(OLED_UNIT_LCD_I2C_ADDR)
#define UNIT_LCD_I2C_ADDR       I2C_ADDR_TO_7BIT(OLED_UNIT_LCD_I2C_ADDR)
#define UNIT_LCD_I2C_FREQ_HZ    OLED_UNIT_LCD_I2C_FREQ_HZ

/* --- Common display parameters --- */
#define OLED_H_RES              128
#define OLED_V_RES               64
#define OLED_PAGES              (OLED_V_RES / 8)
#define I2C_TIMEOUT_MS          100
#define I2C_DATA_CHUNK          16
#define OLED_LINE_COUNT           4
#define OLED_LINE_LEN            64

/* --- Unit LCD parameters --- */
#ifndef UNIT_LCD_UI_HORIZONTAL
#define UNIT_LCD_UI_HORIZONTAL    1
#endif

#if UNIT_LCD_UI_HORIZONTAL
#define UNIT_LCD_WIDTH          240
#define UNIT_LCD_HEIGHT         135
#ifndef UNIT_LCD_ROTATION
#define UNIT_LCD_ROTATION       1   /* Unit LCD cmd 0x36: 1 = 90deg */
#endif
#else
#define UNIT_LCD_WIDTH          135
#define UNIT_LCD_HEIGHT         240
#ifndef UNIT_LCD_ROTATION
#define UNIT_LCD_ROTATION       0   /* Unit LCD cmd 0x36: 0 = normal */
#endif
#endif

#define UNIT_LCD_TEXT_SCALE       2
#ifndef UNIT_LCD_COLOR_STATUS
#define UNIT_LCD_COLOR_STATUS      1
#endif

/* --- SH1107 (M5 Unit OLED) native geometry --- */
#define SH1107_LOGICAL_W         64
#define SH1107_LOGICAL_H        128
#define SH1107_PAGES            (SH1107_LOGICAL_H / 8)
#define SH1107_COL_OFFSET        32

#ifndef SH1107_SEG_REMAP
#define SH1107_SEG_REMAP        0xA0
#endif
#ifndef SH1107_COM_SCAN
#define SH1107_COM_SCAN         0xC0
#endif
#ifndef SH1107_UI_HORIZONTAL
#define SH1107_UI_HORIZONTAL     1
#endif
#ifndef SH1107_ROTATE_CW
#define SH1107_ROTATE_CW         1
#endif
#ifndef SH1107_FONT_SMALL
#define SH1107_FONT_SMALL       0
#endif

#if SH1107_UI_HORIZONTAL
#define SH1107_UI_W             128
#define SH1107_UI_H              64
#else
#define SH1107_UI_W             SH1107_LOGICAL_W
#define SH1107_UI_H             SH1107_LOGICAL_H
#endif

#if SH1107_FONT_SMALL
#define SH1107_FONT_W           3
#define SH1107_FONT_H           5
#define SH1107_FONT_PITCH       4
#else
#define SH1107_FONT_W           5
#define SH1107_FONT_H           7
#define SH1107_FONT_PITCH       6
#endif

#define SH1107_MAX_CHARS        (SH1107_UI_W / SH1107_FONT_PITCH)

/* --- LVGL tunables (SSD1306 only) --- */
#define LVGL_TICK_PERIOD_MS       5
#define LVGL_TASK_STACK_SIZE      (4 * 1024)
#define LVGL_TASK_PRIORITY        2
#define LVGL_PALETTE_SIZE         8
#define LVGL_TASK_MAX_DELAY_MS    500
#define LVGL_TASK_MIN_DELAY_MS    (1000 / CONFIG_FREERTOS_HZ)

/* --- SH1106 max chars per line (128 px / 6 px per glyph) --- */
#define SH1106_MAX_CHARS        21
/* --- Unit LCD max chars per line based on active orientation/width --- */
#define UNIT_LCD_CHAR_PITCH     (5 * UNIT_LCD_TEXT_SCALE + UNIT_LCD_TEXT_SCALE)
#define UNIT_LCD_MAX_CHARS      (UNIT_LCD_WIDTH / UNIT_LCD_CHAR_PITCH)

#define SSD1306_BUS_A_BIT       (1U << 0)
#define SSD1306_BUS_B_BIT       (1U << 1)

#define SSD1306_DRAW_BUF_SIZE   (OLED_H_RES * OLED_V_RES / 8 + LVGL_PALETTE_SIZE)
#ifndef OLED_CURSOR_BLINK_MS
#define OLED_CURSOR_BLINK_MS    500
#endif
#ifndef OLED_DOTS_ANIM_MS
#define OLED_DOTS_ANIM_MS       400
#endif

/* ====================================================================== */
/*                        5x7  ASCII  FONT                                */
/* ====================================================================== */

static const uint8_t font5x7[95][5] = {
    /* 0x20 ' ' */ {0x00,0x00,0x00,0x00,0x00},
    /* 0x21 '!' */ {0x00,0x00,0x5F,0x00,0x00},
    /* 0x22 '"' */ {0x00,0x07,0x00,0x07,0x00},
    /* 0x23 '#' */ {0x14,0x7F,0x14,0x7F,0x14},
    /* 0x24 '$' */ {0x24,0x2A,0x7F,0x2A,0x12},
    /* 0x25 '%' */ {0x23,0x13,0x08,0x64,0x62},
    /* 0x26 '&' */ {0x36,0x49,0x55,0x22,0x50},
    /* 0x27     */ {0x00,0x05,0x03,0x00,0x00},
    /* 0x28 '(' */ {0x00,0x1C,0x22,0x41,0x00},
    /* 0x29 ')' */ {0x00,0x41,0x22,0x1C,0x00},
    /* 0x2A '*' */ {0x14,0x08,0x3E,0x08,0x14},
    /* 0x2B '+' */ {0x08,0x08,0x3E,0x08,0x08},
    /* 0x2C ',' */ {0x00,0x50,0x30,0x00,0x00},
    /* 0x2D '-' */ {0x08,0x08,0x08,0x08,0x08},
    /* 0x2E '.' */ {0x00,0x60,0x60,0x00,0x00},
    /* 0x2F '/' */ {0x20,0x10,0x08,0x04,0x02},
    /* 0x30 '0' */ {0x3E,0x51,0x49,0x45,0x3E},
    /* 0x31 '1' */ {0x00,0x42,0x7F,0x40,0x00},
    /* 0x32 '2' */ {0x42,0x61,0x51,0x49,0x46},
    /* 0x33 '3' */ {0x21,0x41,0x45,0x4B,0x31},
    /* 0x34 '4' */ {0x18,0x14,0x12,0x7F,0x10},
    /* 0x35 '5' */ {0x27,0x45,0x45,0x45,0x39},
    /* 0x36 '6' */ {0x3C,0x4A,0x49,0x49,0x30},
    /* 0x37 '7' */ {0x01,0x71,0x09,0x05,0x03},
    /* 0x38 '8' */ {0x36,0x49,0x49,0x49,0x36},
    /* 0x39 '9' */ {0x06,0x49,0x49,0x29,0x1E},
    /* 0x3A ':' */ {0x00,0x36,0x36,0x00,0x00},
    /* 0x3B ';' */ {0x00,0x56,0x36,0x00,0x00},
    /* 0x3C '<' */ {0x08,0x14,0x22,0x41,0x00},
    /* 0x3D '=' */ {0x14,0x14,0x14,0x14,0x14},
    /* 0x3E '>' */ {0x00,0x41,0x22,0x14,0x08},
    /* 0x3F '?' */ {0x02,0x01,0x51,0x09,0x06},
    /* 0x40 '@' */ {0x32,0x49,0x79,0x41,0x3E},
    /* 0x41 'A' */ {0x7E,0x11,0x11,0x11,0x7E},
    /* 0x42 'B' */ {0x7F,0x49,0x49,0x49,0x36},
    /* 0x43 'C' */ {0x3E,0x41,0x41,0x41,0x22},
    /* 0x44 'D' */ {0x7F,0x41,0x41,0x22,0x1C},
    /* 0x45 'E' */ {0x7F,0x49,0x49,0x49,0x41},
    /* 0x46 'F' */ {0x7F,0x09,0x09,0x09,0x01},
    /* 0x47 'G' */ {0x3E,0x41,0x49,0x49,0x7A},
    /* 0x48 'H' */ {0x7F,0x08,0x08,0x08,0x7F},
    /* 0x49 'I' */ {0x00,0x41,0x7F,0x41,0x00},
    /* 0x4A 'J' */ {0x20,0x40,0x41,0x3F,0x01},
    /* 0x4B 'K' */ {0x7F,0x08,0x14,0x22,0x41},
    /* 0x4C 'L' */ {0x7F,0x40,0x40,0x40,0x40},
    /* 0x4D 'M' */ {0x7F,0x02,0x0C,0x02,0x7F},
    /* 0x4E 'N' */ {0x7F,0x04,0x08,0x10,0x7F},
    /* 0x4F 'O' */ {0x3E,0x41,0x41,0x41,0x3E},
    /* 0x50 'P' */ {0x7F,0x09,0x09,0x09,0x06},
    /* 0x51 'Q' */ {0x3E,0x41,0x51,0x21,0x5E},
    /* 0x52 'R' */ {0x7F,0x09,0x19,0x29,0x46},
    /* 0x53 'S' */ {0x46,0x49,0x49,0x49,0x31},
    /* 0x54 'T' */ {0x01,0x01,0x7F,0x01,0x01},
    /* 0x55 'U' */ {0x3F,0x40,0x40,0x40,0x3F},
    /* 0x56 'V' */ {0x1F,0x20,0x40,0x20,0x1F},
    /* 0x57 'W' */ {0x3F,0x40,0x38,0x40,0x3F},
    /* 0x58 'X' */ {0x63,0x14,0x08,0x14,0x63},
    /* 0x59 'Y' */ {0x07,0x08,0x70,0x08,0x07},
    /* 0x5A 'Z' */ {0x61,0x51,0x49,0x45,0x43},
    /* 0x5B '[' */ {0x00,0x7F,0x41,0x41,0x00},
    /* 0x5C     */ {0x02,0x04,0x08,0x10,0x20},
    /* 0x5D ']' */ {0x00,0x41,0x41,0x7F,0x00},
    /* 0x5E '^' */ {0x04,0x02,0x01,0x02,0x04},
    /* 0x5F '_' */ {0x40,0x40,0x40,0x40,0x40},
    /* 0x60 '`' */ {0x00,0x01,0x02,0x04,0x00},
    /* 0x61 'a' */ {0x20,0x54,0x54,0x54,0x78},
    /* 0x62 'b' */ {0x7F,0x48,0x44,0x44,0x38},
    /* 0x63 'c' */ {0x38,0x44,0x44,0x44,0x20},
    /* 0x64 'd' */ {0x38,0x44,0x44,0x48,0x7F},
    /* 0x65 'e' */ {0x38,0x54,0x54,0x54,0x18},
    /* 0x66 'f' */ {0x08,0x7E,0x09,0x01,0x02},
    /* 0x67 'g' */ {0x0C,0x52,0x52,0x52,0x3E},
    /* 0x68 'h' */ {0x7F,0x08,0x04,0x04,0x78},
    /* 0x69 'i' */ {0x00,0x44,0x7D,0x40,0x00},
    /* 0x6A 'j' */ {0x20,0x40,0x44,0x3D,0x00},
    /* 0x6B 'k' */ {0x7F,0x10,0x28,0x44,0x00},
    /* 0x6C 'l' */ {0x00,0x41,0x7F,0x40,0x00},
    /* 0x6D 'm' */ {0x7C,0x04,0x18,0x04,0x78},
    /* 0x6E 'n' */ {0x7C,0x08,0x04,0x04,0x78},
    /* 0x6F 'o' */ {0x38,0x44,0x44,0x44,0x38},
    /* 0x70 'p' */ {0x7C,0x14,0x14,0x14,0x08},
    /* 0x71 'q' */ {0x08,0x14,0x14,0x18,0x7C},
    /* 0x72 'r' */ {0x7C,0x08,0x04,0x04,0x08},
    /* 0x73 's' */ {0x48,0x54,0x54,0x54,0x20},
    /* 0x74 't' */ {0x04,0x3F,0x44,0x40,0x20},
    /* 0x75 'u' */ {0x3C,0x40,0x40,0x20,0x7C},
    /* 0x76 'v' */ {0x1C,0x20,0x40,0x20,0x1C},
    /* 0x77 'w' */ {0x3C,0x40,0x30,0x40,0x3C},
    /* 0x78 'x' */ {0x44,0x28,0x10,0x28,0x44},
    /* 0x79 'y' */ {0x0C,0x50,0x50,0x50,0x3C},
    /* 0x7A 'z' */ {0x44,0x64,0x54,0x4C,0x44},
    /* 0x7B '{' */ {0x00,0x08,0x36,0x41,0x00},
    /* 0x7C '|' */ {0x00,0x00,0x7F,0x00,0x00},
    /* 0x7D '}' */ {0x00,0x41,0x36,0x08,0x00},
    /* 0x7E '~' */ {0x10,0x08,0x08,0x10,0x08},
};

static const uint8_t *font_get_glyph(char ch)
{
    static const uint8_t fallback[5] = {0x02,0x01,0x51,0x09,0x06};
    if (ch < 0x20 || ch > 0x7E) return fallback;
    return font5x7[ch - 0x20];
}

/* ====================================================================== */
/*                          SHARED  STATE                                 */
/* ====================================================================== */

static display_type_t       s_display_type = DISPLAY_NONE;
static display_type_t       s_forced_type = DISPLAY_NONE;
static _lock_t              s_api_lock;
static uint8_t              s_detected_addr_7bit = 0;
static uint8_t              s_detected_addr_raw = 0;
static uint8_t              s_ssd1306_addr_7bit = SSD1306_I2C_ADDR;
static uint8_t              s_ssd1306_addr_raw = SSD1306_I2C_ADDR_RAW;
static int                  s_ssd1306_sda_gpio = BUS_A_SDA;
static int                  s_ssd1306_scl_gpio = BUS_A_SCL;

static i2c_master_bus_handle_t  s_i2c_bus_b   = NULL;
static i2c_master_dev_handle_t  s_sh1107_dev  = NULL;
static i2c_master_dev_handle_t  s_sh1106_dev  = NULL;
static i2c_master_dev_handle_t  s_ulcd_dev    = NULL;

static lv_display_t *s_lv_display   = NULL;
static lv_obj_t     *s_lv_line[OLED_LINE_COUNT] = {NULL};

static uint8_t *ssd1306_buf = NULL;                 /* OLED_H_RES * OLED_V_RES / 8 */
static uint8_t *sh1107_fb = NULL;                  /* SH1107_PAGES * SH1107_LOGICAL_W */
static uint8_t *sh1106_fb = NULL;                  /* OLED_PAGES * OLED_H_RES */
static uint8_t *s_ssd1306_draw_buf = NULL;         /* SSD1306_DRAW_BUF_SIZE */
static char (*s_line_cache)[OLED_LINE_LEN] = NULL; /* [OLED_LINE_COUNT][OLED_LINE_LEN] */
static bool s_oled_psram_ready = false;
static TaskHandle_t s_cursor_blink_task = NULL;
static bool s_cursor_blink_enabled = false;
static int s_cursor_blink_line = -1;
static int s_cursor_blink_col = -1;
static bool s_cursor_visible = true;
static bool s_dots_anim_enabled = false;
static uint8_t s_dots_anim_phase = 3; /* 1..3 */
static bool s_ssd1306_offline = false;

static void oled_free_psram_buffers(void)
{
    if (ssd1306_buf) {
        heap_caps_free(ssd1306_buf);
        ssd1306_buf = NULL;
    }
    if (sh1107_fb) {
        heap_caps_free(sh1107_fb);
        sh1107_fb = NULL;
    }
    if (sh1106_fb) {
        heap_caps_free(sh1106_fb);
        sh1106_fb = NULL;
    }
    if (s_ssd1306_draw_buf) {
        heap_caps_free(s_ssd1306_draw_buf);
        s_ssd1306_draw_buf = NULL;
    }
    if (s_line_cache) {
        heap_caps_free(s_line_cache);
        s_line_cache = NULL;
    }
    s_oled_psram_ready = false;
}

static bool oled_alloc_psram_buffers(void)
{
    if (s_oled_psram_ready) return true;

    const size_t ssd1306_sz = OLED_H_RES * OLED_V_RES / 8;
    const size_t sh1107_sz = SH1107_PAGES * SH1107_LOGICAL_W;
    const size_t sh1106_sz = OLED_PAGES * OLED_H_RES;
    const size_t ssd1306_draw_buf_sz = SSD1306_DRAW_BUF_SIZE;
    const size_t line_cache_sz = OLED_LINE_COUNT * OLED_LINE_LEN;

    ssd1306_buf = heap_caps_calloc(1, ssd1306_sz, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    sh1107_fb = heap_caps_calloc(1, sh1107_sz, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    sh1106_fb = heap_caps_calloc(1, sh1106_sz, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    s_ssd1306_draw_buf = heap_caps_calloc(1, ssd1306_draw_buf_sz, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    s_line_cache = heap_caps_calloc(OLED_LINE_COUNT, OLED_LINE_LEN, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);

    if (!ssd1306_buf || !sh1107_fb || !sh1106_fb || !s_ssd1306_draw_buf || !s_line_cache) {
        ESP_LOGE(TAG, "PSRAM alloc failed for OLED buffers (ssd1306=%p sh1107=%p sh1106=%p draw=%p cache=%p)",
                 (void *)ssd1306_buf, (void *)sh1107_fb, (void *)sh1106_fb,
                 (void *)s_ssd1306_draw_buf, (void *)s_line_cache);
        oled_free_psram_buffers();
        return false;
    }

    s_oled_psram_ready = true;
    ESP_LOGI(TAG, "OLED buffers allocated in PSRAM (ssd1306=%u, sh1107=%u, sh1106=%u, draw=%u, cache=%u bytes)",
             (unsigned)ssd1306_sz, (unsigned)sh1107_sz, (unsigned)sh1106_sz,
             (unsigned)ssd1306_draw_buf_sz, (unsigned)line_cache_sz);
    return true;
}

/* ====================================================================== */
/*              SSD1306  DRIVER  (esp_lcd + LVGL 9)                       */
/* ====================================================================== */

static void ssd1306_flush_cb(lv_display_t *disp, const lv_area_t *area, uint8_t *px_map)
{
    if (!ssd1306_buf) {
        lv_display_flush_ready(disp);
        return;
    }
    if (s_ssd1306_offline) {
        lv_display_flush_ready(disp);
        return;
    }
    esp_lcd_panel_handle_t panel = lv_display_get_user_data(disp);
    px_map += LVGL_PALETTE_SIZE;

    uint16_t hor_res = lv_display_get_physical_horizontal_resolution(disp);
    int x1 = area->x1, x2 = area->x2, y1 = area->y1, y2 = area->y2;

    for (int y = y1; y <= y2; y++) {
        for (int x = x1; x <= x2; x++) {
            bool chroma = (px_map[(hor_res >> 3) * y + (x >> 3)] & (1 << (7 - (x % 8))));
            uint8_t *buf = ssd1306_buf + hor_res * (y >> 3) + x;
            if (chroma) *buf |=  (1 << (y % 8));
            else        *buf &= ~(1 << (y % 8));
        }
    }
    esp_err_t err = esp_lcd_panel_draw_bitmap(panel, x1, y1, x2 + 1, y2 + 1, ssd1306_buf);
    if (err != ESP_OK) {
        s_ssd1306_offline = true;
        ESP_LOGE(TAG, "SSD1306 draw failed (%s) - display marked offline",
                 esp_err_to_name(err));
        /* on tx failure callback may never fire; unblock LVGL explicitly */
        lv_display_flush_ready(disp);
    }
}

static bool ssd1306_flush_ready_cb(esp_lcd_panel_io_handle_t io,
                                   esp_lcd_panel_io_event_data_t *edata,
                                   void *user_ctx)
{
    lv_display_flush_ready((lv_display_t *)user_ctx);
    return false;
}

static void lvgl_tick_cb(void *arg) { lv_tick_inc(LVGL_TICK_PERIOD_MS); }

static void lvgl_task(void *arg)
{
    ESP_LOGI(TAG, "LVGL task started");
    uint32_t ms = 0;
    while (1) {
        _lock_acquire(&s_api_lock);
        ms = lv_timer_handler();
        _lock_release(&s_api_lock);
        ms = MAX(ms, LVGL_TASK_MIN_DELAY_MS);
        ms = MIN(ms, LVGL_TASK_MAX_DELAY_MS);
        usleep(1000 * ms);
    }
}

static void ssd1306_build_ui(lv_display_t *disp)
{
    lv_obj_t *scr = lv_display_get_screen_active(disp);
    lv_obj_set_style_bg_color(scr, lv_color_black(), 0);
    lv_obj_set_style_bg_opa(scr, LV_OPA_COVER, 0);
    lv_obj_set_style_pad_all(scr, 0, 0);

    static const int y_pos[4] = {0, 14, 28, 48};
    static const lv_label_long_mode_t modes[4] = {
        LV_LABEL_LONG_CLIP,
        LV_LABEL_LONG_SCROLL_CIRCULAR,
        LV_LABEL_LONG_SCROLL_CIRCULAR,
        LV_LABEL_LONG_CLIP,
    };

    for (int i = 0; i < 4; i++) {
        s_lv_line[i] = lv_label_create(scr);
        lv_label_set_long_mode(s_lv_line[i], modes[i]);
        lv_obj_set_width(s_lv_line[i], OLED_H_RES);
        lv_obj_set_style_text_font(s_lv_line[i], &lv_font_unscii_8, 0);
        lv_obj_set_style_text_color(s_lv_line[i], lv_color_white(), 0);
        lv_obj_align(s_lv_line[i], LV_ALIGN_TOP_LEFT, 0, y_pos[i]);
        lv_label_set_text(s_lv_line[i], "");
    }
}

static void ssd1306_show_monster_splash(void)
{
    if (!s_lv_display) return;

    _lock_acquire(&s_api_lock);
    lv_obj_t *scr = lv_display_get_screen_active(s_lv_display);
    lv_obj_t *splash = lv_label_create(scr);
    lv_obj_set_style_text_font(splash, &lv_font_unscii_8, 0);
    lv_obj_set_style_text_color(splash, lv_color_white(), 0);
    lv_label_set_text(splash, "Monster !");
    lv_obj_center(splash);
    _lock_release(&s_api_lock);

    vTaskDelay(pdMS_TO_TICKS(1000));

    _lock_acquire(&s_api_lock);
    lv_obj_delete(splash);
    _lock_release(&s_api_lock);
}

typedef enum {
    OLED_HINT_UNKNOWN = 0,
    OLED_HINT_SSD1306,
    OLED_HINT_SH110X,
} oled_hint_t;

static bool oled_cmd_only(i2c_master_dev_handle_t dev, uint8_t cmd)
{
    uint8_t tx[2] = {0x00, cmd};
    return (i2c_master_transmit(dev, tx, sizeof(tx), I2C_TIMEOUT_MS) == ESP_OK);
}

static bool oled_cmd_arg(i2c_master_dev_handle_t dev, uint8_t cmd, uint8_t arg)
{
    uint8_t tx[3] = {0x00, cmd, arg};
    return (i2c_master_transmit(dev, tx, sizeof(tx), I2C_TIMEOUT_MS) == ESP_OK);
}

/*
 * Heuristic only: on shared 0x3C/0x78 addresses, try controller-specific commands
 * to reduce false positives between SSD1306 and SH110x.
 */
static oled_hint_t oled_probe_hint(i2c_master_bus_handle_t bus, uint8_t addr_7bit)
{
    i2c_master_dev_handle_t dev = NULL;
    i2c_device_config_t cfg = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address = addr_7bit,
        .scl_speed_hz = SH1107_I2C_FREQ_HZ, /* conservative probe speed */
    };
    if (i2c_master_bus_add_device(bus, &cfg, &dev) != ESP_OK) {
        return OLED_HINT_UNKNOWN;
    }

    bool ssd_sig = oled_cmd_arg(dev, 0x8D, 0x14); /* SSD1306 charge-pump command */
    bool sh_sig  = oled_cmd_arg(dev, 0xDC, 0x00) && oled_cmd_only(dev, 0xEE); /* SH1107-specific sequence */

    i2c_master_bus_rm_device(dev);
    dev = NULL;

    if (ssd_sig && !sh_sig) return OLED_HINT_SSD1306;
    if (sh_sig && !ssd_sig) return OLED_HINT_SH110X;
    return OLED_HINT_UNKNOWN;
}

static bool ssd1306_try_bus(i2c_port_num_t port, int sda_gpio, int scl_gpio)
{
    uint8_t candidates_7bit[2] = {SSD1306_I2C_ADDR, SSD1306_I2C_ADDR_ALT};
    uint8_t candidates_raw[2] = {SSD1306_I2C_ADDR_RAW, SSD1306_I2C_ADDR_ALT_RAW};
    size_t candidate_count = (candidates_7bit[0] == candidates_7bit[1]) ? 1 : 2;

    ESP_LOGI(TAG, "Probing SSD1306 on SDA=%d SCL=%d addr raw/7bit: 0x%02X/0x%02X alt 0x%02X/0x%02X",
             sda_gpio, scl_gpio,
             SSD1306_I2C_ADDR_RAW, SSD1306_I2C_ADDR,
             SSD1306_I2C_ADDR_ALT_RAW, SSD1306_I2C_ADDR_ALT);

    i2c_master_bus_handle_t bus = NULL;
    i2c_master_bus_config_t bus_cfg = {
        .clk_source = I2C_CLK_SRC_DEFAULT,
        .glitch_ignore_cnt = 7,
        .i2c_port = port,
        .sda_io_num = sda_gpio,
        .scl_io_num = scl_gpio,
        .flags.enable_internal_pullup = true,
    };
    if (i2c_new_master_bus(&bus_cfg, &bus) != ESP_OK) {
        return false;
    }

    bool found = false;
    for (size_t i = 0; i < candidate_count; i++) {
        if (i2c_master_probe(bus, candidates_7bit[i], I2C_TIMEOUT_MS) == ESP_OK) {
            s_ssd1306_addr_7bit = candidates_7bit[i];
            s_ssd1306_addr_raw = candidates_raw[i];
            s_ssd1306_sda_gpio = sda_gpio;
            s_ssd1306_scl_gpio = scl_gpio;
            found = true;
            break;
        }
    }
    if (!found) {
        i2c_del_master_bus(bus);
        return false;
    }

    bool bus_b_addr_overlap = (sda_gpio == BUS_B_SDA) && (scl_gpio == BUS_B_SCL) &&
                              ((s_ssd1306_addr_7bit == SH1107_I2C_ADDR) ||
                               (s_ssd1306_addr_7bit == SH1106_I2C_ADDR));
    if (bus_b_addr_overlap && s_forced_type != DISPLAY_SSD1306) {
        oled_hint_t hint = oled_probe_hint(bus, s_ssd1306_addr_7bit);
        if (hint == OLED_HINT_SH110X) {
            ESP_LOGW(TAG, "Bus B addr 0x%02X looks like SH110x; skip SSD1306 path",
                     s_ssd1306_addr_7bit);
            i2c_del_master_bus(bus);
            return false;
        }
        if (hint == OLED_HINT_SSD1306) {
            ESP_LOGI(TAG, "Bus B addr 0x%02X hint: SSD1306", s_ssd1306_addr_7bit);
        } else {
            ESP_LOGW(TAG, "Bus B addr 0x%02X hint: unknown",
                     s_ssd1306_addr_7bit);
#if OLED_OVERLAP_UNKNOWN_PREFERS_SH110X
            ESP_LOGW(TAG, "Unknown overlap on bus B: prefer SH110x, skip SSD1306 path");
            i2c_del_master_bus(bus);
            return false;
#else
            ESP_LOGW(TAG, "Unknown overlap on bus B: fallback policy keeps SSD1306 path");
#endif
        }
    } else if (bus_b_addr_overlap && s_forced_type == DISPLAY_SSD1306) {
        ESP_LOGW(TAG, "Bus B overlap at 0x%02X, but SSD1306 is forced by configuration",
                 s_ssd1306_addr_7bit);
    }

    esp_lcd_panel_io_handle_t io = NULL;
    esp_lcd_panel_io_i2c_config_t io_cfg = {
        .dev_addr = s_ssd1306_addr_7bit,
        .scl_speed_hz = SSD1306_I2C_FREQ_HZ,
        .control_phase_bytes = 1,
        .lcd_cmd_bits = 8,
        .lcd_param_bits = 8,
        .dc_bit_offset = 6,
    };
    if (esp_lcd_new_panel_io_i2c(bus, &io_cfg, &io) != ESP_OK) {
        i2c_del_master_bus(bus);
        return false;
    }

    esp_lcd_panel_handle_t panel = NULL;
    esp_lcd_panel_ssd1306_config_t ssd_cfg = { .height = OLED_V_RES };
    esp_lcd_panel_dev_config_t dev_cfg = {
        .bits_per_pixel = 1,
        .reset_gpio_num = -1,
        .vendor_config = &ssd_cfg,
    };
    if (esp_lcd_new_panel_ssd1306(io, &dev_cfg, &panel) != ESP_OK ||
        esp_lcd_panel_reset(panel) != ESP_OK ||
        esp_lcd_panel_init(panel)  != ESP_OK ||
        esp_lcd_panel_disp_on_off(panel, true) != ESP_OK) {
        i2c_del_master_bus(bus);
        return false;
    }

    lv_init();
    s_lv_display = lv_display_create(OLED_H_RES, OLED_V_RES);
    lv_display_set_user_data(s_lv_display, panel);

    if (!s_ssd1306_draw_buf) {
        ESP_LOGE(TAG, "SSD1306 draw buffer missing in PSRAM");
        i2c_del_master_bus(bus);
        return false;
    }

    lv_display_set_color_format(s_lv_display, LV_COLOR_FORMAT_I1);
    lv_display_set_buffers(s_lv_display, s_ssd1306_draw_buf, NULL,
                           SSD1306_DRAW_BUF_SIZE, LV_DISPLAY_RENDER_MODE_FULL);
    lv_display_set_flush_cb(s_lv_display, ssd1306_flush_cb);

    const esp_lcd_panel_io_callbacks_t cbs = { .on_color_trans_done = ssd1306_flush_ready_cb };
    esp_lcd_panel_io_register_event_callbacks(io, &cbs, s_lv_display);

    const esp_timer_create_args_t tick_args = { .callback = &lvgl_tick_cb, .name = "lvgl_tick" };
    esp_timer_handle_t tick_timer = NULL;
    ESP_ERROR_CHECK(esp_timer_create(&tick_args, &tick_timer));
    ESP_ERROR_CHECK(esp_timer_start_periodic(tick_timer, LVGL_TICK_PERIOD_MS * 1000));
    xTaskCreate(lvgl_task, "LVGL", LVGL_TASK_STACK_SIZE, NULL, LVGL_TASK_PRIORITY, NULL);

    _lock_acquire(&s_api_lock);
    ssd1306_build_ui(s_lv_display);
    _lock_release(&s_api_lock);
    s_ssd1306_offline = false;

    ESP_LOGI(TAG, "SSD1306 ready (128x64) on GPIO %d/%d addr raw/7bit: 0x%02X/0x%02X",
             s_ssd1306_sda_gpio, s_ssd1306_scl_gpio, s_ssd1306_addr_raw, s_ssd1306_addr_7bit);
    return true;
}

static bool ssd1306_init(uint32_t bus_mask)
{
    if ((bus_mask & SSD1306_BUS_A_BIT) &&
        ssd1306_try_bus(BUS_A_PORT, BUS_A_SDA, BUS_A_SCL)) {
        return true;
    }

    bool bus_b_same_as_a = (BUS_A_PORT == BUS_B_PORT) &&
                           (BUS_A_SDA == BUS_B_SDA) &&
                           (BUS_A_SCL == BUS_B_SCL);

    if (bus_mask & SSD1306_BUS_B_BIT) {
        if (bus_b_same_as_a && (bus_mask & SSD1306_BUS_A_BIT)) {
            return false;
        }
        if (ssd1306_try_bus(BUS_B_PORT, BUS_B_SDA, BUS_B_SCL)) {
            return true;
        }
    }

    return false;
}

static void ssd1306_update(const char *lines[4])
{
    for (int i = 0; i < 4; i++) {
        if (lines[i] && s_lv_line[i])
            lv_label_set_text(s_lv_line[i], lines[i]);
    }
}

/* ====================================================================== */
/*                SH1107  DRIVER  (raw I2C framebuffer)                   */
/* ====================================================================== */

static esp_err_t sh1107_cmd(uint8_t cmd)
{
    uint8_t tx[2] = {0x00, cmd};
    return i2c_master_transmit(s_sh1107_dev, tx, sizeof(tx), I2C_TIMEOUT_MS);
}

static esp_err_t sh1107_cmd_arg(uint8_t cmd, uint8_t arg)
{
    uint8_t tx[3] = {0x00, cmd, arg};
    return i2c_master_transmit(s_sh1107_dev, tx, sizeof(tx), I2C_TIMEOUT_MS);
}

static esp_err_t sh1107_data(const uint8_t *data, size_t len)
{
    uint8_t tx[1 + I2C_DATA_CHUNK];
    tx[0] = 0x40;
    size_t off = 0;
    while (off < len) {
        size_t chunk = len - off;
        if (chunk > I2C_DATA_CHUNK) chunk = I2C_DATA_CHUNK;
        memcpy(&tx[1], data + off, chunk);
        esp_err_t err = i2c_master_transmit(s_sh1107_dev, tx, 1 + chunk, I2C_TIMEOUT_MS);
        if (err != ESP_OK) return err;
        off += chunk;
    }
    return ESP_OK;
}

static esp_err_t sh1107_set_page_col(uint8_t page, uint8_t col)
{
    uint8_t phys_col = (uint8_t)(col + SH1107_COL_OFFSET);
    esp_err_t e;
    e = sh1107_cmd((uint8_t)(0xB0 | (page & 0x0F)));                    if (e) return e;
    e = sh1107_cmd((uint8_t)(0x10 | ((phys_col >> 4) & 0x0F)));         if (e) return e;
    return sh1107_cmd((uint8_t)(0x00 | (phys_col & 0x0F)));
}

static esp_err_t sh1107_flush(void)
{
    for (uint8_t p = 0; p < SH1107_PAGES; p++) {
        esp_err_t e = sh1107_set_page_col(p, 0);
        if (e) return e;
        e = sh1107_data(&sh1107_fb[p * SH1107_LOGICAL_W], SH1107_LOGICAL_W);
        if (e) return e;
    }
    return ESP_OK;
}

static void sh1107_fb_clear(void)
{
    if (!sh1107_fb) return;
    memset(sh1107_fb, 0, SH1107_PAGES * SH1107_LOGICAL_W);
}

static void sh1107_set_pixel_native(int x, int y)
{
    if (!sh1107_fb) return;
    if (x < 0 || y < 0 || x >= SH1107_LOGICAL_W || y >= SH1107_LOGICAL_H) return;
    sh1107_fb[(y / 8) * SH1107_LOGICAL_W + x] |= (uint8_t)(1 << (y & 7));
}

static void sh1107_set_pixel(int x, int y)
{
    if (x < 0 || y < 0 || x >= SH1107_UI_W || y >= SH1107_UI_H) return;
#if SH1107_UI_HORIZONTAL
#if SH1107_ROTATE_CW
    int nx = y;
    int ny = (SH1107_LOGICAL_H - 1) - x;
#else
    int nx = (SH1107_LOGICAL_W - 1) - y;
    int ny = x;
#endif
    sh1107_set_pixel_native(nx, ny);
#else
    sh1107_set_pixel_native(x, y);
#endif
}

static void sh1107_draw_char(char ch, int cx, int cy)
{
    const uint8_t *g = font_get_glyph(ch);
#if SH1107_FONT_SMALL
    /* Downsample 5x7 glyph to compact 3x5 for better text fit on 64px width. */
    static const uint8_t src_col[SH1107_FONT_W] = {0, 2, 4};
    static const uint8_t src_row[SH1107_FONT_H] = {0, 2, 3, 5, 6};
    for (int col = 0; col < SH1107_FONT_W; col++) {
        uint8_t bits = g[src_col[col]];
        for (int row = 0; row < SH1107_FONT_H; row++) {
            if (bits & (1 << src_row[row])) {
                sh1107_set_pixel(cx + col, cy + row);
            }
        }
    }
#else
    for (int col = 0; col < SH1107_FONT_W; col++) {
        uint8_t bits = g[col];
        for (int row = 0; row < SH1107_FONT_H; row++) {
            if (bits & (1 << row)) {
                sh1107_set_pixel(cx + col, cy + row);
            }
        }
    }
#endif
}

static int truncate_text(const char *src, char *dst, size_t dst_sz, int max_chars)
{
    if (!src) { dst[0] = '\0'; return 0; }
    int len = (int)strlen(src);
    if (len <= max_chars) {
        snprintf(dst, dst_sz, "%s", src);
        return len;
    }
    if (max_chars > 3) {
        int cut = max_chars - 3;
        memcpy(dst, src, cut);
        dst[cut] = '.'; dst[cut+1] = '.'; dst[cut+2] = '.'; dst[cut+3] = '\0';
        return max_chars;
    }
    snprintf(dst, dst_sz, "%.*s", max_chars, src);
    return max_chars;
}

static void sh1107_draw_line_centre(const char *text, int line_y, int max_chars)
{
    if (!text || !text[0]) return;
    char buf[64];
    int len = truncate_text(text, buf, sizeof(buf), max_chars);
    int pixel_w = len * SH1107_FONT_PITCH;
    int start_x = (SH1107_UI_W - pixel_w) / 2;
    if (start_x < 0) start_x = 0;
    for (int i = 0; i < len; i++)
        sh1107_draw_char(buf[i], start_x + i * SH1107_FONT_PITCH, line_y);
}

static void sh1107_draw_line_left(const char *text, int line_y, int max_chars)
{
    if (!text || !text[0]) return;
    char buf[64];
    int len = truncate_text(text, buf, sizeof(buf), max_chars);
    for (int i = 0; i < len; i++)
        sh1107_draw_char(buf[i], 1 + i * SH1107_FONT_PITCH, line_y);
}

static void sh1107_draw_monster(void)
{
    sh1107_fb_clear();
    sh1107_draw_line_centre("Monster !", (SH1107_UI_H - SH1107_FONT_H) / 2, SH1107_MAX_CHARS);
    sh1107_flush();
}

static void sh1107_update(const char *lines[4])
{
    sh1107_fb_clear();
#if SH1107_UI_HORIZONTAL
    static const int line_y[4] = {0, 16, 32, 48};
#else
    static const int line_y[4] = {4, 36, 68, 100};
#endif
    for (int i = 0; i < 4; i++) {
        if (lines[i] && lines[i][0])
            sh1107_draw_line_left(lines[i], line_y[i], SH1107_MAX_CHARS);
    }
    sh1107_flush();
}

static bool sh1107_init(void)
{
    ESP_LOGI(TAG, "Probing SH1107 on SDA=%d SCL=%d addr=0x%02X",
             BUS_B_SDA, BUS_B_SCL, SH1107_I2C_ADDR);

    if (!s_i2c_bus_b) {
        i2c_master_bus_config_t cfg = {
            .clk_source = I2C_CLK_SRC_DEFAULT,
            .i2c_port = BUS_B_PORT,
            .sda_io_num = BUS_B_SDA,
            .scl_io_num = BUS_B_SCL,
            .glitch_ignore_cnt = 7,
            .flags.enable_internal_pullup = true,
        };
        if (i2c_new_master_bus(&cfg, &s_i2c_bus_b) != ESP_OK) return false;
    }

    if (i2c_master_probe(s_i2c_bus_b, SH1107_I2C_ADDR, I2C_TIMEOUT_MS) != ESP_OK)
        return false;

    i2c_device_config_t dev = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address = SH1107_I2C_ADDR,
        .scl_speed_hz = SH1107_I2C_FREQ_HZ,
    };
    if (i2c_master_bus_add_device(s_i2c_bus_b, &dev, &s_sh1107_dev) != ESP_OK)
        return false;

    vTaskDelay(pdMS_TO_TICKS(50));

    typedef struct { uint8_t cmd; int16_t arg; } icmd_t;
    static const icmd_t seq[] = {
        {0xAE, -1},
        {0x40, -1},
        {0xEE, -1},
        {0x20, 0x00},
        {0xDC, 0x00},
        {0xD5, 0x50},
        {0xA8, 0x7F},
        {0xD3, 0x00},
        {0xAD, 0x8B},
        {SH1107_SEG_REMAP, -1},
        {SH1107_COM_SCAN, -1},
        {0xD9, 0x20},
        {0xDB, 0x35},
        {0xA4, -1},
        {0x81, 0x7F},
        {0xDA, 0x12},
        {0xA6, -1},
        {0xAF, -1},
    };

    for (size_t i = 0; i < sizeof(seq)/sizeof(seq[0]); i++) {
        esp_err_t e = (seq[i].arg >= 0) ? sh1107_cmd_arg(seq[i].cmd, (uint8_t)seq[i].arg)
                                         : sh1107_cmd(seq[i].cmd);
        if (e != ESP_OK) {
            i2c_master_bus_rm_device(s_sh1107_dev);
            s_sh1107_dev = NULL;
            return false;
        }
    }

    vTaskDelay(pdMS_TO_TICKS(120));
    sh1107_fb_clear();
    if (sh1107_flush() != ESP_OK) {
        i2c_master_bus_rm_device(s_sh1107_dev);
        s_sh1107_dev = NULL;
        return false;
    }

    ESP_LOGI(TAG, "SH1107 ready (native %dx%d, ui %dx%d %s, col_offset=%d, font=%dx%d pitch=%d) on GPIO %d/%d",
             SH1107_LOGICAL_W, SH1107_LOGICAL_H,
             SH1107_UI_W, SH1107_UI_H, SH1107_UI_HORIZONTAL ? "horizontal" : "vertical",
             SH1107_COL_OFFSET,
             SH1107_FONT_W, SH1107_FONT_H, SH1107_FONT_PITCH, BUS_B_SDA, BUS_B_SCL);
    return true;
}

/* ====================================================================== */
/*                SH1106  DRIVER  (raw I2C framebuffer)                   */
/* ====================================================================== */

static esp_err_t sh1106_cmd(uint8_t cmd)
{
    uint8_t tx[2] = {0x00, cmd};
    return i2c_master_transmit(s_sh1106_dev, tx, sizeof(tx), I2C_TIMEOUT_MS);
}

static esp_err_t sh1106_cmd_arg(uint8_t cmd, uint8_t arg)
{
    uint8_t tx[3] = {0x00, cmd, arg};
    return i2c_master_transmit(s_sh1106_dev, tx, sizeof(tx), I2C_TIMEOUT_MS);
}

static esp_err_t sh1106_data(const uint8_t *data, size_t len)
{
    uint8_t tx[1 + I2C_DATA_CHUNK];
    tx[0] = 0x40;
    size_t off = 0;
    while (off < len) {
        size_t chunk = len - off;
        if (chunk > I2C_DATA_CHUNK) chunk = I2C_DATA_CHUNK;
        memcpy(&tx[1], data + off, chunk);
        esp_err_t err = i2c_master_transmit(s_sh1106_dev, tx, 1 + chunk, I2C_TIMEOUT_MS);
        if (err != ESP_OK) return err;
        off += chunk;
    }
    return ESP_OK;
}

static esp_err_t sh1106_set_page_col(uint8_t page, uint8_t col)
{
    uint8_t phys_col = (uint8_t)(col + 2); /* SH1106 visible area starts at column offset 2 */
    esp_err_t e;
    e = sh1106_cmd((uint8_t)(0xB0 | (page & 0x0F)));                if (e) return e;
    e = sh1106_cmd((uint8_t)(0x00 | (phys_col & 0x0F)));            if (e) return e;
    return sh1106_cmd((uint8_t)(0x10 | ((phys_col >> 4) & 0x0F)));
}

static esp_err_t sh1106_flush(void)
{
    for (uint8_t p = 0; p < OLED_PAGES; p++) {
        esp_err_t e = sh1106_set_page_col(p, 0);
        if (e) return e;
        e = sh1106_data(&sh1106_fb[p * OLED_H_RES], OLED_H_RES);
        if (e) return e;
    }
    return ESP_OK;
}

static void sh1106_fb_clear(void)
{
    if (!sh1106_fb) return;
    memset(sh1106_fb, 0, OLED_PAGES * OLED_H_RES);
}

static void sh1106_set_pixel(int x, int y)
{
    if (!sh1106_fb) return;
    if (x < 0 || y < 0 || x >= OLED_H_RES || y >= OLED_V_RES) return;
    sh1106_fb[(y / 8) * OLED_H_RES + x] |= (uint8_t)(1 << (y & 7));
}

static void sh1106_draw_char(char ch, int cx, int cy)
{
    const uint8_t *g = font_get_glyph(ch);
    for (int col = 0; col < 5; col++) {
        uint8_t bits = g[col];
        for (int row = 0; row < 7; row++) {
            if (bits & (1 << row))
                sh1106_set_pixel(cx + col, cy + row);
        }
    }
}

static void sh1106_draw_line_centre(const char *text, int line_y, int max_chars)
{
    if (!text || !text[0]) return;
    char buf[64];
    int len = truncate_text(text, buf, sizeof(buf), max_chars);
    int pixel_w = len * 6;
    int start_x = (OLED_H_RES - pixel_w) / 2;
    if (start_x < 0) start_x = 0;
    for (int i = 0; i < len; i++)
        sh1106_draw_char(buf[i], start_x + i * 6, line_y);
}

static void sh1106_draw_line_left(const char *text, int line_y, int max_chars)
{
    if (!text || !text[0]) return;
    char buf[64];
    int len = truncate_text(text, buf, sizeof(buf), max_chars);
    for (int i = 0; i < len; i++)
        sh1106_draw_char(buf[i], 1 + i * 6, line_y);
}

static void sh1106_draw_monster(void)
{
    sh1106_fb_clear();
    sh1106_draw_line_centre("Monster !", (OLED_V_RES - 7) / 2, SH1106_MAX_CHARS);
    sh1106_flush();
}

static void sh1106_update(const char *lines[4])
{
    sh1106_fb_clear();
    static const int line_y[4] = {0, 16, 32, 48};
    for (int i = 0; i < 4; i++) {
        if (lines[i] && lines[i][0])
            sh1106_draw_line_left(lines[i], line_y[i], SH1106_MAX_CHARS);
    }
    sh1106_flush();
}

static bool sh1106_init(void)
{
    if (SH1106_I2C_ADDR_RAW != SH1106_I2C_ADDR) {
        ESP_LOGI(TAG, "Probing SH1106 on SDA=%d SCL=%d addr(raw)=0x%02X -> 7bit=0x%02X",
                 BUS_B_SDA, BUS_B_SCL, SH1106_I2C_ADDR_RAW, SH1106_I2C_ADDR);
    } else {
        ESP_LOGI(TAG, "Probing SH1106 on SDA=%d SCL=%d addr=0x%02X",
                 BUS_B_SDA, BUS_B_SCL, SH1106_I2C_ADDR);
    }

    if (!s_i2c_bus_b) {
        i2c_master_bus_config_t cfg = {
            .clk_source = I2C_CLK_SRC_DEFAULT,
            .i2c_port = BUS_B_PORT,
            .sda_io_num = BUS_B_SDA,
            .scl_io_num = BUS_B_SCL,
            .glitch_ignore_cnt = 7,
            .flags.enable_internal_pullup = true,
        };
        if (i2c_new_master_bus(&cfg, &s_i2c_bus_b) != ESP_OK) return false;
    }

    if (i2c_master_probe(s_i2c_bus_b, SH1106_I2C_ADDR, I2C_TIMEOUT_MS) != ESP_OK)
        return false;

    i2c_device_config_t dev = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address = SH1106_I2C_ADDR,
        .scl_speed_hz = SH1106_I2C_FREQ_HZ,
    };
    if (i2c_master_bus_add_device(s_i2c_bus_b, &dev, &s_sh1106_dev) != ESP_OK)
        return false;

    vTaskDelay(pdMS_TO_TICKS(50));

    typedef struct { uint8_t cmd; int16_t arg; } icmd_t;
    static const icmd_t seq[] = {
        {0xAE, -1},
        {0xD5, 0x80},
        {0xA8, 0x3F},
        {0xD3, 0x00},
        {0x40, -1},
        {0x20, 0x00},
        {0xAD, 0x8B},
        {0xA1, -1},
        {0xC8, -1},
        {0xDA, 0x12},
        {0x81, 0x7F},
        {0xD9, 0x22},
        {0xDB, 0x20},
        {0xA4, -1},
        {0xA6, -1},
        {0xAF, -1},
    };

    for (size_t i = 0; i < sizeof(seq)/sizeof(seq[0]); i++) {
        esp_err_t e = (seq[i].arg >= 0) ? sh1106_cmd_arg(seq[i].cmd, (uint8_t)seq[i].arg)
                                         : sh1106_cmd(seq[i].cmd);
        if (e != ESP_OK) {
            i2c_master_bus_rm_device(s_sh1106_dev);
            s_sh1106_dev = NULL;
            return false;
        }
    }

    vTaskDelay(pdMS_TO_TICKS(120));
    sh1106_fb_clear();
    if (sh1106_flush() != ESP_OK) {
        i2c_master_bus_rm_device(s_sh1106_dev);
        s_sh1106_dev = NULL;
        return false;
    }

    ESP_LOGI(TAG, "SH1106 ready (128x64) on GPIO %d/%d addr 0x%02X",
             BUS_B_SDA, BUS_B_SCL, SH1106_I2C_ADDR);
    return true;
}

/* ====================================================================== */
/*            UNIT  LCD  DRIVER  (M5 Unit LCD 1.14" ST7789V2)             */
/* ====================================================================== */

static esp_err_t ulcd_send(const uint8_t *payload, size_t len)
{
    return i2c_master_transmit(s_ulcd_dev, payload, len, I2C_TIMEOUT_MS);
}

static esp_err_t ulcd_fill_rect(uint8_t x1, uint8_t y1, uint8_t x2, uint8_t y2, uint16_t c)
{
    uint8_t cmd[7] = {0x6A, x1, y1, x2, y2, (uint8_t)(c >> 8), (uint8_t)(c & 0xFF)};
    return ulcd_send(cmd, sizeof(cmd));
}

static esp_err_t ulcd_clear(uint16_t color)
{
    return ulcd_fill_rect(0, 0, UNIT_LCD_WIDTH - 1, UNIT_LCD_HEIGHT - 1, color);
}

static bool contains_ci(const char *haystack, const char *needle)
{
    if (!haystack || !needle || !needle[0]) return false;
    size_t nlen = strlen(needle);
    for (const char *h = haystack; *h; h++) {
        size_t i = 0;
        while (i < nlen && h[i] &&
               (tolower((unsigned char)h[i]) == tolower((unsigned char)needle[i]))) {
            i++;
        }
        if (i == nlen) return true;
    }
    return false;
}

static uint16_t ulcd_status_color_for_line(const char *line, int line_index)
{
#if !UNIT_LCD_COLOR_STATUS
    (void)line;
    (void)line_index;
    return 0xFFFF;
#else
    if (!line || !line[0]) return 0xFFFF; /* white */

    /* Critical states first. */
    if (contains_ci(line, "error")   || contains_ci(line, "fail")   ||
        contains_ci(line, "missing") || contains_ci(line, "denied") ||
        contains_ci(line, "stopped") || contains_ci(line, "no fix")) {
        return 0xF800; /* red */
    }

    /* Success states. */
    if (contains_ci(line, "ok")        || contains_ci(line, "ready")     ||
        contains_ci(line, "connected") || contains_ci(line, "active")    ||
        contains_ci(line, "mounted")   || contains_ci(line, "success")) {
        return 0x07E0; /* green */
    }

    /* Ongoing/in-progress states. */
    if (contains_ci(line, "scan")      || contains_ci(line, "boot")      ||
        contains_ci(line, "init")      || contains_ci(line, "wait")      ||
        contains_ci(line, "working")   || contains_ci(line, "upload")    ||
        contains_ci(line, "captur")    || contains_ci(line, "check")     ||
        contains_ci(line, "restart")   || contains_ci(line, "stream")) {
        return 0xFFE0; /* yellow */
    }

    /* Accent defaults by line role. */
    if (line_index == 0) return 0x07FF; /* cyan title */
    if (line_index == 3) return 0xFD20; /* orange hint/action */
    return 0xFFFF;                      /* white normal */
#endif
}

static void ulcd_draw_char(char ch, int cx, int cy, int scale, uint16_t fg)
{
    const uint8_t *g = font_get_glyph(ch);
    for (int col = 0; col < 5; col++) {
        uint8_t bits = g[col];
        for (int row = 0; row < 7; row++) {
            if (!(bits & (1 << row))) continue;
            int px = cx + col * scale;
            int py = cy + row * scale;
            if (px >= UNIT_LCD_WIDTH || py >= UNIT_LCD_HEIGHT) continue;
            int x2 = px + scale - 1;
            int y2 = py + scale - 1;
            if (x2 >= UNIT_LCD_WIDTH)  x2 = UNIT_LCD_WIDTH - 1;
            if (y2 >= UNIT_LCD_HEIGHT) y2 = UNIT_LCD_HEIGHT - 1;
            ulcd_fill_rect((uint8_t)px, (uint8_t)py, (uint8_t)x2, (uint8_t)y2, fg);
        }
    }
}

static void ulcd_draw_text(const char *text, int x, int y, int scale, int max_chars, uint16_t fg)
{
    if (!text || !text[0]) return;
    char buf[64];
    int len = truncate_text(text, buf, sizeof(buf), max_chars);
    int spacing = scale;
    for (int i = 0; i < len; i++)
        ulcd_draw_char(buf[i], x + i * (5 * scale + spacing), y, scale, fg);
}

static void ulcd_draw_monster(void)
{
    const int scale = UNIT_LCD_TEXT_SCALE;
    const char *text = "Monster !";
    int len = (int)strlen(text);
    int char_w = 5 * scale + scale;
    int text_w = len * char_w - scale;
    int text_h = 7 * scale;
    int sx = (UNIT_LCD_WIDTH  - text_w) / 2;
    int sy = (UNIT_LCD_HEIGHT - text_h) / 2;
    if (sx < 0) sx = 0;
    if (sy < 0) sy = 0;
    ulcd_clear(0x0000);
    ulcd_draw_text(text, sx, sy, scale, 20, 0xFFFF);
}

static void ulcd_update(const char *lines[4])
{
    ulcd_clear(0x0000);
#if UNIT_LCD_UI_HORIZONTAL
    static const int line_y[4] = {8, 40, 72, 104};
#else
    static const int line_y[4] = {10, 70, 130, 210};
#endif
    for (int i = 0; i < 4; i++) {
        if (lines[i] && lines[i][0]) {
            uint16_t fg = ulcd_status_color_for_line(lines[i], i);
            ulcd_draw_text(lines[i], 4, line_y[i],
                           UNIT_LCD_TEXT_SCALE, UNIT_LCD_MAX_CHARS, fg);
        }
    }
}

static bool ulcd_init(void)
{
    ESP_LOGI(TAG, "Probing Unit LCD on SDA=%d SCL=%d addr=0x%02X",
             BUS_B_SDA, BUS_B_SCL, UNIT_LCD_I2C_ADDR);

    if (!s_i2c_bus_b) {
        i2c_master_bus_config_t cfg = {
            .clk_source = I2C_CLK_SRC_DEFAULT,
            .i2c_port = BUS_B_PORT,
            .sda_io_num = BUS_B_SDA,
            .scl_io_num = BUS_B_SCL,
            .glitch_ignore_cnt = 7,
            .flags.enable_internal_pullup = true,
        };
        if (i2c_new_master_bus(&cfg, &s_i2c_bus_b) != ESP_OK) return false;
    }

    if (i2c_master_probe(s_i2c_bus_b, UNIT_LCD_I2C_ADDR, I2C_TIMEOUT_MS) != ESP_OK)
        return false;

    i2c_device_config_t dev = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address = UNIT_LCD_I2C_ADDR,
        .scl_speed_hz = UNIT_LCD_I2C_FREQ_HZ,
    };
    if (i2c_master_bus_add_device(s_i2c_bus_b, &dev, &s_ulcd_dev) != ESP_OK)
        return false;

    uint8_t reset_cmd = 0x30;
    if (ulcd_send(&reset_cmd, 1) != ESP_OK) goto fail;
    vTaskDelay(pdMS_TO_TICKS(120));

    uint8_t rot_cmd[2] = {0x36, UNIT_LCD_ROTATION};
    if (ulcd_send(rot_cmd, sizeof(rot_cmd)) != ESP_OK) goto fail;

    uint8_t on_cmd = 0x29;
    if (ulcd_send(&on_cmd, 1) != ESP_OK) goto fail;

    if (ulcd_clear(0x0000) != ESP_OK) goto fail;

    ESP_LOGI(TAG, "Unit LCD ready (%dx%d, ui=%s, rot=0x%02X) on GPIO %d/%d",
             UNIT_LCD_WIDTH, UNIT_LCD_HEIGHT,
             UNIT_LCD_UI_HORIZONTAL ? "horizontal" : "vertical",
             UNIT_LCD_ROTATION,
             BUS_B_SDA, BUS_B_SCL);
    return true;

fail:
    i2c_master_bus_rm_device(s_ulcd_dev);
    s_ulcd_dev = NULL;
    return false;
}

/* ====================================================================== */
/*        ST7735  DRIVER  (LILYGO T-Dongle-C5, raw SPI framebuffer)       */
/* ====================================================================== */

static esp_lcd_panel_io_handle_t s_st7735_io = NULL;
static uint8_t *s_st7735_fb = NULL;       /* PSRAM: ST7735_W * ST7735_H * 2 (RGB565 BE) */
static uint8_t *s_st7735_bounce = NULL;   /* internal DMA: one band (ST7735_BAND_BYTES) */
/* Runtime-tunable for bring-up via the `lcd` CLI command. */
static uint8_t s_st7735_col_off = ST7735_COL_OFFSET;
static uint8_t s_st7735_row_off = ST7735_ROW_OFFSET;

static inline esp_err_t st7735_cmd(uint8_t cmd, const uint8_t *data, size_t len)
{
    return esp_lcd_panel_io_tx_param(s_st7735_io, cmd, data, len);
}

static void st7735_reset_hw(void)
{
    gpio_config_t io = {
        .pin_bit_mask = (1ULL << ST7735_RST_GPIO) | (1ULL << ST7735_BL_GPIO),
        .mode = GPIO_MODE_OUTPUT,
    };
    gpio_config(&io);
    gpio_set_level(ST7735_BL_GPIO, ST7735_BL_OFF);   /* backlight off during init */
    gpio_set_level(ST7735_RST_GPIO, 1);
    vTaskDelay(pdMS_TO_TICKS(10));
    gpio_set_level(ST7735_RST_GPIO, 0);
    vTaskDelay(pdMS_TO_TICKS(20));
    gpio_set_level(ST7735_RST_GPIO, 1);
    vTaskDelay(pdMS_TO_TICKS(120));
}

static esp_err_t st7735_send_init_seq(void)
{
    typedef struct { uint8_t cmd; uint8_t len; uint8_t delay_ms; uint8_t data[16]; } st_cmd_t;
    static const st_cmd_t seq[] = {
        {0x01, 0, 150, {0}},                                   /* SWRESET */
        {0x11, 0, 255, {0}},                                   /* SLPOUT  */
        {0xB1, 3, 0,   {0x01,0x2C,0x2D}},                      /* FRMCTR1 */
        {0xB2, 3, 0,   {0x01,0x2C,0x2D}},                      /* FRMCTR2 */
        {0xB3, 6, 0,   {0x01,0x2C,0x2D,0x01,0x2C,0x2D}},       /* FRMCTR3 */
        {0xB4, 1, 0,   {0x07}},                                /* INVCTR  */
        {0xC0, 3, 0,   {0xA2,0x02,0x84}},                      /* PWCTR1  */
        {0xC1, 1, 0,   {0xC5}},                                /* PWCTR2  */
        {0xC2, 2, 0,   {0x0A,0x00}},                           /* PWCTR3  */
        {0xC3, 2, 0,   {0x8A,0x2A}},                           /* PWCTR4  */
        {0xC4, 2, 0,   {0x8A,0xEE}},                           /* PWCTR5  */
        {0xC5, 1, 0,   {0x0E}},                                /* VMCTR1  */
        {0x21, 0, 0,   {0}},                                   /* INVON (80x160 panels) */
        {0x36, 1, 0,   {ST7735_MADCTL}},                       /* MADCTL  */
        {0x3A, 1, 0,   {0x05}},                                /* COLMOD 16-bit */
        {0xE0, 16, 0,  {0x02,0x1C,0x07,0x12,0x37,0x32,0x29,0x2D,
                        0x29,0x25,0x2B,0x39,0x00,0x01,0x03,0x10}}, /* GMCTRP1 */
        {0xE1, 16, 0,  {0x03,0x1D,0x07,0x06,0x2E,0x2C,0x29,0x2D,
                        0x2E,0x2E,0x37,0x3F,0x00,0x00,0x02,0x10}}, /* GMCTRN1 */
        {0x13, 0, 10,  {0}},                                   /* NORON   */
        {0x29, 0, 100, {0}},                                   /* DISPON  */
    };
    for (size_t i = 0; i < sizeof(seq)/sizeof(seq[0]); i++) {
        esp_err_t e = st7735_cmd(seq[i].cmd, seq[i].len ? seq[i].data : NULL, seq[i].len);
        if (e != ESP_OK) return e;
        if (seq[i].delay_ms) vTaskDelay(pdMS_TO_TICKS(seq[i].delay_ms));
    }
    return ESP_OK;
}

static inline void st7735_put_pixel(int x, int y, uint16_t c)
{
    if (!s_st7735_fb) return;
    if (x < 0 || y < 0 || x >= ST7735_W || y >= ST7735_H) return;
    uint8_t *p = &s_st7735_fb[(y * ST7735_W + x) * 2];
    p[0] = (uint8_t)(c >> 8);   /* ST7735 expects high byte first */
    p[1] = (uint8_t)(c & 0xFF);
}

static void st7735_fb_fill(uint16_t c)
{
    if (!s_st7735_fb) return;
    uint8_t hi = (uint8_t)(c >> 8), lo = (uint8_t)(c & 0xFF);
    for (int i = 0; i < ST7735_W * ST7735_H; i++) {
        s_st7735_fb[i * 2]     = hi;
        s_st7735_fb[i * 2 + 1] = lo;
    }
}

static void st7735_draw_char(char ch, int cx, int cy, int scale, uint16_t fg)
{
    const uint8_t *g = font_get_glyph(ch);
    for (int col = 0; col < 5; col++) {
        uint8_t bits = g[col];
        for (int row = 0; row < 7; row++) {
            if (!(bits & (1 << row))) continue;
            for (int sx = 0; sx < scale; sx++)
                for (int sy = 0; sy < scale; sy++)
                    st7735_put_pixel(cx + col * scale + sx, cy + row * scale + sy, fg);
        }
    }
}

static void st7735_draw_text(const char *text, int x, int y, int scale, int max_chars, uint16_t fg)
{
    if (!text || !text[0]) return;
    char buf[64];
    int len = truncate_text(text, buf, sizeof(buf), max_chars);
    int pitch = 5 * scale + scale;  /* glyph + 1-col gap */
    for (int i = 0; i < len; i++)
        st7735_draw_char(buf[i], x + i * pitch, y, scale, fg);
}

static esp_err_t st7735_flush(void)
{
    if (!s_st7735_io || !s_st7735_fb || !s_st7735_bounce) return ESP_FAIL;
    const uint8_t xs = s_st7735_col_off;
    const uint8_t xe = s_st7735_col_off + ST7735_W - 1;
    uint8_t caset[4] = {0x00, xs, 0x00, xe};

    /* Push the PSRAM framebuffer in horizontal bands through a small internal
     * DMA bounce buffer, so each SPI transfer is tiny and shares the bus nicely
     * with the SD card. Address window is set per band via RASET. */
    for (int y = 0; y < ST7735_H; y += ST7735_FLUSH_ROWS) {
        int rows = ST7735_H - y;
        if (rows > ST7735_FLUSH_ROWS) rows = ST7735_FLUSH_ROWS;
        size_t bytes = (size_t)rows * ST7735_W * 2;

        uint8_t ys = (uint8_t)(s_st7735_row_off + y);
        uint8_t ye = (uint8_t)(s_st7735_row_off + y + rows - 1);
        uint8_t raset[4] = {0x00, ys, 0x00, ye};

        esp_err_t e;
        if ((e = st7735_cmd(0x2A, caset, 4)) != ESP_OK) return e;   /* CASET */
        if ((e = st7735_cmd(0x2B, raset, 4)) != ESP_OK) return e;   /* RASET */

        memcpy(s_st7735_bounce, &s_st7735_fb[(size_t)y * ST7735_W * 2], bytes);
        if ((e = esp_lcd_panel_io_tx_color(s_st7735_io, 0x2C,       /* RAMWR */
                                           s_st7735_bounce, bytes)) != ESP_OK) {
            return e;
        }
    }
    return ESP_OK;
}

static int st7735_max_chars(void)
{
    int pitch = 5 * ST7735_TEXT_SCALE + ST7735_TEXT_SCALE;
    return ST7735_W / pitch;
}

static uint16_t st7735_line_color(const char *line, int idx)
{
#if ST7735_COLOR_STATUS
    return ulcd_status_color_for_line(line, idx);
#else
    (void)line; (void)idx; return 0xFFFF;
#endif
}

static void st7735_update(const char *lines[4])
{
    st7735_fb_fill(0x0000);
    const int scale = ST7735_TEXT_SCALE;
    const int line_h = 7 * scale;
    const int gap = (ST7735_H - 4 * line_h) / 5;  /* even vertical spacing */
    const int mc = st7735_max_chars();
    int y = gap;
    for (int i = 0; i < 4; i++) {
        if (lines[i] && lines[i][0]) {
            uint16_t fg = st7735_line_color(lines[i], i);
            st7735_draw_text(lines[i], 2, y, scale, mc, fg);
        }
        y += line_h + gap;
    }
    st7735_flush();
}

static void st7735_draw_monster(void)
{
    st7735_fb_fill(0x0000);
    const int scale = ST7735_TEXT_SCALE;
    const char *text = "Monster !";
    int pitch = 5 * scale + scale;
    int tw = (int)strlen(text) * pitch - scale;
    int sx = (ST7735_W - tw) / 2;
    int sy = (ST7735_H - 7 * scale) / 2;
    if (sx < 0) sx = 0;
    if (sy < 0) sy = 0;
    st7735_draw_text(text, sx, sy, scale, st7735_max_chars(), 0x07FF);
    st7735_flush();
}

static bool st7735_init(void)
{
    ESP_LOGI(TAG, "Probing ST7735 SPI LCD (CS=%d DC=%d RST=%d BL=%d) on shared SPI bus",
             ST7735_CS_GPIO, ST7735_DC_GPIO, ST7735_RST_GPIO, ST7735_BL_GPIO);

    if (board_shared_spi_bus_init() != ESP_OK) {
        return false;
    }

    if (!s_st7735_fb) {
        /* Full framebuffer in PSRAM (keeps the scarce internal DMA pool free). */
        s_st7735_fb = heap_caps_malloc(ST7735_W * ST7735_H * 2,
                                       MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (!s_st7735_fb) {
            ESP_LOGE(TAG, "ST7735 framebuffer alloc failed (%d bytes)", ST7735_W * ST7735_H * 2);
            return false;
        }
    }
    if (!s_st7735_bounce) {
        /* One band, internal DMA-capable memory for the actual SPI transfers. */
        s_st7735_bounce = heap_caps_malloc(ST7735_BAND_BYTES, MALLOC_CAP_DMA | MALLOC_CAP_8BIT);
        if (!s_st7735_bounce) {
            ESP_LOGE(TAG, "ST7735 bounce buffer alloc failed (%d bytes)", ST7735_BAND_BYTES);
            return false;
        }
    }

    st7735_reset_hw();

    esp_lcd_panel_io_spi_config_t io_cfg = {
        .cs_gpio_num = ST7735_CS_GPIO,
        .dc_gpio_num = ST7735_DC_GPIO,
        .spi_mode = 0,
        .pclk_hz = ST7735_PCLK_HZ,
        .trans_queue_depth = 10,
        .lcd_cmd_bits = 8,
        .lcd_param_bits = 8,
    };
    if (esp_lcd_new_panel_io_spi((esp_lcd_spi_bus_handle_t)BOARD_SPI_HOST,
                                 &io_cfg, &s_st7735_io) != ESP_OK) {
        ESP_LOGE(TAG, "ST7735 panel IO create failed");
        return false;
    }

    if (st7735_send_init_seq() != ESP_OK) {
        ESP_LOGE(TAG, "ST7735 init sequence failed");
        esp_lcd_panel_io_del(s_st7735_io);
        s_st7735_io = NULL;
        return false;
    }

    st7735_fb_fill(0x0000);
    if (st7735_flush() != ESP_OK) {
        ESP_LOGE(TAG, "ST7735 first flush failed");
        esp_lcd_panel_io_del(s_st7735_io);
        s_st7735_io = NULL;
        return false;
    }

    gpio_set_level(ST7735_BL_GPIO, ST7735_BL_ON);  /* backlight on (active-low) */
    ESP_LOGI(TAG, "ST7735 ready (%dx%d landscape) on shared SPI bus", ST7735_W, ST7735_H);
    return true;
}

/* ---- Bring-up debug hooks, driven by the `lcd` CLI command ---- */
void oled_st7735_dbg_backlight(int on)
{
    gpio_set_level(ST7735_BL_GPIO, on ? ST7735_BL_ON : ST7735_BL_OFF);
    ESP_LOGI(TAG, "ST7735 backlight (GPIO%d) %s", ST7735_BL_GPIO, on ? "ON" : "OFF");
}

void oled_st7735_dbg_fill(uint16_t color)
{
    if (s_display_type != DISPLAY_ST7735) return;
    _lock_acquire(&s_api_lock);
    st7735_fb_fill(color);
    st7735_flush();
    _lock_release(&s_api_lock);
    ESP_LOGI(TAG, "ST7735 fill 0x%04X", color);
}

void oled_st7735_dbg_madctl(int madctl, int invert)
{
    if (s_display_type != DISPLAY_ST7735 || !s_st7735_io) return;
    _lock_acquire(&s_api_lock);
    uint8_t m = (uint8_t)madctl;
    st7735_cmd(0x36, &m, 1);                 /* MADCTL */
    st7735_cmd(invert ? 0x21 : 0x20, NULL, 0); /* INVON / INVOFF */
    st7735_flush();
    _lock_release(&s_api_lock);
    ESP_LOGI(TAG, "ST7735 MADCTL=0x%02X invert=%d", (unsigned)(uint8_t)madctl, invert);
}

void oled_st7735_dbg_offset(int col, int row)
{
    s_st7735_col_off = (uint8_t)col;
    s_st7735_row_off = (uint8_t)row;
    oled_st7735_dbg_fill(0xF800);  /* red, so the visible window is obvious */
    ESP_LOGI(TAG, "ST7735 offsets col=%d row=%d", col, row);
}

static void release_bus_b(void)
{
    if (s_i2c_bus_b) {
        i2c_del_master_bus(s_i2c_bus_b);
        s_i2c_bus_b = NULL;
    }
}

static bool select_ssd1306(uint32_t bus_mask)
{
    if (!ssd1306_init(bus_mask)) {
        return false;
    }

    s_display_type = DISPLAY_SSD1306;
    s_detected_addr_7bit = s_ssd1306_addr_7bit;
    s_detected_addr_raw = s_ssd1306_addr_raw;
    ESP_LOGI(TAG, "Display: SSD1306 OLED at raw 0x%02X (7-bit 0x%02X) (GPIO %d/%d)",
             s_ssd1306_addr_raw, s_ssd1306_addr_7bit, s_ssd1306_sda_gpio, s_ssd1306_scl_gpio);
    if ((s_ssd1306_sda_gpio == BUS_B_SDA) && (s_ssd1306_scl_gpio == BUS_B_SCL) &&
        ((s_ssd1306_addr_7bit == SH1107_I2C_ADDR) || (s_ssd1306_addr_7bit == SH1106_I2C_ADDR))) {
        ESP_LOGW(TAG, "SSD1306 selected on bus B at shared address 0x%02X. "
                      "If image is garbled, prefer SH110x on overlap "
                      "(OLED_PREFER_SSD1306_ON_BUS_B=0, OLED_OVERLAP_UNKNOWN_PREFERS_SH110X=1).",
                 s_ssd1306_addr_7bit);
    }
    ssd1306_show_monster_splash();
    return true;
}

static bool select_bus_b_non_ssd_displays(void)
{
#if OLED_PREFER_SH1106
    ESP_LOGI(TAG, "Display detect policy on bus B: SH1106 first");
    if (sh1106_init()) {
        s_display_type = DISPLAY_SH1106;
        s_detected_addr_7bit = SH1106_I2C_ADDR;
        s_detected_addr_raw = SH1106_I2C_ADDR_RAW;
        ESP_LOGI(TAG, "Display: SH1106 OLED at raw 0x%02X (7-bit 0x%02X) (GPIO %d/%d)",
                 SH1106_I2C_ADDR_RAW, SH1106_I2C_ADDR, BUS_B_SDA, BUS_B_SCL);
        sh1106_draw_monster();
        vTaskDelay(pdMS_TO_TICKS(1000));
        return true;
    }

    if (sh1107_init()) {
        s_display_type = DISPLAY_SH1107;
        s_detected_addr_7bit = SH1107_I2C_ADDR;
        s_detected_addr_raw = SH1107_I2C_ADDR_RAW;
        ESP_LOGI(TAG, "Display: SH1107 OLED at raw 0x%02X (7-bit 0x%02X) (GPIO %d/%d)",
                 SH1107_I2C_ADDR_RAW, SH1107_I2C_ADDR, BUS_B_SDA, BUS_B_SCL);
        sh1107_draw_monster();
        vTaskDelay(pdMS_TO_TICKS(1000));
        return true;
    }
#else
    ESP_LOGI(TAG, "Display detect policy on bus B: SH1107 first");
    if (sh1107_init()) {
        s_display_type = DISPLAY_SH1107;
        s_detected_addr_7bit = SH1107_I2C_ADDR;
        s_detected_addr_raw = SH1107_I2C_ADDR_RAW;
        ESP_LOGI(TAG, "Display: SH1107 OLED at raw 0x%02X (7-bit 0x%02X) (GPIO %d/%d)",
                 SH1107_I2C_ADDR_RAW, SH1107_I2C_ADDR, BUS_B_SDA, BUS_B_SCL);
        sh1107_draw_monster();
        vTaskDelay(pdMS_TO_TICKS(1000));
        return true;
    }

    if (sh1106_init()) {
        s_display_type = DISPLAY_SH1106;
        s_detected_addr_7bit = SH1106_I2C_ADDR;
        s_detected_addr_raw = SH1106_I2C_ADDR_RAW;
        ESP_LOGI(TAG, "Display: SH1106 OLED at raw 0x%02X (7-bit 0x%02X) (GPIO %d/%d)",
                 SH1106_I2C_ADDR_RAW, SH1106_I2C_ADDR, BUS_B_SDA, BUS_B_SCL);
        sh1106_draw_monster();
        vTaskDelay(pdMS_TO_TICKS(1000));
        return true;
    }
#endif

    if (ulcd_init()) {
        s_display_type = DISPLAY_UNIT_LCD;
        s_detected_addr_7bit = UNIT_LCD_I2C_ADDR;
        s_detected_addr_raw = UNIT_LCD_I2C_ADDR_RAW;
        ESP_LOGI(TAG, "Display: M5 Unit LCD at raw 0x%02X (7-bit 0x%02X) (GPIO %d/%d)",
                 UNIT_LCD_I2C_ADDR_RAW, UNIT_LCD_I2C_ADDR, BUS_B_SDA, BUS_B_SCL);
        ulcd_draw_monster();
        vTaskDelay(pdMS_TO_TICKS(1000));
        return true;
    }

    return false;
}

static bool select_st7735(void)
{
    if (!st7735_init()) {
        return false;
    }
    s_display_type = DISPLAY_ST7735;
    s_detected_addr_7bit = 0;   /* SPI display, no I2C address */
    s_detected_addr_raw = 0;
    ESP_LOGI(TAG, "Display: ST7735 SPI LCD %dx%d (LILYGO T-Dongle-C5)", ST7735_W, ST7735_H);
    st7735_draw_monster();
    vTaskDelay(pdMS_TO_TICKS(1000));
    return true;
}

static bool select_forced_display(void)
{
    switch (s_forced_type) {
    case DISPLAY_ST7735:
        ESP_LOGI(TAG, "Display force mode: ST7735");
        return select_st7735();

    case DISPLAY_SSD1306:
        ESP_LOGI(TAG, "Display force mode: SSD1306");
        return select_ssd1306(SSD1306_BUS_A_BIT | SSD1306_BUS_B_BIT);

    case DISPLAY_SH1107:
        ESP_LOGI(TAG, "Display force mode: SH1107");
        if (sh1107_init()) {
            s_display_type = DISPLAY_SH1107;
            s_detected_addr_7bit = SH1107_I2C_ADDR;
            s_detected_addr_raw = SH1107_I2C_ADDR_RAW;
            sh1107_draw_monster();
            vTaskDelay(pdMS_TO_TICKS(1000));
            return true;
        }
        return false;

    case DISPLAY_SH1106:
        ESP_LOGI(TAG, "Display force mode: SH1106");
        if (sh1106_init()) {
            s_display_type = DISPLAY_SH1106;
            s_detected_addr_7bit = SH1106_I2C_ADDR;
            s_detected_addr_raw = SH1106_I2C_ADDR_RAW;
            sh1106_draw_monster();
            vTaskDelay(pdMS_TO_TICKS(1000));
            return true;
        }
        return false;

    case DISPLAY_UNIT_LCD:
        ESP_LOGI(TAG, "Display force mode: UNIT_LCD");
        if (ulcd_init()) {
            s_display_type = DISPLAY_UNIT_LCD;
            s_detected_addr_7bit = UNIT_LCD_I2C_ADDR;
            s_detected_addr_raw = UNIT_LCD_I2C_ADDR_RAW;
            ulcd_draw_monster();
            vTaskDelay(pdMS_TO_TICKS(1000));
            return true;
        }
        return false;

    case DISPLAY_NONE:
    default:
        return false;
    }
}

static bool line_has_trailing_ellipsis(const char *s)
{
    if (!s) return false;
    size_t len = strlen(s);
    if (len < 3) return false;
    return (s[len - 1] == '.' && s[len - 2] == '.' && s[len - 3] == '.');
}

static bool oled_recalc_dynamic_state_locked(void)
{
    bool prev_enabled = s_cursor_blink_enabled;
    int prev_line = s_cursor_blink_line;
    int prev_col = s_cursor_blink_col;
    bool prev_visible = s_cursor_visible;
    bool prev_dots_enabled = s_dots_anim_enabled;
    uint8_t prev_dots_phase = s_dots_anim_phase;
    bool changed = false;

    s_cursor_blink_enabled = false;
    s_cursor_blink_line = -1;
    s_cursor_blink_col = -1;
    s_dots_anim_enabled = false;

    if (!s_line_cache) {
        s_cursor_visible = true;
        s_dots_anim_phase = 3;
        return (prev_enabled || !prev_visible || prev_dots_enabled || prev_dots_phase != 3);
    }

    for (int i = 0; i < OLED_LINE_COUNT; i++) {
        char *p = strchr(s_line_cache[i], '_');
        if (p) {
            s_cursor_blink_enabled = true;
            s_cursor_blink_line = i;
            s_cursor_blink_col = (int)(p - s_line_cache[i]);
            break;
        }
    }

    for (int i = 0; i < OLED_LINE_COUNT; i++) {
        if (line_has_trailing_ellipsis(s_line_cache[i])) {
            s_dots_anim_enabled = true;
            break;
        }
    }

    if (s_cursor_blink_enabled) {
        if (!prev_enabled || prev_line != s_cursor_blink_line || prev_col != s_cursor_blink_col) {
            s_cursor_visible = true;
            changed = true;
        }
    } else {
        s_cursor_visible = true;
        if (prev_enabled || !prev_visible) {
            changed = true;
        }
    }

    if (s_dots_anim_enabled) {
        if (!prev_dots_enabled) {
            s_dots_anim_phase = 1;
            changed = true;
        }
    } else {
        s_dots_anim_phase = 3;
        if (prev_dots_enabled || prev_dots_phase != 3) {
            changed = true;
        }
    }

    return changed;
}

static void oled_render_cached_locked(bool cursor_visible)
{
    if (!s_line_cache) return;
    if (s_display_type == DISPLAY_NONE) return;
    if (s_display_type == DISPLAY_SSD1306 && s_ssd1306_offline) return;

    char render_buf[OLED_LINE_COUNT][OLED_LINE_LEN];
    const char *render_lines[OLED_LINE_COUNT];
    for (int i = 0; i < OLED_LINE_COUNT; i++) {
        snprintf(render_buf[i], sizeof(render_buf[i]), "%s", s_line_cache[i]);
        render_lines[i] = render_buf[i];
    }

    if (!cursor_visible && s_cursor_blink_enabled &&
        s_cursor_blink_line >= 0 && s_cursor_blink_line < OLED_LINE_COUNT &&
        s_cursor_blink_col >= 0) {
        int line = s_cursor_blink_line;
        size_t len = strlen(render_buf[line]);
        if ((size_t)s_cursor_blink_col < len && render_buf[line][s_cursor_blink_col] == '_') {
            render_buf[line][s_cursor_blink_col] = ' ';
        }
    }

    if (s_dots_anim_enabled) {
        uint8_t dots = s_dots_anim_phase;
        if (dots < 1) dots = 1;
        if (dots > 3) dots = 3;
        for (int line = 0; line < OLED_LINE_COUNT; line++) {
            if (!line_has_trailing_ellipsis(render_buf[line])) continue;
            size_t len = strlen(render_buf[line]);
            if (len < 3) continue;
            render_buf[line][len - 3] = ' ';
            render_buf[line][len - 2] = ' ';
            render_buf[line][len - 1] = ' ';
            for (uint8_t i = 0; i < dots; i++) {
                render_buf[line][len - 3 + i] = '.';
            }
        }
    }

    if (s_display_type == DISPLAY_SSD1306)
        ssd1306_update(render_lines);
    else if (s_display_type == DISPLAY_SH1107)
        sh1107_update(render_lines);
    else if (s_display_type == DISPLAY_SH1106)
        sh1106_update(render_lines);
    else if (s_display_type == DISPLAY_UNIT_LCD)
        ulcd_update(render_lines);
    else if (s_display_type == DISPLAY_ST7735)
        st7735_update(render_lines);
}

static void oled_cursor_blink_task(void *arg)
{
    (void)arg;
    const uint32_t step_ms = 100;
    const TickType_t tick = pdMS_TO_TICKS(step_ms);
    uint32_t cursor_elapsed = 0;
    uint32_t dots_elapsed = 0;
    while (1) {
        vTaskDelay(tick);
        _lock_acquire(&s_api_lock);
        /* ST7735 shares its SPI bus with the SD card. Flushing the panel from
         * this background task concurrently with SD I/O can deadlock the bus, so
         * the cursor/dots animation is driven only by explicit (main-task)
         * updates for ST7735 - never from here. */
        if ((s_cursor_blink_enabled || s_dots_anim_enabled) &&
            s_display_type != DISPLAY_NONE && s_display_type != DISPLAY_ST7735) {
            bool changed = false;

            if (s_cursor_blink_enabled) {
                cursor_elapsed += step_ms;
                if (cursor_elapsed >= OLED_CURSOR_BLINK_MS) {
                    cursor_elapsed = 0;
                    s_cursor_visible = !s_cursor_visible;
                    changed = true;
                }
            } else {
                cursor_elapsed = 0;
                if (!s_cursor_visible) {
                    s_cursor_visible = true;
                    changed = true;
                }
            }

            if (s_dots_anim_enabled) {
                dots_elapsed += step_ms;
                if (dots_elapsed >= OLED_DOTS_ANIM_MS) {
                    dots_elapsed = 0;
                    s_dots_anim_phase++;
                    if (s_dots_anim_phase > 3) s_dots_anim_phase = 1;
                    changed = true;
                }
            } else {
                dots_elapsed = 0;
                if (s_dots_anim_phase != 3) {
                    s_dots_anim_phase = 3;
                    changed = true;
                }
            }

            if (changed) {
                oled_render_cached_locked(s_cursor_visible);
            }
        } else {
            cursor_elapsed = 0;
            dots_elapsed = 0;
        }
        _lock_release(&s_api_lock);
    }
}

static void oled_cursor_blink_start_once(void)
{
    if (s_cursor_blink_task) return;
    BaseType_t rc = xTaskCreate(oled_cursor_blink_task, "oled_cursor",
                                3 * 1024, NULL, 1, &s_cursor_blink_task);
    if (rc != pdPASS) {
        s_cursor_blink_task = NULL;
        ESP_LOGW(TAG, "Cursor blink task start failed");
    }
}

void oled_display_set_forced_type(display_type_t type)
{
    switch (type) {
    case DISPLAY_NONE:
    case DISPLAY_SSD1306:
    case DISPLAY_SH1107:
    case DISPLAY_SH1106:
    case DISPLAY_UNIT_LCD:
    case DISPLAY_ST7735:
        s_forced_type = type;
        break;
    default:
        s_forced_type = DISPLAY_NONE;
        break;
    }
}

display_type_t oled_display_get_forced_type(void)
{
    return s_forced_type;
}

/* ====================================================================== */
/*                          PUBLIC  API                                   */
/* ====================================================================== */

void oled_display_init(void)
{
    s_display_type = DISPLAY_NONE;
    s_detected_addr_7bit = 0;
    s_detected_addr_raw = 0;

    if (!oled_alloc_psram_buffers()) {
        ESP_LOGE(TAG, "OLED init aborted: PSRAM allocation required");
        return;
    }
    memset(s_line_cache, 0, OLED_LINE_COUNT * OLED_LINE_LEN);
    s_cursor_blink_enabled = false;
    s_cursor_blink_line = -1;
    s_cursor_blink_col = -1;
    s_cursor_visible = true;
    s_dots_anim_enabled = false;
    s_dots_anim_phase = 3;
    s_ssd1306_offline = false;
    oled_cursor_blink_start_once();

    if ((SH1107_I2C_ADDR == SSD1306_I2C_ADDR) ||
        (SH1107_I2C_ADDR == SSD1306_I2C_ADDR_ALT) ||
        (SH1106_I2C_ADDR == SSD1306_I2C_ADDR) ||
        (SH1106_I2C_ADDR == SSD1306_I2C_ADDR_ALT)) {
        ESP_LOGW(TAG, "I2C address overlap detected on bus B (SSD1306/SH110x share 0x%02X). "
                      "Auto-detect is heuristic; bus-B priority is %s",
                 SSD1306_I2C_ADDR,
#if OLED_PREFER_SSD1306_ON_BUS_B
                 "SSD1306");
#else
                 "SH110x");
#endif
    }

    if (s_forced_type != DISPLAY_NONE) {
        if (select_forced_display()) {
            return;
        }
        release_bus_b();
        ESP_LOGW(TAG, "Forced display init failed (type=%d). Check wiring/address and reset force mode to auto.",
                 (int)s_forced_type);
        return;
    }

    /* LILYGO T-Dongle-C5: onboard ST7735 SPI LCD is the primary display. */
    if (select_st7735()) {
        return;
    }

    if (select_ssd1306(SSD1306_BUS_A_BIT)) {
        return;
    }

#if OLED_PREFER_SSD1306_ON_BUS_B
    release_bus_b();
    ESP_LOGI(TAG, "Display detect policy: bus B prefers SSD1306");
    if (select_ssd1306(SSD1306_BUS_B_BIT)) {
        return;
    }
#endif

    if (select_bus_b_non_ssd_displays()) {
        return;
    }

#if !OLED_PREFER_SSD1306_ON_BUS_B
    release_bus_b();
    ESP_LOGI(TAG, "Display detect policy: bus B prefers SH110x; trying SSD1306 fallback");
    if (select_ssd1306(SSD1306_BUS_B_BIT)) {
        return;
    }
#endif

    release_bus_b();
    ESP_LOGW(TAG, "No display detected (probed SSD1306 0x%02X/0x%02X + 0x%02X/0x%02X on %d/%d, SH1107 0x%02X/0x%02X + SH1106 0x%02X/0x%02X + UNIT 0x%02X/0x%02X on %d/%d)",
             SSD1306_I2C_ADDR_RAW, SSD1306_I2C_ADDR, SSD1306_I2C_ADDR_ALT_RAW, SSD1306_I2C_ADDR_ALT, BUS_A_SDA, BUS_A_SCL,
             SH1107_I2C_ADDR_RAW, SH1107_I2C_ADDR, SH1106_I2C_ADDR_RAW, SH1106_I2C_ADDR,
             UNIT_LCD_I2C_ADDR_RAW, UNIT_LCD_I2C_ADDR,
             BUS_B_SDA, BUS_B_SCL);
}

display_type_t oled_display_get_type(void)
{
    return s_display_type;
}

uint8_t oled_display_get_i2c_addr_7bit(void)
{
    return s_detected_addr_7bit;
}

uint8_t oled_display_get_i2c_addr_raw(void)
{
    return s_detected_addr_raw;
}

void oled_display_update(const char *line1, const char *line2)
{
    oled_display_update_full(line1, line2, "", "");
}

void oled_display_update_full(const char *line1, const char *line2,
                              const char *line3, const char *line4)
{
    const char *lines[4] = {line1, line2, line3, line4};

    if (!s_line_cache) {
        ESP_LOGE(TAG, "OLED line cache missing in PSRAM");
        return;
    }

    _lock_acquire(&s_api_lock);
    bool changed = false;
    for (int i = 0; i < OLED_LINE_COUNT; i++) {
        if (lines[i] && strcmp(s_line_cache[i], lines[i]) != 0) {
            changed = true;
            snprintf(s_line_cache[i], OLED_LINE_LEN, "%s", lines[i]);
        }
    }

    bool blink_state_changed = oled_recalc_dynamic_state_locked();
    if (changed || blink_state_changed) {
        oled_render_cached_locked(s_cursor_visible);
    }
    _lock_release(&s_api_lock);
}

void oled_display_clear(void)
{
    oled_display_update_full("", "", "", "");
}
