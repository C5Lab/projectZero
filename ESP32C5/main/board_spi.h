/*
 * Shared SPI bus for the LILYGO T-Dongle-C5.
 *
 * On this board the SD card, the ST7735 LCD and the APA102 LED all hang off the
 * SAME physical SPI bus (SPI2_HOST): SCK=IO06, MOSI=IO02, MISO=IO07. Each
 * peripheral is added as an independent SPI device (own CS), so the ESP-IDF SPI
 * master driver arbitrates bus access between them automatically.
 *
 * The bus must be initialised exactly once; board_shared_spi_bus_init() is
 * idempotent and safe to call from every peripheral's init path.
 */
#pragma once

#include "driver/spi_master.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BOARD_SPI_HOST          SPI2_HOST
#define BOARD_SPI_SCK_PIN       6
#define BOARD_SPI_MOSI_PIN      2
#define BOARD_SPI_MISO_PIN      7
/* Kept small so the shared bus does not hog the ~32K internal DMA pool that the
 * SD card also needs. The ST7735 framebuffer lives in PSRAM and is flushed in
 * small bands through a tiny internal DMA bounce buffer (see oled_display.c). */
#define BOARD_SPI_MAX_TRANSFER  4096

/* Initialise the shared SPI2 bus once. Returns ESP_OK if the bus is ready
 * (including the case where it was already initialised elsewhere). */
esp_err_t board_shared_spi_bus_init(void);

#ifdef __cplusplus
}
#endif
