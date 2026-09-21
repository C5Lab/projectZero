file(TO_CMAKE_PATH "$ENV{IDF_PATH}" CRACK_WORKER_IDF_PATH)
idf_component_register(SRCS "oled_display.c" "main.c" "attack_handshake.c"
                            "crack_worker.c" "crack_worker_core.c" "crack_worker_transfer.c" "crack_worker_crypto.c"
                            "crack_worker_sw_sha1.c" "artifact_inventory_core.c"
                       INCLUDE_DIRS .
                       PRIV_INCLUDE_DIRS "${CRACK_WORKER_IDF_PATH}/components/mbedtls/mbedtls/library"
                       REQUIRES esp_timer esp_wifi esp_event esp_psram nvs_flash 
                                console driver fatfs mbedtls esp-tls esp_http_server 
                                esp_http_client esp_https_ota app_update cjson
                                lwip sdmmc espressif__led_strip bt
                                frame_analyzer hccapx_serializer pcap_serializer sniffer
                                nrf24_jammer zig_recon capture_gateway
                                esp_driver_uart esp_driver_gpio esp_driver_spi esp_driver_sdspi
                                esp_lcd esp_driver_i2c)

# Suppress strict null-pointer warnings from GCC 15 in IDF v6.0
target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-error=nonnull)
