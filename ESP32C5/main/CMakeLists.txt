idf_component_register(SRCS "main.c" "attack_handshake.c" 
                       INCLUDE_DIRS .
                       REQUIRES esp_timer esp_wifi esp_event esp_psram nvs_flash 
                                console driver fatfs mbedtls esp_http_server 
                                esp_http_client esp_https_ota app_update cjson
                                lwip sdmmc espressif__led_strip bt
                                frame_analyzer hccapx_serializer pcap_serializer sniffer
                                esp_driver_uart esp_driver_gpio esp_driver_spi esp_driver_sdspi)

# Suppress strict null-pointer warnings from GCC 15 in IDF v6.0
target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-error=nonnull)
