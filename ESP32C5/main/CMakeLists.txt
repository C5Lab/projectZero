idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS .
    REQUIRES
        bt
        esp_psram
        nvs_flash
        console
        driver
        esp_event
        esp_netif
        esp_wifi
        esp_http_server
        fatfs
        lwip
        sdmmc
        mbedtls
        led_strip)
