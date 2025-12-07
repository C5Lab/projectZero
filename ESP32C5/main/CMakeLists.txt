idf_component_register(SRCS "main.c" "attack_handshake.c" 
                       INCLUDE_DIRS .
                       REQUIRES esp_timer esp_wifi esp_event esp_psram nvs_flash 
                                console driver fatfs mbedtls esp_http_server 
                                lwip sdmmc espressif__led_strip bt
                                frame_analyzer hccapx_serializer pcap_serializer sniffer)
