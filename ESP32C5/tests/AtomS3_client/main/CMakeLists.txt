idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    REQUIRES console esp_event esp_netif esp_wifi nvs_flash vfs esp_driver_uart esp_http_client
)
