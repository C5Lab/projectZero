idf_component_register(
    SRCS "capture_gateway.c"
    INCLUDE_DIRS "include"
    REQUIRES esp_wifi esp_netif lwip freertos
)
