file(TO_CMAKE_PATH "$ENV{IDF_PATH}" JANOS_WPS_IDF_PATH)
set(ROOT "${CMAKE_CURRENT_LIST_DIR}/../..")

# Compile the component-owned, reviewed WPS engines and workflow closure.
# Standalone entry points stay excluded; production routes the component-owned
# Pixie/JWPS/campaign engines through janos_wps_runtime and the shared service.
idf_component_register(
    SRCS "janos_wps_memory.c" "janos_radio_lease.c" "janos_wps_service.c"
        "janos_wps_command.c"
        "janos_wps_wire.c"
         "janos_wps_transport.c" "janos_wps_runtime.c"
         "private/workflow/lab_secret.c"
         "private/workflow/lab_result_store.c"
         "private/workflow/lab_platform.c"
         "private/workflow/lab_radio.c"
         "private/session/lab_wps_session.c"
         "private/session/lab_wps_session_esp.c"
         "private/session/lab_wps_rx_gate.c"
         "private/workflow/lab_workflows.c"
         "${ROOT}/main/sta_mac_policy_core.c"
         "${ROOT}/main/sta_mac_policy_store.c"
         "${ROOT}/main/vendor_db.c"
         "${ROOT}/main/wps_pin_db.c"
         "${ROOT}/main/wps_pin_algorithms.c"
         "private/campaign/campaign_policy.c"
         "private/campaign/campaign_runner.c"
         "private/session/session_policy.c"
         "private/session/session_frames.c"
         "private/pixie/pixie.c"
         "private/pixie/pixie_prng.c"
         "private/pixie/pixie_time.c"
         "private/pin/pin_crypto.c"
         "private/pin/pin_protocol.c"
         "private/protocol/protocol.c"
         "private/protocol/m3_protocol.c"
         "private/protocol/wsc_fragment.c"
         "private/transport/wps_transport_core.c"
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "private/protocol" "private/pin" "private/pixie"
                      "private/session" "private/transport" "private/campaign"
                      "private/workflow" "${ROOT}/main"
                      "${JANOS_WPS_IDF_PATH}/components/wpa_supplicant/esp_supplicant/src"
                      "${JANOS_WPS_IDF_PATH}/components/wpa_supplicant/src"
                      "${JANOS_WPS_IDF_PATH}/components/mbedtls/mbedtls/include"
    REQUIRES esp_wifi esp_event esp_timer esp_hw_support heap nvs_flash
             wpa_supplicant mbedtls fatfs sdmmc esp_driver_spi)
