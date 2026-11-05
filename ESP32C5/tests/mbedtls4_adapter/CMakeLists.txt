cmake_minimum_required(VERSION 3.16)

project(router_cve_mbedtls4_adapter_test C)

if(NOT DEFINED IDF_PATH OR NOT DEFINED JANOS_ROOT OR
   NOT DEFINED JANOS_CONFIG_INCLUDE)
    message(FATAL_ERROR "IDF_PATH, JANOS_ROOT and JANOS_CONFIG_INCLUDE are required")
endif()

set(MBEDTLS_SOURCE "${IDF_PATH}/components/mbedtls/mbedtls")
set(MBEDTLS_PORT_INCLUDE "${IDF_PATH}/components/mbedtls/port/include")
set(MBEDTLS_BUILTIN_INCLUDE
    "${MBEDTLS_SOURCE}/tf-psa-crypto/drivers/builtin/include")

set(GEN_FILES OFF CACHE BOOL "" FORCE)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(DISABLE_PACKAGE_CONFIG_AND_INSTALL ON CACHE BOOL "" FORCE)
set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "" FORCE)
set(USE_STATIC_MBEDTLS_LIBRARY ON CACHE BOOL "" FORCE)

# ESP-IDF 6.0.1 keeps selected public Mbed TLS 4 headers in its port tree.
# The include order is significant because those wrappers use include_next.
include_directories(BEFORE
    "${JANOS_CONFIG_INCLUDE}"
    "${MBEDTLS_BUILTIN_INCLUDE}"
    "${MBEDTLS_PORT_INCLUDE}")

add_subdirectory("${MBEDTLS_SOURCE}" mbedtls)

add_executable(router_cve_mbedtls4_test
    "${JANOS_ROOT}/tests/router_cve_mbedtls4_test.c"
    "${JANOS_ROOT}/main/router_cve_verify.c"
    "${JANOS_ROOT}/main/router_cve_db.c"
    "${JANOS_ROOT}/main/router_fingerprint.c")
target_compile_features(router_cve_mbedtls4_test PRIVATE c_std_11)
target_compile_definitions(router_cve_mbedtls4_test PRIVATE ESP_PLATFORM)
target_compile_options(router_cve_mbedtls4_test PRIVATE
    -Wall -Wextra -Werror)
target_include_directories(router_cve_mbedtls4_test PRIVATE
    "${JANOS_ROOT}/main")
target_link_libraries(router_cve_mbedtls4_test PRIVATE
    mbedtls mbedx509 tfpsacrypto)
