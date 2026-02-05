cmake_minimum_required(VERSION 3.20)
project(c5lab C)

add_library(c5lab
    src/app.c
    src/uart_comm.c
    src/screen.c
    src/screen_main_menu.c
    src/screen_wifi_scan.c
    src/screen_attack_selection.c
    src/screen_deauth.c
    src/screen_evil_twin.c
    src/screen_sae_overflow.c
    src/screen_handshaker.c
    src/screen_sniffer.c
    src/screen_global_handshaker.c
)

target_include_directories(c5lab PUBLIC include)
target_link_libraries(c5lab PUBLIC core_headers)
