cmake_minimum_required(VERSION 3.13)
project(Lab_C5 C)

add_library(Lab_C5 STATIC Lab_C5.c qrcodegen.c)

# Link with flipper libraries (placeholder, depends on SDK)
target_link_libraries(Lab_C5 furi)
