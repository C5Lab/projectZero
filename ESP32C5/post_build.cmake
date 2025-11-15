if(NOT DEFINED DEST)
  message(FATAL_ERROR "post_build.cmake: DEST is not set")
endif()
if(NOT DEFINED BLD)
  message(FATAL_ERROR "post_build.cmake: BLD is not set")
endif()
if(NOT DEFINED APP)
  message(FATAL_ERROR "post_build.cmake: APP is not set")
endif()

file(MAKE_DIRECTORY "${DEST}")

file(GLOB OLD_BINS "${DEST}/*.bin")
if(OLD_BINS)
  foreach(OLD_FILE ${OLD_BINS})
    get_filename_component(OLD_NAME "${OLD_FILE}" NAME)
    if(NOT OLD_NAME STREQUAL "oui_wifi.bin")
      file(REMOVE "${OLD_FILE}")
    endif()
  endforeach()
endif()

set(SRCS
  "${BLD}/${APP}"
  "${BLD}/bootloader/bootloader.bin"
  "${BLD}/partition_table/partition-table.bin"
)

foreach(F ${SRCS})
  if(EXISTS "${F}")
    file(COPY "${F}" DESTINATION "${DEST}")
  else()
    message(WARNING "post_build.cmake: Missing file: ${F}")
  endif()
endforeach()
