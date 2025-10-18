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
  file(REMOVE ${OLD_BINS})
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
