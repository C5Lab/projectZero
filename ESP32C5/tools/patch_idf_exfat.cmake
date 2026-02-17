if(NOT DEFINED ENV{IDF_PATH} OR "$ENV{IDF_PATH}" STREQUAL "")
  message(WARNING "exFAT patch: IDF_PATH is not set, skipping.")
  return()
endif()

set(_ffconf "$ENV{IDF_PATH}/components/fatfs/src/ffconf.h")
if(NOT EXISTS "${_ffconf}")
  message(WARNING "exFAT patch: ffconf.h not found at ${_ffconf}, skipping.")
  return()
endif()

file(READ "${_ffconf}" _ffconf_content)
set(_ffconf_patched "${_ffconf_content}")
set(_changed FALSE)

if(_ffconf_patched MATCHES "#define[ \t]+FF_FS_EXFAT[ \t]+1")
  message(STATUS "exFAT patch: FF_FS_EXFAT already enabled in ${_ffconf}")
else()
  string(REGEX REPLACE
    "#define[ \t]+FF_FS_EXFAT[ \t]+0"
    "#define FF_FS_EXFAT\t\t1"
    _ffconf_patched
    "${_ffconf_patched}"
  )
  if(_ffconf_patched MATCHES "#define[ \t]+FF_FS_EXFAT[ \t]+1")
    set(_changed TRUE)
    message(STATUS "exFAT patch: enabled FF_FS_EXFAT in ${_ffconf}")
  else()
    message(WARNING "exFAT patch: FF_FS_EXFAT define not found in ${_ffconf}, skipping.")
  endif()
endif()

# Compatibility fix for IDF versions where this option may be absent in sdkconfig.h.
if(_ffconf_patched MATCHES "#define[ \t]+FF_USE_LABEL[ \t]+CONFIG_FATFS_USE_LABEL")
  string(REGEX REPLACE
    "#define[ \t]+FF_USE_LABEL[ \t]+CONFIG_FATFS_USE_LABEL"
    "#ifdef CONFIG_FATFS_USE_LABEL\n#define FF_USE_LABEL\t1\n#else\n#define FF_USE_LABEL\t0\n#endif"
    _ffconf_patched
    "${_ffconf_patched}"
  )
  set(_changed TRUE)
  message(STATUS "exFAT patch: normalized FF_USE_LABEL guard in ${_ffconf}")
endif()

if(NOT _changed)
  message(STATUS "exFAT patch: no file changes needed in ${_ffconf}")
  return()
endif()

if(_ffconf_patched STREQUAL _ffconf_content)
  message(STATUS "exFAT patch: no file changes needed in ${_ffconf}")
  return()
endif()

file(WRITE "${_ffconf}" "${_ffconf_patched}")
