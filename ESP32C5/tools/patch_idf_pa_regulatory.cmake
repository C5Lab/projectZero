# Run after project.cmake defines PYTHON, but before project() consumes the
# ESP-IDF esp_wifi sources. The helper preserves the IDF files' line endings.
if(NOT DEFINED ENV{IDF_PATH} OR "$ENV{IDF_PATH}" STREQUAL "")
  message(FATAL_ERROR "PA regulatory patch: IDF_PATH is not set")
endif()
if(NOT DEFINED PYTHON OR "${PYTHON}" STREQUAL "")
  message(FATAL_ERROR "PA regulatory patch: ESP-IDF PYTHON is not set")
endif()

execute_process(
  COMMAND "${PYTHON}" "${CMAKE_CURRENT_LIST_DIR}/patch_idf_pa_regulatory.py" "$ENV{IDF_PATH}"
  RESULT_VARIABLE _pa_result
  OUTPUT_VARIABLE _pa_stdout
  ERROR_VARIABLE _pa_stderr
)
if(NOT _pa_result STREQUAL "0")
  string(STRIP "${_pa_stderr}" _pa_stderr)
  if(_pa_stderr STREQUAL "")
    message(FATAL_ERROR "PA regulatory patch: helper failed (${_pa_result})")
  endif()
  message(FATAL_ERROR "${_pa_stderr}")
endif()
string(STRIP "${_pa_stdout}" _pa_stdout)
message(STATUS "${_pa_stdout}")
