if(NOT DEFINED ENV{IDF_PATH} OR "$ENV{IDF_PATH}" STREQUAL "")
  message(WARNING "linenoise UTF-8 patch: IDF_PATH is not set, skipping.")
  return()
endif()

set(_linenoise "$ENV{IDF_PATH}/components/console/linenoise/linenoise.c")
if(NOT EXISTS "${_linenoise}")
  message(WARNING "linenoise UTF-8 patch: linenoise.c not found at ${_linenoise}, skipping.")
  return()
endif()

file(READ "${_linenoise}" _ln_content)
set(_ln_patched "${_ln_content}")
set(_changed FALSE)

# -----------------------------------------------------------------------
# Bug 1: linenoiseDumb() filters bytes >= 0x80 because 'c' is signed char
#        and the comparison  c <= UNIT_SEP  is true for values like -60.
#
# Before: } else if (c <= UNIT_SEP) {
# After:  } else if ((unsigned char)c <= UNIT_SEP) {
# -----------------------------------------------------------------------
if(_ln_patched MATCHES "\\(unsigned char\\)c <= UNIT_SEP")
  message(STATUS "linenoise UTF-8 patch: dumb-mode filter already patched.")
else()
  string(REPLACE
    "} else if (c <= UNIT_SEP) {"
    "} else if ((unsigned char)c <= UNIT_SEP) {"
    _ln_patched
    "${_ln_patched}"
  )
  if(_ln_patched MATCHES "\\(unsigned char\\)c <= UNIT_SEP")
    set(_changed TRUE)
    message(STATUS "linenoise UTF-8 patch: patched dumb-mode UNIT_SEP filter.")
  else()
    message(WARNING "linenoise UTF-8 patch: could not find UNIT_SEP pattern, skipping that fix.")
  endif()
endif()

# -----------------------------------------------------------------------
# Bug 2: sanitize() calls isprint(c) where 'c' is int derived from signed char.
#        isprint(-60) == false in the C locale, so all high bytes are stripped.
#
# Before: if (isprint(c)) {
# After:  if (isprint((unsigned char)c) || (unsigned char)c >= 0x80) {
# -----------------------------------------------------------------------
if(_ln_patched MATCHES "isprint\\(\\(unsigned char\\)c\\)")
  message(STATUS "linenoise UTF-8 patch: sanitize() already patched.")
else()
  string(REPLACE
    "        if (isprint(c)) {"
    "        if (isprint((unsigned char)c) || (unsigned char)c >= 0x80) {"
    _ln_patched
    "${_ln_patched}"
  )
  if(_ln_patched MATCHES "isprint\\(\\(unsigned char\\)c\\)")
    set(_changed TRUE)
    message(STATUS "linenoise UTF-8 patch: patched sanitize() isprint filter.")
  else()
    message(WARNING "linenoise UTF-8 patch: could not find isprint(c) pattern in sanitize(), skipping that fix.")
  endif()
endif()

if(NOT _changed)
  message(STATUS "linenoise UTF-8 patch: no changes needed.")
  return()
endif()

if(_ln_patched STREQUAL _ln_content)
  message(STATUS "linenoise UTF-8 patch: content unchanged, nothing written.")
  return()
endif()

file(WRITE "${_linenoise}" "${_ln_patched}")
message(STATUS "linenoise UTF-8 patch: wrote ${_linenoise}")
