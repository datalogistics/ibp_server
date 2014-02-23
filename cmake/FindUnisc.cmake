# -*- cmake -*-

# - Find Phoebus libraries and includes
#
# This module defines
#    UNIS_C_INCLUDE_DIR - where to find libxsp_client.h
#    UNIS_C_LIBRARIES - the libraries needed to use Phoebus.
#    UNIS_C_FOUND - If false didn't find phoebus

# Find the include path

find_path(UNIS_C_INCLUDE_DIR unis_registration.h)

find_library(UNIS_C_LIBRARY NAMES unis-c curl jansson)
find_library(CURL_LIBRARY NAMES curl)
find_library(JANSSON_LIBRARY NAMES jansson)

if (CURL_LIBRARY)
  SET(CURL_FOUND "YES")
endif (CURL_LIBRARY)

if (JANSSON_LIBRARY)
  SET(JANSSON_FOUND "YES")
endif (JANSSON_LIBRARY)

if (UNIS_C_LIBRARY AND UNIS_C_INCLUDE_DIR)
    SET(UNIS_C_FOUND "YES")
endif (UNIS_C_LIBRARY AND UNIS_C_INCLUDE_DIR)

if (UNIS_C_FOUND)
  message(STATUS "Found unis-c library: ${UNIS_C_LIBRARY}")
else (UNIS_C_FOUND)
   message(STATUS "Could not find unis-c library")
endif (UNIS_C_FOUND)

if (CURL_FOUND)
  message(STATUS "Found curl library: ${CURL_LIBRARY}")
else (CURL_FOUND)
   message(STATUS "Could not find curl library")
endif (CURL_FOUND)

if (JANSSON_FOUND)
  message(STATUS "Found jansson library: ${JANSSON_LIBRARY}")
else (JANSSON_FOUND)
   message(STATUS "Could not find jansson library")
endif (JANSSON_FOUND)

MARK_AS_ADVANCED(
  UNIS_C_LIBRARY
  JANSSON_LIBRARY
  CURL_LIBRARY
  UNIS_C_FOUND
  JANSSON_FOUND
  CURL_FOUND
)

