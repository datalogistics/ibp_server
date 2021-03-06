# -*- cmake -*-

# - Find Phoebus libraries and includes
#
# This module defines
#    PHOEBUS_INCLUDE_DIR - where to find libxsp_client.h
#    PHOEBUS_LIBRARIES - the libraries needed to use Phoebus.
#    PHOEBUS_FOUND - If false didn't find phoebus

# Find the include path

find_path(PHOEBUS_INCLUDE_DIR libxsp_client.h)

set(APR_NAMES ${APR_NAMES} apr-1)
find_library(PHOEBUS_LIBRARY NAMES xsp_client dl)

if (PHOEBUS_LIBRARY AND PHOEBUS_INCLUDE_DIR)
    SET(PHOEBUS_FOUND "YES")
#else (PHOEBUS_LIBRARY AND PHOEBUS_INCLUDE_DIR)
#   set(PHOEBUS_FOUND "NO")
endif (PHOEBUS_LIBRARY AND PHOEBUS_INCLUDE_DIR)


if (PHOEBUS_FOUND)
   message(STATUS "Found Phoebus: ${PHOEBUS_LIBRARY}")
else (PHOEBUS_FOUND)
   message(STATUS "Could not find Phoebus library")
endif (PHOEBUS_FOUND)


MARK_AS_ADVANCED(
  PHOEBUS_LIBRARY
  PHOEBUS_INCLUDE_DIR
  PHOEBUS_FOUND
)

