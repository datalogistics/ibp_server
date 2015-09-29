# -*- cmake -*-

# - Find Apache Portable Runtime
# Find the APR includes and libraries
# This module defines
#  APR_INCLUDE_DIR and APRUTIL_INCLUDE_DIR, where to find apr.h, etc.
#  APR_LIBRARIES and APRUTIL_LIBRARIES, the libraries needed to use APR.
#  APR_FOUND and APRUTIL_FOUND, If false, do not try to use APR.
# also defined, but not for general use are
#  APR_LIBRARY and APRUTIL_LIBRARY, where to find the APR library.
#  APR_FLAGS, the flags to use to compile.

# APR first.

# Find the *relative* include path
# find_path(apr_inc apr-1/apr.h)

# Now convert it to the full path
# if (apr_inc)     
#   find_path(APR_INCLUDE_DIR apr.h ${apr_inc}/apr-1 )
# else (apr_inc)
#   find_path(APR_INCLUDE_DIR apr.h)
# endif (apr_inc)

# FIND_LIBRARY(APR_LIBRARY NAMES apr-1)
# changes made to support debian distributions
FIND_PATH(APR_INCLUDE_DIR apr.h
          /usr/local/include/apr-1
          /usr/local/include/apr-1.0
          /usr/include/apr-1
          /usr/include/apr-1.0
          )

SET(APR_NAMES ${APR_NAMES} apr-1)
    FIND_LIBRARY(APR_LIBRARY
    NAMES ${APR_NAMES}
    PATHS /usr/lib /usr/local/lib
    )

IF (APR_LIBRARY AND APR_INCLUDE_DIR)
    SET(APR_LIBRARIES ${APR_LIBRARY})
    SET(APR_FOUND "YES")
ELSE (APR_LIBRARY AND APR_INCLUDE_DIR)
  SET(APR_FOUND "NO")
ENDIF (APR_LIBRARY AND APR_INCLUDE_DIR)


IF (APR_FOUND)
   IF (NOT APR_FIND_QUIETLY)
      MESSAGE(STATUS "Found APR: ${APR_LIBRARIES} ${APR_INCLUDE_DIR}")
   ENDIF (NOT APR_FIND_QUIETLY)
   
   FIND_PROGRAM(APR_CONFIG_EXECUTABLE
      apr-1-config
      /usr/local/bin
      /usr/bin
   )
   MARK_AS_ADVANCED(APR_CONFIG_EXECUTABLE)
   MACRO(_APR_INVOKE _VARNAME _REGEXP)
      EXECUTE_PROCESS(
          COMMAND ${APR_CONFIG_EXECUTABLE} ${ARGN}
          OUTPUT_VARIABLE _APR_OUTPUT
          RESULT_VARIABLE _APR_FAILED     
      )
   
      IF (_APR_FAILED)
         MESSAGE(FATAL_ERROR "${APR_CONFIG_EXECUTABLE} ${ARGN} failed")
      ELSE (_APR_FAILED)
         STRING(REGEX REPLACE "[\r\n]" "" _APR_OUTPUT "${_APR_OUTPUT}")
         STRING(REGEX REPLACE " +$"    "" _APR_OUTPUT "${_APR_OUTPUT}")

         IF (NOT ${_REGEXP} STREQUAL "")
            STRING(REGEX REPLACE "${_REGEXP}" " " _APR_OUTPUT "${_APR_OUTPUT}")
         ENDIF (NOT ${_REGEXP} STREQUAL "")
         
         IF (NOT ${_VARNAME} STREQUAL "APR_FLAGS")
            SEPARATE_ARGUMENTS(_APR_OUTPUT)
         ENDIF (NOT ${_VARNAME} STREQUAL "APR_FLAGS")

         SET(${_VARNAME} "${_APR_OUTPUT}")
      ENDIF (_APR_FAILED)
   ENDMACRO(_APR_INVOKE)

   _APR_INVOKE(APR_FLAGS "" --cppflags --cflags)
ELSE (APR_FOUND)
   IF (APR_FIND_REQUIRED)
      MESSAGE(FATAL_ERROR "Could not find APR library")
   ENDIF (APR_FIND_REQUIRED)
ENDIF (APR_FOUND)

# Deprecated declarations.
SET(NATIVE_APR_INCLUDE_PATH ${APR_INCLUDE_DIR} )
GET_FILENAME_COMPONENT(NATIVE_APR_LIB_PATH ${APR_LIBRARY} PATH)

MARK_AS_ADVANCED(
  APR_LIBRARY
  APR_INCLUDE_DIR
  )

