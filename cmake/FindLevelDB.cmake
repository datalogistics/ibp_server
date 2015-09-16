# -*- cmake -*-
 
# - Find LevelDB
# Find the LevelDB includes and library
# This module defines
# LEVELDB_INCLUDE_DIR, where to find db.h, etc.
# LEVELDB_LIBRARIES, the libraries needed to use LevelDB.
# LEVELDB_FOUND, If false, do not try to use LevelDB.
# also defined, but not for general use are
# LEVELDB_LIBRARY, where to find the LevelDB library.

find_path(LEVELDB_INCLUDE_DIR
    NAMES leveldb/c.h
    HINTS ${LEVELDB_ROOT_DIR}/include)
 
find_library(LEVELDB_LIBRARIES
    NAMES leveldb
    HINTS ${LEVELDB_ROOT_DIR}/lib64)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(leveldb DEFAULT_MSG
    LEVELDB_LIBRARIES
    LEVELDB_INCLUDE_DIR)
 
mark_as_advanced(
  LEVELDB_ROOT_DIR
  LEVELDB_LIBRARIES
  LEVELDB_INCLUDE_DIR
  )
 
