# -*- cmake -*-
 
# - Find LevelDB
# Find the LevelDB includes and library
# This module defines
# LEVELDB_INCLUDE_DIR, where to find db.h, etc.
# LEVELDB_LIBRARIES, the libraries needed to use LevelDB.
# LEVELDB_FOUND, If false, do not try to use LevelDB.
# also defined, but not for general use are
# LEVELDB_LIBRARY, where to find the LevelDB library.
 
find_path(LEVELDB_INCLUDE_DIR leveldb/c.h PATHS
    leveldb/include
    NO_DEFAULT_PATH
    )
 
set(LEVELDB_NAME leveldb)
find_library(LEVELDB_LIBRARY NAMES libleveldb.a PATHS
    leveldb/
    NO_DEFAULT_PATH
    )
 
if (LEVELDB_LIBRARY AND LEVELDB_INCLUDE_DIR)
  set(LEVELDB_LIBRARIES ${LEVELDB_LIBRARY})
  set(LEVELDB_FOUND "YES")
  message(STATUS "Found LevelDB: ${LEVELDB_LIBRARY} ${LEVELDB_INCLUDE_DIR}")
else (LEVELDB_LIBRARY AND LEVELDB_INCLUDE_DIR)
  set(LEVELDB_FOUND "NO")
  message(STATUS "Could not find LevelDB")
endif (LEVELDB_LIBRARY AND LEVELDB_INCLUDE_DIR)
 
mark_as_advanced(
  LEVELDB_LIBRARY
  LEVELDB_INCLUDE_DIR
  )
 
