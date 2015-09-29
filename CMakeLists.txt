# make a project
project( IBP_SERVER C CXX )

# User changes should go here
#----------------------------------------
OPTION(CMAKE_BUILD_TYPE "What type of build to generate (Debug/Release)" Debug)
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_REQUIRED_FLAGS} -O0 -Wall -g -D_ENABLE_DEBUG -DHAVE_CONFIG_H -DLINUX=2 -D_REENTRANT -D_GNU_SOURCE -D_LARGEFILE64_SOURCE" )
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_REQUIRED_FLAGS} -O -DHAVE_CONFIG_H -DLINUX=2 -D_REENTRANT -D_GNU_SOURCE -D_LARGEFILE64_SOURCE" )
#----------------------------------------

cmake_minimum_required(VERSION 2.6)

set(CMAKE_INCLUDE_CURRENT_DIR "on")
if ( "${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
  set(CMAKE_VERBOSE_MAKEFILE "on")
endif ( "${CMAKE_BUILD_TYPE}" STREQUAL "Debug")

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)
INCLUDE(CheckIncludeFile)
include(${CMAKE_SOURCE_DIR}/cmake/Date.cmake)
include(${CMAKE_SOURCE_DIR}/cmake/CompilerVersion.cmake)
include(${CMAKE_SOURCE_DIR}/cmake/CompilerFlags.cmake)

# Prefer to use static libraries
if(WIN32)
 set(CMAKE_FIND_LIBRARY_SUFFIXES .lib .a ${CMAKE_FIND_LIBRARY_SUFFIXES})
else(WIN32)
 set(CMAKE_FIND_LIBRARY_SUFFIXES .a ${CMAKE_FIND_LIBRARY_SUFFIXES})
endif(WIN32)

# Get required dependancies
find_package(BerkeleyDB REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(APR REQUIRED)
find_package(APRUtil REQUIRED)
include_directories(${BDB_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR}
                    ${APR_INCLUDE_DIR} ${APRUTIL_INCLUDE_DIR})
list(APPEND LIBS ${BDB_LIBRARIES}  ${OPENSSL_LIBRARIES}
     ${CRYPTO_LIBRARIES} ${PROTOBUF_LIBRARY}  ${APRUTIL_LIBRARY} 
     ${APR_LIBRARY} rt pthread dl m z)
if (APPLE)
    list(REMOVE_ITEM LIBS rt)
endif (APPLE)

if (CMAKE_SYSTEM_NAME MATCHES "Linux")
if (CMAKE_SYSTEM_PROCESSOR MATCHES "^i[3-9]86$")
    add_definitions(${APR_CONFIG_EXECUTABLE} ${APR_FLAGS})
endif (CMAKE_SYSTEM_PROCESSOR MATCHES "^i[3-9]86$")
endif (CMAKE_SYSTEM_NAME MATCHES "Linux")

# Try finding optional dependencies
find_package(Phoebus)
find_package(Unisc)
find_package(LevelDB)
find_package(Snappy)
OPTION( _ENABLE_LEVELDB "Enable LevelDB support" ${LEVELDB_FOUND} )
OPTION( _ENABLE_PHOEBUS "Enable PHOEBUS support" ${PHOEBUS_FOUND} )
OPTION( _ENABLE_UNIS_C "Enable UNIS support" ${UNIS_C_FOUND} )
if (NOT LEVELDB_FOUND AND _ENABLE_LEVELDB)
    message(FATAL_ERROR "LevelDB requested but not found. We can't use the "
                        "LevelDB provided by Google, you must install the "
                        "in-tree version by executing:\ngit submodule init\n"
                        "git submodule update\ncd leveldb\nmake"
                        )
endif  (NOT LEVELDB_FOUND AND _ENABLE_LEVELDB)
if (NOT PHOEBUS_FOUND AND _ENABLE_PHOEBUS)
    message(FATAL_ERROR "Phoebus requested but not found")
endif (NOT PHOEBUS_FOUND AND _ENABLE_PHOEBUS)
if (NOT UNIS_C_FOUND AND _ENABLE_UNIS_C)
    message(FATAL_ERROR "Unis requested but not found")
endif (NOT UNIS_C_FOUND AND _ENABLE_UNIS_C)

# Check for OS support
check_include_file("stdint.h" HAVE_STDINT_H)
check_include_file("inttypes.h" HAVE_INTTYPES_H)

# Configure LevelDB
if (_ENABLE_LEVELDB)
    add_definitions(-D_ENABLE_LEVELDB)
    include_directories(${LEVELDB_INCLUDE_DIR})
    list(APPEND LIBS ${LEVELDB_LIBRARIES})
    if (SNAPPY_FOUND)
        list(APPEND LIBS ${SNAPPY_LIBRARIES})
    endif (SNAPPY_FOUND)
    if (APPLE)
        list(INSERT LIBS 0 -lc++)
        SET( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -mmacosx-version-min=10.8 " )
    endif (APPLE)
endif (_ENABLE_LEVELDB)

# config options
if (_ENABLE_PHOEBUS)
  add_definitions(-D_ENABLE_PHOEBUS)
  include_directories(${PHOEBUS_INCLUDE_DIR})
  list(APPEND LIBS ${PHOEBUS_LIBRARY})
endif (_ENABLE_PHOEBUS)

# Check if we found unis lib c and the set options
if (_ENABLE_UNIS_C)
  add_definitions(-D_ENABLE_UNIS_C)
  include_directories(${UNIS_C_INCLUDE_DIR})
  list(APPEND LIBS ${UNIS_C_LIBRARY} curl jansson)
endif (_ENABLE_UNIS_C)

CONFIGURE_FILE( ${CMAKE_SOURCE_DIR}/config.h.in ${CMAKE_SOURCE_DIR}/config.h )

#Make the version file
set(IBP_SERVER_VERSION "ibp_server(no FIFO): v1.6.8")
site_name(BUILD_HOST)
Date(BUILD_DATE)
CompilerVersion(COMPILER_VERSION)
CompilerFlags(COMPILER_FLAGS)
configure_file("${PROJECT_SOURCE_DIR}/server_version.c.in" "${PROJECT_BINARY_DIR}/server_version.c")

# common objects
SET(RESOURCE_OBJS resource.c alloc_history.c cap_timestamp.c random.c osd_fs.c
                  db_resource.c log.c atomic_counter.c debug.c rid.c 
                  pigeon_hole.c pigeon_coop.c )
SET(NETWORK_OBJS network.c net_sock.c net_1_ssl.c net_2_ssl.c net_fd.c 
                 net_phoebus.c phoebus.c chksum.c )
set(STRING_OBJS string_token.c append_printf.c iniparse.c statsd-client.c)
SET(COMMON_OBJS stack.c dns_cache.c log.c atomic_counter.c dns_cache.c
                cmd_send.c subnet.c )
if (LEVELDB_FOUND)
    list(APPEND RESOURCE_OBJS leveldb_fd.c leveldb_fs.c leveldb_range.c leveldb_state.c osd_leveldb.c leveldb_iterator.c)
endif (LEVELDB_FOUND)

# various executables
ADD_EXECUTABLE(ibp_server ibp_server.c server_lib.c  global_data.c
   parse_commands.c install_commands.c commands.c
   handle_commands.c resource_list.c subnet.c stack.c
   buffer_transfer.c dns_cache.c transfer_stats.c register_unis.c
   server_version.c lock_alloc.c activity_log.c thread_slots.c envelope.c
   envelope_net ${STRING_OBJS} ${RESOURCE_OBJS} ${NETWORK_OBJS} ${PROTO_SRC})

ADD_EXECUTABLE(mkfs.resource mkfs_resource.c chksum.c network.c net_sock.c
    ${COMMON_OBJS} ${STRING_OBJS} ${RESOURCE_OBJS})
ADD_EXECUTABLE(get_corrupt get_corrupt.c
    cmd_send.c ${COMMON_OBJS} ${STRING_OBJS} ${NETWORK_OBJS})
ADD_EXECUTABLE(get_config get_config.c cmd_send.c ${COMMON_OBJS}
    ${STRING_OBJS} ${NETWORK_OBJS})
ADD_EXECUTABLE(get_version get_version.c
    cmd_send.c ${COMMON_OBJS} ${STRING_OBJS} ${NETWORK_OBJS})
ADD_EXECUTABLE(get_alloc get_alloc.c print_alloc.c cmd_send.c ${COMMON_OBJS}
    ${STRING_OBJS} ${NETWORK_OBJS})
ADD_EXECUTABLE(read_alloc read_alloc.c
    print_alloc.c ${COMMON_OBJS} ${STRING_OBJS} ${NETWORK_OBJS}
    ${RESOURCE_OBJS})
ADD_EXECUTABLE(get_rid_status get_rid_status.c stack.c
    dns_cache.c subnet.c print_alloc.c ${STRING_OBJS} ${NETWORK_OBJS}
    ${RESOURCE_OBJS})
ADD_EXECUTABLE(repair_history repair_history.c stack.c
    dns_cache.c subnet.c print_alloc.c ${STRING_OBJS} ${NETWORK_OBJS}
    ${RESOURCE_OBJS})
ADD_EXECUTABLE(date_spacefree date_spacefree.c log.c
    atomic_counter.c stack.c dns_cache.c cmd_send.c ${STRING_OBJS}
    ${NETWORK_OBJS})
ADD_EXECUTABLE(expire_list expire_list.c log.c
    atomic_counter.c stack.c dns_cache.c cmd_send.c ${STRING_OBJS}
    ${NETWORK_OBJS})
ADD_EXECUTABLE(print_alog print_alog.c activity_log.c
    subnet.c dns_cache.c stack.c ${PROTO_SRC} ${NETWORK_OBJS} envelope.c
    envelope_net.c ${STRING_OBJS} resource_list.c ${RESOURCE_OBJS} )
ADD_EXECUTABLE(ibp_rescan ibp_rescan.c log.c atomic_counter.c stack.c
    dns_cache.c cmd_send.c ${STRING_OBJS} ${NETWORK_OBJS})
ADD_EXECUTABLE(ibp_undelete ibp_undelete.c log.c atomic_counter.c stack.c
    dns_cache.c cmd_send.c ${STRING_OBJS} ${NETWORK_OBJS})
ADD_EXECUTABLE(ibp_detach_rid ibp_detach_rid.c log.c atomic_counter.c stack.c
    dns_cache.c cmd_send.c ${STRING_OBJS} ${NETWORK_OBJS})
ADD_EXECUTABLE(ibp_attach_rid ibp_attach_rid.c log.c atomic_counter.c stack.c
    dns_cache.c cmd_send.c ${STRING_OBJS} ${NETWORK_OBJS})
ADD_EXECUTABLE(ibp_rid_mode ibp_rid_mode.c log.c atomic_counter.c stack.c
    dns_cache.c cmd_send.c ${STRING_OBJS} ${NETWORK_OBJS})
ADD_EXECUTABLE(chksum_test chksum_test.c chksum.c)

if (LEVELDB_FOUND)
    ADD_EXECUTABLE(testing_leveldb testing_leveldb.c log.c cmd_send.c
        ${COMMON_OBJS} ${RESOURCE_OBJS} ${STRING_OBJS} ${NETWORK_OBJS})
endif (LEVELDB_FOUND)

TARGET_LINK_LIBRARIES( ibp_server ${LIBS})
TARGET_LINK_LIBRARIES( mkfs.resource ${LIBS})
TARGET_LINK_LIBRARIES( get_corrupt ${LIBS})
TARGET_LINK_LIBRARIES( get_config ${LIBS})
TARGET_LINK_LIBRARIES( get_version ${LIBS})
TARGET_LINK_LIBRARIES( get_rid_status ${LIBS})
TARGET_LINK_LIBRARIES( get_alloc ${LIBS})
TARGET_LINK_LIBRARIES( read_alloc ${LIBS})
TARGET_LINK_LIBRARIES( repair_history ${LIBS})
TARGET_LINK_LIBRARIES( date_spacefree ${LIBS})
TARGET_LINK_LIBRARIES( expire_list ${LIBS})
TARGET_LINK_LIBRARIES( print_alog ${LIBS})
TARGET_LINK_LIBRARIES( ibp_rescan ${LIBS})
TARGET_LINK_LIBRARIES( ibp_detach_rid ${LIBS})
TARGET_LINK_LIBRARIES( ibp_attach_rid ${LIBS})
TARGET_LINK_LIBRARIES( ibp_rid_mode ${LIBS})
TARGET_LINK_LIBRARIES( ibp_undelete ${LIBS})
TARGET_LINK_LIBRARIES( chksum_test ${OPENSSL_LIBRARIES} ${CRYPTO_LIBRARIES})
if (LEVELDB_FOUND)
    TARGET_LINK_LIBRARIES( testing_leveldb ${LIBS})
endif (LEVELDB_FOUND)

set(ALL_TARGETS  chksum_test date_spacefree expire_list get_alloc get_config 
                 get_corrupt get_version get_rid_status ibp_attach_rid ibp_detach_rid
                 ibp_rescan ibp_rid_mode ibp_server ibp_undelete mkfs.resource
                 print_alog read_alloc repair_history )

if (LEVELDB_FOUND)
    # leveldb is a c++ library, so we need to link properly
    LIST(APPEND ALL_TARGETS testing_leveldb)
    SET_TARGET_PROPERTIES(${ALL_TARGETS} PROPERTIES LINKER_LANGUAGE CXX)
endif (LEVELDB_FOUND)

install(TARGETS ${ALL_TARGETS} DESTINATION bin)
install(FILES misc/ibp.cfg DESTINATION etc)
install(FILES misc/ibp-server DESTINATION etc/init.d)

