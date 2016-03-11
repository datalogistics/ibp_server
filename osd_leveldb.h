//
// Top level include for leveldb IBP backend -
//          Andrew Melo <andrew.m.melo@vanderbilt.edu>
//
#include <apr_hash.h>
#include <arpa/inet.h>
#include <leveldb/c.h>
#include "osd_abstract.h"
#ifndef IBP_OSD_LEVELDB_INCLUDE
#define IBP_OSD_LEVELDB_INCLUDE 1
//
// Macros
//

#define CheckNoError(err)                                               \
  if ((err) != NULL) {                                                  \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, (err)); \
    abort();                                                            \
  }

// Defines for munging 64 bit ints into big-endian. Want it this way to get
// our ints to sort right when sorted lexicographically
#ifndef htonll
#define htonll(x) ((1==htonl(1)) ? (x) : ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#endif
#ifndef ntohll
#define ntohll(x) ((1==ntohl(1)) ? (x) : ((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))
#endif
// Top 8 bits of the ID are reserved for flags
#define LEVELDB_FLAG_BITMASK 0xFF00000000000000U
#define LEVELDB_INDEX_FLAG   (1 << 0)
#define LEVELDB_PAYLOAD_FLAG (1 << 1)

#define LEVELDB_INIT_MSG ((unsigned char) 1)
#define LEVELDB_WRITE_MSG ((unsigned char) 2)
#define LEVELDB_TRUNCATE_MSG ((unsigned char) 3)
#define LEVELDB_SETSTATE_MSG ((unsigned char) 4)

#define LEVELDB_COMMAND_VERSION 0

#define LEVELDB_TRASH_DELETE 0
#define LEVELDB_TRASH_EXPIRE 1 
#define LEVELDB_TRASH_PERMENANT 2
#define LEVELDB_TRASH_NOTTRASH 3
#define LEVELDB_TRASH_COUNT 4
//
// Structs
//

// A levelDB FS corresponds to a single RID
struct leveldb_fs_s {
    leveldb_t * db; // leveldb database object
    leveldb_options_t* options;
    leveldb_readoptions_t* roptions;
    leveldb_writeoptions_t* woptions;
    struct leveldb_fs_state_list_s * state_head;
    uint64_t counter;
    char * path;
    apr_pool_t * pool;
    apr_thread_mutex_t *id_lock;
    apr_thread_mutex_t *counter_lock;
    apr_thread_mutex_t *cache_lock;
    apr_hash_t * allocation_cache[LEVELDB_TRASH_COUNT];
};

// A levelDB FD corresponds to a single allocation within an FD
struct leveldb_fd_s {
    struct leveldb_fs_s * fs;
    osd_id_t id;
    struct leveldb_state_s * state;
};

// Each entry in the index log corresponds to the following:
struct leveldb_log_entry_s {
    unsigned char message_type;
    osd_off_t len;
    osd_off_t off;
    char * payload;
    size_t payload_len;
    struct leveldb_log_entry_s * prev;
    struct leveldb_log_entry_s * next;
};


struct leveldb_key_s {
    unsigned short flags;
    uint64_t id;
    uint64_t counter;
};
struct leveldb_key_serialized_s {
    char buffer[16];
    size_t length;
};

// Per-allocation singleton, handles serializing reads/writes
struct leveldb_state_s {
    struct leveldb_range_s * range;
    struct leveldb_fs_s * fs;
    int file_state;
    osd_id_t id;
    apr_thread_mutex_t *lock;
    struct leveldb_fs_cache_value_s * cache;
    struct leveldb_range_s * range_bak;
};

struct leveldb_range_s {
    char initialized;
    struct leveldb_rangeelem_s * head;
    struct leveldb_rangeelem_s * tail;
};
struct leveldb_rangeelem_s {
    osd_off_t left;
    osd_off_t right;
    osd_off_t buffer_left;
    char * buffer_key;
    size_t buffer_key_len;
    struct leveldb_rangeelem_s * next;
    struct leveldb_rangeelem_s * prev;
};

// WARNING: Changing this will break all existing databases
struct leveldb_command_s {
    char magic[6];
    osd_off_t off;
    osd_off_t len;
    osd_off_t buffer_left;
    size_t buffer_key_len;
    unsigned char command;
    int state;
    ibp_time_t time;
    char * buffer_key;
};

// Linked list storing current extant states for this resource
struct leveldb_fs_state_list_s {
    struct leveldb_state_s * state;
    unsigned int refs;
    struct leveldb_fs_state_list_s * next;
};

struct leveldb_fs_cache_value_s {
    apr_time_t mtime;
};
struct leveldb_fs_cache_iterator_s {
    apr_pool_t * pool;
    osd_id_t id;
    apr_hash_index_t * iter;
    apr_time_t mtime;
    struct leveldb_fs_s * fs;
};
typedef struct leveldb_command_s leveldb_command_t;
typedef struct leveldb_fd_s leveldb_fd_t;
typedef struct leveldb_fs_s leveldb_fs_t;
typedef struct leveldb_fs_cache_value_s leveldb_fs_cache_value_t;
typedef struct leveldb_fs_cache_iterator_s leveldb_fs_cache_iterator_t;
typedef struct leveldb_fs_state_list_s leveldb_fs_state_list_t;
typedef struct leveldb_key_s leveldb_key_t;
typedef struct leveldb_key_serialized_s leveldb_key_serialized_t;
typedef struct leveldb_range_s leveldb_range_t;
typedef struct leveldb_rangeelem_s leveldb_rangeelem_t;
typedef struct leveldb_state_s leveldb_state_t;
typedef struct leveldb_log_entry_s leveldb_log_entry_t;

//
// Forward declaratios
//

// osd_leveldb.c - entry point
osd_t *osd_mount_leveldb(const char *device);

// leveldb_fs.c
leveldb_fs_t * leveldb_fs_open(const char * fname);
void leveldb_fs_close(leveldb_fs_t * db);
uint64_t leveldb_fs_get_counter(leveldb_fs_t *db);
uint64_t leveldb_fs_get_max_counter(leveldb_fs_t *db);
leveldb_key_t leveldb_fs_deserialize_key(const char * key, size_t keylen);
leveldb_key_serialized_t leveldb_fs_serialize_key(leveldb_key_t);
leveldb_fd_t * leveldb_fs_file_open(leveldb_fs_t * fs, osd_id_t id);
int leveldb_fs_file_close(leveldb_fs_t * fs, leveldb_fd_t * fd);
leveldb_state_t * leveldb_fs_acquire_state(leveldb_fs_t * fs, osd_id_t id);
void leveldb_fs_release_state(leveldb_fs_t * fs, leveldb_state_t * state);
int leveldb_fs_id_exists(leveldb_fs_t * fs, osd_id_t id);
osd_id_t leveldb_fs_reserve_id(leveldb_fs_t * fs, osd_id_t id);
int leveldb_fs_remove(leveldb_fs_t * fs, osd_id_t id, int trash_type);
int leveldb_fs_unremove(leveldb_fs_t * fs, osd_id_t id);
leveldb_fs_cache_iterator_t *  leveldb_fs_cache_iterator_create(leveldb_fs_t * fs, int state);
void  leveldb_fs_cache_iterator_destroy(leveldb_fs_cache_iterator_t * iter);
leveldb_fs_cache_value_t * leveldb_fs_cache_allocation_state(leveldb_fs_t * fs, osd_id_t id, int state, apr_time_t when);
void  leveldb_fs_cache_iterator_next(leveldb_fs_t * fs, leveldb_fs_cache_iterator_t * iter);
int  leveldb_fs_cache_iterator_valid(leveldb_fs_cache_iterator_t * iter);


// leveldb_range.c
leveldb_range_t * leveldb_range_create();
leveldb_rangeelem_t * leveldb_rangeelem_create(osd_off_t left, osd_off_t right,
                                              osd_off_t buffer_left,
                                              char * buffer_key, size_t buffer_key_len); 
leveldb_rangeelem_t * leveldb_rangeelem_copy(leveldb_rangeelem_t * other);
void leveldb_rangeelem_destroy(leveldb_rangeelem_t * other);
void leveldb_range_destroy(leveldb_range_t * other);
leveldb_rangeelem_t * leveldb_range_insert(leveldb_range_t * r, osd_off_t left,
                                           osd_off_t right, osd_off_t buffer_left,
                                           char * buffer_key, size_t buffer_key_len);
leveldb_rangeelem_t * leveldb_position_search(leveldb_range_t * r, osd_off_t pos);
leveldb_range_t * leveldb_range_search(leveldb_range_t * r, osd_off_t pos, osd_off_t len);
void leveldb_range_truncate(leveldb_range_t *r, osd_off_t len);
int leveldb_range_validate(leveldb_range_t * r);
//leveldb_state_c
leveldb_state_t * leveldb_state_create(leveldb_fs_t * fs,
                                       osd_id_t id);
void leveldb_state_destroy(leveldb_state_t * val);
int leveldb_state_write(leveldb_state_t * s, osd_off_t off, 
                              osd_off_t len, osd_off_t buffer_left,
                              char * buffer_key, size_t buffer_key_len);
leveldb_range_t * leveldb_state_read(leveldb_state_t * s, 
                              osd_off_t off, osd_off_t len);
int leveldb_state_load_message(leveldb_state_t *s, 
                              leveldb_command_t * cmd,
                              int log_commit);
int leveldb_state_append_to_log(leveldb_state_t *s,
                                leveldb_key_serialized_t * key,
                                char * val, size_t val_len);
int leveldb_state_replay(leveldb_state_t *s);
char * leveldb_state_command_to_string(leveldb_command_t * cmd, 
                                            size_t * len);
leveldb_command_t * leveldb_state_string_to_command(const char * cmd,
                                                    size_t len);
leveldb_command_t * leveldb_command_create();
void leveldb_command_destroy(leveldb_command_t * cmd);
osd_off_t leveldb_state_get_size(leveldb_state_t * s);
int leveldb_state_set_filestate(leveldb_state_t *s, int trash_type);
int leveldb_state_get_filestate(leveldb_state_t *s);
void leveldb_state_truncate(leveldb_state_t *s, osd_off_t len);
// fd - file descriptors
osd_off_t leveldb_fd_read(leveldb_fd_t * fd, osd_off_t offset, osd_off_t len, buffer_t buffer);
osd_off_t leveldb_fd_write(leveldb_fd_t * fd, osd_off_t offset, osd_off_t len, buffer_t buffer); 
osd_off_t leveldb_fd_truncate(leveldb_fd_t * fd, osd_off_t len);
osd_off_t leveldb_fd_size(leveldb_fd_t * fd);
int leveldb_fd_remove(leveldb_fd_t * fd, int trash_type);
int leveldb_fd_unremove(leveldb_fd_t * fd);
leveldb_fd_t * leveldb_fd_create(leveldb_fs_t * fs, leveldb_state_t * state);
void leveldb_fd_destroy(leveldb_fd_t * fd);

// So named to avoid clashing with leveldb's iterator struct
struct leveldb_ibp_iter_s {
    leveldb_fs_t * fs;
    osd_id_t current_id;
    ibp_time_t current_mtime;
    int type;
    leveldb_iterator_t * iter; // from leveldb itself
};
typedef struct leveldb_ibp_iter_s leveldb_ibp_iter_t;
// iterator - iterates over bits of the resource
leveldb_ibp_iter_t * leveldb_iterator_create(leveldb_fs_t * fs, int type);
int leveldb_iterator_next(leveldb_ibp_iter_t * iter);
ibp_time_t leveldb_iterator_mtime(leveldb_ibp_iter_t * iter);
osd_id_t leveldb_iterator_id(leveldb_ibp_iter_t * iter);
void leveldb_iterator_destroy(leveldb_ibp_iter_t * iter);

#endif
