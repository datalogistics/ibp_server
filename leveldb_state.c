#include <leveldb/c.h>
#include <stdlib.h>
#include "osd_leveldb.h"
#include "log.h"

// Serializes access to a single file
leveldb_state_t * leveldb_state_create(leveldb_fs_t * fs,
                                       osd_id_t id) {
    leveldb_state_t * self = malloc(sizeof(leveldb_state_t));
    memset(self, 0, sizeof(leveldb_state_t));
    self->range = leveldb_range_create();
    if (!self->range) { goto cleanup; }
    self->fs = fs;
    self->id = id;
    self->range_bak = self->range;
    if (apr_thread_mutex_create(&(self->lock), APR_THREAD_MUTEX_DEFAULT, 
                            fs->pool) != APR_SUCCESS) {
        goto cleanup2;
    }
    leveldb_state_replay(self);
    return self;
cleanup2:
    free(self->range);
cleanup:
    free(self);
    return NULL;
}
void leveldb_state_destroy(leveldb_state_t * val) {
    assert(val->range == val->range_bak);
    apr_thread_mutex_destroy(val->lock);
    leveldb_range_destroy(val->range);
    free(val);
}

osd_off_t leveldb_state_get_size(leveldb_state_t * s) {
    osd_off_t size;
    apr_thread_mutex_lock(s->lock);
    if (s->range->head) {
        size = (s->range->tail->right - s->range->head->left);
    } else {
        size = 0;
    }
    apr_thread_mutex_unlock(s->lock);
    return size;
}

int leveldb_state_exists(leveldb_state_t * s, osd_off_t off, osd_off_t len) {
    int retval;
    apr_thread_mutex_lock(s->lock);
    if (s->range->initialized) {
        retval = 1;
    } else {
        retval = 0;
    }
    apr_thread_mutex_unlock(s->lock);
    return retval;
}


leveldb_range_t * leveldb_state_read(leveldb_state_t * s, osd_off_t off, osd_off_t len) {
    apr_thread_mutex_lock(s->lock);
    assert(s->range = s->range_bak);
    leveldb_range_t * range = leveldb_range_search(s->range, off, len);
    leveldb_range_validate(range);
    apr_thread_mutex_unlock(s->lock);
    return range;
}
void printfkey(const char * key, size_t len) {
    size_t i;
    for (i = 0; i < len; ++i) printf("%02x", (unsigned char) key[i]);
}

int leveldb_state_replay(leveldb_state_t * s) {
    // Top level function to replay all log entries from the DB to in-memory
    // storage
    leveldb_key_t start_key;
    start_key.id = s->id;
    start_key.flags = LEVELDB_INDEX_FLAG;
    start_key.counter = 0;
    leveldb_key_serialized_t start_blob = leveldb_fs_serialize_key(start_key);
    log_printf(0, "Replaying log beginning for %lld\n", s->id);
    //if (s->range == NULL) {
        //leveldb_range_destroy(s->range);
    //    s->range = leveldb_range_create();
    //}
    leveldb_iterator_t* iter = leveldb_create_iterator(s->fs->db, s->fs->roptions);
    printf("start: ");printfkey(start_blob.buffer, start_blob.length);printf("\n");
    /*
    leveldb_iter_seek_to_first(iter);
    for ( ;leveldb_iter_valid(iter);leveldb_iter_next(iter)) {
        size_t key_len;
        const char * key = leveldb_iter_key(iter, &key_len);
        printf(" 1key: ");printfkey(key, key_len);printf("\n");
    }*/
    leveldb_iter_seek(iter, start_blob.buffer, start_blob.length);
    for ( ;leveldb_iter_valid(iter);leveldb_iter_next(iter)) {
        size_t key_len;
        const char * key = leveldb_iter_key(iter, &key_len);
        leveldb_key_t current_key = leveldb_fs_deserialize_key(key, key_len);
        if ((current_key.flags != LEVELDB_INDEX_FLAG) ||
            (current_key.id != s->id)) {
            // Not looking at the right guy anymore
            break;
        }
        size_t val_len;
        const char * val = leveldb_iter_value(iter, &val_len);
        leveldb_command_t * cmd = leveldb_state_string_to_command(val, val_len);
        if (!cmd || leveldb_state_load_message(s, cmd, 0)) {
            if (cmd) { leveldb_command_destroy(cmd); }
            log_printf(0, "Failed to replay log for %lld\n", s->id);
            printf("Failed to replay log for %lld\n", s->id);
            leveldb_iter_destroy(iter);
            return 1;
        }
        leveldb_command_destroy(cmd);
    }
    log_printf(0, "Replaying log complete for %lld\n", s->id);
    leveldb_iter_destroy(iter);
    return 0;
}
/* 
 * To perform a mutating operation against an allocation, two steps need to be
 * performed. a) The in-memory leveldb_range_t for the object needs to be
 * modified. b) A log message needs to be committed to permenant storage [1].
 *
 * There are two paths to mutating an allocation: 1) command from the above
 * IBP layers 2) replaying a log from disk to get the in-memory structure
 * up-to-date. The difference between (1) and (2) is that (1) generates the
 * command structures using arguments from above and (2) deserializes log
 * entries from the logfile. Both shunt their commands to 
 * leveldb_state_load_message
 *
 * 1) leveldb_state_write  \
 *                          >- leveldb_state_load_message(cmd)
 * 2) leveldb_state_replay /
 *
 * [1] - leveldb provides the same guarantees as write() for durability. If
 *       the process itself dies after the write, the OS will eventually sync
 *       the contents to disk. Only in the case of the whole machine dying
 *       will there be missing entries in the log. Leveldb-provided
 *       checksumming ensures the log merely has missing entries, it is not
 *       corrupt
 */

// leveldb_state_write - 0 on sucess 
int leveldb_state_write(leveldb_state_t * s, osd_off_t off, 
                              osd_off_t len, osd_off_t buffer_left,
                              char * buffer_key, size_t buffer_key_len) {
    leveldb_command_t * cmd = leveldb_command_create();
    cmd->off = off;
    cmd->len = len;
    cmd->buffer_left = buffer_left;
    cmd->buffer_key = buffer_key;
    cmd->buffer_key_len = buffer_key_len;
    cmd->command = LEVELDB_WRITE_MSG;
    int ret = leveldb_state_load_message(s, cmd, 1);
    // We don't own the buffer, keep us from destroying
    cmd->buffer_key_len = 0;
    cmd->buffer_key = NULL;
    leveldb_command_destroy(cmd);
    return ret;
}

void leveldb_state_truncate(leveldb_state_t * s, osd_off_t len) {
    leveldb_command_t * cmd = leveldb_command_create();
    cmd->len = len;
    cmd->command = LEVELDB_TRUNCATE_MSG;
    int ret = leveldb_state_load_message(s, cmd, 1);
    leveldb_command_destroy(cmd);
}
// Commit one message to the log - 0 on success
int leveldb_state_load_message(leveldb_state_t *s,
                                     leveldb_command_t * cmd,
                                     int log_commit) {
    //printf( LU ": cmd: %d len: " I64T "off: " I64T "\n", s->id, cmd->command,cmd->len, cmd->off);
    int retval = 0;
    char * cmd_string;
    size_t cmd_len;
    leveldb_rangeelem_t * range = NULL;
    leveldb_key_t key;
    memset(&key, 0, sizeof(leveldb_key_t));
    key.id = s->id;  
    if (log_commit) {
        cmd->time = apr_time_now();
        cmd_string = leveldb_state_command_to_string(cmd, &cmd_len);
        if (!cmd_string) { return 1; }
    }
    apr_thread_mutex_lock(s->lock);
    leveldb_range_validate(s->range);
    // Interesting concurrency/durability question: Do I want to write to the
    // in-memory range structure, then unlock and write into the database? The
    // persistence counter is acquired from within the lock, so assuming
    // everything goes well, the writes will still be ordered properly, but it
    // could somehow be possible a later write to succeed and the process die
    // before the current write is persisted to disk, leaving things somewhat
    // inconsistent. Is that something I care about? Hm.
    switch (cmd->command) {
        case LEVELDB_WRITE_MSG:
            s->range->initialized = 1;
            assert(s->range = s->range_bak);
            range = leveldb_range_insert(s->range, cmd->off,
                                                    cmd->off + cmd->len - 1,
                                                    cmd->buffer_left,
                                                    cmd->buffer_key,
                                                    cmd->buffer_key_len);
            assert(s->range = s->range_bak);
            leveldb_range_validate(s->range);
            if (!range) {
                retval = 1;
            }
            if (s->cache) {
                s->cache->mtime = cmd->time;
            }
            key.flags = LEVELDB_INDEX_FLAG;
            break;
        case LEVELDB_INIT_MSG:
            s->range->initialized = 1;
            s->file_state = LEVELDB_TRASH_NOTTRASH;
            key.flags = LEVELDB_INDEX_FLAG;
            s->cache = leveldb_fs_cache_allocation_state(s->fs, s->id, LEVELDB_TRASH_NOTTRASH, cmd->time);
            break;
        case LEVELDB_TRUNCATE_MSG:
            leveldb_range_truncate(s->range, cmd->len);
            key.flags = LEVELDB_INDEX_FLAG;
            break;
        case LEVELDB_SETSTATE_MSG:
            key.flags = LEVELDB_INDEX_FLAG;
            s->cache = leveldb_fs_cache_allocation_state(s->fs, s->id, cmd->state, cmd->time);
            s->file_state = cmd->state; 
            break;
        default:
            apr_thread_mutex_unlock(s->lock);
            return 2;
    }
    leveldb_range_validate(s->range);
    if (retval) {
        // Couldn't apply the value to the in-memory database
        apr_thread_mutex_unlock(s->lock);
        return retval;
    }
    if (log_commit) {
        key.counter = leveldb_fs_get_counter(s->fs);
        leveldb_key_serialized_t key_buf = leveldb_fs_serialize_key(key);
        retval = leveldb_state_append_to_log(s, &key_buf, cmd_string, cmd_len);
        log_printf(0,"Committing id: %lld counter %lld\n", key.id, key.counter);
        free(cmd_string);
    }
    apr_thread_mutex_unlock(s->lock);
    return 0;
}

int leveldb_state_append_to_log(leveldb_state_t *s,
                                leveldb_key_serialized_t * key,
                                char * val, size_t val_len) {
    if (!val || !val_len) {
        log_printf(0, "ERROR: Blank val passed along\n");
        return 1;
    }
    char * errstr = NULL;
    //printf("Insert key: ");printfkey(key->buffer, key->length);printf("\n");
    leveldb_put(s->fs->db, s->fs->woptions, key->buffer, key->length, 
                                            val, val_len, &errstr);
    if (errstr) {
        log_printf(0, "ERROR: %s\n", errstr);
        return 2;
    }
    return 0;
}

char * leveldb_state_command_to_string(leveldb_command_t * cmd, 
                                            size_t * len) {
    assert(strncmp("MaGiC", cmd->magic, sizeof(cmd->magic)) == 0);
    size_t struct_len = sizeof(unsigned char) + sizeof(leveldb_command_t);
    if (cmd->buffer_key && cmd->buffer_key_len) {
        struct_len += cmd->buffer_key_len;
    }
    char * buf = malloc(struct_len);
    if (!buf) { return NULL; }
    unsigned char version = LEVELDB_COMMAND_VERSION; 
    memcpy(buf, &version, sizeof(unsigned char));
    memcpy(buf + sizeof(unsigned char), cmd, sizeof(leveldb_command_t));
    if ((cmd->buffer_key_len != 0) && cmd->buffer_key) {
        memcpy(buf + sizeof(unsigned char) + sizeof(leveldb_command_t),
                cmd->buffer_key,
                cmd->buffer_key_len);
    }
    *len = struct_len;
    return buf;
}

leveldb_command_t * leveldb_state_string_to_command(const char * cmd,
                                                    size_t len) {
    if (!len || !cmd) { return NULL; }
    if (len < sizeof(unsigned char) + sizeof(leveldb_command_t)) {
        log_printf(0, "Wrong length command received %lld < (%lld + %lld)\n", len, sizeof(unsigned char), sizeof(leveldb_command_t));
        return NULL;
    }
    leveldb_command_t * ret = leveldb_command_create();
    if (!ret) { return NULL; }
    unsigned char version;
    memcpy((void *) &version, cmd, sizeof(unsigned char));
    memcpy((void *) ret, cmd + sizeof(unsigned char),
                        sizeof(leveldb_command_t));
    if (!ret->buffer_key_len) {
        return ret;
    }
    ret->buffer_key = malloc(ret->buffer_key_len);
    if (!ret->buffer_key) {
        free(ret);
        return NULL;
    }
    memcpy((void *) ret->buffer_key,
                cmd + sizeof(unsigned char) + sizeof(leveldb_command_t),
                ret->buffer_key_len);
    assert(strcmp("MaGiC", ret->magic) == 0);
    return ret;
}
leveldb_command_t * leveldb_command_create() {
    leveldb_command_t * ret = malloc(sizeof(leveldb_command_t));
    if (!ret) { return NULL; }
    memset((void *) ret, 0, sizeof(leveldb_command_t));
    memcpy(ret->magic, "MaGiC", 6);
    ret->buffer_key = NULL;
    return ret;
}
void leveldb_command_destroy(leveldb_command_t * cmd) {
    if ((cmd->buffer_key_len != 0) && (cmd->buffer_key != NULL)) {
        free(cmd->buffer_key);
    }
    free(cmd);
}

int leveldb_state_set_filestate(leveldb_state_t *s, int trash_type) {
    leveldb_command_t * cmd = leveldb_command_create();
    cmd->command = LEVELDB_SETSTATE_MSG;
    cmd->state = trash_type;
    int ret = leveldb_state_load_message(s, cmd, 1);
    leveldb_command_destroy(cmd);
    return ret;
}
int leveldb_state_get_filestate(leveldb_state_t *s) {
    apr_thread_mutex_lock(s->lock);
    int ret = s->file_state;
    apr_thread_mutex_unlock(s->lock);
    return ret;
}
