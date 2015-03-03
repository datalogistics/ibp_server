#include "log.h"
#include "osd_leveldb.h"
#include <leveldb/c.h>
#include <stdlib.h>
// iterator - iterates over bits of the resource
leveldb_ibp_iter_t * leveldb_iterator_create(leveldb_fs_t * fs, int type) {
    leveldb_ibp_iter_t * iter = malloc(sizeof(leveldb_ibp_iter_t));
    if (!iter) { return NULL; }
    iter->fs = fs;
    iter->current_id = 0;
    iter->type = type;
    // Not sure if taking a snapshot is truly necessary
    iter->iter = leveldb_create_iterator(fs->db, fs->roptions);
    leveldb_key_t input_key;
    input_key.flags = LEVELDB_INDEX_FLAG; 
    input_key.id = 1;
    input_key.counter = 0;
    leveldb_key_serialized_t serial = leveldb_fs_serialize_key(input_key);
    leveldb_iter_seek(iter->iter, serial.buffer, serial.length);
    return iter;
}
ibp_time_t leveldb_iterator_extract_mtime(leveldb_ibp_iter_t * iter) {
    size_t len;
    const char * cmd = leveldb_iter_value(iter->iter, &len);
    leveldb_command_t * cmd_struct = leveldb_state_string_to_command(cmd, len);
    ibp_time_t ret = cmd_struct->time;
    leveldb_command_destroy(cmd_struct);
    return ret;
}


int leveldb_iterator_next(leveldb_ibp_iter_t * iter) {
    char seeking_mtime = 0;
    osd_id_t last_id = iter->current_id;
    leveldb_key_t last_key;
    char got_value = 0;
    if (iter->type != LEVELDB_TRASH_NOTTRASH) {
        return 0;
    }
    while (leveldb_iter_valid(iter->iter)) {
        size_t key_len;
        const char * key_buf = leveldb_iter_key(iter->iter, &key_len);
        leveldb_key_t key = leveldb_fs_deserialize_key(key_buf, key_len);
        log_printf(0, "Iterating key %lld counter %lld flags %d\n", key.id, key.counter, key.flags);
        if (key.flags != LEVELDB_INDEX_FLAG) {
            break;
        }
        if ((!seeking_mtime) && (key.id == iter->current_id)) {
            // someone else came by and updated while we were away.
            //ast_key = key;
        }
        if ((seeking_mtime) && (key.id != iter->current_id)) {
            // found the last update
            log_printf(0, "Iterating key %lld\n", key.id);
            iter->current_mtime = leveldb_iterator_extract_mtime(iter);
            iter->current_id = key.id;   
            return 1;
        }
        if ((!seeking_mtime) && (key.id != iter->current_id)) {
            // got a new ID, start looking for the last update
            seeking_mtime = 1;
            last_key = key;
            last_id = key.id;
            iter->current_id = key.id;
            got_value = 1;
        }
        if ((seeking_mtime) && (key.id == iter->current_id)) {
            // keep on trucking
            last_key = key;
            last_id = key.id;
        }
        leveldb_iter_next(iter->iter);
    }
    if (got_value) {
        // back up one
        leveldb_key_serialized_t buf = leveldb_fs_serialize_key(last_key);
        leveldb_iter_seek(iter->iter, buf.buffer, buf.length);
        iter->current_id = last_id;
        iter->current_mtime = leveldb_iterator_extract_mtime(iter);
    }
    return 0;
}
ibp_time_t leveldb_iterator_mtime(leveldb_ibp_iter_t * iter) {
    return iter->current_mtime;
}

osd_id_t leveldb_iterator_id(leveldb_ibp_iter_t * iter) {
    return iter->current_id;
}
void leveldb_iterator_destroy(leveldb_ibp_iter_t * iter) {
    leveldb_iter_destroy(iter->iter);
    free(iter);
}
