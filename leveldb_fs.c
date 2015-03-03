//
// leveldb_fs_ * - implementation of a single leveldb resource; interface with
//                 IBP
//
#include <leveldb/c.h>
#include <stdlib.h>
#include "apr.h"
#include "log.h"
#include "osd_leveldb.h"
#include "random.h"
leveldb_fs_t * leveldb_fs_open(const char * fname) {
    leveldb_fs_t * db = malloc(sizeof(leveldb_fs_t));
    if (!db) { goto cleanup8; }
    memset(db, 0, sizeof(leveldb_fs_t));
    if (apr_pool_create(&(db->pool), NULL) != APR_SUCCESS) { goto cleanup7; }
    apr_thread_mutex_create(&(db->id_lock), APR_THREAD_MUTEX_DEFAULT, db->pool);
    apr_thread_mutex_create(&(db->cache_lock), APR_THREAD_MUTEX_DEFAULT, db->pool);
    if (!db->id_lock) { goto cleanup6; };
    apr_thread_mutex_create(&(db->counter_lock), APR_THREAD_MUTEX_DEFAULT, 
                                                                    db->pool);
    if (!db->counter_lock) { goto cleanup5; };
    db->options = leveldb_options_create();
    if (!db->options) { goto cleanup4; };
    leveldb_options_set_create_if_missing(db->options, 1);
    leveldb_options_set_write_buffer_size(db->options, 60 * 1024 * 1024);
    db->roptions = leveldb_readoptions_create();
    if (!db->roptions) { goto cleanup3; };
    db->woptions = leveldb_writeoptions_create();
    if (!db->woptions) { goto cleanup2; };
    char * errptr = NULL;
    db->db = leveldb_open(db->options, fname, &errptr);
    if (!db->db) { goto cleanup1; };
    db->counter = leveldb_fs_get_max_counter(db);
    if (db->counter == 0) {
        goto cleanup1;
    }
    db->path = strdup(fname);
    int i;
    for (i = 0; i < LEVELDB_TRASH_COUNT; ++i) {
        assert(db->allocation_cache[i] = apr_hash_make(db->pool));
    }
    log_printf(0, "Opened leveldb. Counter is at %lld, path: %s\n", db->counter, fname);
    return db;
cleanup1:
    log_printf(0,"Couldn't open database: %s\n", errptr);
    free(errptr);
    free(db->db);
cleanup2:
    free(db->woptions);
cleanup3:
    free(db->roptions);
cleanup4:
    free(db->options);
cleanup5:
    apr_thread_mutex_destroy(db->counter_lock);
cleanup6:
    apr_thread_mutex_destroy(db->id_lock);
cleanup7:
    apr_pool_destroy(db->pool);
cleanup8:
    free(db);
    return NULL;
}

void leveldb_fs_close(leveldb_fs_t * db) {
    leveldb_options_destroy(db->options);
    leveldb_readoptions_destroy(db->roptions);
    leveldb_writeoptions_destroy(db->woptions);
    leveldb_close(db->db);
    apr_thread_mutex_destroy(db->counter_lock);
    apr_thread_mutex_destroy(db->id_lock);
    apr_pool_destroy(db->pool);
    free(db);
}

// REQUIRED: id_lock has ot be held
int leveldb_fs_id_exists(leveldb_fs_t * fs, osd_id_t id) {
    return 0;
}

osd_id_t _leveldb_fs_generate_key() {
    osd_id_t r;
    r = 0;
    get_random(&r, 6);
    return(r);
}

osd_id_t leveldb_fs_reserve_id(leveldb_fs_t * fs, osd_id_t id) {
    apr_thread_mutex_lock(fs->id_lock);
    if (id == 0) {
        do {      //Generate a unique key
            id = _leveldb_fs_generate_key();
        } while (leveldb_fs_id_exists(fs, id) || id < 100);
    }
    apr_thread_mutex_unlock(fs->id_lock);
    return id;
}

leveldb_state_t * leveldb_fs_acquire_state(leveldb_fs_t * fs, osd_id_t id) {
    apr_thread_mutex_lock(fs->id_lock);
    leveldb_fs_state_list_t * curr;
    for (curr = fs->state_head; curr != NULL; curr = curr->next) {
        if (curr->state->id == id) {
            ++curr->refs;
            apr_thread_mutex_unlock(fs->id_lock);
            return curr->state;
        }
    }
    // First one to request this id, so make a new state object
    curr = malloc(sizeof(leveldb_fs_state_list_t));
    if (!curr) { 
        apr_thread_mutex_unlock(fs->id_lock);
        return NULL;
    }
    curr->refs = 1;
    curr->state = leveldb_state_create(fs, id);
    if (!curr->state) {
        apr_thread_mutex_unlock(fs->id_lock);
        free(curr);
        return NULL;
    }
    curr->next = fs->state_head;
    fs->state_head = curr;
    apr_thread_mutex_unlock(fs->id_lock);
    return curr->state;
}

leveldb_fs_cache_iterator_t *  leveldb_fs_cache_iterator_create(leveldb_fs_t * fs, int state) {
    leveldb_fs_cache_iterator_t * ret = malloc(sizeof(leveldb_fs_cache_iterator_t));
    memset(ret, 0, (sizeof(leveldb_fs_cache_iterator_t)));
    if (apr_pool_create(&(ret->pool), fs->pool) != APR_SUCCESS) { free(ret); return NULL; }
    apr_thread_mutex_lock(fs->cache_lock);
    ret->iter = apr_hash_first(ret->pool, fs->allocation_cache[state]);
    osd_id_t * id;
    leveldb_fs_cache_iterator_t * val;
    ret->fs = fs;
    if (ret->iter) {
        apr_hash_this(ret->iter, (const void **)&id, NULL, (void **)&val);
        ret->id = *id;
        ret->mtime = val->mtime;
    }
    apr_thread_mutex_unlock(fs->cache_lock);
    return ret;
}
void  leveldb_fs_cache_iterator_destroy(leveldb_fs_cache_iterator_t * iter) {
    apr_pool_destroy(iter->pool);
    free(iter);
}
void  leveldb_fs_cache_iterator_next(leveldb_fs_t * fs, leveldb_fs_cache_iterator_t * iter) {
    apr_thread_mutex_lock(fs->cache_lock);
    if (!iter->iter) {
        apr_thread_mutex_unlock(fs->cache_lock);
        return;
    }
    iter->iter = apr_hash_next(iter->iter);
    if (!iter->iter) {
        apr_thread_mutex_unlock(fs->cache_lock);
        return;
    }
    osd_id_t * id;
    leveldb_fs_cache_value_t * val;
    apr_hash_this(iter->iter, (const void **) &id, NULL,(void **) &val);
    apr_thread_mutex_unlock(fs->cache_lock);
}
int  leveldb_fs_cache_iterator_valid(leveldb_fs_cache_iterator_t * iter) {
    return (iter->iter != NULL);
}

leveldb_fs_cache_value_t * leveldb_fs_cache_allocation_state(leveldb_fs_t * fs, osd_id_t id, int state, apr_time_t when) {
    leveldb_fs_cache_value_t * ret = apr_pcalloc(fs->pool, sizeof(leveldb_fs_cache_value_t));
    ret->mtime = when;
    apr_thread_mutex_lock(fs->cache_lock);
    int i;
    for (i = 0; i < LEVELDB_TRASH_COUNT; ++i) {
        if (i == state) {
            apr_hash_set(fs->allocation_cache[i], &id, sizeof(osd_id_t), ret);
        } else {
            apr_hash_set(fs->allocation_cache[i], &id, sizeof(osd_id_t), NULL);
        }
    }
    apr_thread_mutex_unlock(fs->cache_lock);
    return ret;
}

void leveldb_fs_release_state(leveldb_fs_t * fs, leveldb_state_t * state) {
    apr_thread_mutex_lock(fs->id_lock);
    leveldb_fs_state_list_t * curr;
    leveldb_fs_state_list_t * prev = NULL;
    for (curr = fs->state_head; curr != NULL; curr = curr->next) {
        if (curr->state == state) {
            --curr->refs;
            if (curr->refs == 0) { //release the state
                leveldb_state_destroy(state);
                if (prev == NULL) {
                    fs->state_head = curr->next;
                } else {
                    prev->next = curr->next;
                }
                free(curr);
            }
            break;
        }
    }
    apr_thread_mutex_unlock(fs->id_lock);
}

leveldb_fd_t * leveldb_fs_file_open(leveldb_fs_t * fs, osd_id_t id) {
    leveldb_state_t * state = leveldb_fs_acquire_state(fs, id); // ref counting
    if (!state) { return NULL; }
    leveldb_fd_t * ret = leveldb_fd_create(fs, state);
    if (!ret) {
        leveldb_fs_release_state(fs, state);
        return NULL;
    }
    return ret;
}

int leveldb_fs_file_close(leveldb_fs_t * fs, leveldb_fd_t * fd) {
    leveldb_fs_release_state(fs, fd->state); // ref counting
    leveldb_fd_destroy(fd);
    return 0;
}

// Atomically fetch and increment the per-database counter
uint64_t leveldb_fs_get_counter(leveldb_fs_t *db) {
    uint64_t res;
    apr_thread_mutex_lock(db->counter_lock);
    res = db->counter;
    db->counter++;
    log_printf(0,"New counter is %lld\n", db->counter);
    apr_thread_mutex_unlock(db->counter_lock);
    return res;
}

// Figure out what the next available counter is. Scans the whole database
// at startup. I have to do this until I can get the sequance number directly
// from the database
uint64_t leveldb_fs_get_max_counter(leveldb_fs_t *db) {
    leveldb_iterator_t * iter = leveldb_create_iterator(db->db, db->roptions);
    uint64_t max = 1;
    for (leveldb_iter_seek_to_first(iter); leveldb_iter_valid(iter); leveldb_iter_next(iter)) {
        size_t keylen;
        const char * key = leveldb_iter_key(iter, &keylen);
        leveldb_key_t curr = leveldb_fs_deserialize_key(key, keylen);
        max = (max > curr.counter) ? max : curr.counter;
    }
    char * err = NULL;
    leveldb_iter_get_error(iter, &err);
    if (err) {
        log_printf(0,"ERROR: Couldn't get max counter: %s\n", err);
        return 0;
    }
    leveldb_iter_destroy(iter);
    return max;
}

leveldb_key_t leveldb_fs_deserialize_key(const char * key, size_t keylen) {
    leveldb_key_t ret;
    memset(&ret, 0, sizeof(ret));
    if (keylen != 16) {
        // not good!
        return ret;
    }
    memcpy((void *)&ret.id, key, sizeof(ret.id));
    ret.id = ntohll(ret.id);
    ret.flags = (ret.id >> 48);
    ret.id = ((ret.id << 16) >> 16);
    memcpy((void *)&ret.counter, key + sizeof(ret.id), sizeof(ret.counter));
    ret.counter = ntohll(ret.counter);
    return ret;
}
leveldb_key_serialized_t leveldb_fs_serialize_key(leveldb_key_t key) {
    leveldb_key_serialized_t ret;
    memset(&ret, 0, sizeof(ret));
    uint64_t flag_buffer = key.flags;
    uint64_t buffer = (flag_buffer << 48) + ((key.id << 16) >> 16);
    buffer = htonll(buffer);
    memcpy(ret.buffer, (const void *)&buffer, sizeof(key.id));
    buffer = htonll(key.counter);
    memcpy(ret.buffer + sizeof(key.id), (const void *)&buffer, sizeof(key.id));
    ret.length = sizeof(uint64_t) * 2;
    return ret;
}
int leveldb_fs_remove(leveldb_fs_t * fs, osd_id_t id, int trash_type) {
    leveldb_fd_t *fd = leveldb_fs_file_open(fs, id);
    leveldb_fd_remove(fd, trash_type);
    leveldb_fs_file_close(fs, fd);
    return 0;
}
int leveldb_fs_unremove(leveldb_fs_t * fs, osd_id_t id) {
    leveldb_fd_t *fd = leveldb_fs_file_open(fs, id);
    leveldb_fd_unremove(fd);
    leveldb_fs_file_close(fs, fd);
    return 0;
}
