//
// leveldb_fd - Coordinates a single flie descriptor
//

#include "log.h"
#include "osd_leveldb.h"
#include <stdlib.h>
//    int (*truncate)(osd_t *d, osd_id_t id, osd_off_t len);  // Truncate the object
//    osd_off_t (*size)(osd_t *d, osd_id_t);      // Object size in bytes
//    osd_off_t (*fd_size)(osd_t *d, osd_fd_t *fd);      // Object size in bytes
//    osd_off_t (*read)(osd_t *d, osd_fd_t *fd, osd_off_t offset, osd_off_t len, buffer_t buffer);   //Read data
//    osd_off_t (*write)(osd_t *d, osd_fd_t *fd, osd_off_t offset, osd_off_t len, buffer_t buffer);  //Store data to disk
//    osd_fd_t *(*open)(osd_t *d, osd_id_t id, int mode);      // Open an object for use
//    int (*get_state)(osd_t *d, osd_fd_t *fd);  //** Retreive the objects state
//    int (*close)(osd_t *d, osd_fd_t *fd);      // Close the object
void printfkey(char * key, size_t len);
osd_off_t leveldb_fd_read(leveldb_fd_t * fd, osd_off_t offset, osd_off_t len, buffer_t buffer) {
    leveldb_range_t * range = leveldb_state_read(fd->state, offset, len);
    if (!range) {
       return 0;
    }
    memset(buffer, 0, len);
    leveldb_rangeelem_t * curr;
    size_t size;
    char * errmsg = NULL;
    osd_off_t copied_len = 0;
    osd_off_t remaining_len = len;
    osd_off_t current_offset = offset;
    for (curr = range->head; curr != NULL; curr = curr->next) {
        char * ldb_buffer = leveldb_get(fd->fs->db, fd->fs->roptions,
                                        curr->buffer_key, curr->buffer_key_len,
                                        &size, &errmsg);
        //assert(size >= (curr->right - curr->left + 1));
        //printf("read:  (%zu) ",curr->buffer_key_len);printfkey(curr->buffer_key, curr->buffer_key_len);printf("\n");
        if (errmsg) {
            log_printf(0, "ERROR reading: %s\n", errmsg);
        }
        if (!buffer) {
            return copied_len;
        }
        size_t get_offset; // offset into the leveldb buffer
        size_t get_len;
        if (current_offset == curr->left) {
            get_offset = 0 + curr->buffer_left;  
        } else if (current_offset > curr->left) {
            get_offset = offset - curr->left + curr->buffer_left;
        } else {
            log_printf(0, "ERROR: Bad invariant on copy\n");
            return copied_len;
        }
        if (remaining_len + current_offset >= curr->right) {
            // reading all the way past the ole buffer
            // the +1 is because buffer_right includes the character at that
            // index
            get_len = curr->right - current_offset + 1;
        } else {
            get_len = remaining_len;
        }
        assert(get_offset >= 0);
        assert(get_len <= size);
        assert((copied_len + get_len) <= len);
        assert((buffer + copied_len + get_len) <= (buffer + len));
        memcpy(buffer + copied_len, ldb_buffer + get_offset, get_len);
        free(ldb_buffer);
        remaining_len -= get_len;
        copied_len += get_len;
        current_offset += get_len;
    }
    return copied_len;
}
osd_off_t leveldb_fd_write(leveldb_fd_t * fd, osd_off_t offset, osd_off_t len, buffer_t buffer) {
    leveldb_key_t key;
    key.id = fd->id;
    key.flags = LEVELDB_PAYLOAD_FLAG;
    key.counter = leveldb_fs_get_counter(fd->fs);
    leveldb_key_serialized_t key_blob = leveldb_fs_serialize_key(key);
    char * errmsg = NULL;
    assert(key_blob.length == 16);
    leveldb_put(fd->fs->db, fd->fs->woptions, key_blob.buffer, key_blob.length, 
                                                (char *) buffer, len, &errmsg);
    if (errmsg) {
        log_printf(0, "ERROR writing: %s\n", errmsg);
        return 0;
    }
    apr_thread_mutex_lock(fd->state->lock);
    assert(fd->state->range = fd->state->range_bak);
    leveldb_range_validate(fd->state->range);
    apr_thread_mutex_unlock(fd->state->lock);
    if (leveldb_state_write(fd->state, offset, len, 0, key_blob.buffer, key_blob.length)) {
        return 0;
    }
    apr_thread_mutex_lock(fd->state->lock);
    leveldb_range_validate(fd->state->range);
    apr_thread_mutex_unlock(fd->state->lock);


    leveldb_range_t * range = leveldb_state_read(fd->state, offset, len);
    assert(range->head == range->tail);
    assert(memcmp(range->head->buffer_key, key_blob.buffer, key_blob.length) == 0);
    leveldb_range_destroy(range);
    return len;
}
osd_off_t leveldb_fd_truncate(leveldb_fd_t * fd, osd_off_t len) {
    leveldb_state_truncate(fd->state, len);
    return len;
}

osd_off_t leveldb_fd_size(leveldb_fd_t * fd) {
    return leveldb_state_get_size(fd->state);
}

leveldb_fd_t * leveldb_fd_create(leveldb_fs_t * fs, leveldb_state_t * state) {
    leveldb_fd_t * ret = malloc(sizeof(leveldb_fd_t));
    if (!ret) { return NULL; }
    ret->fs = fs;
    ret->id = state->id;
    ret->state = state;
    return ret;
}

void leveldb_fd_destroy(leveldb_fd_t * fd) {
    free(fd);
}

int leveldb_fd_get_filestate(leveldb_fd_t *fd) {
    return leveldb_state_get_filestate(fd->state);
}

int leveldb_fd_set_filestate(leveldb_fd_t *fd, int trash_type) {
    return leveldb_state_set_filestate(fd->state, trash_type);
}

int leveldb_fd_remove(leveldb_fd_t * fd, int trash_type) {
    return leveldb_fd_set_filestate(fd, trash_type);
}
int leveldb_fd_unremove(leveldb_fd_t * fd) {
    return leveldb_fd_set_filestate(fd, LEVELDB_TRASH_NOTTRASH);
}
