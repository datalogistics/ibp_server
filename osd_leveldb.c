//
// osd_leveldb.c - LevelDB-backed implementation of an IBP resource
//                  Andrew Melo <andrew.m.melo@vanderbilt.edu>
//
//              Special thanks to Alan Tackett for replying to my constant
//              question barrage.
//
//              This file strictly handles thunking IBP calls to the lower level
//*******************************************

#include <sys/types.h>
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 600
#endif
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <apr_time.h>
#include <math.h>
#include "string_token.h"
#include "osd_abstract.h"
#include "osd_fs.h"
#include "fmttypes.h"
#include "log.h"
#include "type_malloc.h"
#ifdef _HAS_XFS
#include <xfs/xfs.h>
#endif

// begin things I care about
#include <leveldb/c.h>
#include "log.h"
#include "osd.h"

//*************************************************************
// fs_umount - Unmounts the resource
//*************************************************************
int leveldb_thunk_umount(osd_t *d)
{
    leveldb_fs_t *fs = (leveldb_fs_t *)(d->private);
    log_printf(15, "leveldb_umount fs=%p\n",fs);
    leveldb_fs_close(fs);
    free(d);
    return(0);
}

//**************************************************
//  reserve - Preallocates space for allocation
//**************************************************
int leveldb_thunk_reserve(osd_t *d, osd_id_t id, osd_off_t len) {
    // Don't need to preallocate, we logappend
    log_printf(10, "leveldb_reserve(%lld)\n", id);
    return 0;
}

//*************************************************************
// statfs - Determine the file system stats
//*************************************************************
int leveldb_thunk_statfs(osd_t *d, struct statfs *buf)
{
    // Gives a pessimistic view of the amount of bytes available on the 
    // resource, since there might be non GC-d values in the DB
    leveldb_fs_t *fs = (leveldb_fs_t *)(d->private);
    log_printf(10, "leveldb_statfs(%s)\n", fs->path);
    return(statfs(fs->path, buf));
}

//*************************************************************
// fs_open - Opens an object for R/W
//*************************************************************
osd_fd_t *leveldb_thunk_open(osd_t *d, osd_id_t id, int mode)
{
    log_printf(10, "leveldb_open(%lld)\n", id);
    leveldb_fs_t *fs = (leveldb_fs_t *)(d->private);
    return (osd_fd_t *) leveldb_fs_file_open(fs, id);
}

//*************************************************************
// fs_close - Closes an object
//*************************************************************
int leveldb_thunk_close(osd_t *d, osd_fd_t *ofd)
{
    leveldb_fs_t *fs = (leveldb_fs_t *)(d->private);
    leveldb_fd_t *fd = (leveldb_fd_t *)ofd;
    if (fd == NULL) return(0);
    log_printf(10, "leveldb_close(%lld)\n", fd->id);
    return leveldb_fs_file_close(fs, fd);
}

//*************************************************************
//  write - Stores data to an id given the offset and length
//*************************************************************
osd_off_t leveldb_thunk_write(osd_t *d, osd_fd_t *ofd, osd_off_t offset, osd_off_t len, buffer_t buffer)
{
    leveldb_fd_t *fd = (leveldb_fd_t *)ofd;
    if (fd == NULL) {
        log_printf(0, "leveldb_write(NULL, " I64T ", " I64T ", buffer) invalid fd!\n", offset, len);
        return(-1);
    }
    log_printf(10, "leveldb_write(%p, " I64T ", " I64T ", buffer) start!\n", fd, offset, len);
    osd_off_t err = leveldb_fd_write(fd, offset, len, buffer);
    log_printf(10, "leveldb_write(%p, " I64T ", " I64T ", buffer)=" I64T " end!\n", fd, offset, len, err);

    return(err);
}

//*************************************************************
//  read - Reads data from the id given at offset and length
//*************************************************************
osd_off_t leveldb_thunk_read(osd_t *d, osd_fd_t *ofd, osd_off_t offset, osd_off_t len, buffer_t buffer)
{
    osd_off_t err;
    leveldb_fd_t *fd = (leveldb_fd_t *)ofd;
    if (fd == NULL) {
        log_printf(0, "fs_write(NULL, " I64T ", " I64T ", buffer) invalid fd!\n", offset, len);
        return(-1);
    }

    log_printf(10, "fs_read(%p, " I64T ", " I64T ", buffer) start!\n", fd, offset, len);
    err = leveldb_fd_read(fd, offset, len, buffer);
    log_printf(10, "fs_read(%p, " I64T ", " I64T ", buffer)=" I64T " end!\n", fd, offset, len, err);

    return(err);
}


//*************************************************************
// truncate - truncates a file to a logical fixed size
//*************************************************************
int leveldb_thunk_truncate(osd_t *d, osd_id_t id, osd_off_t l_size) {
    leveldb_fs_t *fs = (leveldb_fs_t *)(d->private);
    leveldb_fd_t *fd = (leveldb_fd_t *)leveldb_fs_file_open(fs, id);
    log_printf(10, "leveldb_truncate(%lld) size=%lld\n", id, l_size);
    int retval = leveldb_fd_truncate(fd, id);
    leveldb_fs_file_close(fs, fd);
    return retval;
}

//**************************************************
// id_exists - Checks to see if the ID exists
//**************************************************
int leveldb_thunk_id_exists(osd_t *d, osd_id_t id) {
    leveldb_fs_t *fs = (leveldb_fs_t *)(d->private);
    log_printf(10, "leveldb_exists(%lld)", id);
    return leveldb_fs_id_exists(fs, id);
}

//**************************************************
// create_id - Creates a new object id for use.
//**************************************************
osd_id_t leveldb_thunk_create_id(osd_t *d, int chksum_type, int header_size, int block_size, osd_id_t id) {
    leveldb_fs_t *fs = (leveldb_fs_t *)(d->private);
    return leveldb_fs_reserve_id(fs, id);
}

//*************************************************************
// size - Returns the fd size in bytes
//*************************************************************
osd_off_t leveldb_thunk_fd_size(osd_t *d, osd_fd_t *ofd)
{
    leveldb_fd_t *fd = (leveldb_fd_t *)ofd;
    return leveldb_fd_size(fd);
}

//*************************************************************
// size - Returns the id size in bytes
//*************************************************************
osd_off_t leveldb_thunk_size(osd_t *d, osd_id_t id) {
    leveldb_fs_t *fs = (leveldb_fs_t *)(d->private);
    leveldb_fd_t *fd = (leveldb_fd_t *)leveldb_fs_file_open(fs, id);
    int retval = leveldb_fd_size(fd);
    leveldb_fs_file_close(fs, fd);
    return retval;
}

//*************************************************************
// fs_trash_size - Returns the trash file size in bytes
//*************************************************************
osd_off_t leveldb_thunk_trash_size(osd_t *d, int trash_type, const char *trash_id) {
    osd_id_t id;
    memcpy(&id, trash_id, 16);
    return leveldb_thunk_size(d, id);
}

//**************************************************
//  physical_remove - Removes the id (really does it)
//**************************************************
int leveldb_thunk_physical_remove(osd_t *d, osd_id_t id) {
    log_printf(10, "physical_remove(" LU ")\n", id);
    leveldb_fs_t *fs = (leveldb_fs_t *)(d->private);
    return leveldb_fs_remove(fs, id, LEVELDB_TRASH_PERMENANT);
}

//**************************************************
//  trash_physical_remove - Removes the id from trash (really does it)
//**************************************************
int leveldb_thunk_trash_physical_remove(osd_t *d, int trash_type, const char *trash_id) {
    log_printf(10, "trash_physical_remove(%d, %s)\n", trash_type, trash_id);
    osd_id_t id;
    memcpy(&id, trash_id, sizeof(osd_id_t));
    return leveldb_thunk_physical_remove(d, id);
}

//**************************************************
//  delete_remove - Moved the ID to the deleted_trash dir
//**************************************************
int leveldb_thunk_delete_remove(osd_t *d, osd_id_t id) {
    log_printf(10,"delete_remove(" LU ")\n", id);
    leveldb_fs_t *fs = (leveldb_fs_t *)(d->private);
    return leveldb_fs_remove(fs, id, LEVELDB_TRASH_DELETE);
}

//**************************************************
//  expire_remove - Moved the ID to the expired_trash dir
//**************************************************
int leveldb_thunk_expire_remove(osd_t *d, osd_id_t id) {
    log_printf(10,"expire_remove(" LU ")\n", id);
    leveldb_fs_t *fs = (leveldb_fs_t *)(d->private);
    return leveldb_fs_remove(fs, id, LEVELDB_TRASH_EXPIRE);
}

//**************************************************
//  remove - Wrapper for physical/expire/delete remove
//**************************************************
int leveldb_thunk_remove(osd_t *d, int rmode, osd_id_t id) {
    if (rmode == OSD_DELETE_ID) {
        return(leveldb_thunk_delete_remove(d, id));
    } else if (rmode == OSD_EXPIRE_ID) {
        return(leveldb_thunk_expire_remove(d, id));
    } else if (rmode == OSD_PHYSICAL_ID) {
        return(leveldb_thunk_physical_remove(d, id));
    }

    return(-1);
}

//**************************************************
// trash_undelete - Undeletes a trashed id
//**************************************************
osd_id_t leveldb_thunk_trash_undelete(osd_t *d, int trash_type, const char *trash_id) {
    leveldb_fs_t *fs = (leveldb_fs_t *)(d->private);
    osd_id_t id;
    memcpy(&id, trash_id, sizeof(osd_id_t));
    return leveldb_fs_unremove(fs, id);
}


// Helper function to unify different iterators
osd_iter_t * _leveldb_thunk_new_iterator(osd_t *d, int trash_type) {
    log_printf(20, "New iterator\n");
    leveldb_fs_t *fs = (leveldb_fs_t *)(d->private);
    osd_iter_t *oi = (osd_iter_t *)malloc(sizeof(osd_iter_t));
    if (!oi) { return NULL; }
    oi->d = d;
    oi->arg = (void *) leveldb_fs_cache_iterator_create(fs, trash_type);
    if (!oi->arg) { free(oi); return NULL; }
    return oi;
}
int _leveldb_thunk_iterator_next(osd_iter_t *oi, osd_id_t *id, ibp_time_t *move_time, char *trash_id)
{
    log_printf(20, "Next iterator\n");
    if (oi == NULL) return(-1);  //** Bad iterator
    leveldb_fs_cache_iterator_t * iter = (leveldb_fs_cache_iterator_t *)oi->arg;
    leveldb_fs_cache_iterator_next(iter->fs, iter);
    if (!leveldb_fs_cache_iterator_valid(iter)) { return 1; }
    *move_time = iter->mtime;
    *id = iter->id;
    memcpy(trash_id, id, sizeof(osd_id_t));
    return(0);
}

//*************************************************************
//  new_trash_iterator - Creates a new iterator to walk through trash
//*************************************************************
osd_iter_t *leveldb_thunk_new_trash_iterator(osd_t *d, int trash_type)
{
    return _leveldb_thunk_new_iterator(d, trash_type);
}


//*************************************************************
//  new_iterator - Creates a new iterator to walk through the files
//*************************************************************
osd_iter_t *leveldb_thunk_new_iterator(osd_t *d)
{
    return _leveldb_thunk_new_iterator(d, LEVELDB_TRASH_NOTTRASH);
}

//*************************************************************
//  destroy_iterator - Destroys an iterator
//*************************************************************
void leveldb_thunk_destroy_iterator(osd_iter_t *oi)
{
    if (oi == NULL) return;
    leveldb_fs_cache_iterator_t * iter = (leveldb_fs_cache_iterator_t *)oi->arg;
    leveldb_fs_cache_iterator_destroy(iter);
    free(oi);
}

//*************************************************************
//  iterator_next - Returns the next key for the iterator
//*************************************************************
int leveldb_thunk_iterator_next(osd_iter_t *oi, osd_id_t *id)
{
    ibp_time_t move_time;
    char trash_id[16];
    return  _leveldb_thunk_iterator_next(oi,id, &move_time, trash_id);
}

//*************************************************************
//  trash_iterator_next - Returns the next key for the trash iterator
//*************************************************************
int leveldb_thunk_trash_iterator_next(osd_iter_t *oi, osd_id_t *id, ibp_time_t *move_time, char *trash_id)
{
    return _leveldb_thunk_iterator_next(oi, id, move_time, trash_id);
}

//
// Stubs - The following functionality isn't supported
//

//*************************************************************
// fs_get_state - Returns the current state of the object
//*************************************************************
int leveldb_thunk_get_state(osd_t *d, osd_fd_t *ofd)
{
    return OSD_STATE_GOOD;
}
//******************************************************************************
// leveldb_thunk_corrupt_count - Returns the number of corrupt objects encountered during
//    execution
//******************************************************************************
int leveldb_thunk_corrupt_count(osd_t *d)
{
    // I currently haven't an idea of what a corrupted allocation would be
    return 0;
}

//*************************************************************
//  leveldb_thunk_new_corrupt_iterator - Creates a new iterator to walk through the files
//*************************************************************
osd_iter_t *leveldb_thunk_new_corrupt_iterator(osd_t *d)
{
    osd_iter_t *oi = (osd_iter_t *)malloc(sizeof(osd_iter_t));
    osd_fs_corrupt_iter_t *ci = (osd_fs_corrupt_iter_t *)malloc(sizeof(osd_fs_corrupt_iter_t));

    if (oi == NULL) return(NULL);
    if (ci == NULL) return(NULL);

    ci->iter = NULL;
    ci->first_time = 1;
    ci->fs = (osd_fs_t *)d->private;

    oi->d = d;
    oi->arg = (void *)ci;

    return(oi);
}

//*************************************************************
//  leveldb_thunk_corrupt_destroy_iterator - Destroys an iterator
//*************************************************************
void leveldb_thunk_destroy_corrupt_iterator(osd_iter_t *oi)
{
    osd_fs_corrupt_iter_t *iter = (osd_fs_corrupt_iter_t *)oi->arg;
    if (iter == NULL) return;
    free(iter);
    free(oi);
}

//*************************************************************
//  corrupt_iterator_next - Returns the next key for the iterator
//*************************************************************
int leveldb_thunk_corrupt_iterator_next(osd_iter_t *oi, osd_id_t *id)
{
    return 1;
}
//*************************************************************
//  fs_native_open - Opens the ID and positions the fd to len
//*************************************************************
int leveldb_thunk_native_open(osd_t *d, osd_id_t id, osd_off_t offset, int mode)
{
    return 0;
}

//*************************************************************
//  fs_native_close - Closes the fd
//*************************************************************
int leveldb_thunk_native_close(osd_t *d, int fd)
{
    return 0;
}

//*************************************************************
//  fs_chksum_info - Retreives the objects chksum info
//    If no chksum info is available 1 is returned
//*************************************************************
int leveldb_thunk_chksum_info(osd_t *d, osd_id_t id, int *cs_type, osd_off_t *header_blocksize, osd_off_t *blocksize)
{
    return 1;
}

//*************************************************************
//  fs_get_chksum - Retreives the chksum data and stores it in the provided buffer
//     If the buffer is too small a value of the needed buffer size is returned
//     as a negative number. Otherwise the number of bytes used is returned
//*************************************************************
osd_off_t leveldb_thunk_get_chksum(osd_t *d, osd_id_t id, char *disk_buffer, char *calc_buffer, osd_off_t buffer_size, osd_off_t *block_len,
        char *good_block, osd_off_t start_block, osd_off_t end_block)
{
    return 0;
}

//*************************************************************
//  fs_validate_chksum - Reads the entire object verifying the chksum data.
//     If correct_errors = 1 any errors encountered are corrected.
//     The block error count is returned or 0 if no errors occured.
//     A negative value represents a disk or other internal error.
//*************************************************************
int leveldb_thunk_validate_chksum(osd_t *d, osd_id_t id, int correct_errors)
{
    return 0;
}
//
//
// Entry function - Returns an OSD-compatible object describing this resource
//

//*************************************************************
// osd_mount_fs - Mounts the device
//*************************************************************
osd_t *osd_mount_leveldb(const char *device)
{
    osd_t *d = (osd_t *)malloc(sizeof(osd_t));
    assert(d != NULL);
    char buf[1024];
    snprintf(buf, 1024, "%s/leveldb_db/", device);
    leveldb_fs_t *fs = leveldb_fs_open(buf);
    assert(fs != NULL);


    d->private = (void *)fs;

    log_printf(10, "osd_leveldb_mount: %s mount_type=%d\n", device);
    log_printf(15, "fs_mount fs=%p rid=%s\n",fs, device);

    //** Lastly set up all the pointers
    d->chksum_info = leveldb_thunk_chksum_info;
    d->close = leveldb_thunk_close;
    d->corrupt_iterator_next = leveldb_thunk_corrupt_iterator_next;
    d->create_id = leveldb_thunk_create_id;
    d->delete_remove = leveldb_thunk_delete_remove;
    d->destroy_corrupt_iterator = leveldb_thunk_destroy_corrupt_iterator;
    d->destroy_iterator = leveldb_thunk_destroy_iterator;
    d->expire_remove = leveldb_thunk_expire_remove;
    d->fd_size = leveldb_thunk_fd_size;
    d->get_chksum = leveldb_thunk_get_chksum;
    d->get_corrupt_count = leveldb_thunk_corrupt_count;
    d->get_state = leveldb_thunk_get_state;
    d->id_exists = leveldb_thunk_id_exists;
    d->iterator_next = leveldb_thunk_iterator_next;
    d->native_close = leveldb_thunk_native_close;
    d->native_open = leveldb_thunk_native_open;
    d->new_corrupt_iterator = leveldb_thunk_new_corrupt_iterator;
    d->new_iterator = leveldb_thunk_new_iterator;
    d->new_trash_iterator = leveldb_thunk_new_trash_iterator;
    d->open = leveldb_thunk_open;
    d->physical_remove = leveldb_thunk_physical_remove;
    d->read = leveldb_thunk_read;
    d->remove = leveldb_thunk_remove;
    d->reserve = leveldb_thunk_reserve;
    d->size = leveldb_thunk_size;
    d->statfs = leveldb_thunk_statfs;
    d->trash_iterator_next = leveldb_thunk_trash_iterator_next;
    d->trash_physical_remove = leveldb_thunk_trash_physical_remove;
    d->trash_size = leveldb_thunk_trash_size;
    d->trash_undelete = leveldb_thunk_trash_undelete;
    d->truncate = leveldb_thunk_truncate;
    d->umount = leveldb_thunk_umount;
    d->validate_chksum = leveldb_thunk_validate_chksum;
    d->write = leveldb_thunk_write;
    return(d);
}


// fs_umount - Unmounts the dir.
//    int (*umount)(osd_t *d);
// create_id - Creates a new object id for use.
//    osd_id_t (*create_id)(osd_t *d, int chksum_type, int header_size, int block_size, osd_id_t id);    // Returns an OSD object.  Think of it as a filename
//    Make this false.
//    osd_native_fd_t (*native_open)(osd_t *d, osd_id_t id, osd_off_t offset, int mode);   //Native open
//    make this also false
//    int (*native_close)(osd_t *d, osd_native_fd_t fd);   //Native close
//    return 0
//    int (*validate_chksum)(osd_t *d, osd_id_t id, int correct_errors);
//    return 0
//    osd_off_t (*get_chksum)(osd_t *d, osd_id_t id, char *disk_buffer, char *calc_buffer, osd_off_t buffer_size, osd_off_t *block_len, char *good_block, osd_off_t start_block, osd_off_t end_block);
//    return 1
//    int (*chksum_info)(osd_t *d, osd_id_t id, int *cs_type, osd_off_t *header_blocksize, osd_off_t *blocksize);
//    return 0
//    possibly a noop - return 0
//    int (*reserve)(osd_t *d, osd_id_t id, osd_off_t len);  // Reserve space for the file
//
//    int (*truncate)(osd_t *d, osd_id_t id, osd_off_t len);  // Truncate the object
//    osd_off_t (*size)(osd_t *d, osd_id_t);      // Object size in bytes
//    osd_off_t (*fd_size)(osd_t *d, osd_fd_t *fd);      // Object size in bytes
//    osd_off_t (*read)(osd_t *d, osd_fd_t *fd, osd_off_t offset, osd_off_t len, buffer_t buffer);   //Read data
//    osd_off_t (*write)(osd_t *d, osd_fd_t *fd, osd_off_t offset, osd_off_t len, buffer_t buffer);  //Store data to disk
//    osd_fd_t *(*open)(osd_t *d, osd_id_t id, int mode);      // Open an object for use
//    int (*get_state)(osd_t *d, osd_fd_t *fd);  //** Retreive the objects state
//    int (*close)(osd_t *d, osd_fd_t *fd);      // Close the object
//    int (*id_exists)(osd_t *d, osd_id_t id);   //Determine if the id currently exists
//    int (*statfs)(osd_t *d, struct statfs *buf);    // Get File system stats
//    osd_iter_t *(*new_iterator)(osd_t *d);
//    void (*destroy_iterator)(osd_iter_t *oi);
//    int (*iterator_next)(osd_iter_t *oi, osd_id_t *id);
//
//  Deletion Handling - There are seperate trashes for deleted and expired 
//                      allocations
//    int (*remove)(osd_t *d, int rmode, osd_id_t id);  //** Wrapper for delete/expire/physical_remove
//        int fs_remove(osd_t *d, int rmode, osd_id_t id) {
//           if (rmode == OSD_DELETE_ID) {
//              return(fs_delete_remove(d, id));
//           } else if (rmode == OSD_EXPIRE_ID) {
//              return(fs_expire_remove(d, id));
//           } else if (rmode == OSD_PHYSICAL_ID) {
//              return(fs_physical_remove(d, id));
//           }
//           return(-1);
//        }
//    Actual deletions -
//      int (*delete_remove)(osd_t *d, osd_id_t id);  // Move an object from valid->deleted bin
//      int (*expire_remove)(osd_t *d, osd_id_t id);  // Move an object from valid->expired bin
//      int (*physical_remove)(osd_t *d, osd_id_t id);  // Remove the valid object completely.. non-recoverable
//
//    osd_iter_t *(*new_trash_iterator)(osd_t *d, int trash_type);
//    int (*trash_iterator_next)(osd_iter_t *oi, osd_id_t *id, ibp_time_t *move_time, char *trash_id);
//    osd_off_t (*trash_size)(osd_t *d, int trash_type, const char *trash_id);      // Trash Object size in bytes
//    int (*trash_physical_remove)(osd_t *d, int trash_type, const char *trash_id); // Remove the trash object completely... non-recoverable
//    osd_id_t (*trash_undelete)(osd_t *d, int trash_type, const char *trash_id);
//
//
//  Corrupt Handling - Use if allocations are there but are known to be corrupted
//    return 0
//    int (*get_corrupt_count)(osd_t *d);                   // Number of corrupt objects
//    return NULL
//    osd_iter_t *(*new_corrupt_iterator)(osd_t *d);         // Corrupt iterator
//    return
//    void (*destroy_corrupt_iterator)(osd_iter_t *iter);   // Corrupt iterator destruction
//    return 1
//    int (*corrupt_iterator_next)(osd_iter_t *iter, osd_id_t *id);    // Corrupt iterator next//

