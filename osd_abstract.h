/*
Advanced Computing Center for Research and Education Proprietary License
Version 1.0 (April 2006)

Copyright (c) 2006, Advanced Computing Center for Research and Education,
 Vanderbilt University, All rights reserved.

This Work is the sole and exclusive property of the Advanced Computing Center
for Research and Education department at Vanderbilt University.  No right to
disclose or otherwise disseminate any of the information contained herein is
granted by virtue of your possession of this software except in accordance with
the terms and conditions of a separate License Agreement entered into with
Vanderbilt University.

THE AUTHOR OR COPYRIGHT HOLDERS PROVIDES THE "WORK" ON AN "AS IS" BASIS,
WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT
LIMITED TO THE WARRANTIES OF MERCHANTABILITY, TITLE, FITNESS FOR A PARTICULAR
PURPOSE, AND NON-INFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Vanderbilt University
Advanced Computing Center for Research and Education
230 Appleton Place
Nashville, TN 37203
http://www.accre.vanderbilt.edu
*/

//**************************************************
//
//**************************************************

#ifndef __OSD_ABSTRACT_H
#define __OSD_ABSTRACT_H

#include <stdio.h>
#include <stdint.h>
#include "statfs.h"
#include "ibp_time.h"
#include "statsd-client.h"

 //** Type of ID
#define OSD_ID        0
#define OSD_DELETE_ID 1
#define OSD_EXPIRE_ID 2
#define OSD_PHYSICAL_ID OSD_ID

   //** R/W mode definitions
#define OSD_READ_MODE  1
#define OSD_WRITE_MODE 2

   //** Allocation state definitions
#define OSD_STATE_GOOD       0
#define OSD_STATE_BAD_HEADER 1
#define OSD_STATE_BAD_BLOCK  2

typedef int osd_native_fd_t;

typedef uint64_t osd_id_t;
typedef void *buffer_t;
typedef int64_t osd_off_t;

struct osd_s;
typedef struct osd_s osd_t;

typedef struct {
   osd_t *d;
   void *arg;
} osd_iter_t;

typedef struct {
  osd_off_t lo;
  osd_off_t hi;
} osd_range_t;

typedef struct {
  int n_read;    //** Current number of read operations
  int n_write;   //** Current number of write operations
  void *private; //** Private OSD argument
  osd_off_t *range_list;  //** List of host R/W block ranges
  apr_thread_mutex_t *lock;
  apr_pool_t *pool;
} osd_object_t;

typedef struct {
  osd_object_t *obj;
  int  my_index;
} osd_fd_t;

#define osd_umount(d) (STATSD_COUNT(d->stats, "ops.umount",1),(d)->umount(d))
#define osd_create_id(d, type, header, block, id) (STATSD_COUNT(d->stats, "opps.create_id", 1),(d)->create_id(d, type, header, block, id))
#define osd_native_open_id(d, id, offset, mode) (STATSD_COUNT(d->stats, "ops.native_open_id", 1),(d)->native_open(d, id, offset, mode))
#define osd_native_enabled(d) (STATSD_COUNT(d->stats, "ops.native_enabled", 1),(d)->native_open)
#define osd_native_close_id(d, fd) (STATSD_COUNT(d->stats, "ops.native_close_id", 1),(d)->native_close(d, fd))
#define osd_validate_chksum(d, id, correct_errors) (STATSD_COUNT(d->stats, "ops.validate_chksum", 1),(d)->validate_chksum(d, id, correct_errors))
#define osd_get_chksum(d, id, disk_buffer, calc_buffer, bsize, block_len, good_block, start_block, end_block) (STATSD_COUNT(d->stats, "ops.get_chksum", 1),(d)->get_chksum(d, id, disk_buffer, calc_buffer, bsize, block_len, good_block, start_block, end_block))
#define osd_chksum_info(d, id, cs_type, hbs, bs) (STATSD_COUNT(d->stats, "ops.chksum_info", 1),(d)->chksum_info(d, id, cs_type, hbs, bs))
#define osd_get_corrupt_count(d) (STATSD_COUNT(d->stats, "ops.get_corrupt_count", 1),(d)->get_corrupt_count(d))
#define osd_new_corrupt_iterator(d) (STATSD_COUNT(d->stats, "ops.net_corrupt_iterator", 1),(d)->new_corrupt_iterator(d))
#define osd_destroy_corrupt_iterator(iter) (STATSD_COUNT(iter->d->stats, "ops.destroy_corrupt_iterator", 1),(iter)->d->destroy_corrupt_iterator(iter))
#define osd_corrupt_iterator_next(iter, id) (STATSD_COUNT(iter->d->stats, "ops.orrupt_iterator_next", 1),(iter)->d->corrupt_iterator_next(iter, id))
#define osd_reserve(d, id, len) (STATSD_COUNT(d->stats, "ops.reserve",1),(d)->reserve(d, id, len))
#define osd_remove(d, rmode, id)  (STATSD_COUNT(d->stats, "ops.remove",1),(d)->remove(d, rmode, id))
#define osd_delete_remove(d, id)  (STATSD_COUNT(d->stats, "ops.delete_remove",1),(d)->delete_remove(d, id))
#define osd_expire_remove(d, id)  (STATSD_COUNT(d->stats, "ops.expire_remove",1),(d)->expire_remove(d, id))
#define osd_physical_remove(d, id)  (STATSD_COUNT(d->stats, "ops.physical_remove",1),(d)->physical_remove(d, id))
#define osd_trash_physical_remove(d, trash_type, trash_id)  (STATSD_COUNT(d->stats, "ops.trash_physical_rewmove",1),(d)->trash_physical_remove(d, trash_type, trash_id))
#define osd_trash_undelete(d, trash_type, trash_id)  (STATSD_COUNT(d->stats, "ops.trash_undelete",1),(d)->trash_undelete(d, trash_type, trash_id))
#define osd_truncate(d, id, len)  (STATSD_COUNT(d->stats, "ops.truncate",1),(d)->truncate(d, id, len))
#define osd_size(d, id)  (STATSD_COUNT(d->stats, "ops.size",1),(d)->size(d, id))
#define osd_fd_size(d, fd)  (STATSD_COUNT(d->stats, "ops.fd_size",1),(d)->fd_size(d, fd))
#define osd_trash_size(d, trash_type, trash_id)  (STATSD_COUNT(d->stats, "ops.trash_size",1),(d)->trash_size(d, trash_type, trash_id))
#define osd_read(d, fd, offset, len, buffer)  (STATSD_COUNT(d->stats, "ops.read",1),(d)->read(d, fd, offset, len, buffer))
#define osd_write(d, fd, offset, len, buffer)  (STATSD_COUNT(d->stats, "ops.write",1),(d)->write(d, fd, offset, len, buffer))
#define osd_open(d, id, mode)  (STATSD_COUNT(d->stats, "ops.open",1),(d)->open(d, id, mode))
#define osd_get_state(d, fd)  (STATSD_COUNT(d->stats, "ops.get_state",1),(d)->get_state(d, fd))
#define osd_close(d, fd)  (STATSD_COUNT(d->stats, "ops.close",1),(d)->close(d, fd))
#define osd_id_exists(d, id)  (STATSD_COUNT(d->stats, "ops.id_exists",1),(d)->id_exists(d, id))
#define osd_statfs(d, buf)  (STATSD_COUNT(d->stats, "ops.statfs",1),(d)->statfs(d, buf))
#define osd_new_iterator(d)  (STATSD_COUNT(d->stats, "ops.new_iterator",1),(d)->new_iterator(d))
#define osd_new_trash_iterator(d, trash_type)  (STATSD_COUNT(d->stats, "ops.new_trash_iterator",1),(d)->new_trash_iterator(d, trash_type))
#define osd_destroy_iterator(oi)  (STATSD_COUNT(oi->d->stats, "ops.destroy_iterator",1),(oi)->d->destroy_iterator(oi))
#define osd_iterator_next(oi, id)  (STATSD_COUNT(oi->d->stats, "ops.iterator_next",1),(oi)->d->iterator_next(oi, id))
#define osd_trash_iterator_next(oi, id, move_time, trash_id)  (STATSD_COUNT(oi->d->stats, "ops.trash_iterator_next",1),(oi)->d->trash_iterator_next(oi, id, move_time, trash_id))

struct osd_s {
    void *private;  //** All private implementation specific data goes here
    statsd_link * stats;
    int (*umount)(osd_t *d);
    osd_id_t (*create_id)(osd_t *d, int chksum_type, int header_size, int block_size, osd_id_t id);    // Returns an OSD object.  Think of it as a filename
    osd_native_fd_t (*native_open)(osd_t *d, osd_id_t id, osd_off_t offset, int mode);   //Native open
    int (*native_close)(osd_t *d, osd_native_fd_t fd);   //Native close
    int (*validate_chksum)(osd_t *d, osd_id_t id, int correct_errors);
    osd_off_t (*get_chksum)(osd_t *d, osd_id_t id, char *disk_buffer, char *calc_buffer, osd_off_t buffer_size, osd_off_t *block_len, char *good_block, osd_off_t start_block, osd_off_t end_block);
    int (*chksum_info)(osd_t *d, osd_id_t id, int *cs_type, osd_off_t *header_blocksize, osd_off_t *blocksize);
    int (*get_corrupt_count)(osd_t *d);                   // Number of corrupt objects
    osd_iter_t *(*new_corrupt_iterator)(osd_t *d);         // Corrupt iterator
    void (*destroy_corrupt_iterator)(osd_iter_t *iter);   // Corrupt iterator destruction
    int (*corrupt_iterator_next)(osd_iter_t *iter, osd_id_t *id);    // Corrupt iterator next
    int (*reserve)(osd_t *d, osd_id_t id, osd_off_t len);  // Reserve space for the file
    int (*remove)(osd_t *d, int rmode, osd_id_t id);  //** Wrapper for delete/expire/physical_remove
    int (*delete_remove)(osd_t *d, osd_id_t id);  // Move an object from valid->deleted bin
    int (*expire_remove)(osd_t *d, osd_id_t id);  // Move an object from valid->expired bin
    int (*physical_remove)(osd_t *d, osd_id_t id);  // Remove the valid object completely.. non-recoverable
    int (*trash_physical_remove)(osd_t *d, int trash_type, const char *trash_id); // Remove the trash object completely... non-recoverable
    osd_id_t (*trash_undelete)(osd_t *d, int trash_type, const char *trash_id);
    int (*truncate)(osd_t *d, osd_id_t id, osd_off_t len);  // Truncate the object
    osd_off_t (*size)(osd_t *d, osd_id_t);      // Object size in bytes
    osd_off_t (*fd_size)(osd_t *d, osd_fd_t *fd);      // Object size in bytes
    osd_off_t (*trash_size)(osd_t *d, int trash_type, const char *trash_id);      // Trash Object size in bytes
    osd_off_t (*read)(osd_t *d, osd_fd_t *fd, osd_off_t offset, osd_off_t len, buffer_t buffer);   //Read data
    osd_off_t (*write)(osd_t *d, osd_fd_t *fd, osd_off_t offset, osd_off_t len, buffer_t buffer);  //Store data to disk
    osd_fd_t *(*open)(osd_t *d, osd_id_t id, int mode);      // Open an object for use
    int (*get_state)(osd_t *d, osd_fd_t *fd);  //** Retreive the objects state
    int (*close)(osd_t *d, osd_fd_t *fd);      // Close the object
    int (*id_exists)(osd_t *d, osd_id_t id);   //Determine if the id currently exists
    int (*statfs)(osd_t *d, struct statfs *buf);    // Get File system stats
    osd_iter_t *(*new_iterator)(osd_t *d);
    osd_iter_t *(*new_trash_iterator)(osd_t *d, int trash_type);
    void (*destroy_iterator)(osd_iter_t *oi);
    int (*iterator_next)(osd_iter_t *oi, osd_id_t *id);
    int (*trash_iterator_next)(osd_iter_t *oi, osd_id_t *id, ibp_time_t *move_time, char *trash_id);
};


#endif
