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

//************************************************************************************
//************************************************************************************
#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#include <fcntl.h>
#include <unistd.h>

#include <string.h>
#include <limits.h>
#include <time.h>
#include "ibp_server.h"
#include "log.h"
#include "debug.h"
#include "allocation.h"
#include "resource.h"
#include "network.h"
#include "ibp_task.h"
#include "ibp_protocol.h"

int _init_table = 1;
int _res_splice_enabled[RES_TYPE_MAX];
int _ns_splice_enabled[NS_TYPE_MAX];


//************************************************************************************
// iovec_start - Determines the starting position in the iovec list
//************************************************************************************

void iovec_start(iovec_t *iovec, int *index, ibp_off_t *ioff, ibp_off_t *ileft)
{
  int i;
  ibp_off_t n;

  for (i=0; i<iovec->n; i++) {
log_printf(15, "iovec_start: i=%d transfer_total=" I64T " off=" I64T " len=" I64T " cumlen= " I64T "\n",
	i, iovec->transfer_total, iovec->vec[i].off, iovec->vec[i].len, iovec->vec[i].cumulative_len);
     if (iovec->transfer_total < iovec->vec[i].cumulative_len) break;
  }

  if (i < iovec->n) {
     *index = i;
     n = iovec->transfer_total;
     if (i > 0) n = iovec->transfer_total - iovec->vec[i-1].cumulative_len;
     (*ioff) = iovec->vec[i].off + n;
     (*ileft) = iovec->vec[i].len - n;
  } else {
     *index = -1;
     *ioff = 0;
     *ileft = 0;
  }

log_printf(15, "iovec_start: n=%d transfer_total=" I64T " index= %d ioff=" I64T " ileft=" I64T "\n",
   iovec->n, iovec->transfer_total, *index, *ioff, *ileft);
  return;
}


//************************************************************************************
// iovec_single - Initializes an iovec structure with a single task
//************************************************************************************

void iovec_single(iovec_t *iovec, ibp_off_t off, ibp_off_t len)
{
  iovec->n = 1;
  iovec->transfer_total = 0;
  iovec->total_len = len;
  iovec->vec[0].off = off;
  iovec->vec[0].len = len;
  iovec->vec[0].cumulative_len = len;
}

//************************************************************************************
// ---------------------------- Kernel space routines --------------------------------
//************************************************************************************

#ifndef SPLICE_F_MOVE

int splice_kernel(ns_native_fd_t src_fd, osd_native_fd_t dest_fd, ibp_off_t *nbytes, apr_time_t end_time, int *src_disable, int *dest_disable)
{
  *src_disable = -1;
  *dest_disable = -1;
  return(-1);
}

#else

//************************************************************************************
//  splice_kernel - Handles the data transfer between 2 fd's
//************************************************************************************

int splice_kernel(ns_native_fd_t src_fd, osd_native_fd_t dest_fd, ibp_off_t *nbytes, apr_time_t end_time, int *src_disable, int *dest_disable)
{
  ibp_off_t ntotal;
  int shortread;
  ibp_off_t lenbytes, nread;
  long bytes_copied, tmp;
  int pipefd[2], err;
  apr_time_t start_time = apr_time_now();

  int splice_mode = SPLICE_F_MOVE|SPLICE_F_NONBLOCK;
//  int splice_mode = SPLICE_F_MOVE|SPLICE_F_MORE;

  //** This forces use of user space methods
  if (global_config->server.splice_enable == 0) {
    *src_disable=-1;
    *dest_disable=-1;
    return(-2);
  }

  err = pipe(pipefd);
  if (err != 0) {
     log_printf(0, "splice_kernel:  Error creating the pipe!  errno=%d\n", errno);
     return(-1);
  }

  lenbytes = *nbytes;
  ntotal = 0;
  shortread = 0;
log_printf(15, "splice_kernel: START sfd=%d start=" TT " time=" TT " end=" TT "\n", src_fd, start_time, apr_time_now(), end_time);

  do {
//    psize = (lenbytes > 4*1024-1) ? 4*1024: lenbytes;
    bytes_copied = splice(src_fd, NULL, pipefd[1], NULL, lenbytes, splice_mode);
log_printf(15, "splice_kernel: initial splice bytes_copied=%ld errno=%d sfd=%d time=" TT " end=" TT "\n", bytes_copied, errno, src_fd, apr_time_now(), end_time);
    if (bytes_copied == -1) {
log_printf(15, "splice_kernel: initial splice error trap bytes_copied=%ld errno=%d sfd=%d time=" TT " end=" TT "\n", bytes_copied, errno, src_fd, apr_time_now(), end_time);

       if (errno == EAGAIN) bytes_copied = 0;
    }

    if (bytes_copied > 0) {
        nread = bytes_copied;
        do {
          tmp = splice(pipefd[0], NULL, dest_fd, NULL, nread, splice_mode);
          if (tmp == -1) {
             if (errno == EAGAIN) tmp = 0;
          }
          nread = nread - tmp;
        } while ((nread > 0) && (tmp != -1));

        if (tmp == -1) {
           bytes_copied = -3;
          *dest_disable = -1;
        }
    } else if (bytes_copied == -1) {
      *src_disable = -1;
      bytes_copied = -2;
    }
    if (bytes_copied == 0) shortread++;
    if (bytes_copied > 0) {
       ntotal = ntotal + bytes_copied;
       lenbytes = lenbytes - bytes_copied;
    }

    if (apr_time_now() > end_time) bytes_copied = -1;  //** command expired

    log_printf(15, "splice_kernel: left=" I64T " shortread=%d ntotal=" I64T " bytes_copied=%ld errno=%d sfd=%d time=" TT " end=" TT "\n",
            lenbytes, shortread, ntotal, bytes_copied, errno, src_fd, apr_time_now(), end_time);
//---  } while ((lenbytes>0) && (shortread < 3) && (bytes_copied > -1));
  } while ((lenbytes>0) && (bytes_copied > -1));

  log_printf(15, "splice_kernel: END left=" I64T " shortread=%d ntotal=" I64T " bytes_copied=%ld errno=%d sfd=%d start=" TT " time=" TT " end=" TT "\n", lenbytes, shortread, ntotal, bytes_copied, errno, src_fd, start_time, apr_time_now(), end_time);

  close(pipefd[0]); close(pipefd[1]);

  err = (bytes_copied >= 0) ?  0 : bytes_copied;

  *nbytes = *nbytes - ntotal;
  return(err);
}

#endif

//************************************************************************************
//  get_splice_fds - Does the fd translations
//************************************************************************************

int get_splice_fds(Resource_t *res, osd_native_fd_t *rfd, osd_id_t id, ibp_off_t pos, int mode, NetStream_t *ns, ns_native_fd_t *nfd)
{
  if (ns_native_enabled(ns) != NULL) {
     *nfd = ns_native_fd(ns);
     if (*nfd == -1) return(-1);

     if (resource_native_enabled(res) != NULL) {
        *rfd = resource_native_open_id(res, id, pos, mode);
        if (*rfd == -1) return(-1);
     }
  }

  return(0);
}

//************************************************************************************
//  disk_to_disk_copy_kernel - Copies data between allocations using kernel buffers
//    IBP_OK - Success
//    other value - failure
//************************************************************************************

int disk_to_disk_copy_kernel(Resource_t *src_res, osd_id_t src_id, ibp_off_t src_offset,
                      Resource_t *dest_res, osd_id_t dest_id, ibp_off_t dest_offset, ibp_off_t len, apr_time_t end_time)
{
  int err;
  osd_native_fd_t src_fd, dest_fd;

  log_printf(0, "disk_to_disk_copy_kernel: src_id=" LU " src_offset=" I64T " dest_id=" LU " dest_offset=" I64T " len=" I64T "\n", src_id, src_offset, dest_id, dest_offset, len);
return(-2);

  //** Open the allocations
  src_fd = resource_native_open_id(src_res, src_id, src_offset, OSD_READ_MODE);
  if (src_fd == -1) {
     log_printf(0, "disk_to_disk_copy_kernel: Error with src_id open id=" LU " offset=" I64T " len=" I64T ", buffer) = %d\n", src_id, src_offset, len, src_fd);
     return(IBP_E_FILE_READ);
  }

  dest_fd = resource_native_open_id(dest_res, dest_id, dest_offset, OSD_WRITE_MODE);
  if (dest_fd == -1) {
     log_printf(0, "disk_to_disk_copy_kernel: Error with dest_id open id=" LU " offset=" I64T " len=" I64T ", buffer) = %d\n", dest_id, dest_offset, len, dest_fd);
     return(IBP_E_FILE_WRITE);
  }

  //** Do the transfer
  err = splice_kernel(src_fd, dest_fd, &len, end_time,
         &(_res_splice_enabled[resource_get_type(src_res)]), &(_res_splice_enabled[resource_get_type(dest_res)]));

posix_fadvise(dest_fd, dest_offset+4096, len, POSIX_FADV_DONTNEED);

  //** Close the allocations
  resource_native_close_id(src_res, src_fd);
  resource_native_close_id(dest_res, dest_fd);

  if (err == 0) {
    err = IBP_OK;
  } else {
    err = IBP_E_INTERNAL;
  }

  return(err);
}

//************************************************************************************
//  read_from_disk_kernel - Reads data from the disk buffer and transfers it using
//     kernel bufers.  Return values are
//    -3 -- ns doesn't support splice
//    -2 -- resource doesn't support splice
//    -1 -- Dead connection
//     0 -- Transfered as much as data as possible
//     1 -- Completed provided task
//************************************************************************************

int read_from_disk_kernel(ibp_task_t *task, Allocation_t *a, ibp_off_t *left, Resource_t *res)
{
  NetStream_t *ns = task->ns;
  ibp_off_t nbytes, ntotal, pos;
  int task_status, err;
  ns_native_fd_t sock_fd;
  osd_native_fd_t fd;

  nbytes = a->size;
  log_printf(10, "read_from_disk_kernel: ns=%d id=" LU " a.size=" I64T " a.r_pos=" I64T " len=" I64T "\n", task->ns->id, a->id, nbytes, a->r_pos, *left);
flush_log();
return(-2);

  if (*left == 0) return(1);  //** Nothing to do

  task_status = 0;

  pos = a->r_pos;  //** Get the disk start pos from the allocation
//  nleft = (*left > a->size) ? a->size : *left;
  if (a->size <= 0) {
     return(0);   //** Nothing in the buffer to send
  }

  err = get_splice_fds(res, &fd, a->id, pos, OSD_WRITE_MODE, task->ns, &sock_fd);
  if (err == -1) {
     log_printf(10, "read_from_disk_kernel: Error with get_splice_ids! ns=%d closing connection\n", ns->id);
     return(-1);
  }

  ntotal = *left;
  err = splice_kernel(fd, sock_fd, left, task->cmd_timeout,
         &(_res_splice_enabled[resource_get_type(res)]), &(_ns_splice_enabled[ns_get_type(task->ns)]));
  ntotal = ntotal - *left;

  resource_native_close_id(res, fd);  //** Don't forget to close it!

  a->r_pos += ntotal;
  a->size -= ntotal;
  task->stat.nbytes += ntotal;

  if (err < 0) {
     task_status = err;        //** Dead connection, timed out, or splice fail
     log_printf(10, "read_from_disk_kernel: Socket error with ns=%d err=%d\n", ns->id, err);
  } else {
     task_status = 0;

     if (*left == 0) {   //** Finished data transfer
        log_printf(10, "read_from_disk_kernel: Completed transfer! ns=%d tid=" LU " a.size=" I64T " a.w_pos=" I64T "\n", task->ns->id, task->tid, a->size, a->w_pos);
        task_status = 1;
     } else {
        log_printf(10, "read_from_disk_kernel: task_status=%d returning ns=%d back to caller.  a.size=" I64T " short read.  tid=" LU "\n", task_status, task->ns->id, a->size, task->tid);
     }
  }

  return(task_status);
}


//************************************************************************************
//  write_to_disk_kernel - Writes data to the disk buffer and transfers it using
//     kernel space buffers.  Return values are
//    -3 -- resource doesn't support splice
//    -2 -- ns doesn't support splice
//    -1 -- Dead connection
//     0 -- Transfered as much as data as possible
//     1 -- Completed provided task
//     2 -- Buffer full so block
//************************************************************************************

int write_to_disk_kernel(ibp_task_t *task, Allocation_t *a, ibp_off_t *left, Resource_t *res)
{
  ibp_off_t ntotal, pos, nleft;
  int task_status, err;
  ns_native_fd_t sock_fd;
  osd_native_fd_t fd;

  log_printf(10, "write_to_disk_kernel: id=" LU " ns=%d\n", a->id, task->ns->id);
return(-2);

  if (*left == 0) return(1);   //** Nothing to do

  task_status = 0;

  if ((a->size == 0) && (a->type != IBP_BYTEARRAY)) { a->r_pos = a->w_pos = 0; }

  pos = a->w_pos;
  nleft = *left;
  if (a->type == IBP_BYTEARRAY) {
     nleft = *left;   //** Already validated range in calling routine
  } else {  //** The code below doesn't support wrap around buffers!!!!!!!!!!!!!!!!!!!!!!!!
     nleft = (*left > (a->max_size - a->size)) ? (a->max_size - a->size) : *left;
  }

  ntotal = 0;
  debug_printf(10, "write_to_disk_kernel(BA): start.... id=" LU " * max_size=" I64T " * curr_size=" I64T " * max_transfer=" I64T " pos=" I64T " left=" I64T " ns=%d\n",
         a->id, a->max_size, a->size, nleft, pos, *left, task->ns->id);

  if (nleft == 0) {  //** no space to store anything
     return(0);
  }

  err = get_splice_fds(res, &fd, a->id, pos, OSD_WRITE_MODE, task->ns, &sock_fd);
  if (err == -1) {
     log_printf(10, "write_to_disk_kernel: Error with get_splice_ids! ns=%d closing connection\n", task->ns->id);
     return(-1);
  }

  ntotal = *left;
  err = splice_kernel(sock_fd, fd, left, task->cmd_timeout,
         &(_ns_splice_enabled[ns_get_type(task->ns)]), &(_res_splice_enabled[resource_get_type(res)]));
  ntotal = ntotal - *left;

  resource_native_close_id(res, fd);  //** Don't forget to close it!

  if (err < 0) {
     task_status = err;        //** Dead connection, timed out, or splice fail
     log_printf(10, "write_to_disk_kernel: Socket error with ns=%d err=%d\n", task->ns->id, err);
  } else {
     pos = pos + ntotal;
     if (a->type == IBP_BYTEARRAY) {
        if (pos > a->size) a->size = pos;
     } else {
       a->size += ntotal;
     }

     task->stat.nbytes += ntotal;
     a->w_pos = pos;
     task_status = 0;

     if (*left == 0) {   //** Finished data transfer
        log_printf(10, "write_to_disk_kernel: Completed transfer! ns=%d tid=" LU " a.size=" I64T " a.w_pos=" I64T "\n", task->ns->id, task->tid, a->size, a->w_pos);
        task_status = 1;
     } else {
        log_printf(10, "write_to_disk_kernel: task_status=%d returning ns=%d back to caller.  a.size=" I64T " short read.  tid=" LU "\n", task_status, task->ns->id, a->size, task->tid);
     }
  }

  return(task_status);
}

//************************************************************************************
// ---------------------------- User space routines ----------------------------------
//************************************************************************************

//************************************************************************************
//  disk_to_disk_copy_user - Copies data between allocations using user space buffers
//     IBP_OK - Successful copy
//     any other value  - error
//************************************************************************************

int disk_to_disk_copy_user(Resource_t *src_res, osd_id_t src_id, ibp_off_t src_offset,
                      Resource_t *dest_res, osd_id_t dest_id, ibp_off_t dest_offset, ibp_off_t len, apr_time_t end_time)
{
  int i;
  osd_fd_t *sfd, *dfd;
  ibp_off_t nleft, soff, doff, nbytes, err;

  const int bufsize = 1048576;
  char buffer[bufsize];

  log_printf(15, "disk_to_disk_copy_user: src_id=" LU " src_offset=" I64T " dest_id=" LU " dest_offset=" I64T "\n", src_id, src_offset, dest_id, dest_offset);

  nleft = len;
  soff = src_offset; doff = dest_offset;

  sfd = open_allocation(src_res, src_id, OSD_READ_MODE);
  if (sfd == NULL) {
     log_printf(0, "disk_to_disk_copy_user: Error with src open_allocation(-res-, " LU ", " I64T ", " I64T ", buffer) = %d\n", src_id, soff, len, errno);
     return(IBP_E_FILE_READ);
  }

  dfd = open_allocation(dest_res, dest_id, OSD_WRITE_MODE);
  if (dfd == NULL) {
     err = errno;
     log_printf(0, "disk_to_disk_copy_user: Error with dest open_allocation(-res-, " LU ", " I64T ", " I64T ", buffer) = " I64T "\n", dest_id, doff, len, err);
     close_allocation(dest_res, dfd);
     return(IBP_E_FILE_WRITE);
  }

  for (i=0; i<len; i=i+bufsize) {
     nbytes = (nleft > bufsize) ? bufsize : nleft;
     nleft = nleft - bufsize;
     err = read_allocation(src_res, sfd, soff, nbytes, buffer);
     if (err != 0) {
        log_printf(0, "disk_to_disk_copy_user: Error with read_allocation(-res-, " LU ", " I64T ", " I64T ", buffer) = " I64T "\n", src_id, soff, nbytes, err);
        close_allocation(src_res, sfd);
        close_allocation(dest_res, dfd);
        return(IBP_E_FILE_READ);
     }

     err = write_allocation(dest_res, dfd, doff, nbytes, buffer);
     if (err != 0) {
        log_printf(0, "disk_to_disk_copy_user: Error with write_allocation(-res-, " LU ", " I64T ", " I64T ", buffer) = " I64T "\n", dest_id, doff, nbytes, err);
        close_allocation(src_res, sfd);
        close_allocation(dest_res, dfd);
        return(IBP_E_FILE_WRITE);
     }

     soff = soff + nbytes;
     doff = doff + nbytes;
  }

  close_allocation(src_res, sfd);
  close_allocation(dest_res, dfd);

  return(IBP_OK);
}

//************************************************************************************
//  read_from_disk_user - Reads data from the disk buffer and transfers it using
//     "user space" bufers.  Return values are
//    -1 -- Dead connection
//     0 -- Transfered as much as data as possible
//     1 -- Completed provided task
//************************************************************************************

int read_from_disk_user(ibp_task_t *task, Allocation_t *a, ibp_off_t *left, Resource_t *res)
{
  NetStream_t *ns = task->ns;
  int bufsize = 2*1048576;
  osd_fd_t *fd;
  ibp_off_t  nbytes, nwrite, shortwrite, nleft, err;
  ibp_off_t bpos, btotal, bleft, ioff, ileft;
  char buffer[bufsize];
  Net_timeout_t dt;
  int task_status;
  int finished, index;
  ibp_off_t cleft;
  Cmd_state_t *cmd = &(task->cmd);
  Cmd_read_t *r = &(cmd->cargs.read);
  iovec_t *iovec = &(r->iovec);

  nbytes = a->size;
  log_printf(10, "read_from_disk: ns=%d id=" LU " a.size=" I64T " a.r_pos=" I64T " len=" I64T "\n", task->ns->id, a->id, nbytes, a->r_pos, *left);
flush_log();
  if (*left == 0) return(1);  //** Nothing to do

  task_status = 0;
  set_net_timeout(&dt, 1, 0);  //** set the max time we'll wait for data

  shortwrite = 0;

  fd = open_allocation(res, a->id, OSD_READ_MODE);
  if (fd == NULL) {
     log_printf(0, "read_disk_user: Error with open_allocation(-res-, " LU ") = %d\n", a->id,  errno);
     return(IBP_E_FILE_READ);
  }

  iovec_start(&(r->iovec), &index, &ioff, &ileft);

  nleft = *left;
  do {
     shortwrite = 0;

     //** Fill the buffer
     bpos = 0;
     bleft = bufsize;
     nbytes = 0;
     finished = 0;
     do {
        cleft = (bleft > ileft) ? ileft : bleft;
        err = read_allocation(res, fd, ioff, cleft, &(buffer[bpos]));
        if (err != 0) {
           char tmp[128];
           log_printf(0, "read_disk: Error with read_allocation(%s, " LU ", " I64T ", " I64T ", buffer) = " I64T "\n",
                ibp_rid2str(res->rid, tmp), a->id, ioff, cleft, err);
           shortwrite = 100;
           nwrite = err;
        }

        bleft -= cleft;
        bpos += cleft;
        ileft -= cleft;
        ioff += cleft;
        if ((ileft <= 0) && (index < (iovec->n-1))) {
           index++;
           ileft = iovec->vec[index].len;
           ioff = iovec->vec[index].off;
        } else if (index >= (iovec->n - 1)) {
           finished = 1;
        }
     } while ((bleft > 0) && (finished==0));

     //** and send it
     bleft = bpos;
     bpos = 0; btotal = 0;
     do {  //** Loop until data is completely sent or blocked
        nwrite = write_netstream(task->ns, &(buffer[bpos]), bleft, dt);
        if (nwrite > 0) {
           btotal += nwrite;
           bpos += nwrite;
           bleft -= nwrite;
           task->stat.nbytes += nwrite;
        } else if (nwrite == 0) {
           shortwrite++;
        } else {
           shortwrite = 100;  //** closed connection
        }

        log_printf(15, "read_from_disk: id=" LU " -- bpos=" I64T " bleft=" I64T ", ntotal=" I64T ", nwrite=" I64T " * shortwrite=" I64T " ns=%d\n",
             a->id, bpos, bleft, btotal, nwrite, shortwrite, task->ns->id);
     } while ((bleft > 0) && (shortwrite < 3));

     //** Update totals
     nleft -= btotal;
     *left -= btotal;
     a->r_pos += btotal;
     iovec->transfer_total += btotal;

     log_printf(15, "read_from_disk: nleft=" I64T " nwrite=" I64T " off=" I64T " shortwrite=" I64T "\n", nleft, nwrite, ioff, shortwrite);
  } while ((nleft > 0) && (shortwrite < 3));

  close_allocation(res, fd);

  if ((nwrite < 0) || (shortwrite >= 100)) {        //** Dead connection
     log_printf(10, "read_from_disk: Socket error with ns=%dfrom closing connection\n", ns->id);
     task_status = -1;
  } else {           //** short write
     if (*left == 0) {   //** Finished data transfer
        log_printf(10, "read_from_disk: Completed transfer! ns=%d tid=" LU "\n", task->ns->id, task->tid);
        task_status = 1;
     } else {
        log_printf(10, "read_from_disk: returning ns=%d back to caller.  short read.  tid=" LU "\n", task->ns->id, task->tid);
        task_status = 0;
     }
  }

  if (task_status != 0) {  //** Error on send so unwind the iovec buffer

  }

  return(task_status);
}

//************************************************************************************
//  write_to_disk_user - Writes data to the disk buffer and transfers it using
//     user space buffers.  Return values are
//    -1 -- Dead connection
//     0 -- Transfered as much as data as possible
//     1 -- Completed provided task
//     2 -- Buffer full so block
//************************************************************************************

int write_to_disk_user(ibp_task_t *task, Allocation_t *a, ibp_off_t *left, Resource_t *res)
{
  int bufsize = 2*1048576;
  ibp_off_t nbytes, ntotal, nread, nleft, err, cleft;
  Cmd_state_t *cmd = &(task->cmd);
  Cmd_write_t *w = &(cmd->cargs.write);
  iovec_t *iovec = &(w->iovec);
//char *buffer;
  char buffer[bufsize];
  Net_timeout_t dt;
  int task_status, shortread, index;
  osd_fd_t *fd;
  ibp_off_t bpos, ncurrread, ioff, ileft;
  log_printf(10, "write_to_disk_user: id=" LU " ns=%d\n", a->id, task->ns->id);

  if (*left == 0) return(1);   //** Nothing to do

  task_status = 0;
  set_net_timeout(&dt, 1, 0);  //** set the max time we'll wait for data

  shortread = 0;

  nleft = *left;
  if (a->type == IBP_BYTEARRAY) {
     nleft = *left;   //** Already validated range in calling routine
  } else {
     nleft = (*left > (a->max_size - a->size)) ? (a->max_size - a->size) : *left;
  }

  ntotal = 0;
  debug_printf(10, "write_to_disk_user(BA): start.... id=" LU " * max_size=" I64T " * curr_size=" I64T " * max_transfer=" I64T " left=" I64T " ns=%d\n",
         a->id, a->max_size, a->size, nleft, *left, task->ns->id);

  if (nleft == 0) {  //** no space to store anything
     return(0);
  }

  fd = open_allocation(res, a->id, OSD_WRITE_MODE);
  if (fd == NULL) {
     log_printf(0, "write_disk_user: Error with open_allocation(-res-, " LU ") = %d\n", a->id,  errno);
     return(IBP_E_FILE_WRITE);
  }

  iovec_start(&(w->iovec), &index, &ioff, &ileft);

  do {
     bpos = 0;
     nbytes = (nleft < bufsize) ? nleft : bufsize;
     do {
        ncurrread = read_netstream(task->ns, &(buffer[bpos]), nbytes, dt);
        if (ncurrread > 0) {
            nbytes -= ncurrread;
            bpos += ncurrread;
            task->stat.nbytes += ncurrread;
        } else if (ncurrread == 0) {
            shortread++;
        } else {
            shortread = 100;
        }
log_printf(10, "write_to_disk_user: id=" LU " ns=%d inner loop ncurrread= " I64T " bpos=" I64T " nbytes=" I64T " shortread=%d bufsize=" ST "\n",
    a->id, task->ns->id, ncurrread, bpos, nbytes, shortread, sizeof(buffer));
     } while ((nbytes > 0) && (shortread < 3));
     nread = bpos;

log_printf(10, "write_to_disk_user: id=" LU " ns=%d after loop ncurrread= " I64T " bpos=" I64T " shortread=%d\n", a->id, task->ns->id, ncurrread, bpos, shortread);

     if (nread > 0) {
        bpos = 0;
        do {
           cleft = (nread > ileft) ? ileft : nread;
           err = write_allocation(res, fd, ioff, cleft, &(buffer[bpos]));
           if (err != 0) {
              char tmp[128];
              log_printf(0, "write_to_disk_user: Error with write_allocation(%s, " LU ", " I64T ", " I64T ", buffer) = " I64T "  tid=" LU "\n",
                      ibp_rid2str(res->rid, tmp), a->id, ioff, cleft, err, task->tid);
              shortread = 100;
              nread = err;
           }

           ileft -= cleft;
           ioff += cleft;
           ntotal += cleft;
           iovec->transfer_total += cleft;
           nleft -= cleft;
           bpos += cleft;
           nread -= cleft;

           if (a->type == IBP_BYTEARRAY) {  //** Update the size before moving on
             if (ioff > a->size) a->size = ioff;
           }

           if ((ileft <= 0) && (index < (iovec->n-1))) {
              index++;
              ileft = iovec->vec[index].len;
              ioff = iovec->vec[index].off;
           }
        } while (nread > 0);
      } else {
         shortread++;
      }

     log_printf(15, "write_to_disk_user: id=" LU " left=" I64T " -- pos=" I64T ", nleft=" I64T ", ntotal=" I64T ", nread=" I64T " ns=%d shortread=%d\n",
              a->id, *left, ioff, nleft, ntotal, nread, task->ns->id, shortread);
  } while ((nleft > 0) && (shortread < 3));
//  } while ((ntotal < nleft) && (shortread < 3));

  *left = nleft;

  if (shortread >= 100) {        //** Dead connection
     log_printf(10, "write_to_disk_user: network error  ns=%d\n", ns_getid(task->ns));
     task_status = -1;
  } else {           //** short write
     task_status = 0;

     if (*left == 0) {   //** Finished data transfer
        log_printf(10, "write_to_disk_user: Completed transfer! ns=%d tid=" LU " a.size=" I64T "\n", task->ns->id, task->tid, a->size);
        task_status = 1;
     } else {
        log_printf(10, "write_to_disk_user: task_status=%d returning ns=%d back to caller.  a.size=" LU " short read.  tid=" LU "\n", task_status, task->ns->id, a->size, task->tid);
     }
  }

  close_allocation(res, fd);

//free(buffer);

  return(task_status);
}

//************************************************************************************
// ------------------------------ Wrapper routines------------------------------------
//************************************************************************************


//************************************************************************************
//  _buffer_transfer_init - Initializes the arrays
//************************************************************************************

void _buffer_transfer_init()
{
  memset(_ns_splice_enabled, 0, sizeof(_ns_splice_enabled));
  memset(_res_splice_enabled, 0, sizeof(_res_splice_enabled));

  _init_table = 0; //** DOn't need to do it again
}


//************************************************************************************
//  read_from_disk - Reads data from the disk buffer and transfers it.
//    Return values are
//    -1 -- Dead connection
//     0 -- Transfered as much as data as possible
//     1 -- Completed provided task
//************************************************************************************

int read_from_disk(ibp_task_t *task, Allocation_t *a, ibp_off_t *left, Resource_t *res)
{
  int ns_type, res_type, err;

  ns_type = ns_get_type(task->ns);
  res_type = resource_get_type(res);

  if (_init_table == 1) _buffer_transfer_init();

log_printf(15, "read_from_disk_ ns=%d splice=%d res=%s splice=%d\n",
   ns_getid(task->ns), _ns_splice_enabled[ns_type],
   res->name, _res_splice_enabled[res_type]);

  if ((_ns_splice_enabled[ns_type] == 1) && (_res_splice_enabled[res_type] == 1)) {
     err = read_from_disk_kernel(task, a, left, res);
     if (err < -1) return(read_from_disk_user(task, a, left, res));
  } else if ((_ns_splice_enabled[ns_type] == -1) || (_res_splice_enabled[res_type] == -1)) {
     return(read_from_disk_user(task, a, left, res));
  } else {  //** Need to test this combination
    if (ns_native_enabled(task->ns) == NULL) _ns_splice_enabled[ns_type] = -1;
    if (resource_native_enabled(res) == NULL) _res_splice_enabled[res_type] = -1;

    if ((ns_native_enabled(task->ns) != NULL) && (resource_native_enabled(res) != NULL)) {
        err = read_from_disk_kernel(task, a, left, res);
        if (err < -1) {  //** The kernel routines updated the failure table
           return(read_from_disk_user(task, a, left, res));
        } else {   //** Update the table for success
          if (_ns_splice_enabled[ns_type] == 0) _ns_splice_enabled[ns_type] = 1;
          if (_res_splice_enabled[res_type] == 0) _res_splice_enabled[res_type] = 1;
          return(err);
        }
    }
  }

  return(read_from_disk_user(task, a, left, res));
}

//************************************************************************************
//  write_to_disk - Writes data to the disk buffer and transfers it.
//    Return values are
//    -1 -- Dead connection
//     0 -- Transfered as much as data as possible
//     1 -- Completed provided task
//************************************************************************************

int write_to_disk(ibp_task_t *task, Allocation_t *a, ibp_off_t *left, Resource_t *res)
{
  int ns_type, res_type, err;

  ns_type = ns_get_type(task->ns);
  res_type = resource_get_type(res);

  if (_init_table == 1) _buffer_transfer_init();

log_printf(15, "write_to_disk_ ns=%d splice=%d res=%s splice=%d\n",
   ns_getid(task->ns), _ns_splice_enabled[ns_type],
   res->name, _res_splice_enabled[res_type]);

  if ((_ns_splice_enabled[ns_type] == 1) && (_res_splice_enabled[res_type] == 1)) {
     err = write_to_disk_kernel(task, a, left, res);
     if (err < -1) return(write_to_disk_user(task, a, left, res));
  } else if ((_ns_splice_enabled[ns_type] == -1) || (_res_splice_enabled[res_type] == -1)) {
     return(write_to_disk_user(task, a, left, res));
  } else {  //** Need to test this combination
    if (ns_native_enabled(task->ns) == NULL) _ns_splice_enabled[ns_type] = -1;
    if (resource_native_enabled(res) == NULL) _res_splice_enabled[res_type] = -1;

    if ((ns_native_enabled(task->ns) != NULL) && (resource_native_enabled(res) != NULL)) {
        err = write_to_disk_kernel(task, a, left, res);
        if (err < -1) {  //** The kernel routines updated the failure table
           return(write_to_disk_user(task, a, left, res));
        } else {   //** Update the table for success
          if (_ns_splice_enabled[ns_type] == 0) _ns_splice_enabled[ns_type] = 1;
          if (_res_splice_enabled[res_type] == 0) _res_splice_enabled[res_type] = 1;
          return(err);
        }
    }
  }

  return(write_to_disk_user(task, a, left, res));
}

//************************************************************************************
//  disk_to_disk_copy - Copies data between allocations.
//    Return values are
//    -1 -- Dead connection
//     0 -- Transfered as much as data as possible
//     1 -- Completed provided task
//************************************************************************************

int disk_to_disk_copy(Resource_t *src_res, osd_id_t src_id, ibp_off_t src_offset,
                      Resource_t *dest_res, osd_id_t dest_id, ibp_off_t dest_offset, ibp_off_t len, apr_time_t end_time)
{
  int src_type, dest_type, err;

  src_type = resource_get_type(src_res);
  dest_type = resource_get_type(dest_res);

  if (_init_table == 1) _buffer_transfer_init();

log_printf(15, "disk_to_disk_copy src_res=%s splice=%d dest_res=%s splice=%d\n",
   src_res->name, _res_splice_enabled[src_type],
   dest_res->name, _res_splice_enabled[dest_type]);

  if ((_res_splice_enabled[src_type] == 1) && (_res_splice_enabled[dest_type] == 1)) {
     err = disk_to_disk_copy_kernel(src_res, src_id, src_offset, dest_res, dest_id, dest_offset, len, end_time);
     if (err != IBP_OK) return(disk_to_disk_copy_user(src_res, src_id, src_offset, dest_res, dest_id, dest_offset, len, end_time));
  } else if ((_res_splice_enabled[src_type] == -1) || (_res_splice_enabled[dest_type] == -1)) {
     return(disk_to_disk_copy_user(src_res, src_id, src_offset, dest_res, dest_id, dest_offset, len, end_time));
  } else {  //** Need to test this combination
    if (resource_native_enabled(src_res) == NULL) _res_splice_enabled[src_type] = -1;
    if (resource_native_enabled(dest_res) == NULL) _res_splice_enabled[dest_type] = -1;

    if ((resource_native_enabled(src_res) != NULL) && (resource_native_enabled(dest_res) != NULL)) {
        err = disk_to_disk_copy_kernel(src_res, src_id, src_offset, dest_res, dest_id, dest_offset, len, end_time);
        if (err != IBP_OK) {  //** The kernel routines updated the failure table
           return(disk_to_disk_copy_user(src_res, src_id, src_offset, dest_res, dest_id, dest_offset, len, end_time));
        } else {   //** Update the table for success
          if (_res_splice_enabled[src_type] == 0) _res_splice_enabled[src_type] = 1;
          if (_res_splice_enabled[dest_type] == 0) _res_splice_enabled[dest_type] = 1;
          return(err);
        }
    }
  }

  return(disk_to_disk_copy_user(src_res, src_id, src_offset, dest_res, dest_id, dest_offset, len, end_time));
}
