#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <errno.h>
#include "allocation.h"
#include "ibp_ClientLib.h"
#include "ibp_server.h"
#include "network.h"
#include "log.h"
#include "dns_cache.h"
#include "fmttypes.h"
#include "subnet.h"
#include "ibp_time.h"

void print_manage_history(Allocation_manage_ts_t *ts_list, int start)
{
  char print_time[128];
  char print_time2[128];
  char hostip[256];
  char *cmd, *subcmd, *rel;
  apr_time_t t, t2;
  int i, slot;
  Allocation_manage_ts_t *ts;

  for (i=0; i<ALLOC_HISTORY; i++) {
     slot = (i + start) % ALLOC_HISTORY;
     ts = &(ts_list[slot]);

     t = ibp2apr_time(ts->ts.time);
     if (t != 0) {
        switch (ts->subcmd) {
          case IBP_PROBE: subcmd = "IBP_PROBE"; break;
          case IBP_INCR : subcmd = "IBP_INCR "; break;
          case IBP_DECR : subcmd = "IBP_DECR "; break;
          case IBP_CHNG : subcmd = "IBP_CHNG "; break;
          default : subcmd = "UNKNOWN";
        }

        switch (ts->cmd) {
          case IBP_MANAGE:         cmd = "IBP_MANAGE       "; break;
          case IBP_ALIAS_MANAGE:   cmd = "IBP_ALIAS_MANAGE "; break;
          case IBP_RENAME:         cmd = "IBP_RENAME        "; subcmd = "        "; break;
          case IBP_ALIAS_ALLOCATE: cmd = "IBP_ALIAS_ALLOCATE"; subcmd = "        "; break;
          default : cmd = "UNKNOWN";
        }

        switch (ts->reliability) {
          case ALLOC_HARD: rel = "IBP_HARD"; break;
          case ALLOC_SOFT: rel = "IBP_SOFT"; break;
          default : rel = "UNKNOWN";
        }

        apr_ctime(print_time, t);
        t2 = ibp2apr_time(ts->expiration);
        apr_ctime(print_time2, t2);
        address2ipdecstr(hostip, ts->ts.host.ip, ts->ts.host.atype);
        if ((ts->cmd == IBP_ALIAS_ALLOCATE) || (ts->cmd == IBP_ALIAS_MANAGE)) {
          printf("   " TT " * %s  * %s * " LU " * %s * %s * " LU " * " LU " * " TT " * %s\n", t, print_time, hostip, ts->id, cmd, subcmd, ts->reliability, ts->size, t2, print_time2);
        } else {
          printf("   " TT " * %s  * %s * " LU " * %s * %s * %s * " LU " * " TT " * %s\n", t, print_time, hostip, ts->id, cmd, subcmd, rel, ts->size, t2, print_time2);
        }
     }
  }
}

void print_rw_history(Allocation_rw_ts_t *ts_list, int start)
{
  char print_time[128];
  char hostip[256];
  apr_time_t t;
  int i, slot;
  Allocation_rw_ts_t *ts;

  for (i=0; i<ALLOC_HISTORY; i++) {
     slot = (i + start) % ALLOC_HISTORY;
     ts = &(ts_list[slot]);

     t = ibp2apr_time(ts->ts.time);
     if (t != 0) {
        apr_ctime(print_time, t);
        address2ipdecstr(hostip, ts->ts.host.ip, ts->ts.host.atype);
        printf("   " TT " * %s * %s * " LU " * " LU " * " LU "\n", t, print_time, hostip, ts->id, ts->offset, ts->size);
     }
  }
}

//*************************************************************************
//*************************************************************************

int main(int argc, char **argv)
{
  int bufsize = 1024*1024;
  char buffer[bufsize], *bstate;
  Allocation_t a;
  int err, type_key;
  int n, npos;
  Net_timeout_t dt;
  apr_time_t t;

  if (argc < 5) {
     printf("date_spacefree host port RID key_type key\n");
     printf("where key_type is read|write|manage|id\n");
     return(0);
  }

  assert(apr_initialize() == APR_SUCCESS);

  char *host = argv[1];
  int port = atoi(argv[2]);
  char *rid = argv[3];
  char *key = argv[5];

  if (strcmp("read", argv[4])==0) {
     type_key = IBP_READCAP;
  } else if (strcmp("write", argv[4])==0) {
     type_key = IBP_WRITECAP;
  } else if (strcmp("manage", argv[4])==0) {
     type_key = IBP_MANAGECAP;
  } else if (strcmp("id", argv[4])==0) {
     type_key = INTERNAL_ID;
  } else {
     printf("invalid type_key = %s\n", argv[3]);
    return(1);
  }

  dns_cache_init(10);

  NetStream_t *ns = new_netstream();
  set_net_timeout(&dt, 5, 0);

  err = net_connect(ns, host, port, dt);
  if (err != 0) {
     printf("get_alloc:  Can't connect to host!  host=%s port=%d  err=%d\n", host, port, err);
     return(err);
  }

  sprintf(buffer, "1 %d %s %d %s 10\n", INTERNAL_GET_ALLOC, rid, type_key, key);
  n = write_netstream(ns, buffer, strlen(buffer), dt);
  n = readline_netstream(ns, buffer, bufsize, dt);
  if (n > 0) {
     n = atoi(string_token(buffer, " ", &bstate, &err));
     if (n != IBP_OK) {
        printf("Error %d returned!\n", n);
        close_netstream(ns);
        return(n);
     }
  }

  //** Read the Allocation ***
  npos = 0;
  bufsize = sizeof(Allocation_t);
  while (bufsize > 0) {
     n = read_netstream(ns, &(buffer[npos]), bufsize, dt);
     if (n > 0) {
        npos = npos + n;
        bufsize = bufsize - n;
     }
  }

  memcpy(&a, buffer, sizeof(Allocation_t));

  close_netstream(ns);

  //** Print the allocation information
  printf("Allocation summary\n");
  printf("-----------------------------------------\n");
  printf("ID: " LU "\n", a.id);
  t = ibp2apr_time(a.creation_ts.time);
  apr_ctime(print_time, t);
  address2ipdecstr(hostip, a.creation_ts.host.ip, a.creation_ts.host.atype);
  printf("Created on: " TT " -- %s by host %s\n", t, print_time, hostip);
  t = ibp2apr_time(a.expiration);
  apr_ctime(print_time, t);
  if (apr_time_now() > t) {
     printf("Expiration: " TT " -- %s (EXPIRED)\n", t, print_time);
  } else {
     printf("Expiration: " TT " -- %s\n", t, print_time);
  }

  printf("is_alias: %d\n", a.is_alias);
  printf("Read cap: %s\n", a.caps[READ_CAP].v);
  printf("Write cap: %s\n", a.caps[WRITE_CAP].v);
  printf("Manage cap: %s\n", a.caps[MANAGE_CAP].v);

  switch (a.type) {
    case IBP_BYTEARRAY: printf("Type: IBP_BYTEARRAY\n"); break;
    case IBP_BUFFER: printf("Type: IBP_BUFFER\n"); break;
    case IBP_FIFO: printf("Type: IBP_FIFO\n"); break;
    case IBP_CIRQ: printf("Type: IBP_CIRQ\n"); break;
    default: printf("Type: (%d) UNKNOWN TYPE!!!! \n", a.type); break;
  }

  switch (a.reliability) {
    case ALLOC_HARD: printf("Reliability: IBP_HARD\n"); break;
    case ALLOC_SOFT: printf("Reliability: IBP_SOFT\n"); break;
    default: printf("Reliability: (%d) UNKNOWN RELIABILITY!!!\n", a.reliability);
  }

  printf("Current size: " LU "\n", a.size);
  printf("Max size: " LU "\n", a.max_size);
  printf("Read pos: " LU "\n", a.r_pos);
  printf("Write pos: " LU "\n", a.w_pos);
  printf("Read ref count: %u\n", a.read_refcount);
  printf("Write ref count: %u\n", a.write_refcount);

  if (a.is_alias) {
     printf("Alias offset: " LU "\n", a.alias_offset);
     printf("Alias size: " LU "\n", a.alias_size);
     printf("Alias ID: " LU "\n", a.alias_id);

  }

  printf("\n");
  printf("Read history (slot=%d) (epoch, time, host, id, offset, size\n", a.read_slot);
  printf("---------------------------------------------\n");
  print_rw_history(a.read_ts, a.read_slot);

  printf("\n");
  printf("Write history (slot=%d) (epoch, time, host, id, offset, size)\n", a.write_slot);
  printf("---------------------------------------------\n");
  print_rw_history(a.write_ts, a.write_slot);

  printf("\n");
  printf("Manage history (slot=%d) (epoch, time, host, id, cmd, subcmd, reliability, size, expiration_epoch, expiration)\n", a.manage_slot);
  printf("---------------------------------------------\n");
  print_manage_history(a.manage_ts, a.manage_slot);

  printf("\n");

  apr_terminate();
  return(0);
}
