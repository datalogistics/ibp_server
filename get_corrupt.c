#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include "network.h"
#include "net_sock.h"
#include "log.h"
#include "dns_cache.h"
#include "string_token.h"
#include "cmd_send.h"

//*************************************************************************
//*************************************************************************

int main(int argc, char **argv)
{
  int bufsize = 1024*1024;
  char buffer[bufsize], *bstate;
  int err;
  int n, i;
  NetStream_t *ns;
  Net_timeout_t dt;

  if (argc < 4) {
     printf("get_corrupt host port rid [timeout]\n");
     return(0);
  }

  char cmd[512];
  char *host = argv[1];
  int port = atoi(argv[2]);
  char *rid = argv[3];
  int timeout = 15;

  if (argc == 5) timeout = atoi(argv[4]);

  sprintf(cmd, "1 93 %s %d\n", rid, timeout);

  assert(apr_initialize() == APR_SUCCESS);

  dns_cache_init(10);

  ns = cmd_send(host, port, cmd, &bstate, timeout);

  //** Get the number of corrupt allocations
  n = atoi(string_token(NULL, " ", &bstate, &err));

  printf("Corrupt Allocation count: %d\n", n);

  //** and read them in
  set_net_timeout(&dt, timeout, 0);
  for (i=0; i<n; i++) {
     err = readline_netstream(ns, buffer, sizeof(buffer), dt);
     printf("%s\n", buffer);
  }

  //** Close the connection
  close_netstream(ns);

  apr_terminate();

  return(0);
}
