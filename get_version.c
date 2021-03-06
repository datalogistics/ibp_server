#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
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

//** This is a hack to not have to have the ibp source
#define IBP_OK 1
#define IBP_E_OUT_OF_SOCKETS -66

//*************************************************************************
//*************************************************************************

int main(int argc, char **argv)
{
  int bufsize = 1024*1024;
  char buffer[bufsize], *bstate;
  int n;
  Net_timeout_t dt;
  NetStream_t *ns;
  char cmd[512];
  char *host;
  int port = 6714;
  int timeout = 15;


  if (argc < 2) {
     printf("get_version -a | host [port timeout]\n");
     printf("   -a   -Use the local host and default port\n");
     return(0);
  }

  if (strcmp(argv[1], "-a") == 0) {
    host = (char *)malloc(1024);
    gethostname(host, 1023);
  } else {
    host = argv[1];
  }

  if (argc > 2) port = atoi(argv[2]);
  if (argc == 4) timeout = atoi(argv[3]);
  set_net_timeout(&dt, timeout, 0);

  sprintf(cmd, "1 4 5 %d\n", timeout);  // IBP_ST_VERSION command

  assert(apr_initialize() == APR_SUCCESS);

  dns_cache_init(10);

  ns = cmd_send(host, port, cmd, &bstate, timeout);
  if (ns == NULL) return(-1);
  if (bstate != NULL) free(bstate);

  //** Read the result.  Termination occurs when the line "END" is read.
  //** Note that readline_netstream strips the "\n" from the end of the line
  n = NS_OK;
  while (n == NS_OK) {
     n = readline_netstream(ns, buffer, bufsize, dt);
     if (n == NS_OK) {
        if (strcmp(buffer, "END") == 0) {
           n = NS_OK+1;
        } else {
           printf("%s\n", buffer);
        }
     }
  }

  //** Close the connection
  close_netstream(ns);

  apr_terminate();
  return(0);
}
