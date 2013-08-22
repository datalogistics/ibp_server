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
#include <time.h>
#include <assert.h>
#include "allocation.h"
#include "allocation_v1-1-6.h"
#include "ibp_ClientLib.h"
#include "ibp_server.h"
#include "log.h"
#include "fmttypes.h"
#include "subnet.h"

#define HEADER_SIZE 4096

void migrate_allocation_v120(Allocation_v116_t *olda, Allocation_t *a)
{
 //** Clear the new record ***
  memset(a, 0, sizeof(Allocation_t));

  //** Migrate existing data ***
  a->expiration = olda->expiration;
  a->id = olda->id;
  a->size = olda->size;
  a->max_size = olda->max_size;
  a->r_pos = olda->r_pos;
  a->w_pos = olda->w_pos;
  a->type = olda->type;
  a->reliability = olda->reliability;
  a->read_refcount = olda->read_refcount;
  a->write_refcount = olda->write_refcount - 1;  //** The old alloc defaulted this to 1
  memcpy(a->caps[0].v, olda->caps[0].v, CAP_SIZE+1);
  memcpy(a->caps[1].v, olda->caps[1].v, CAP_SIZE+1);
  memcpy(a->caps[2].v, olda->caps[2].v, CAP_SIZE+1);

  //** Init the new fields as needed **
  a->is_alias = 0;   //** Technically don't need to to this cause of the memset but it's a reminder
}

//*************************************************************************
//*************************************************************************

int main(int argc, char **argv)
{
  Allocation_t new_a;
  Allocation_v116_t old_a;
  FILE *afd;
  int err;

  if (argc < 2) {
     printf("migrate_alloc rid_file\n");
     printf("\n");
     return(0);
  }

  char *afile = argv[1];

  afd = fopen(afile, "r+");
  assert(afd != NULL);

  //** Read the old Allocation ***
  err = fread(&old_a, sizeof(old_a), 1, afd);

  migrate_allocation_v120(&old_a, &new_a);   //** Migrate the data

  fseek(afd, 0, SEEK_SET);
  fwrite(&new_a, sizeof(new_a), 1, afd);

  fclose(afd);

  return(0);
}
