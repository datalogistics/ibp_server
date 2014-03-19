#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "chksum.h"


//*************************************************************************
//*************************************************************************

int main(int argc, char **argv)
{
  char sig[CHKSUM_MAX_SIZE];
  char *data;
  int n, i, repcount;
  chksum_t cs;

  if (argc < 4) {
     printf("chksum_test type data rep_count\n");
     return(0);
  }

  i=1;
  if (strcmp(argv[i], "SHA1") == 0) {
     chksum_set(&cs, CHKSUM_SHA1);
  } else if (strcmp(argv[i], "SHA256") == 0) {
     chksum_set(&cs, CHKSUM_SHA256);
  } else if (strcmp(argv[i], "SHA512") == 0) {
     chksum_set(&cs, CHKSUM_SHA512);
  } else if (strcmp(argv[i], "MD5") == 0) {
     chksum_set(&cs, CHKSUM_MD5);
  } else {
     printf("Invalid chksum type.  Got %s should be SHA1, SHA256, SHA512, or MD5\n", argv[i]);
     abort();
  }
  i++;

  data = argv[i]; i++;


  repcount = atoi(argv[i]); i++;

  n = strlen(data);
  for (i=0; i<repcount; i++) {
     chksum_add(&cs, n, data);
  }

  chksum_get(&cs, CHKSUM_DIGEST_HEX, sig);

  printf("Data: \"%s\"  RepCount: %d\n", data, repcount);
  printf("Signature: %s\n", sig);

  return(0);
}
