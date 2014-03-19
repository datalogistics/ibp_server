#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <fcntl.h>
#include <linux/falloc.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>

int main(int argc, const char **argv)
{
  long int nbytes;
  long int dt;
  char fname[4096];
  char *path;
  int ifd, err;
  FILE *fd;

  if (argc < 3) {
     printf("%s nbytes_mb /dir/to/use\n", argv[0]);
     return(1);
  }

  nbytes = atol(argv[1]);
  path = argv[2];
  printf(" Creating a %ldMB files in directory %s\n", nbytes, path);
  nbytes *= 1024*1024;

  snprintf(fname, sizeof(fname), "%s/posix_fallocate.dat", path);
  fd = fopen(fname, "w");
  if (fd == NULL) {
     printf("ERROR creating file: %s\n", fname);
     return(1);
  }
  ifd = fileno(fd);

  dt = time(NULL);
  err = posix_fallocate(ifd, 0, nbytes);
  dt = time(NULL) - dt;
  printf("posix_fallocate dt=%ld\n", dt);
  fclose(fd);

//  remove(fname);

  if (err != 0) {
     printf("ERROR with posix_fallocate file: %s\n", fname);
     return(1);
  }


  snprintf(fname, sizeof(fname), "%s/fallocate.dat", path);
  fd = fopen(fname, "w");
  if (fd == NULL) {
     printf("ERROR creating file: %s\n", fname);
     return(1);
  }
  ifd = fileno(fd);

  dt = time(NULL);
  err = fallocate(ifd, FALLOC_FL_KEEP_SIZE, 0, nbytes);
//  err = fallocate(ifd, 0, 0, nbytes);
  dt = time(NULL) - dt;
  printf("fallocate dt=%ld\n", dt);
  fclose(fd);

//  remove(fname);

  if (err != 0) {
     printf("ERROR with fallocate file: %s errno=%d\n", fname, errno);
     return(1);
  }

  return(0);
}

