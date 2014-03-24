#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mntent.h>
#include <assert.h>

char *fname2dev(char *fname)
{
  FILE *fd;
  struct mntent minfo;
  char buffer[4096];
  char *apath, *dev;
  int len;

  apath = realpath(fname, NULL);
  dev = NULL;

  fd = setmntent("/etc/mtab", "r");
  assert(fd != NULL);

  while (getmntent_r(fd, &minfo, buffer, sizeof(buffer)) != NULL) {
     len = strlen(minfo.mnt_dir);
     if (strncmp(apath, minfo.mnt_dir, len) == 0) {
        if (strlen(apath) > len) {
           if ((apath[len] == '/') || (minfo.mnt_dir[len-1] == '/')) {
              if (dev) free(dev);
              dev = strdup(minfo.mnt_fsname);
           }
        } else {
          if (dev) free(dev);
          dev = strdup(minfo.mnt_fsname);
        }
     }
  }

  endmntent(fd);

  return(dev);
}

int main(int argc, char **argv)
{
  char *fname, *dev;

  if (argc != 2) {
    printf("mntparse fname\n");
    return(0);
  }

  fname = argv[1];
  dev = fname2dev(fname);
  if (dev == NULL) {
     printf("Missing device entry for fname=%s\n", fname);
  } else {
     printf("fname=%s maps to devic=%s\n",fname, dev);
  }

  return(0);
}

