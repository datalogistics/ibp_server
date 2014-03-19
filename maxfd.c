#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>

int main(int argc, const char **argv)
{
  struct rlimit rlim;
  int lo, hi;
  int maxfd = sysconf(_SC_OPEN_MAX);
  int err = getrlimit(RLIMIT_NOFILE,&rlim);

  lo = rlim.rlim_cur;
  hi = rlim.rlim_max;
  printf("start maxfd=%d lo=%d hi=%d\n", maxfd, lo, hi);

  lo = 2*lo;
  rlim.rlim_cur = lo;
  rlim.rlim_max = hi;
  err = setrlimit(RLIMIT_NOFILE,&rlim);

  err = getrlimit(RLIMIT_NOFILE,&rlim);
  lo = rlim.rlim_cur;
  hi = rlim.rlim_max;
  printf("After change err=%d  lo=%d hi=%d\n", maxfd, lo, hi);

}

