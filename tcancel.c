#include <pthread.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>


char *dirname = NULL;
DIR *dfd = NULL;
int timeout = 5;
int shutdown = 0;

#define handle_error_en(en, msg) \
        do { errno = en; perror(msg); exit(EXIT_FAILURE); } while (0)

static void *thread_func(void *ignored_argument)
{
  int s, n;
  struct dirent entry;
  struct dirent *result;
  char fname[4096];
  FILE *fd;

  /* Disable cancellation for a while, so that we don't
     immediately react to a cancellation request */
  s = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
  if (s != 0) handle_error_en(s, "pthread_setcancelstate");

  dfd = opendir(dirname);
  if (dfd == NULL) {
     printf("Can't open dir=%s\n", dirname);
     exit(1);
  }

  s = pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
  if (s != 0) handle_error_en(s, "pthread_setcancelstate");

  do {
     result = NULL;
     n = readdir_r(dfd, &entry,  &result);

     if ((n != 0) || (result == NULL)) {
        printf("thread: FINISHED n=%d result=%p\nRestarting\n)", n, result);

        closedir(dfd);
        dfd = opendir(dirname);
        if (dfd == NULL) {
           printf("thread: Can't open dir=%s\n", dirname);
           exit(1);
        }
     } else {
       printf("thread: n=%d entry=%s\n", n, result->d_name); fflush(stdout);
       snprintf(fname, sizeof(fname), "%s/%s", dirname, result->d_name);
       fd = fopen(fname, "r");
       if (fd == NULL) {
          printf("Can't open file entry=%s\n", result->d_name);
       } else {
          fseeko(fd, 0, SEEK_END);
          n = ftell(fd;
          fclose(fd);
          printf("entry=%s size=%d\n", result->d_name, n);
       }
       sleep(timeout);
       printf("thread: Reading next entry shutdown=%d\n", shutdown); fflush(stdout);
     }
  } while (shutdown == 0);

  /* Should never get here */
  printf("thread_func(): not canceled!\n");
  return NULL;
}

int main(int argc, char **argv)
{
  pthread_t thr;
  void *res;
  int s;
  char string[512];

  if (argc < 3) {
     printf("tcancel sleep directory\n");
     exit(0);
  }

  timeout = atoi(argv[1]);
  dirname = argv[2];

  printf("main: sleep=%d dirname=%s\n", timeout, dirname);
  printf("main: Press enter to signal thread\n");

  /* Start a thread and then send it a cancellation request */
  s = pthread_create(&thr, NULL, &thread_func, NULL);
  if (s != 0) handle_error_en(s, "pthread_create");

  scanf("%s", string);

  printf("main: Waiting before cancel\n");
  shutdown = 1;
  sleep(timeout+2);           /* Give thread a chance to get started */

  printf("main: sending cancellation request\n");
  s = pthread_cancel(thr);
  if (s != 0) handle_error_en(s, "pthread_cancel");

  /* Join with thread to see what its exit status was */
  s = pthread_join(thr, &res);
  if (s != 0) handle_error_en(s, "pthread_join");

  if (res == PTHREAD_CANCELED) {
    printf("main: thread was canceled closedir()=%d\n", closedir(dfd));
    printf("main: Press enter to exit\n");
    scanf("%s", string);
  } else {
    printf("main: thread wasn't canceled (shouldn't happen!)\n");
  }

  exit(EXIT_SUCCESS);
}

