#include <stdio.h>
#include <string.h>

//*****************************************************************************
//*****************************************************************************
//*****************************************************************************

int main(int argc, const char **argv)
{
  int i, j;
  char *text, buffer[100];

  FILE *fd1 = fopen("dummy.txt", "w+"); fclose(fd1); fd1 = fopen("dummy.txt", "r+");
  FILE *fd2 = fopen("dummy.txt", "r+");

  text="0123456789";
  i = fwrite(text, 1, strlen(text), fd1); fflush(fd1);

  //** Get file size
//  j = fseek(fd2, 0, SEEK_END);
//  j = ftell(fd2);
//  i = fseek(fd1, 0, SEEK_END);
//  i = ftell(fd1);
//  printf("File size1=%d size2=%d\n", i, j);

  //** Read straddles EOF
  i = fseek(fd2, 6, SEEK_SET);
  i = fread(buffer, 1, 5, fd2);
  printf("Read straddles EOF: i=%d\n", i);

  //** Read beyond EOF
  i = fseek(fd2, 11, SEEK_SET);
  i = fread(buffer, 1, 5, fd2);
  printf("Read beyond EOF: i=%d\n", i);

  //** Get file size
  i = fseek(fd1, 0, SEEK_END);
  i = ftell(fd1);
  j = fseek(fd2, 0, SEEK_END);
  j = ftell(fd2);
  printf("File size1=%d size2=%d\n", i, j);

  fclose(fd1);
  fclose(fd2);

  return(0);
}

