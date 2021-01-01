#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

void vuln(){
  char buf[0x10]="\0";
  printf("Data : ");
  read(STDIN_FILENO,buf,0x100);
  printf("%s\n",buf);
  getchar();
  return;
}

int main(){
  setvbuf(stdin,NULL,_IONBF,0);
  setvbuf(stdout,NULL,_IONBF,0);
  setvbuf(stderr,NULL,_IONBF,0);

  puts("how2leak");
  vuln();
  puts("done");

  return 0;
}
