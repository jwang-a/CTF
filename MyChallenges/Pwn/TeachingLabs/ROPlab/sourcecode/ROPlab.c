#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

void initproc(){
  setvbuf(stdin,NULL,_IONBF,0);
  setvbuf(stdout,NULL,_IONBF,0);
  setvbuf(stderr,NULL,_IONBF,0);
  return;
}

int main(){
  initproc();
  char buf[0x10]="\0";
  printf("What is your name : ");
  read(STDIN_FILENO,buf,0x100);
  printf("Hello %s\nLeave your message here : ",buf);
  read(STDIN_FILENO,buf,0x100);
  printf("We have received your message : %s\nAny additional remarks? ");
  read(STDIN_FILENO,buf,0x100);
  printf("Thanks for your feedback");
  return 0;
}
