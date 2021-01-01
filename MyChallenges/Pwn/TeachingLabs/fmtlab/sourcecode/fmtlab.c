#include<stdio.h>
#include<stdlib.h>

void initproc(){
  setvbuf(stdin,NULL,_IONBF,0);
  setvbuf(stdout,NULL,_IONBF,0);
  setvbuf(stderr,NULL,_IONBF,0);
  return;
}

void win(){
  system("/bin/sh");
  return;
}

int main(){
  initproc();
  int end=1;
  char buf[0x20];
  while(end){
    printf("Your message : ");
    scanf("%31s",buf);
    printf(buf); 
  }
  return 0;
}
