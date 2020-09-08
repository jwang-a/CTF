/*gcc -z now -z noexecstack -fpie -fstack-protector formatfree.c -o formatfree*/

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
  char name[0x40]="\0";
  char buf[0x200]="\0";
  printf("Your name : ");
  scanf("%63s",name);
  printf("Hello %s, here is a little gift for you %p\n",name,&system);
  printf("Feedback : ");
  scanf("%511s",buf);
  puts("Your feedback");
  printf(buf);
  printf("Thank you %s, have a great day\n",name);
  _exit(0);
}
