/*gcc -no-pie -z relro gotlab.c -o gotlab*/
#include<stdio.h>
#include<stdlib.h>

void initproc(){
  setvbuf(stdin,NULL,_IONBF,0);
  setvbuf(stdout,NULL,_IONBF,0);
  setvbuf(stderr,NULL,_IONBF,0);
  return;
}

int main(){
  unsigned long long int *P; 
  initproc();
  printf("address : ");
  scanf("%llu",&P);
  printf("%llx\n",*P);
  printf("address : ");
  scanf("%llu",&P);
  printf("value : ");
  scanf("%llu",P);
  exit(0);
}
