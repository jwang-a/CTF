/*gcc -z now -z noexecstack -fstack-protector survey.c -o survey*/

#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include"SECCOMP.h"

struct sock_filter seccompfilter[]={
  BPF_STMT(BPF_LD | BPF_W | BPF_ABS, ArchField),
  BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
  BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
  BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SyscallNum),
  Allow(read),
  Allow(write),
  Allow(open),
  Allow(close),
  Allow(fstat),
  Allow(rt_sigreturn),
  Allow(brk),
  Allow(exit),
  Allow(exit_group),
  BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
};

struct sock_fprog filterprog={
  .len=sizeof(seccompfilter)/sizeof(struct sock_filter),
  .filter=seccompfilter
};

void apply_seccomp(){
  if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)){
    perror("Seccomp Error");
    exit(1);
  }
  if(prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&filterprog)==-1){
    perror("Seccomp Error");
    exit(1);
  }
  return;
}

int main(){
  apply_seccomp();
  char buf[0x10];
  printf("What is your name : ");
  fflush(stdout);
  read(STDIN_FILENO,buf,0x30);
  printf("Hello, %s\nLeave your message here : ", buf);
  fflush(stdout);
  read(STDIN_FILENO,buf,0x30);
  printf("We have received your message : %s\nThanks for your feedbacks\n");
  fflush(stdout);
  return 0;
}
