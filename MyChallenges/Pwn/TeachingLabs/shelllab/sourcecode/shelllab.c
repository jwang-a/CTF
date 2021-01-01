/*gcc -z now -z noexecstack -fstack-protector shelllab.c -o shelllab*/

#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<sys/mman.h>
#include"SECCOMP.h"

struct sock_filter seccompfilter[]={
  BPF_STMT(BPF_LD | BPF_W | BPF_ABS, ArchField),
  BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
  BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
  BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SyscallNum),
  Allow(read),
  Allow(write),
  Allow(open),
  Allow(mmap),
  Allow(rt_sigreturn),
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

void initproc(){
  setvbuf(stdin,NULL,_IONBF,0);
  setvbuf(stdout,NULL,_IONBF,0);
  setvbuf(stderr,NULL,_IONBF,0);
  apply_seccomp();
  return;
}

int main(){
  initproc();
  void (*shellcode)() = mmap(NULL,0x100,PROT_EXEC|PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
  if(shellcode==(void*)-1){
    puts("mmap error");
    exit(0);
  }
  printf("Give me your shellcode : ");
  read(STDIN_FILENO,shellcode,0x100);
  shellcode();
  return 0;
}
