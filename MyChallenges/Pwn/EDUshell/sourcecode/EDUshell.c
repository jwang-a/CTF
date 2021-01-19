#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>
#include<fcntl.h>
#include<sys/mman.h>
#include"SECCOMP.h"

struct sock_filter seccompfilter[]={
  BPF_STMT(BPF_LD | BPF_W | BPF_ABS, ArchField),
  BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
  BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
  BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SyscallNum),
  Allow(read),
  Allow(mmap),
  Allow(exit),
  Allow(exit_group),
  BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
};

struct sock_fprog filterprog={
  .len=sizeof(seccompfilter)/sizeof(struct sock_filter),
  .filter=seccompfilter
};

char flag[0x100];

void printerror(char *msg){
  puts(msg);
  _exit(0);
}

void apply_seccomp(){
  if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)) printerror("Seccomp Error");
  if(prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&filterprog)==-1) printerror("Seccomp Error");
  return;
}

void initproc(){
  setvbuf(stdin,NULL,_IONBF,0);
  setvbuf(stdout,NULL,_IONBF,0);
  setvbuf(stderr,NULL,_IONBF,0);
  return;
}

void loadflag(){
  int fd = open("flag",0,0);
  if(fd<0)
    printerror("load flag failed");
  if(read(fd,flag,0x100)<=0)
    printerror("load flag failed");
  apply_seccomp();
  return;
}

void exec(char *cmd){
  if(flag[0]=='\0') _exit(0);
  char *space=strchr(cmd,' ');
  if(space==NULL) _exit(0);
  cmd = space+1;
  void (*shellcode)() = mmap(NULL,0x1000,PROT_EXEC|PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
  strcpy((char *)shellcode,cmd);
  shellcode();
  return;
}

void help(){
  puts("EDU bash, version 0.0.1-release (x86_64-pc-linux-EDU)");
  puts("These shell commands are defined internally.  Type `help' to see this list.");
  puts("");
  puts(" Nope");
  return;
}

void cat(char *cmd){
  char *cursor=strchr(cmd,' ');
  if(cursor!=NULL) cursor+=1;
  else{
    scanf("%255[^\n]",cmd);
    getchar();
    cursor=cmd;
  }
  cmd = cursor;
  cursor=strchr(cmd,' ');
  if(cursor!=NULL) *cursor='\0';
  if(!strcmp(cmd,"flag")) puts("cat: flag: Permission denied");
  else if(!strcmp(cmd,"EDUshell")){
    char *buf=malloc(17021);
    if(buf==NULL) _exit(0);
    int fd=open("/dev/urandom",0,0);
    if(fd<0) _exit(0);
    if(read(fd,buf,17021)!=17021) _exit(0);
    if(write(1,buf,17021)!=17021) _exit(0);
  }
  else printf("cat: %s: No such file or directory\n",cmd);
}

void cmdnotfound(char *cmd){
  char *space=strchr(cmd,' ');
  if(space!=NULL) *space='\0';
  printf("-bash: %s: command not found\n",cmd);
  return;
}

int main(){
  char cmd[0x100];
  initproc();
  while(1){
    if(flag[0]=='\0') printf("nobody@EDUSHELL $ ");
    scanf("%255[^\n]",cmd);
    getchar();
    if(cmd[0]=='\0') continue;
    else if(!strncmp(cmd,"loadflag",8)) loadflag();
    else if(!strncmp(cmd,"exec",4)) exec(cmd);
    else if(!strncmp(cmd,"help",4)) help();
    else if(!strncmp(cmd,"whoami",6)) puts("nobody");
    else if(!strncmp(cmd,"ls",2)) puts("EDUshell flag");
    else if(!strncmp(cmd,"cat",3)) cat(cmd);
    else if(!strncmp(cmd,"exit",4)) exit(0);
    else cmdnotfound(cmd);
    cmd[0]='\0';
  }
  return 0;
}
