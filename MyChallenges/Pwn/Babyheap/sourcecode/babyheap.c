/*gcc -Wl,-z,now -fpie -fstack-protector-all babyheap.c -o babyheap*/
#include<stdio.h>
#include<stdlib.h>
#include"SECCOMP.h"

#define MINSIZE 0x78
#define MAXSIZE 0x408
#define CREATE_QUOTA 10
#define SHOW_QUOTA 2
#define EDIT_QUOTA 1
#define DELETE_QUOTA 8
#define ULTRA_QUOTA 2

char *chunk = NULL;
unsigned int chunksize = 0;
unsigned int create_quota = CREATE_QUOTA;
unsigned int show_quota = SHOW_QUOTA;
unsigned int edit_quota = EDIT_QUOTA;
unsigned int delete_quota = DELETE_QUOTA;
unsigned int ultra_quota = ULTRA_QUOTA;

struct sock_filter seccompfilter[]={
  BPF_STMT(BPF_LD | BPF_W | BPF_ABS, ArchField),
  BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
  BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
  BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SyscallNum),
  Allow(read),
  Allow(write),
  Allow(open),
  Allow(fstat),
  Allow(mprotect),
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

void init_proc(){
  apply_seccomp();
  return;
}

void printerror(char *msg){
  perror(msg);
  exit(0);
}

int menu(){
  puts("==============");
  puts("📚  babyheap 📚 ");
  puts("==============");
  puts("  [C]reate    ");
  puts("  [S]how      ");
  puts("  [E]dit      ");
  puts("  [D]elete    ");
  puts("  [U]ltra     ");
  puts("==============");
  printf("choice : ");
  fflush(stdout);
  return getchar();
}

void create(){
  if(create_quota==0){
    puts("Nope");
    return;
  }
  create_quota--;
  unsigned int size;
  printf("Size : ");
  fflush(stdout);
  if(scanf("%4u",&size)!=1)
    printerror("scanf error");
  getchar();
  if(size<MINSIZE || size>MAXSIZE){
    puts("Nope");
    return;
  }
  chunk = calloc(1,size);
  if(chunk==NULL)
    printerror("calloc error");
  chunksize = size;
  printf("Data : ");
  fflush(stdout);
  if(fgets(chunk,chunksize,stdin)==NULL)
    printerror("fgets error");
  return;
}

void show(){
  if(show_quota==0 || chunk==NULL){
    puts("Nope");
    return;
  }
  show_quota--;
  puts(chunk);
  return;
}

void edit(){
  if(edit_quota==0 || chunk==NULL){
    puts("Nope");
    return;
  }
  edit_quota--;
  printf("Data : ");
  fflush(stdout);
  if(fgets(chunk,chunksize,stdin)==NULL)
    printerror("fgets error");
  return;
}

void delete(){
  if(delete_quota==0 || chunk==NULL){
    puts("Nope");
    return;
  }
  delete_quota--;
  free(chunk);
  return;
}

void ultra(){
  char *ptr = malloc(0x18);
  printf("Data : ");
  fflush(stdout);
  if(fgets(ptr,0x18,stdin)==NULL)
    printerror("fgets error");
  return;
}

int main(){
  init_proc();
  while(1){
    switch(menu()){
      case 'C':
        create();
        break;
      case 'S':
        show();
        break;
      case 'E':
        edit();
        break;
      case 'D':
        delete();
        break;
      case 'U':
        ultra();
        break;
      default:
        puts("Nope");
        break;
    }
  }
  return 0;
}
