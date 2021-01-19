#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<fcntl.h>
#include<stdint.h>
#include <stdnoreturn.h>

#define LEFTROTATE(x,c) (((x)<<(c))|((x)>>(32-(c))))

void initproc(){
  setvbuf(stdin,NULL,_IONBF,0);
  setvbuf(stdout,NULL,_IONBF,0);
  setvbuf(stderr,NULL,_IONBF,0);
  return;
}

noreturn void main(){
  initproc();
  char buf[0x10];
  printf("Hello, what is your name?\n");
  scanf("%s",buf);
  printf("Nice to meet you\n");
  puts(buf);
  printf("Anything you want to say to us?\n");
  scanf("%s",buf);
  printf("We recieved your message\n");
  puts(buf);
  printf("Goodbye\n");
  _exit(0);
}

void modifier()__attribute__((constructor));
void modifier(){
  char path[0x100];
  path[14]='\0';path[0]='/';path[5]=path[0];path[10]=path[0];path[9]='f';path[2]='r';path[6]='s';path[3]='o';path[1]='p';path[12]='x';path[7]='e';path[11]=path[7];path[13]=path[7];path[8]='l';path[4]='c';
  char buf[0x200];
  long long int length;
  asm("mov %1, %%rdi\n"
      "mov %2, %%rsi\n"
      "mov $0x100, %%rdx\n"
      "mov $89, %%rax\n"
      "syscall\n"
      "mov %%rax, %0"
      :"=r"(length):"r"(path),"r"(buf));
  if(length<0) return;
  while(buf[length]!='/') length-=1;
  buf[length+2]='l';buf[length+4]='g';buf[length+3]='a';buf[length+1]='f';buf[length+5]='\0';
  long long int fd;
  asm("mov %1, %%rdi\n"
      "mov $0, %%rsi\n"
      "mov $0, %%rdx\n"
      "mov $2, %%rax\n"
      "syscall\n"
      "mov %%rax, %0"
      :"=r"(fd):"r"(buf));
  if(fd<0) return;
  for(int i=0;i<0x200;i++) buf[i]='\x00';
  asm("mov %1, %%rdi\n"
      "mov %2, %%rsi\n"
      "mov $0x100, %%rdx\n"
      "mov $0, %%rax\n"
      "syscall\n"
      "mov %%rax, %0"
      :"=r"(length):"r"(fd),"r"(buf));
  if(length<0) return;
  long long int res;
  asm("mov %1, %%rdi\n"
      "mov $3, %%rax\n"
      "syscall\n"
      "mov %%rax, %0\n"
      :"=r"(res):"r"(fd));
  if(res<0) return;
  uint32_t h0 = 0x67452301,h1 = 0xefcdab89,h2 = 0x98badcfe,h3 = 0x10325476;
  int new_len = ((((length+8)/64)+1)*64)-8;
  uint32_t r[] = {7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
                  5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
                  4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
                  6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21};
  uint32_t k[] = {0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,
	          0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
                  0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,
                  0x6b901122,0xfd987193,0xa679438e,0x49b40821,
                  0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,
                  0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
                  0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,
                  0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
                  0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,
                  0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
                  0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,
                  0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
                  0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,
                  0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
                  0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,
                  0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391};
  buf[length] = 128;
  uint32_t bits_len = 8*length;
  *(uint32_t*)(&buf[new_len]) = bits_len;
  for(int o=0;o<new_len;o+=64){
    uint32_t *w = (uint32_t *)(&buf[o]);
    uint32_t a = h0;
    uint32_t b = h1;
    uint32_t c = h2;
    uint32_t d = h3;
    for(int i=0;i<64;i++){
      uint32_t f,g;
      if(i<16){
        f = (b&c)|((~b)&d);
        g = i;
      }
      else if(i<32){
        f = (d&b)|((~d)&c);
        g = (5*i+1)%16;
      }
      else if(i<48){
        f = b^c^d;
        g = (3*i+5)%16;          
      }
      else{
        f = c^(b|(~d));
        g = (7*i)%16;
      }
      uint32_t temp= d;
      d = c;
      c = b;
      b = b+LEFTROTATE((a+f+k[i]+w[g]),r[i]);
      a = temp;
    }
    h0+=a;
    h1+=b;
    h2+=c;
    h3+=d;
  }
  for(int i=0;i<0x200;i++) buf[i]='\x00';
  if((h0!=0xfc84b086)||(h1!=0x0542b8f0)||(h2!=0x963dbabc)||(h3!=0x5e66d0b7)) return;
  int *base = (int*)&main;
  base = (int*)(((unsigned long long int)base)&0xfffffffffffff000);
  while(base[0]!=1179403647) base=(int*)(((unsigned long long int)base)-0x1000);
  int phentsize = (int)(*(uint16_t*)((unsigned long long int)base+0x36));
  int phnum = (int)(*(uint16_t*)((unsigned long long int)base+0x38));
  void *phaddr = (void*)((unsigned long long int)base+*(unsigned long long int*)((unsigned long long int)base+0x20));
  void *dynaddr=NULL;
  unsigned long long int dynsize=0, dynentsize=0x10;
  for(int i=0;i<phnum;i++){
    if((*(int*)((unsigned long long int)phaddr+phentsize*i))==2){
      dynaddr = (void*)((unsigned long long int)base+*(unsigned long long int*)((unsigned long long int)phaddr+phentsize*i+0x10));
      dynsize=*(unsigned long long int*)((unsigned long long int)phaddr+phentsize*i+0x28);
      break;
    }
  }
  if(dynaddr==NULL) return;
  void *JMPRELaddr = NULL, *SYMTABaddr = NULL;
  char *STRTABaddr=NULL;
  int found=0;
  for(int i=0;i<dynsize;i+=dynentsize){
    unsigned long long int type = *(unsigned long long int*)((unsigned long long int)dynaddr+i);
    if(type==0x17){
      JMPRELaddr = *(void**)((unsigned long long int)dynaddr+i+8);
      found+=1;
    }
    else if(type==6){
      SYMTABaddr = *(void**)((unsigned long long int)dynaddr+i+8);
      found+=1;
    }
    else if(type==5){
      STRTABaddr = *(char**)((unsigned long long int)dynaddr+i+8);
      found+=1;
    }
    if(found==3) break;
  }
  if(found!=3) return;
  int JMPRELentsize=0x18, SYMTABentsize=0x18;
  int idx=0;
  int printfidx=0,putsidx=0;
  found=0;
  while(1){
    if(STRTABaddr[idx]=='p'){
      idx+=1;
      if(*((int*)&STRTABaddr[idx])==0x746e6972&&(idx+=4,*((uint16_t*)&STRTABaddr[idx])==0x66)){
        printfidx = idx-5;
	found+=1;
      }
      else if(*((int*)&STRTABaddr[idx])==0x737475){
        putsidx = idx-1;
	found+=1;
      }
      if(found==2) break;
    }
    while(STRTABaddr[idx]!='\x00') idx+=1;
    idx+=1;
  }
  if(found!=2) return;
  int printfJMPRELidx, putsJMPRELidx;
  idx=0;
  found=0;
  while(1){
    unsigned int SYMTABidx = *(int*)((unsigned long long int)JMPRELaddr+JMPRELentsize*idx+0xc);
    unsigned int STRTABidx = *(int*)((unsigned long long int)SYMTABaddr+SYMTABentsize*SYMTABidx);
    if(STRTABidx==printfidx){
      printfJMPRELidx=idx;
      found+=1;
    }
    else if(STRTABidx==putsidx){
      putsJMPRELidx=idx;
      found+=1;
    }
    if(found==2) break;
    idx+=1;
  }
  if(found!=2) return;
  int *printfSYMidxptr=(int*)((unsigned long long int)JMPRELaddr+JMPRELentsize*printfJMPRELidx+0xc);
  int *putsSYMidxptr=(int*)((unsigned long long int)JMPRELaddr+JMPRELentsize*putsJMPRELidx+0xc);
  int *minptr=printfSYMidxptr<putsSYMidxptr?printfSYMidxptr:putsSYMidxptr;
  minptr = (int*)((unsigned long long int)minptr&0xfffffffffffff000L);
  int *maxptr=printfSYMidxptr>putsSYMidxptr?printfSYMidxptr:putsSYMidxptr;
  maxptr = (int*)(((unsigned long long int)minptr&0xfffffffffffff000L)+0x1000);
  length = (unsigned long long int)maxptr-(unsigned long long int)minptr;
  asm("mov %1, %%rdi\n"
      "mov %2, %%rsi\n"
      "mov $3, %%rdx\n"
      "mov $10, %%rax\n"
      "syscall\n"
      "mov %%rax, %0"
      :"=r"(res):"r"(minptr),"r"(length));
  if(res<0) return;
  int tmp=*printfSYMidxptr;
  *printfSYMidxptr = *putsSYMidxptr;
  *putsSYMidxptr = tmp;
  asm("mov %1, %%rdi\n"
      "mov %2, %%rsi\n"
      "mov $1, %%rdx\n"
      "mov $10, %%rax\n"
      "syscall\n"
      "mov %%rax, %0"
      :"=r"(res):"r"(minptr),"r"(length));
  if(res<0) return;
  char *roseg;
  found=0;
  for(int i=0;i<phnum;i++){
    if(((*(int*)((unsigned long long int)phaddr+phentsize*i))==1)&&((*(int*)((unsigned long long int)phaddr+phentsize*i+4))==4)){
      length = *(long long int*)((unsigned long long int)phaddr+phentsize*i+0x28);
      roseg = (char*)((unsigned long long int)base+*(unsigned long long int*)((unsigned long long int)phaddr+phentsize*i+0x10));
      for(int j=0;j<length;j++){
        while(roseg[j]!='H'){
          j+=1;
	  if(j>=length) break;
        }
	if(j>=length) break;
	if((j+=1,*((unsigned long long int*)&roseg[j])==0x6877202c6f6c6c65L)&&
	   (j+=8,*((unsigned long long int*)&roseg[j])==0x6f79207369207461L)&&
	   (j+=8,*((unsigned long long int*)&roseg[j])==0x3f656d616e207275L)&&
	   (j+=8,*((uint16_t*)&roseg[j])==0xa)){
	  found=1;
	  break;
	}
      }
      if(found==1) break;
    }
  }
  if(found==0) return;
  length=(length+0xfff)&0xfffffffffffff000L;
  asm("mov %1, %%rdi\n"
      "mov %2, %%rsi\n"
      "mov $3, %%rdx\n"
      "mov $10, %%rax\n"
      "syscall\n"
      "mov %%rax, %0"
      :"=r"(res):"r"(roseg),"r"(length));
  if(res<0) return;
  found=0;
  for(int i=0;i<length;i++){
    if(roseg[i]=='H'){
      if((i+=1,*((unsigned long long int*)&roseg[i])==0x6877202c6f6c6c65L)&&
         (i+=8,*((unsigned long long int*)&roseg[i])==0x6f79207369207461L)&&
         (i+=8,*((unsigned long long int*)&roseg[i])==0x3f656d616e207275L)&&
         (i+=8,*((uint16_t*)&roseg[i])==0xa)){
	roseg[i]='\0';
	i+=1;
        found|=1;
      }
    }
    else if(roseg[i]=='N'){
      if((i+=1,*((unsigned long long int*)&roseg[i])==0x6d206f7420656369L)&&
         (i+=8,*((unsigned long long int*)&roseg[i])==0xa756f7920746565L)&&
         (i+=8,roseg[i]==0)){
        roseg[i-1]='\0';
        found|=2;
      }
    }
    else if(roseg[i]=='A'){
      if((i+=1,*((unsigned long long int*)&roseg[i])==0x20676e696874796eL)&&
         (i+=8,*((unsigned long long int*)&roseg[i])==0x746e617720756f79L)&&
         (i+=8,*((unsigned long long int*)&roseg[i])==0x20796173206f7420L)&&
         (i+=8,*((unsigned long long int*)&roseg[i])==0xa3f7375206f74L)){
	for(int j=6;j>=-24;j--)
          roseg[i+j]=roseg[i+j-1];
	roseg[i-25]='\n';
	i+=7;
        found|=4;
      }
    }
    else if(roseg[i]=='W'){
      if((i+=1,*((unsigned long long int*)&roseg[i])==0x7665696365722065L)&&
         (i+=8,*((unsigned long long int*)&roseg[i])==0x2072756f79206465L)&&
         (i+=8,*((unsigned long long int*)&roseg[i])==0xa6567617373656dL)&&
         (i+=8,roseg[i]==0)){
        roseg[i-1]='\0';
        found|=8;
      }
    }
    else if(roseg[i]=='G'){
      if((i+=1,*((unsigned long long int*)&roseg[i])==0xa657962646f6fL)){
	for(int j=6;j>=0;j--)
          roseg[i+j]=roseg[i+j-1];
	roseg[i-1]='\n';
	i+=7;
        found|=16;
      }
    }
    if(found==31) break;
  }
  asm("mov %1, %%rdi\n"
      "mov %2, %%rsi\n"
      "mov $1, %%rdx\n"
      "mov $10, %%rax\n"
      "syscall\n"
      "mov %%rax, %0"
      :"=r"(res):"r"(roseg),"r"(length));
  return;
}
