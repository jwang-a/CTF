/*gcc -fPIE -z now -z noexecstack -fstack-protector stashlab.c -o stashlab*/

#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<sys/mman.h>

#define NOTEMAX 0x20
#define MINSIZE 0x8
#define MAXSIZE 0x88

typedef struct{
  unsigned long long int size;
  unsigned long long int uuid;
  char data[1];
}NOTE;

char *target;
NOTE *notes[NOTEMAX];

void printerror(char *msg){
  puts(msg);
  exit(0);
}

void initproc(){
  setvbuf(stdin,NULL,_IONBF,0);
  setvbuf(stdout,NULL,_IONBF,0);
  setvbuf(stderr,NULL,_IONBF,0);
  target = mmap(NULL,0x1000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
  char *chunk = malloc(0x18);
  if(target==NULL || chunk==NULL)
    printerror("mmap error");
  printf("Lock address : %p\n",&(((unsigned long long int*)target)[3]));
  printf("Chunk address : %p\n",chunk);
  return;
}

void readstr(char *buf, unsigned long long int length){
  int res = read(STDIN_FILENO, buf, length);
  if(res<=0)
    printerror("read error");
  if(buf[res-1]=='\n')
    buf[res-1]='\0';
  return;
}

unsigned long long int readint(){
  char buf[0x20]="\0";
  readstr(buf,0x18);
  return atoll(buf);
}

int menu(){	
  puts("========Menu========");
  puts(" 1. Create Note");
  puts(" 2. Edit Note");
  puts(" 3. Delete Note");
  puts(" 4. Create Super Note");
  puts(" 5. Backdoor");
  puts(" 6. Leave");
  puts("====================");
  printf("Choice >");
  return readint();
}

void create(){
  int idx;
  for(idx=0;idx<NOTEMAX;idx++)
    if(notes[idx]==NULL)
      break;
  if(idx==NOTEMAX){
    puts("Notes full");
    return;
  }
  printf("Note size : ");
  unsigned long long int size = readint();
  if(size<MINSIZE || size>MAXSIZE){
    puts("Invalid note size");
    return;
  }
  notes[idx] = calloc(1,size+0x10);
  if(notes[idx]==NULL)
    printerror("allocate error");
  notes[idx]->size = size;
  printf("UUID : ");
  notes[idx]->uuid = readint();
  printf("Content : ");
  readstr(notes[idx]->data,size);
  return;
}

void edit(){
  printf("Note index : ");
  unsigned int idx = readint();
  if(idx<0 || idx>=NOTEMAX || notes[idx]==NULL){
    puts("Invalid index");
    return;
  }
  printf("UUID : ");
  notes[idx]->uuid = readint();
  return;
}

void delete(){
  printf("Note index : ");
  unsigned int idx = readint();
  if(idx<0 || idx>=NOTEMAX || notes[idx]==NULL){
    puts("Invalid index");
    return;
  }
  free(notes[idx]);
  return;
}

void super(){
  printf("Note size : ");
  unsigned long long int size = readint();
  if(size<MINSIZE || size>MAXSIZE){
    puts("Invalid note size");
    return;
  }
  NOTE *supernote = malloc(size+0x10);
  if(notes==NULL)
    printerror("allocate error");
  supernote->size = size;
  printf("UUID : ");
  supernote->uuid = readint();
  printf("Content : ");
  readstr(supernote->data,size);
  return;
}

void backdoor(){
  if(((unsigned long long int*)target)[3]!=0){
    puts("Here is your shell");
    execve("/bin/sh",NULL,NULL);
    exit(0);
  }
  puts("Backdoor locked");
  return;
}

int main(){
  initproc();
  while(1){
    switch(menu()){
      case 1:
        create();
        break;
      case 2:
	edit();
        break;
      case 3:
	delete();
        break;
      case 4:
	super();
	break;
      case 5:
	backdoor();
        break;
      case 6:
	puts("Goodbye");
	return 0;
      default:
	puts("No such instruction");
	break;
    }
  }
  return 0;
}

