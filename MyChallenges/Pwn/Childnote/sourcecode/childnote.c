/*gcc -fPIE -z now -z noexecstack -fstack-protector childnote.c -o childnote*/

#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

#define NOTEMAX 0x11
#define MINSIZE 0x80
#define MAXSIZE 0x100

typedef struct{
  unsigned long long int size;
  char data[1];
}NOTE;

NOTE *notes[NOTEMAX];

void initproc(){
  setvbuf(stdin,NULL,_IONBF,0);
  setvbuf(stdout,NULL,_IONBF,0);
  setvbuf(stderr,NULL,_IONBF,0);
  return;
}

void printerror(char *msg){
  puts(msg);
  exit(0);
}

void readstr(char *buf, unsigned long long int length){
  int res = read(STDIN_FILENO, buf, length);
  if(res<=0)
    printerror("read error");
  buf[res]='\0';
  return;
}

int readint(){
  char buf[0x20]="\0";
  readstr(buf,0x18);
  return atoi(buf);
}

int menu(){	
  puts("========Menu========");
  puts(" 1. Create Note");
  puts(" 2. Show Note");
  puts(" 3. Edit Note");
  puts(" 4. Delete Note");
  puts(" 5. Leave");
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
  notes[idx] = calloc(1,size+8);
  if(notes[idx]==NULL)
    printerror("allocate error");
  notes[idx]->size = size;
  printf("Content : ");
  readstr(notes[idx]->data,size);
  return;
}

void show(){
  printf("Note index : ");
  unsigned int idx = readint();
  if(idx<0 || idx>=NOTEMAX || notes[idx]==NULL){
    puts("Invalid index");
    return;
  }
  puts(notes[idx]->data);
  return;
}

void edit(){
  printf("Note index : ");
  unsigned int idx = readint();
  if(idx<0 || idx>=NOTEMAX || notes[idx]==NULL){
    puts("Invalid index");
    return;
  }
  printf("Content : ");
  readstr(notes[idx]->data,notes[idx]->size);
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

int main(){
  initproc();
  while(1){
    switch(menu()){
      case 1:
        create();
        break;
      case 2:
	show();
	break;
      case 3:
	edit();
        break;
      case 4:
	delete();
	break;
      case 5:
	puts("Goodbye");
	return 0;
      default:
	puts("No such instruction");
	break;
    }
  }
  return 0;
}
